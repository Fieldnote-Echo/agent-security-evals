"""Pinned source downloads and deterministic suite preparation."""

from __future__ import annotations

import re
import urllib.request
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from agent_security_evals.contracts import EvalRecord
from agent_security_evals.extractors import EXTRACTORS
from agent_security_evals.io import (
    metadata_path,
    read_json,
    sha256_file,
    write_json,
    write_jsonl,
)


_SAFE_IDENTIFIER = re.compile(r"[a-z0-9][a-z0-9._-]*\Z")
_SAFE_FILE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\Z")
_DOWNLOAD_TIMEOUT_SECONDS = 60
_CHUNK_BYTES = 1024 * 1024


@dataclass(frozen=True)
class SourceFile:
    name: str
    bytes: int
    sha256: str
    url: str | None
    packaged_path: str | None

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> SourceFile:
        name = value.get("name")
        if not isinstance(name, str) or not _SAFE_FILE_NAME.fullmatch(name):
            raise ValueError(f"Unsafe source file name: {name}")
        size = value.get("bytes")
        if not isinstance(size, int) or size < 0:
            raise ValueError(f"Invalid byte count for {name}")
        digest = value.get("sha256")
        if (
            not isinstance(digest, str)
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
        ):
            raise ValueError(f"Invalid SHA-256 for {name}")
        url = value.get("url")
        packaged_path = value.get("packaged_path")
        if (url is None) == (packaged_path is None):
            raise ValueError(f"{name} must have one source location")
        if url is not None and (
            not isinstance(url, str) or not url.startswith("https://")
        ):
            raise ValueError(f"Invalid download URL for {name}")
        if packaged_path is not None:
            if not isinstance(packaged_path, str):
                raise ValueError(f"Invalid packaged path for {name}")
            packaged = Path(packaged_path)
            if packaged.is_absolute() or ".." in packaged.parts:
                raise ValueError(f"Unsafe packaged path for {name}")
        return cls(
            name=name,
            bytes=size,
            sha256=digest,
            url=url,
            packaged_path=packaged_path,
        )


@dataclass(frozen=True)
class SourceSpec:
    name: str
    homepage: str
    revision: str
    license: str
    redistribution: str
    extractor: str
    files: tuple[SourceFile, ...]

    @classmethod
    def from_dict(cls, name: str, value: Mapping[str, Any]) -> SourceSpec:
        if not _SAFE_IDENTIFIER.fullmatch(name):
            raise ValueError(f"Unsafe source name: {name}")
        raw = dict(value)
        for field in ("homepage", "revision", "license", "redistribution"):
            if not isinstance(raw.get(field), str) or not raw[field]:
                raise ValueError(f"{name}.{field} must be a string")
        if not raw["homepage"].startswith("https://"):
            raise ValueError(f"{name}.homepage must use HTTPS")
        extractor = raw.get("extractor")
        if extractor not in EXTRACTORS:
            raise ValueError(f"Unknown extractor for {name}: {extractor}")
        files_raw = raw.get("files")
        if not isinstance(files_raw, list) or not files_raw:
            raise ValueError(f"{name}.files must be a non-empty list")
        files = tuple(SourceFile.from_dict(item) for item in files_raw)
        if len({file.name for file in files}) != len(files):
            raise ValueError(f"{name} contains duplicate file names")
        return cls(
            name=name,
            homepage=raw["homepage"],
            revision=raw["revision"],
            license=raw["license"],
            redistribution=raw["redistribution"],
            extractor=extractor,
            files=files,
        )

    def as_extractor_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "homepage": self.homepage,
            "revision": self.revision,
            "license": self.license,
        }


@dataclass(frozen=True)
class Manifest:
    sources: dict[str, SourceSpec]
    suites: dict[str, tuple[str, ...]]


def load_manifest(path: Path) -> Manifest:
    raw = read_json(path)
    if raw.get("schema_version") != 1:
        raise ValueError(f"Unsupported manifest schema: {raw.get('schema_version')}")
    sources_raw = raw.get("sources")
    suites_raw = raw.get("suites")
    if not isinstance(sources_raw, dict) or not isinstance(suites_raw, dict):
        raise ValueError("Manifest sources and suites must be objects")
    sources = {
        name: SourceSpec.from_dict(name, value) for name, value in sources_raw.items()
    }
    suites: dict[str, tuple[str, ...]] = {}
    for name, members in suites_raw.items():
        if not _SAFE_IDENTIFIER.fullmatch(name):
            raise ValueError(f"Unsafe suite name: {name}")
        if not isinstance(members, list) or not members:
            raise ValueError(f"Suite {name} must contain sources")
        if any(member not in sources for member in members):
            raise ValueError(f"Suite {name} names an unknown source")
        if len(set(members)) != len(members):
            raise ValueError(f"Suite {name} contains a source more than once")
        suites[name] = tuple(members)
    return Manifest(sources=sources, suites=suites)


def _validate_file(path: Path, source: str, spec: SourceFile) -> None:
    if not path.is_file():
        raise ValueError(f"Missing source file for {source}: {path}")
    actual_bytes = path.stat().st_size
    if actual_bytes != spec.bytes:
        raise ValueError(
            f"{source}/{spec.name}: expected {spec.bytes} bytes, found {actual_bytes}"
        )
    actual_hash = sha256_file(path)
    if actual_hash != spec.sha256:
        raise ValueError(
            f"{source}/{spec.name}: expected SHA-256 {spec.sha256}, found {actual_hash}"
        )


def _download(source: SourceSpec, file: SourceFile, destination: Path) -> None:
    if file.url is None:
        raise ValueError(f"{source.name}/{file.name} is not downloadable")
    destination.parent.mkdir(parents=True, exist_ok=True)
    partial = destination.with_name(f"{destination.name}.part")
    partial.unlink(missing_ok=True)
    request = urllib.request.Request(
        file.url, headers={"User-Agent": "agent-security-evals/0.1"}
    )
    received = 0
    try:
        with (
            urllib.request.urlopen(
                request, timeout=_DOWNLOAD_TIMEOUT_SECONDS
            ) as response,
            partial.open("wb") as output,
        ):
            final_url = response.geturl()
            if not isinstance(final_url, str) or not final_url.startswith("https://"):
                raise ValueError(f"{source.name}/{file.name} redirected outside HTTPS")
            while block := response.read(_CHUNK_BYTES):
                received += len(block)
                if received > file.bytes:
                    raise ValueError(
                        f"{source.name}/{file.name} exceeds its declared size"
                    )
                output.write(block)
        _validate_file(partial, source.name, file)
        partial.replace(destination)
    except BaseException:
        partial.unlink(missing_ok=True)
        raise


def _file_path(
    source: SourceSpec, file: SourceFile, data_dir: Path, package_root: Path
) -> Path:
    if file.packaged_path is not None:
        path = (package_root / file.packaged_path).resolve()
        try:
            path.relative_to(package_root.resolve())
        except ValueError as exc:
            raise ValueError(f"Packaged source escaped its root: {file.name}") from exc
        return path
    return data_dir / "raw" / source.name / source.revision / file.name


def fetch_sources(
    manifest: Manifest,
    source_names: tuple[str, ...],
    data_dir: Path,
    package_root: Path,
) -> dict[str, list[Path]]:
    paths: dict[str, list[Path]] = {}
    for source_name in source_names:
        source = manifest.sources[source_name]
        source_paths: list[Path] = []
        for file in source.files:
            destination = _file_path(source, file, data_dir, package_root)
            if destination.exists():
                _validate_file(destination, source.name, file)
            elif file.url is not None:
                _download(source, file, destination)
            else:
                raise ValueError(f"Missing packaged source: {destination}")
            source_paths.append(destination)
        paths[source_name] = source_paths
    return paths


def prepare_suite(
    *,
    manifest: Manifest,
    suite: str,
    data_dir: Path,
    package_root: Path,
) -> Path:
    if suite not in manifest.suites:
        raise ValueError(f"Unknown suite: {suite}")
    source_names = manifest.suites[suite]
    paths = fetch_sources(manifest, source_names, data_dir, package_root)

    records: list[EvalRecord] = []
    counts: dict[str, int] = {}
    seen: set[str] = set()
    for source_name in source_names:
        spec = manifest.sources[source_name]
        extractor = EXTRACTORS[spec.extractor]
        extracted = list(extractor(spec.as_extractor_dict(), paths[source_name]))
        for record in extracted:
            if record.id in seen:
                raise ValueError(f"Duplicate record ID: {record.id}")
            seen.add(record.id)
        records.extend(extracted)
        counts[source_name] = len(extracted)

    records.sort(key=lambda record: record.id)
    output = data_dir / "processed" / f"{suite}.jsonl"
    write_jsonl(output, (record.to_dict() for record in records))
    output_hash = sha256_file(output)
    write_json(
        metadata_path(output),
        {
            "schema_version": 1,
            "suite": suite,
            "count": len(records),
            "unique_texts": len({record.text_sha256 for record in records}),
            "labels": dict(Counter(record.label["value"] for record in records)),
            "output_sha256": output_hash,
            "sources": {
                name: {
                    "revision": manifest.sources[name].revision,
                    "license": manifest.sources[name].license,
                    "count": counts[name],
                    "files": [
                        {"name": file.name, "sha256": file.sha256}
                        for file in manifest.sources[name].files
                    ],
                }
                for name in source_names
            },
        },
    )
    return output
