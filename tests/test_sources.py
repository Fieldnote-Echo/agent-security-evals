from __future__ import annotations

import json
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq
import pytest

from agent_security_evals.contracts import EvalRecord
from agent_security_evals.extractors import (
    extract_data_agent_harbor,
    extract_openhands_feedback,
)
from agent_security_evals.io import sha256_file, write_jsonl
from agent_security_evals.sources import (
    Manifest,
    SourceFile,
    SourceSpec,
    _download,
    load_manifest,
    prepare_suite,
)


PACKAGE_ROOT = Path(__file__).parents[1] / "src" / "agent_security_evals"
MANIFEST_PATH = PACKAGE_ROOT / "data" / "manifest.json"


def _source(name: str) -> dict[str, str]:
    return {
        "name": name,
        "revision": "1",
        "homepage": "https://example.invalid/source",
        "license": "MIT",
    }


def test_public_manifest_is_valid() -> None:
    manifest = load_manifest(MANIFEST_PATH)

    assert manifest.suites["labeled-core"] == (
        "llmail_phase2",
        "gandalf",
        "notinject",
        "injecagent",
    )
    assert manifest.sources["llmail_phase2"].redistribution == "vendored-normalized"


def test_prepare_smoke_is_byte_stable(tmp_path: Path) -> None:
    manifest = load_manifest(MANIFEST_PATH)

    first = prepare_suite(
        manifest=manifest,
        suite="smoke",
        data_dir=tmp_path,
        package_root=PACKAGE_ROOT,
    )
    first_bytes = first.read_bytes()
    second = prepare_suite(
        manifest=manifest,
        suite="smoke",
        data_dir=tmp_path,
        package_root=PACKAGE_ROOT,
    )

    assert second.read_bytes() == first_bytes
    assert len(first_bytes.splitlines()) == 4


def test_prepare_rejects_duplicate_record_ids(tmp_path: Path) -> None:
    record = EvalRecord.create(
        record_id="duplicate:0",
        text="text",
        surface="thought",
        origin="synthetic",
        group_id=None,
        source={
            "dataset": "duplicate",
            "revision": "1",
            "homepage": "https://example.invalid/source",
            "license": "MIT",
            "coordinates": {"row": 0},
        },
        label={
            "value": "unknown",
            "provenance": "authored",
            "confidence": "unknown",
        },
    )
    source_path = tmp_path / "duplicate.jsonl"
    write_jsonl(source_path, [record.to_dict(), record.to_dict()])
    file = SourceFile(
        name="duplicate.jsonl",
        bytes=source_path.stat().st_size,
        sha256=sha256_file(source_path),
        url=None,
        packaged_path="duplicate.jsonl",
    )
    source = SourceSpec(
        name="duplicate",
        homepage="https://example.invalid/source",
        revision="1",
        license="MIT",
        redistribution="vendored",
        extractor="vendored",
        files=(file,),
    )

    with pytest.raises(ValueError, match="Duplicate record ID"):
        prepare_suite(
            manifest=Manifest(
                sources={"duplicate": source}, suites={"duplicate": ("duplicate",)}
            ),
            suite="duplicate",
            data_dir=tmp_path / "data",
            package_root=tmp_path,
        )


def test_manifest_rejects_path_traversal(tmp_path: Path) -> None:
    manifest = {
        "schema_version": 1,
        "sources": {
            "bad": {
                "homepage": "https://example.invalid/source",
                "revision": "1",
                "license": "MIT",
                "redistribution": "vendored",
                "extractor": "vendored",
                "files": [
                    {
                        "name": "bad.jsonl",
                        "bytes": 0,
                        "sha256": "0" * 64,
                        "packaged_path": "../bad.jsonl",
                    }
                ],
            }
        },
        "suites": {"bad": ["bad"]},
    }
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(ValueError, match="Unsafe packaged path"):
        load_manifest(path)


def test_download_stops_at_declared_size_and_removes_partial(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class Response:
        def __init__(self) -> None:
            self.sent = False

        def __enter__(self) -> Response:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def geturl(self) -> str:
            return "https://example.invalid/data"

        def read(self, _size: int) -> bytes:
            if self.sent:
                return b""
            self.sent = True
            return b"too large"

    monkeypatch.setattr("urllib.request.urlopen", lambda *_args, **_kwargs: Response())
    file = SourceFile(
        name="data.bin",
        bytes=2,
        sha256="0" * 64,
        url="https://example.invalid/data",
        packaged_path=None,
    )
    source = SourceSpec(
        name="source",
        homepage="https://example.invalid/source",
        revision="1",
        license="MIT",
        redistribution="download-only",
        extractor="vendored",
        files=(file,),
    )
    destination = tmp_path / "data.bin"

    with pytest.raises(ValueError, match="exceeds its declared size"):
        _download(source, file, destination)

    assert not destination.exists()
    assert not (tmp_path / "data.bin.part").exists()


def test_download_rejects_https_redirect_to_http(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class Response:
        def __enter__(self) -> Response:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def geturl(self) -> str:
            return "http://example.invalid/data"

        def read(self, _size: int) -> bytes:
            return b""

    monkeypatch.setattr("urllib.request.urlopen", lambda *_args, **_kwargs: Response())
    file = SourceFile(
        name="data.bin",
        bytes=0,
        sha256="0" * 64,
        url="https://example.invalid/data",
        packaged_path=None,
    )
    source = SourceSpec(
        name="source",
        homepage="https://example.invalid/source",
        revision="1",
        license="MIT",
        redistribution="download-only",
        extractor="vendored",
        files=(file,),
    )
    destination = tmp_path / "data.bin"

    with pytest.raises(ValueError, match="redirected outside HTTPS"):
        _download(source, file, destination)

    assert not destination.exists()
    assert not (tmp_path / "data.bin.part").exists()


def test_openhands_extractor_preserves_command(tmp_path: Path) -> None:
    command = "printf 'first\\nsecond'\n  ls"
    path = tmp_path / "openhands.parquet"
    pq.write_table(
        pa.Table.from_pylist(
            [
                {
                    "trajectory": [
                        {
                            "action": "run",
                            "extras": json.dumps({"command": command}),
                            "id": "event",
                            "source": "agent",
                        },
                        {
                            "action": "run",
                            "extras": json.dumps({"command": "from user"}),
                            "id": "user-event",
                            "source": "user",
                        },
                        {
                            "action": "run",
                            "extras": json.dumps({"command": "from human"}),
                            "id": "human-event",
                            "source": "human",
                        },
                        {
                            "action": "run",
                            "extras": json.dumps({"command": "from unknown"}),
                            "id": "unknown-event",
                            "source": "tool",
                        },
                    ]
                }
            ]
        ),
        path,
    )

    records = list(extract_openhands_feedback(_source("openhands_feedback"), [path]))

    assert [record.text for record in records] == [
        command,
        "from user",
        "from human",
        "from unknown",
    ]
    assert [record.origin for record in records] == [
        "agent",
        "human",
        "human",
        "unknown",
    ]
    assert records[0].label["value"] == "operational"


def test_harbor_extractor_preserves_bash_calls(tmp_path: Path) -> None:
    message = json.dumps(
        {
            "tool_calls": [
                {
                    "type": "function",
                    "function": {
                        "name": "bash",
                        "arguments": {"command": "echo one"},
                    },
                }
            ]
        }
    )
    path = tmp_path / "harbor.parquet"
    pq.write_table(
        pa.Table.from_pylist(
            [{"task_id": "task", "source_agent": "agent", "messages": [message]}]
        ),
        path,
    )

    records = list(extract_data_agent_harbor(_source("data_agent_harbor"), [path]))

    assert [record.text for record in records] == ["echo one"]
    assert records[0].group_id == "data_agent_harbor:task"
