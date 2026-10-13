from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import urllib.request
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parent
DEFAULT_MANIFEST = ROOT / "corpora.json"
DEFAULT_DATA_DIR = ROOT / "data" / "raw"
ANALYZER_NAMES = ("pattern", "policy_rails")


@dataclass(frozen=True)
class CorpusSpec:
    name: str
    repo_id: str
    revision: str
    file: str
    bytes: int
    sha256: str
    license: str
    homepage: str
    default_sample_size: int

    @property
    def url(self) -> str:
        return (
            f"https://huggingface.co/datasets/{self.repo_id}/resolve/"
            f"{self.revision}/{self.file}"
        )

    def local_path(self, data_dir: Path) -> Path:
        return data_dir / self.name / self.revision / Path(self.file).name


def _sha256_bytes(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def _write_jsonl(path: Path, values: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as stream:
        for value in values:
            stream.write(json.dumps(value, ensure_ascii=False, sort_keys=True))
            stream.write("\n")


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    values = []
    with path.open(encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, start=1):
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSON at {path}:{line_number}") from exc
            if not isinstance(value, dict):
                raise ValueError(f"Expected an object at {path}:{line_number}")
            values.append(value)
    return values


def _metadata_path(path: Path) -> Path:
    return path.with_suffix(".meta.json")


def load_manifest(path: Path) -> dict[str, CorpusSpec]:
    raw = json.loads(path.read_text())
    return {
        name: CorpusSpec(name=name, **value) for name, value in raw["corpora"].items()
    }


def _validate_download(path: Path, spec: CorpusSpec) -> None:
    actual_bytes = path.stat().st_size
    if actual_bytes != spec.bytes:
        raise ValueError(
            f"{spec.name}: expected {spec.bytes} bytes, found {actual_bytes}"
        )
    actual_hash = _sha256_file(path)
    if actual_hash != spec.sha256:
        raise ValueError(
            f"{spec.name}: expected SHA-256 {spec.sha256}, found {actual_hash}"
        )


def fetch_corpora(specs: dict[str, CorpusSpec], data_dir: Path) -> None:
    for spec in specs.values():
        destination = spec.local_path(data_dir)
        if destination.exists():
            _validate_download(destination, spec)
            print(f"verified {spec.name}: {destination}")
            continue

        destination.parent.mkdir(parents=True, exist_ok=True)
        partial = destination.with_suffix(destination.suffix + ".part")
        request = urllib.request.Request(
            spec.url,
            headers={"User-Agent": "agent-shell-corpus/0.1"},
        )
        try:
            with urllib.request.urlopen(request) as response, partial.open("wb") as out:
                while block := response.read(1024 * 1024):
                    out.write(block)
            _validate_download(partial, spec)
            partial.replace(destination)
        except BaseException:
            partial.unlink(missing_ok=True)
            raise
        print(f"downloaded {spec.name}: {destination}")


def _record(
    *,
    corpus: str,
    command: str,
    coordinates: dict[str, Any],
    metadata: dict[str, Any],
) -> dict[str, Any]:
    coordinate_text = ":".join(str(value) for value in coordinates.values())
    record_id = f"{corpus}:{coordinate_text}"
    return {
        "id": record_id,
        "corpus": corpus,
        "command": command,
        "command_sha256": _sha256_bytes(command),
        "coordinates": coordinates,
        "metadata": metadata,
    }


def extract_openhands_feedback(path: Path) -> list[dict[str, Any]]:
    import pyarrow.parquet as pq

    records = []
    table = pq.read_table(path, columns=["trajectory"])
    for row_index, trajectory in enumerate(table.column("trajectory").to_pylist()):
        for event_index, event in enumerate(trajectory or []):
            if event.get("action") != "run":
                continue
            extras = json.loads(event["extras"])
            command = extras.get("command")
            if not isinstance(command, str):
                continue
            records.append(
                _record(
                    corpus="openhands_feedback",
                    command=command,
                    coordinates={"row": row_index, "event": event_index},
                    metadata={
                        "event_id": event.get("id"),
                        "source": event.get("source"),
                    },
                )
            )
    return records


def extract_data_agent_harbor(path: Path) -> list[dict[str, Any]]:
    import pyarrow.parquet as pq

    records = []
    table = pq.read_table(path, columns=["task_id", "source_agent", "messages"])
    for row_index, row in enumerate(table.to_pylist()):
        for message_index, encoded_message in enumerate(row["messages"] or []):
            message = json.loads(encoded_message)
            for call_index, call in enumerate(message.get("tool_calls") or []):
                function = call.get("function") or {}
                if call.get("type") != "function" or function.get("name") != "bash":
                    continue
                arguments = function.get("arguments")
                if not isinstance(arguments, dict):
                    continue
                command = arguments.get("command")
                if not isinstance(command, str):
                    continue
                records.append(
                    _record(
                        corpus="data_agent_harbor",
                        command=command,
                        coordinates={
                            "row": row_index,
                            "message": message_index,
                            "tool_call": call_index,
                        },
                        metadata={
                            "task_id": row["task_id"],
                            "source_agent": row["source_agent"],
                        },
                    )
                )
    return records


def _sample(
    records: list[dict[str, Any]],
    size: int,
    seed: str,
) -> list[dict[str, Any]]:
    if size < 0:
        raise ValueError("Sample size must not be negative")
    if size > len(records):
        raise ValueError(f"Requested {size} records, but only {len(records)} exist")
    ranked = sorted(
        records,
        key=lambda record: hashlib.sha256(f"{seed}\0{record['id']}".encode()).digest(),
    )[:size]
    return sorted(ranked, key=lambda record: record["id"])


def extract_corpora(
    specs: dict[str, CorpusSpec],
    data_dir: Path,
    output: Path,
    seed: str,
    sample_sizes: dict[str, int],
) -> None:
    adapters = {
        "openhands_feedback": extract_openhands_feedback,
        "data_agent_harbor": extract_data_agent_harbor,
    }
    selected = []
    counts = {}
    for name, spec in specs.items():
        source = spec.local_path(data_dir)
        _validate_download(source, spec)
        records = adapters[name](source)
        sample = _sample(records, sample_sizes[name], seed)
        selected.extend(sample)
        counts[name] = {"available": len(records), "selected": len(sample)}

    _write_jsonl(output, selected)
    _write_json(
        _metadata_path(output),
        {
            "seed": seed,
            "count": len(selected),
            "corpora": {
                name: {
                    "revision": spec.revision,
                    "file": spec.file,
                    "sha256": spec.sha256,
                    **counts[name],
                }
                for name, spec in specs.items()
            },
        },
    )
    print(f"wrote {len(selected)} shell-call records: {output}")


def _git_head(checkout: Path) -> str:
    head = subprocess.run(
        ["git", "-C", str(checkout), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    )
    status = subprocess.run(
        ["git", "-C", str(checkout), "status", "--porcelain=v1"],
        check=True,
        capture_output=True,
        text=True,
    )
    if status.stdout:
        raise ValueError(f"SDK checkout is not clean: {checkout}")
    return head.stdout.strip()


def analyze(
    *,
    checkout: Path,
    python: Path,
    input_path: Path,
    output: Path,
    label: str,
) -> None:
    checkout = checkout.resolve()
    python = python.absolute()
    input_path = input_path.resolve()
    output = output.resolve()
    input_metadata_path = _metadata_path(input_path)
    output_metadata_path = _metadata_path(output)
    if {input_path, input_metadata_path} & {output, output_metadata_path}:
        raise ValueError("Input and output paths must not overlap")
    sdk_source = checkout / "openhands-sdk"
    if not sdk_source.is_dir():
        raise ValueError(f"SDK source does not exist: {sdk_source}")
    if not python.is_file():
        raise ValueError(f"Python executable does not exist: {python}")

    output.parent.mkdir(parents=True, exist_ok=True)
    output.unlink(missing_ok=True)
    output_metadata_path.unlink(missing_ok=True)
    sdk_commit = _git_head(checkout)
    input_hash = _sha256_file(input_path)
    input_metadata_hash = _sha256_file(input_metadata_path)
    environment = {
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": os.defpath,
        "PYTHONPATH": str(sdk_source),
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONNOUSERSITE": "1",
        "OPENHANDS_SUPPRESS_BANNER": "1",
        "LITELLM_LOCAL_MODEL_COST_MAP": "True",
    }
    command = [
        str(python),
        str(Path(__file__).resolve()),
        "_analyze-worker",
        "--input",
        str(input_path),
        "--output",
        str(output),
    ]
    try:
        subprocess.run(command, check=True, cwd=checkout, env=environment)
        if _git_head(checkout) != sdk_commit:
            raise ValueError("SDK checkout changed during analysis")
        if _sha256_file(input_path) != input_hash:
            raise ValueError("Analyzer input changed during analysis")
        if _sha256_file(input_metadata_path) != input_metadata_hash:
            raise ValueError("Analyzer input metadata changed during analysis")
        results = _read_jsonl(output)
        sample_metadata = json.loads(input_metadata_path.read_text())
    except BaseException:
        output.unlink(missing_ok=True)
        output_metadata_path.unlink(missing_ok=True)
        raise
    _write_json(
        output_metadata_path,
        {
            "label": label,
            "sdk_checkout": str(checkout),
            "sdk_commit": sdk_commit,
            "input": str(input_path),
            "input_sha256": input_hash,
            "sample": sample_metadata,
            "count": len(results),
            "harness_started_shell": False,
            "worker_sandboxed": False,
        },
    )
    print(f"analyzed {len(results)} shell-call records: {output}")


def _analyze_worker(input_path: Path, output: Path) -> None:
    from openhands.sdk.event import ActionEvent
    from openhands.sdk.llm import MessageToolCall, TextContent
    from openhands.sdk.security import (
        PatternSecurityAnalyzer,
        PolicyRailSecurityAnalyzer,
    )

    analyzers = {
        "pattern": PatternSecurityAnalyzer(),
        "policy_rails": PolicyRailSecurityAnalyzer(),
    }
    results = []
    for record in _read_jsonl(input_path):
        command = record.get("command")
        if not isinstance(command, str):
            raise ValueError(f"Record {record.get('id')} has no string command")
        if record.get("command_sha256") != _sha256_bytes(command):
            raise ValueError(f"Record {record.get('id')} has an invalid command hash")
        action = ActionEvent(
            thought=[TextContent(text="corpus replay")],
            tool_name="bash",
            tool_call_id=record["id"],
            tool_call=MessageToolCall(
                id=record["id"],
                name="bash",
                arguments=json.dumps({"command": command}),
                origin="completion",
            ),
            llm_response_id=record["id"],
        )
        analyzer_results = {}
        for name, analyzer in analyzers.items():
            try:
                analyzer_results[name] = {
                    "risk": analyzer.security_risk(action).name,
                    "error": None,
                }
            except Exception as exc:
                analyzer_results[name] = {
                    "risk": "ERROR",
                    "error": f"{type(exc).__name__}: {exc}",
                }
        results.append({**record, "analyzers": analyzer_results})
    _write_jsonl(output, results)


def _result_signature(record: dict[str, Any]) -> tuple[tuple[str, str, Any], ...]:
    return tuple(
        (
            name,
            record["analyzers"][name]["risk"],
            record["analyzers"][name]["error"],
        )
        for name in ANALYZER_NAMES
    )


def _is_high(record: dict[str, Any]) -> bool:
    return any(record["analyzers"][name]["risk"] == "HIGH" for name in ANALYZER_NAMES)


def _has_error(record: dict[str, Any]) -> bool:
    return any(record["analyzers"][name]["error"] for name in ANALYZER_NAMES)


def _all_low(record: dict[str, Any]) -> bool:
    return all(record["analyzers"][name]["risk"] == "LOW" for name in ANALYZER_NAMES)


def _result_counts(records: list[dict[str, Any]]) -> dict[str, dict[str, int]]:
    return {
        name: dict(Counter(record["analyzers"][name]["risk"] for record in records))
        for name in ANALYZER_NAMES
    }


def compare(
    *,
    base_path: Path,
    candidate_path: Path,
    review_output: Path,
    report: Path,
    low_sample_size: int,
    seed: str,
) -> None:
    base_records = _read_jsonl(base_path)
    candidate_records = _read_jsonl(candidate_path)
    base = {record["id"]: record for record in base_records}
    candidate = {record["id"]: record for record in candidate_records}
    if len(base) != len(base_records) or len(candidate) != len(candidate_records):
        raise ValueError("Result files contain duplicate record IDs")
    if base.keys() != candidate.keys():
        raise ValueError("Result files do not contain the same record IDs")
    for record_id in base:
        for field in ("corpus", "command", "command_sha256", "coordinates"):
            if base[record_id][field] != candidate[record_id][field]:
                raise ValueError(f"Record {record_id} differs in {field}")

    changed = {
        record_id
        for record_id in base
        if _result_signature(base[record_id]) != _result_signature(candidate[record_id])
    }
    high = {
        record_id
        for record_id in base
        if _is_high(base[record_id]) or _is_high(candidate[record_id])
    }
    errors = {
        record_id
        for record_id in base
        if _has_error(base[record_id]) or _has_error(candidate[record_id])
    }
    low_candidates = [
        base[record_id]
        for record_id in base
        if record_id not in changed
        and _all_low(base[record_id])
        and _all_low(candidate[record_id])
    ]
    low_sample = {
        record["id"]
        for record in _sample(
            low_candidates,
            min(low_sample_size, len(low_candidates)),
            seed,
        )
    }
    review_ids = sorted(changed | high | errors | low_sample)
    review = []
    for record_id in review_ids:
        reasons = []
        if record_id in changed:
            reasons.append("changed")
        if record_id in high:
            reasons.append("high")
        if record_id in errors:
            reasons.append("error")
        if record_id in low_sample:
            reasons.append("unchanged_low_sample")
        review.append(
            {
                "id": record_id,
                "corpus": base[record_id]["corpus"],
                "command": base[record_id]["command"],
                "command_sha256": base[record_id]["command_sha256"],
                "coordinates": base[record_id]["coordinates"],
                "metadata": base[record_id]["metadata"],
                "reasons": reasons,
                "base": base[record_id]["analyzers"],
                "candidate": candidate[record_id]["analyzers"],
            }
        )
    base_meta = json.loads(_metadata_path(base_path).read_text())
    candidate_meta = json.loads(_metadata_path(candidate_path).read_text())
    if base_meta["input_sha256"] != candidate_meta["input_sha256"]:
        raise ValueError("Analyzer runs do not use the same input file")
    if base_meta["sample"] != candidate_meta["sample"]:
        raise ValueError("Analyzer runs do not use the same sample metadata")
    sample_meta = base_meta["sample"]
    _write_jsonl(review_output, review)
    corpus_lines = [
        (
            f"- `{name}`: {value['selected']} of {value['available']} shell-call "
            f"records; revision `{value['revision']}`"
        )
        for name, value in sample_meta["corpora"].items()
    ]
    report_text = "\n".join(
        [
            "# Analyzer corpus comparison",
            "",
            (
                "The harness did not start a shell or pass corpus commands as "
                "subprocess arguments or environment values. It passed each command "
                "only to the selected analyzer APIs."
            ),
            "",
            "## Inputs",
            "",
            *corpus_lines,
            f"- Base SDK: `{base_meta['sdk_commit']}`",
            f"- Candidate SDK: `{candidate_meta['sdk_commit']}`",
            "",
            "## Results",
            "",
            f"- Shell-call records: {len(base)}",
            f"- Shell-call records with changed results: {len(changed)}",
            f"- Shell-call records with a `HIGH` result: {len(high)}",
            f"- Shell-call records with an analyzer error: {len(errors)}",
            f"- Unchanged `LOW` sample: {len(low_sample)}",
            f"- Review records: {len(review)}",
            "",
            f"- Base counts: `{json.dumps(_result_counts(base_records), sort_keys=True)}`",
            "- Candidate counts: "
            f"`{json.dumps(_result_counts(candidate_records), sort_keys=True)}`",
            "",
            f"Review the exact commands and results in `{review_output.name}`.",
            "",
        ]
    )
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text(report_text)
    print(f"wrote {len(review)} review records: {review_output}")
    print(f"wrote comparison report: {report}")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Check OpenHands security analyzers against public agent traces."
    )
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    subparsers = parser.add_subparsers(dest="command", required=True)

    fetch_parser = subparsers.add_parser("fetch")
    fetch_parser.add_argument("--data-dir", type=Path, default=DEFAULT_DATA_DIR)

    extract_parser = subparsers.add_parser("extract")
    extract_parser.add_argument("--data-dir", type=Path, default=DEFAULT_DATA_DIR)
    extract_parser.add_argument("--output", type=Path, required=True)
    extract_parser.add_argument("--seed", default="agent-shell-corpus-v1")
    extract_parser.add_argument("--openhands-count", type=int)
    extract_parser.add_argument("--harbor-count", type=int)

    analyze_parser = subparsers.add_parser("analyze")
    analyze_parser.add_argument("--sdk-checkout", type=Path, required=True)
    analyze_parser.add_argument("--python", type=Path, required=True)
    analyze_parser.add_argument("--input", type=Path, required=True)
    analyze_parser.add_argument("--output", type=Path, required=True)
    analyze_parser.add_argument("--label", required=True)

    worker_parser = subparsers.add_parser("_analyze-worker", help=argparse.SUPPRESS)
    worker_parser.add_argument("--input", type=Path, required=True)
    worker_parser.add_argument("--output", type=Path, required=True)

    compare_parser = subparsers.add_parser("compare")
    compare_parser.add_argument("--base", type=Path, required=True)
    compare_parser.add_argument("--candidate", type=Path, required=True)
    compare_parser.add_argument("--review-output", type=Path, required=True)
    compare_parser.add_argument("--report", type=Path, required=True)
    compare_parser.add_argument("--low-sample-size", type=int, default=20)
    compare_parser.add_argument("--seed", default="agent-shell-corpus-review-v1")
    return parser


def main() -> None:
    args = _parser().parse_args()
    if args.command == "_analyze-worker":
        _analyze_worker(args.input, args.output)
        return

    if args.command == "analyze":
        analyze(
            checkout=args.sdk_checkout,
            python=args.python,
            input_path=args.input,
            output=args.output,
            label=args.label,
        )
        return

    if args.command == "compare":
        compare(
            base_path=args.base,
            candidate_path=args.candidate,
            review_output=args.review_output,
            report=args.report,
            low_sample_size=args.low_sample_size,
            seed=args.seed,
        )
        return

    specs = load_manifest(args.manifest)
    if args.command == "fetch":
        fetch_corpora(specs, args.data_dir)
        return

    sample_sizes = {name: spec.default_sample_size for name, spec in specs.items()}
    if args.openhands_count is not None:
        sample_sizes["openhands_feedback"] = args.openhands_count
    if args.harbor_count is not None:
        sample_sizes["data_agent_harbor"] = args.harbor_count
    extract_corpora(
        specs,
        args.data_dir,
        args.output,
        args.seed,
        sample_sizes,
    )


if __name__ == "__main__":
    main()
