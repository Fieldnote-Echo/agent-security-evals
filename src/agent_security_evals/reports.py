"""Metrics and comparison reports for neutral analyzer results."""

from __future__ import annotations

import math
import statistics
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable

from agent_security_evals.contracts import EvalRecord, EvalResult
from agent_security_evals.io import (
    metadata_path,
    read_json,
    read_jsonl,
    sha256_text,
    write_json,
    write_jsonl,
    write_text,
)


def _wilson(successes: int, total: int) -> dict[str, float] | None:
    if total == 0:
        return None
    z = 1.959963984540054
    proportion = successes / total
    denominator = 1 + z * z / total
    center = (proportion + z * z / (2 * total)) / denominator
    spread = (
        z
        * math.sqrt(proportion * (1 - proportion) / total + z * z / (4 * total * total))
        / denominator
    )
    return {
        "value": proportion,
        "lower_95": max(0.0, center - spread),
        "upper_95": min(1.0, center + spread),
    }


def _percentile(values: list[int], fraction: float) -> int:
    if not values:
        return 0
    ordered = sorted(values)
    index = max(0, math.ceil(fraction * len(ordered)) - 1)
    return ordered[index]


def _rate_block(results: Iterable[EvalResult]) -> dict[str, Any]:
    values = list(results)
    status = Counter(result.status for result in values)
    determinate = status["match"] + status["no_match"]
    return {
        "total": len(values),
        "determinate": determinate,
        "coverage": determinate / len(values) if values else None,
        "matches": status["match"],
        "rate": _wilson(status["match"], determinate),
        "statuses": dict(sorted(status.items())),
    }


def calculate_metrics(
    records: list[EvalRecord], results: list[EvalResult]
) -> dict[str, Any]:
    by_id = {record.id: record for record in records}
    joined = [(by_id[result.record_id], result) for result in results]
    by_label: dict[str, list[EvalResult]] = defaultdict(list)
    by_source: dict[str, list[EvalResult]] = defaultdict(list)
    by_surface: dict[str, list[EvalResult]] = defaultdict(list)
    for record, result in joined:
        by_label[record.label["value"]].append(result)
        by_source[record.source["dataset"]].append(result)
        by_surface[record.surface].append(result)

    label_metrics = {
        label: _rate_block(values) for label, values in sorted(by_label.items())
    }
    if "attack" in label_metrics:
        label_metrics["attack"]["rate_name"] = "recall"
    if "benign" in label_metrics:
        label_metrics["benign"]["rate_name"] = "false_positive_rate"
    if "operational" in label_metrics:
        label_metrics["operational"]["rate_name"] = "alert_rate"

    unique_results: dict[str, EvalResult] = {}
    unique_signatures: dict[str, set[str]] = defaultdict(set)
    for record, result in joined:
        unique_results.setdefault(record.text_sha256, result)
        unique_signatures[record.text_sha256].add(result.semantic_signature())
    inconsistent_unique_texts = sum(
        len(signatures) > 1 for signatures in unique_signatures.values()
    )
    consistent_unique_results = (
        result
        for text_hash, result in unique_results.items()
        if len(unique_signatures[text_hash]) == 1
    )
    latency = [result.elapsed_ns for result in results]
    return {
        "schema_version": 1,
        "records": len(records),
        "unique_texts": len(unique_results),
        "inconsistent_unique_texts": inconsistent_unique_texts,
        "statuses": dict(sorted(Counter(result.status for result in results).items())),
        "labels": label_metrics,
        "sources": {
            name: _rate_block(values) for name, values in sorted(by_source.items())
        },
        "surfaces": {
            name: _rate_block(values) for name, values in sorted(by_surface.items())
        },
        "unique_text_statuses": dict(
            sorted(
                Counter(result.status for result in consistent_unique_results).items()
            )
        ),
        "latency_ns": {
            "count": len(latency),
            "median": int(statistics.median(latency)) if latency else 0,
            "p95": _percentile(latency, 0.95),
            "maximum": max(latency, default=0),
            "total": sum(latency),
        },
    }


def _rate_line(label: str, block: dict[str, Any]) -> str:
    rate = block["rate"]
    if rate is None:
        value = "not available"
    else:
        value = (
            f"{rate['value']:.2%} "
            f"(95% CI {rate['lower_95']:.2%}-{rate['upper_95']:.2%})"
        )
    name = block.get("rate_name", "match_rate").replace("_", " ")
    return (
        f"- `{label}` {name}: {value}; {block['determinate']} determinate of "
        f"{block['total']} records"
    )


def write_run_report(
    path: Path,
    metrics: dict[str, Any],
    run_metadata: dict[str, Any],
) -> None:
    adapter_metadata = run_metadata["adapter_metadata"]
    lines = [
        "# Agent security evaluation",
        "",
        f"- Adapter: `{run_metadata['adapter']}`",
        f"- Input records: {metrics['records']}",
        f"- Unique text values: {metrics['unique_texts']}",
        (
            "- Unique text values with different semantic results: "
            f"{metrics['inconsistent_unique_texts']}"
        ),
        f"- Status counts: `{metrics['statuses']}`",
        "",
        "## Labeled and operational rates",
        "",
    ]
    lines.extend(_rate_line(label, block) for label, block in metrics["labels"].items())
    project_to = run_metadata.get("project_to")
    if project_to is not None:
        lines.extend(
            [
                "",
                "## Projection",
                "",
                f"Every record was explicitly projected to `{project_to}`.",
                "This result measures pattern behavior on that field.",
                "It does not measure native end-to-end detection.",
            ]
        )
    lines.extend(
        [
            "",
            "Attack recall and benign false-positive rate use only determinate results.",
            "Unknown, skipped, and error results stay separate in the status counts.",
            "Operational alert rate is not a false-positive rate.",
            "",
            "## Runtime",
            "",
            f"- Median: {metrics['latency_ns']['median']} ns",
            f"- p95: {metrics['latency_ns']['p95']} ns",
            f"- Maximum: {metrics['latency_ns']['maximum']} ns",
            f"- Total: {metrics['latency_ns']['total']} ns",
        ]
    )
    if adapter_metadata.get("complete_rule_evaluation") is False:
        lines.extend(
            [
                "",
                "## Coverage limit",
                "",
                "The adapter did not evaluate every rule condition.",
                "See `results.jsonl.meta.json` for the exact degraded conditions.",
            ]
        )
    lines.extend(
        [
            "",
            "This public dataset is not a held-out benchmark.",
            "The report does not include source text.",
            "",
        ]
    )
    write_text(path, "\n".join(lines))


def _load_results(path: Path) -> list[EvalResult]:
    return [EvalResult.from_dict(value) for value in read_jsonl(path)]


def compare_runs(
    *,
    base_path: Path,
    candidate_path: Path,
    output_dir: Path,
    stable_sample_size: int = 20,
) -> dict[str, Any]:
    base_results = _load_results(base_path)
    candidate_results = _load_results(candidate_path)
    base = {result.record_id: result for result in base_results}
    candidate = {result.record_id: result for result in candidate_results}
    if len(base) != len(base_results) or len(candidate) != len(candidate_results):
        raise ValueError("Result files contain duplicate record IDs")
    if base.keys() != candidate.keys():
        raise ValueError("Result files do not contain the same record IDs")
    for record_id in base:
        if base[record_id].text_sha256 != candidate[record_id].text_sha256:
            raise ValueError(f"Record {record_id} has different text hashes")
        if base[record_id].case_id != candidate[record_id].case_id:
            raise ValueError(f"Record {record_id} has different evaluation cases")

    base_meta = read_json(metadata_path(base_path))
    candidate_meta = read_json(metadata_path(candidate_path))
    if base_meta["input_sha256"] != candidate_meta["input_sha256"]:
        raise ValueError("Runs do not use the same input content")
    if base_meta.get("project_to") != candidate_meta.get("project_to"):
        raise ValueError("Runs do not use the same projection")

    changed = {
        record_id
        for record_id in base
        if base[record_id].semantic_signature()
        != candidate[record_id].semantic_signature()
    }
    matched = {
        record_id
        for record_id in base
        if "match" in {base[record_id].status, candidate[record_id].status}
    }
    failures = {
        record_id
        for record_id in base
        if base[record_id].status == "error" or candidate[record_id].status == "error"
    }
    stable_no_match = sorted(
        (
            record_id
            for record_id in base
            if base[record_id].status == "no_match"
            and candidate[record_id].status == "no_match"
            and record_id not in changed
        ),
        key=lambda record_id: sha256_text(f"stable-v1\0{record_id}"),
    )[:stable_sample_size]
    review_ids = sorted(changed | matched | failures | set(stable_no_match))

    records: dict[str, EvalRecord] = {}
    input_path = Path(base_meta["input"])
    if input_path.is_file():
        records = {
            record.id: record
            for record in (
                EvalRecord.from_dict(value) for value in read_jsonl(input_path)
            )
        }
    review: list[dict[str, Any]] = []
    for record_id in review_ids:
        reasons = []
        if record_id in changed:
            reasons.append("changed")
        if record_id in matched:
            reasons.append("match")
        if record_id in failures:
            reasons.append("error")
        if record_id in stable_no_match:
            reasons.append("stable_no_match_sample")
        record = records.get(record_id)
        review.append(
            {
                "record_id": record_id,
                "text_sha256": base[record_id].text_sha256,
                "source": record.source["dataset"] if record else None,
                "surface": record.surface if record else None,
                "label": record.label["value"] if record else None,
                "reasons": reasons,
                "base": base[record_id].to_dict(),
                "candidate": candidate[record_id].to_dict(),
            }
        )

    summary = {
        "schema_version": 1,
        "records": len(base),
        "changed": len(changed),
        "matched": len(matched),
        "errors": len(failures),
        "stable_no_match_sample": len(stable_no_match),
        "review_records": len(review),
        "base_adapter": base_meta["adapter"],
        "candidate_adapter": candidate_meta["adapter"],
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    write_jsonl(output_dir / "review.jsonl", review)
    write_json(output_dir / "comparison.json", summary)
    lines = [
        "# Agent security evaluation comparison",
        "",
        f"- Records: {summary['records']}",
        f"- Semantic changes: {summary['changed']}",
        f"- Matches in either run: {summary['matched']}",
        f"- Errors in either run: {summary['errors']}",
        f"- Review records: {summary['review_records']}",
        "",
        "Latency does not affect semantic change detection.",
        "The review file does not include source text.",
        "",
    ]
    write_text(output_dir / "comparison.md", "\n".join(lines))
    return summary
