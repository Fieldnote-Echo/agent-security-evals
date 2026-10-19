from __future__ import annotations

from pathlib import Path

import pytest

from agent_security_evals.contracts import EvalRecord, EvalResult
from agent_security_evals.reports import calculate_metrics, write_run_report


def _record(record_id: str) -> EvalRecord:
    return EvalRecord.create(
        record_id=record_id,
        text="duplicate text",
        surface="thought",
        origin="synthetic",
        group_id=None,
        source={
            "dataset": "fixture",
            "revision": "1",
            "homepage": "https://example.invalid/fixture",
            "license": "MIT",
            "coordinates": {"id": record_id},
        },
        label={
            "value": "attack",
            "provenance": "authored",
            "confidence": "high",
        },
    )


def _result(record: EvalRecord, status: str) -> EvalResult:
    return EvalResult.from_dict(
        {
            "schema_version": 1,
            "record_id": record.id,
            "text_sha256": record.text_sha256,
            "adapter": "fixture",
            "case_id": "native",
            "status": status,
            "findings": [],
            "attributes": {},
            "elapsed_ns": 1,
            "error": None,
        }
    )


def test_metrics_report_inconsistent_results_for_duplicate_text() -> None:
    first = _record("fixture:1")
    second = _record("fixture:2")

    metrics = calculate_metrics(
        [first, second],
        [_result(first, "match"), _result(second, "no_match")],
    )

    assert metrics["unique_texts"] == 1
    assert metrics["inconsistent_unique_texts"] == 1
    assert metrics["unique_text_statuses"] == {}


def test_run_report_preserves_existing_file_when_replace_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "report.md"
    path.write_text("existing report", encoding="utf-8")

    def fail_replace(_source: Path, _target: Path) -> Path:
        raise OSError("replace failed")

    monkeypatch.setattr(Path, "replace", fail_replace)

    with pytest.raises(OSError, match="replace failed"):
        write_run_report(
            path,
            {
                "records": 1,
                "unique_texts": 1,
                "inconsistent_unique_texts": 0,
                "statuses": {"no_match": 1},
                "labels": {},
                "latency_ns": {
                    "median": 1,
                    "p95": 1,
                    "maximum": 1,
                    "total": 1,
                },
            },
            {"adapter": "fixture", "adapter_metadata": {}},
        )

    assert path.read_text(encoding="utf-8") == "existing report"
    assert list(tmp_path.glob(".report.md.*.part")) == []
