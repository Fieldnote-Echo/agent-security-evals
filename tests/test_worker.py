from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from agent_security_evals.adapters import AdapterOutcome
from agent_security_evals.contracts import EvalRecord, Finding
from agent_security_evals.io import read_jsonl, write_json, write_jsonl
from agent_security_evals.worker import run_worker


def _email_record(text: str = "message text") -> EvalRecord:
    return EvalRecord.create(
        record_id="fixture:0",
        text=text,
        surface="email",
        origin="synthetic",
        group_id=None,
        source={
            "dataset": "fixture",
            "revision": "1",
            "homepage": "https://example.invalid/fixture",
            "license": "MIT",
            "coordinates": {"row": 0},
        },
        label={
            "value": "attack",
            "provenance": "authored",
            "confidence": "high",
        },
    )


def test_openhands_projection_is_explicit_and_preserves_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    record = _email_record()
    input_path = tmp_path / "input.jsonl"
    write_jsonl(input_path, [record.to_dict()])

    def evaluate(evaluated: EvalRecord) -> AdapterOutcome:
        if evaluated.surface == "email":
            return AdapterOutcome(status="skipped")
        return AdapterOutcome(
            status="match",
            findings=(Finding("fixture", "high", evaluated.surface),),
            attributes={"observed_surface": evaluated.surface},
        )

    monkeypatch.setattr(
        "agent_security_evals.worker.create_adapter",
        lambda _name, _config: SimpleNamespace(
            evaluate=evaluate,
            metadata=lambda: {"adapter": "fixture"},
        ),
    )

    native_config = tmp_path / "native.json"
    native_output = tmp_path / "native.jsonl"
    write_json(native_config, {"adapter": "openhands-pattern"})
    run_worker(
        input_path,
        native_output,
        tmp_path / "native-adapter.json",
        native_config,
    )

    projected_config = tmp_path / "projected.json"
    projected_output = tmp_path / "projected.jsonl"
    write_json(
        projected_config,
        {"adapter": "openhands-pattern", "project_to": "thought"},
    )
    run_worker(
        input_path,
        projected_output,
        tmp_path / "projected-adapter.json",
        projected_config,
    )

    native = read_jsonl(native_output)[0]
    projected = read_jsonl(projected_output)[0]
    assert native["status"] == "skipped"
    assert native["case_id"] == "native"
    assert projected["status"] == "match"
    assert projected["case_id"] == "projected:thought"
    assert projected["attributes"] == {
        "evaluated_surface": "thought",
        "observed_surface": "thought",
        "source_surface": "email",
    }
    assert projected["findings"][0]["field"] == "thought"
    assert EvalRecord.from_dict(read_jsonl(input_path)[0]).surface == "email"


def test_worker_error_does_not_copy_record_text(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    record = _email_record("private source text")
    input_path = tmp_path / "input.jsonl"
    output_path = tmp_path / "output.jsonl"
    config_path = tmp_path / "config.json"
    write_jsonl(input_path, [record.to_dict()])
    write_json(config_path, {"adapter": "_self-test"})

    def evaluate(_record: EvalRecord) -> AdapterOutcome:
        raise ValueError(record.text)

    monkeypatch.setattr(
        "agent_security_evals.worker.create_adapter",
        lambda _name, _config: SimpleNamespace(
            evaluate=evaluate,
            metadata=lambda: {"adapter": "fixture"},
        ),
    )

    run_worker(
        input_path,
        output_path,
        tmp_path / "adapter.json",
        config_path,
    )

    result = read_jsonl(output_path)[0]
    assert result["status"] == "error"
    assert result["error"] == "builtins.ValueError"
    assert record.text not in str(result)
