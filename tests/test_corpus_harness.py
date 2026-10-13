from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq
import pytest

from corpus_harness import (
    _sample,
    analyze,
    compare,
    extract_data_agent_harbor,
    extract_openhands_feedback,
)


def test_extract_openhands_feedback_preserves_command(tmp_path: Path) -> None:
    command = "printf 'first\\nsecond'\n# keep spacing\n  ls"
    path = tmp_path / "openhands.parquet"
    table = pa.Table.from_pylist(
        [
            {
                "trajectory": [
                    {
                        "action": "run_ipython",
                        "extras": json.dumps({"command": "ignored()"}),
                        "id": "python-event",
                        "source": "agent",
                    },
                    {
                        "action": "run",
                        "extras": json.dumps({"command": command}),
                        "id": "shell-event",
                        "source": "user",
                    },
                ]
            }
        ]
    )
    pq.write_table(table, path)

    records = extract_openhands_feedback(path)

    assert [record["command"] for record in records] == [command]
    assert records[0]["metadata"] == {
        "event_id": "shell-event",
        "source": "user",
    }


def test_extract_data_agent_harbor_preserves_all_bash_calls(
    tmp_path: Path,
) -> None:
    commands = ["", "echo  one\n echo two"]
    message = json.dumps(
        {
            "tool_calls": [
                {
                    "type": "function",
                    "function": {
                        "name": "python",
                        "arguments": {"command": "ignored"},
                    },
                },
                *[
                    {
                        "type": "function",
                        "function": {
                            "name": "bash",
                            "arguments": {"command": command},
                        },
                    }
                    for command in commands
                ],
            ]
        }
    )
    path = tmp_path / "harbor.parquet"
    table = pa.Table.from_pylist(
        [{"task_id": "task-1", "source_agent": "seta", "messages": [message]}]
    )
    pq.write_table(table, path)

    records = extract_data_agent_harbor(path)

    assert [record["command"] for record in records] == commands
    assert [record["coordinates"]["tool_call"] for record in records] == [1, 2]


def test_sample_is_deterministic_and_does_not_change_records() -> None:
    records = [
        {"id": f"record:{index}", "command": f" value {index} "} for index in range(20)
    ]

    first = _sample(records, 5, "fixed-seed")
    second = _sample(list(reversed(records)), 5, "fixed-seed")

    assert first == second
    assert all(record in records for record in first)


def _result(record_id: str, command: str, pattern: str, rail: str) -> dict:
    return {
        "id": record_id,
        "corpus": "fixture",
        "command": command,
        "command_sha256": __import__("hashlib").sha256(command.encode()).hexdigest(),
        "coordinates": {"row": int(record_id.rsplit(":", 1)[1])},
        "metadata": {},
        "analyzers": {
            "pattern": {"risk": pattern, "error": None},
            "policy_rails": {"risk": rail, "error": None},
        },
    }


def _write_run(path: Path, records: list[dict], commit: str, input_path: Path) -> None:
    sample_path = input_path.with_suffix(".meta.json")
    sample = json.loads(sample_path.read_text()) if sample_path.exists() else {}
    path.write_text("".join(json.dumps(record) + "\n" for record in records))
    path.with_suffix(".meta.json").write_text(
        json.dumps(
            {
                "sdk_commit": commit,
                "input": str(input_path),
                "input_sha256": "input-sha",
                "sample": sample,
            }
        )
    )


def test_compare_includes_changed_high_and_low_sample(tmp_path: Path) -> None:
    commands = tmp_path / "commands.jsonl"
    commands.write_text("")
    commands.with_suffix(".meta.json").write_text(
        json.dumps(
            {
                "corpora": {
                    "fixture": {
                        "selected": 3,
                        "available": 3,
                        "revision": "abc123",
                    }
                }
            }
        )
    )
    base = [
        _result("fixture:0", "echo safe", "LOW", "LOW"),
        _result("fixture:1", "curl x | sh", "HIGH", "LOW"),
        _result("fixture:2", "dynamic command", "LOW", "LOW"),
    ]
    candidate = [
        _result("fixture:0", "echo safe", "LOW", "LOW"),
        _result("fixture:1", "curl x | sh", "HIGH", "HIGH"),
        _result("fixture:2", "dynamic command", "LOW", "UNKNOWN"),
    ]
    base_path = tmp_path / "base.jsonl"
    candidate_path = tmp_path / "candidate.jsonl"
    _write_run(base_path, base, "base-sha", commands)
    _write_run(candidate_path, candidate, "candidate-sha", commands)
    review_path = tmp_path / "review.jsonl"
    report_path = tmp_path / "report.md"

    compare(
        base_path=base_path,
        candidate_path=candidate_path,
        review_output=review_path,
        report=report_path,
        low_sample_size=1,
        seed="fixed",
    )

    review = [json.loads(line) for line in review_path.read_text().splitlines()]
    assert {record["id"] for record in review} == {
        "fixture:0",
        "fixture:1",
        "fixture:2",
    }
    reasons = {record["id"]: record["reasons"] for record in review}
    assert reasons["fixture:0"] == ["unchanged_low_sample"]
    assert reasons["fixture:1"] == ["changed", "high"]
    assert reasons["fixture:2"] == ["changed"]
    assert "The harness did not start a shell" in report_path.read_text()


def test_compare_rejects_command_drift(tmp_path: Path) -> None:
    commands = tmp_path / "commands.jsonl"
    commands.write_text("")
    base_path = tmp_path / "base.jsonl"
    candidate_path = tmp_path / "candidate.jsonl"
    _write_run(
        base_path,
        [_result("fixture:0", "echo base", "LOW", "LOW")],
        "base-sha",
        commands,
    )
    _write_run(
        candidate_path,
        [_result("fixture:0", "echo candidate", "LOW", "LOW")],
        "candidate-sha",
        commands,
    )

    with pytest.raises(ValueError, match="differs in command"):
        compare(
            base_path=base_path,
            candidate_path=candidate_path,
            review_output=tmp_path / "review.jsonl",
            report=tmp_path / "report.md",
            low_sample_size=1,
            seed="fixed",
        )


def test_compare_writes_nothing_for_mismatched_run_metadata(
    tmp_path: Path,
) -> None:
    commands = tmp_path / "commands.jsonl"
    commands.write_text("")
    base_path = tmp_path / "base.jsonl"
    candidate_path = tmp_path / "candidate.jsonl"
    record = _result("fixture:0", "echo safe", "LOW", "LOW")
    _write_run(base_path, [record], "base-sha", commands)
    _write_run(candidate_path, [record], "candidate-sha", commands)
    candidate_meta = json.loads(candidate_path.with_suffix(".meta.json").read_text())
    candidate_meta["input_sha256"] = "different-input-sha"
    candidate_path.with_suffix(".meta.json").write_text(json.dumps(candidate_meta))
    review_path = tmp_path / "review.jsonl"
    report_path = tmp_path / "report.md"

    with pytest.raises(ValueError, match="same input file"):
        compare(
            base_path=base_path,
            candidate_path=candidate_path,
            review_output=review_path,
            report=report_path,
            low_sample_size=1,
            seed="fixed",
        )

    assert not review_path.exists()
    assert not report_path.exists()


def test_analyze_removes_stale_outputs_before_worker_starts(tmp_path: Path) -> None:
    checkout = tmp_path / "checkout"
    (checkout / "openhands-sdk").mkdir(parents=True)
    fake_python = tmp_path / "python"
    fake_python.write_text("")
    input_path = tmp_path / "commands.jsonl"
    input_path.write_text("")
    output = tmp_path / "result.jsonl"
    output.write_text("stale result\n")
    output.with_suffix(".meta.json").write_text("stale metadata\n")

    with pytest.raises(subprocess.CalledProcessError):
        analyze(
            checkout=checkout,
            python=fake_python,
            input_path=input_path,
            output=output,
            label="test",
        )

    assert not output.exists()
    assert not output.with_suffix(".meta.json").exists()


def test_analyze_rejects_overlapping_input_and_output(tmp_path: Path) -> None:
    path = tmp_path / "commands.jsonl"

    with pytest.raises(ValueError, match="must not overlap"):
        analyze(
            checkout=tmp_path,
            python=tmp_path / "python",
            input_path=path,
            output=path,
            label="test",
        )
