from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from agent_security_evals.contracts import EvalRecord
from agent_security_evals.io import metadata_path, read_json, read_jsonl, write_jsonl
from agent_security_evals.reports import compare_runs
from agent_security_evals.runner import _validate_results, run_adapter
from agent_security_evals.sources import load_manifest, prepare_suite
from agent_security_evals.worker import run_worker


PACKAGE_ROOT = Path(__file__).parents[1] / "src" / "agent_security_evals"
MANIFEST_PATH = PACKAGE_ROOT / "data" / "manifest.json"
CANARY = Path("/tmp/agent-security-evals-canary")


def _prepared_smoke(tmp_path: Path) -> Path:
    return prepare_suite(
        manifest=load_manifest(MANIFEST_PATH),
        suite="smoke",
        data_dir=tmp_path / "data",
        package_root=PACKAGE_ROOT,
    )


def test_runner_does_not_execute_corpus_text(tmp_path: Path) -> None:
    CANARY.unlink(missing_ok=True)
    input_path = _prepared_smoke(tmp_path)

    results_path = run_adapter(
        input_path=input_path,
        output_dir=tmp_path / "run",
        adapter="_self-test",
    )

    assert not CANARY.exists()
    results = read_jsonl(results_path)
    assert len(results) == 4
    assert {result["status"] for result in results} == {"match", "no_match"}
    metrics = read_json(tmp_path / "run" / "metrics.json")
    assert metrics["labels"]["attack"]["rate"]["value"] == 1.0
    assert metrics["labels"]["benign"]["rate"]["value"] == 0.0
    run_metadata = read_json(metadata_path(results_path))
    assert run_metadata["corpus_text_in_process_arguments"] is False


def test_runner_rejects_missing_worker_result() -> None:
    record = EvalRecord.from_dict(read_jsonl(PACKAGE_ROOT / "data" / "smoke.jsonl")[0])

    with pytest.raises(ValueError, match="Worker output IDs differ"):
        _validate_results([record], [], "_self-test")


def test_runner_rejects_worker_result_text_hash_drift() -> None:
    record = EvalRecord.from_dict(read_jsonl(PACKAGE_ROOT / "data" / "smoke.jsonl")[0])
    result = {
        "schema_version": 1,
        "record_id": record.id,
        "text_sha256": "0" * 64,
        "adapter": "_self-test",
        "case_id": "native",
        "status": "no_match",
        "findings": [],
        "attributes": {},
        "elapsed_ns": 1,
        "error": None,
    }

    with pytest.raises(ValueError, match="changed the text hash"):
        _validate_results([record], [result], "_self-test")


def test_compare_ignores_latency(tmp_path: Path) -> None:
    input_path = _prepared_smoke(tmp_path)
    base = run_adapter(
        input_path=input_path,
        output_dir=tmp_path / "base",
        adapter="_self-test",
    )
    candidate = run_adapter(
        input_path=input_path,
        output_dir=tmp_path / "candidate",
        adapter="_self-test",
    )

    summary = compare_runs(
        base_path=base,
        candidate_path=candidate,
        output_dir=tmp_path / "comparison",
    )

    assert summary["changed"] == 0
    assert (tmp_path / "comparison" / "review.jsonl").is_file()


def test_compare_rejects_different_evaluation_cases(tmp_path: Path) -> None:
    input_path = _prepared_smoke(tmp_path)
    base = run_adapter(
        input_path=input_path,
        output_dir=tmp_path / "base",
        adapter="_self-test",
    )
    candidate = run_adapter(
        input_path=input_path,
        output_dir=tmp_path / "candidate",
        adapter="_self-test",
    )
    values = read_jsonl(candidate)
    values[0]["case_id"] = "projected:thought"
    write_jsonl(candidate, values)

    with pytest.raises(ValueError, match="different evaluation cases"):
        compare_runs(
            base_path=base,
            candidate_path=candidate,
            output_dir=tmp_path / "comparison",
        )


def test_runner_removes_partial_results_on_timeout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    input_path = _prepared_smoke(tmp_path)

    def timeout(*_args: object, **_kwargs: object) -> None:
        raise subprocess.TimeoutExpired(
            "worker",
            1,
            output=b"partial output\n",
            stderr=b"partial failure\n",
        )

    monkeypatch.setattr("agent_security_evals.runner.subprocess.run", timeout)

    with pytest.raises(subprocess.TimeoutExpired):
        run_adapter(
            input_path=input_path,
            output_dir=tmp_path / "timeout",
            adapter="_self-test",
            timeout_seconds=1,
        )

    assert not (tmp_path / "timeout" / "results.jsonl").exists()
    assert (tmp_path / "timeout" / "worker.stdout.log").read_text() == (
        "partial output\n"
    )
    assert (tmp_path / "timeout" / "worker.stderr.log").read_text() == (
        "partial failure\n"
    )


def test_runner_keeps_symlinked_python_in_worker_command(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    input_path = _prepared_smoke(tmp_path)
    python = tmp_path / "venv-python"
    python.symlink_to(sys.executable)
    commands: list[list[str]] = []

    def execute_worker(
        command: list[str], **_kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        run_worker(
            input_path=Path(command[command.index("--input") + 1]),
            output_path=Path(command[command.index("--output") + 1]),
            adapter_metadata_path=Path(
                command[command.index("--adapter-metadata") + 1]
            ),
            config_path=Path(command[command.index("--config") + 1]),
        )
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr("agent_security_evals.runner.subprocess.run", execute_worker)

    run_adapter(
        input_path=input_path,
        output_dir=tmp_path / "run",
        adapter="_self-test",
        python=python,
    )

    assert commands[0][0] == str(python)


def test_runner_removes_stale_worker_logs(tmp_path: Path) -> None:
    input_path = _prepared_smoke(tmp_path)
    output_dir = tmp_path / "run"
    output_dir.mkdir()
    (output_dir / "worker.stdout.log").write_text("stale", encoding="utf-8")
    (output_dir / "worker.stderr.log").write_text("stale", encoding="utf-8")

    run_adapter(
        input_path=input_path,
        output_dir=output_dir,
        adapter="_self-test",
    )

    assert not (output_dir / "worker.stdout.log").exists()
    assert not (output_dir / "worker.stderr.log").exists()


def test_runner_preserves_failed_worker_logs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    input_path = _prepared_smoke(tmp_path)
    output_dir = tmp_path / "run"

    def failed_worker(
        command: list[str], **_kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            command,
            17,
            stdout="worker output\n",
            stderr="worker failure\n",
        )

    monkeypatch.setattr("agent_security_evals.runner.subprocess.run", failed_worker)

    with pytest.raises(subprocess.CalledProcessError):
        run_adapter(
            input_path=input_path,
            output_dir=output_dir,
            adapter="_self-test",
        )

    assert (output_dir / "worker.stdout.log").read_text(encoding="utf-8") == (
        "worker output\n"
    )
    assert (output_dir / "worker.stderr.log").read_text(encoding="utf-8") == (
        "worker failure\n"
    )
