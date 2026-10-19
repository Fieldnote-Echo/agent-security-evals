"""Run adapters and validate their complete output."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from typing import Any

from agent_security_evals.adapters import ALL_ADAPTERS, OPENHANDS_PROJECTABLE_SURFACES
from agent_security_evals.contracts import EvalRecord, EvalResult
from agent_security_evals.io import (
    metadata_path,
    read_json,
    read_jsonl,
    sha256_file,
    write_json,
    write_text,
)
from agent_security_evals.reports import calculate_metrics, write_run_report


def _git_state(checkout: Path) -> dict[str, str]:
    head = subprocess.run(
        ["git", "-C", str(checkout), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    status = subprocess.run(
        ["git", "-C", str(checkout), "status", "--porcelain=v1"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    if status:
        raise ValueError(f"Git checkout is not clean: {checkout}")
    return {"commit": head}


def _validate_results(
    records: list[EvalRecord],
    raw_results: list[dict[str, Any]],
    adapter: str,
    case_id: str = "native",
) -> list[EvalResult]:
    results = [EvalResult.from_dict(value) for value in raw_results]
    expected = {record.id: record for record in records}
    actual = {result.record_id: result for result in results}
    if len(actual) != len(results):
        raise ValueError("Worker output contains duplicate record IDs")
    if expected.keys() != actual.keys():
        missing = sorted(expected.keys() - actual.keys())
        extra = sorted(actual.keys() - expected.keys())
        raise ValueError(f"Worker output IDs differ; missing={missing}, extra={extra}")
    for record_id, result in actual.items():
        if result.text_sha256 != expected[record_id].text_sha256:
            raise ValueError(f"Worker changed the text hash for {record_id}")
        if result.adapter != adapter:
            raise ValueError(f"Worker used the wrong adapter for {record_id}")
        if result.case_id != case_id:
            raise ValueError(f"Worker used the wrong case for {record_id}")
    return results


def _write_worker_logs(
    output_dir: Path,
    stdout: str | bytes | None,
    stderr: str | bytes | None,
) -> None:
    for name, output in (
        ("worker.stdout.log", stdout),
        ("worker.stderr.log", stderr),
    ):
        if not output:
            continue
        text = output.decode(errors="replace") if isinstance(output, bytes) else output
        write_text(output_dir / name, text)


def run_adapter(
    *,
    input_path: Path,
    output_dir: Path,
    adapter: str,
    python: Path | None = None,
    sdk_checkout: Path | None = None,
    rules_dir: Path | None = None,
    project_to: str | None = None,
    timeout_seconds: int = 600,
) -> Path:
    if adapter not in ALL_ADAPTERS:
        raise ValueError(f"Unknown adapter: {adapter}")
    if timeout_seconds <= 0:
        raise ValueError("Worker timeout must be positive")
    if project_to is not None:
        if not adapter.startswith("openhands-"):
            raise ValueError("Only OpenHands adapters support projection")
        if project_to not in OPENHANDS_PROJECTABLE_SURFACES:
            raise ValueError(f"Unsupported OpenHands projection surface: {project_to}")
    input_path = input_path.resolve()
    input_metadata_path = metadata_path(input_path)
    if not input_path.is_file() or not input_metadata_path.is_file():
        raise ValueError(f"Prepared suite is incomplete: {input_path}")
    input_hash = sha256_file(input_path)
    input_metadata_hash = sha256_file(input_metadata_path)
    prepared_metadata = read_json(input_metadata_path)
    if prepared_metadata.get("output_sha256") != input_hash:
        raise ValueError("Prepared suite metadata does not match its JSONL file")

    records = [EvalRecord.from_dict(value) for value in read_jsonl(input_path)]
    if len({record.id for record in records}) != len(records):
        raise ValueError("Prepared suite contains duplicate record IDs")

    python = (python or Path(sys.executable)).absolute()
    if not python.is_file():
        raise ValueError(f"Python executable does not exist: {python}")
    checkout_state: dict[str, str] | None = None
    sdk_source: Path | None = None
    if adapter.startswith("openhands-"):
        if sdk_checkout is None:
            raise ValueError(f"{adapter} requires an SDK checkout")
        sdk_checkout = sdk_checkout.resolve()
        sdk_source = sdk_checkout / "openhands-sdk"
        if not sdk_source.is_dir():
            raise ValueError(f"SDK source does not exist: {sdk_source}")
        checkout_state = _git_state(sdk_checkout)
    if adapter == "atr-direct" and rules_dir is None:
        raise ValueError("atr-direct requires an ATR rules directory")

    output_dir = output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    results_path = output_dir / "results.jsonl"
    adapter_metadata_path = output_dir / "adapter.json"
    config_path = output_dir / "worker.json"
    for path in (
        results_path,
        metadata_path(results_path),
        adapter_metadata_path,
        config_path,
        output_dir / "metrics.json",
        output_dir / "report.md",
        output_dir / "worker.stdout.log",
        output_dir / "worker.stderr.log",
    ):
        path.unlink(missing_ok=True)

    worker_config: dict[str, Any] = {"adapter": adapter}
    if rules_dir is not None:
        worker_config["rules_dir"] = str(rules_dir.resolve())
    if project_to is not None:
        worker_config["project_to"] = project_to
    write_json(config_path, worker_config)

    package_parent = Path(__file__).resolve().parent.parent
    python_paths = [str(package_parent)]
    if sdk_source is not None:
        python_paths.append(str(sdk_source))
    environment = {
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": os.defpath,
        "PYTHONPATH": os.pathsep.join(python_paths),
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONNOUSERSITE": "1",
        "OPENHANDS_SUPPRESS_BANNER": "1",
        "LITELLM_LOCAL_MODEL_COST_MAP": "True",
    }
    command = [
        str(python),
        "-m",
        "agent_security_evals.worker",
        "--input",
        str(input_path),
        "--output",
        str(results_path),
        "--adapter-metadata",
        str(adapter_metadata_path),
        "--config",
        str(config_path),
    ]
    try:
        try:
            completed = subprocess.run(
                command,
                check=False,
                cwd=sdk_checkout if sdk_checkout is not None else output_dir,
                env=environment,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
            )
        except subprocess.TimeoutExpired as exc:
            _write_worker_logs(output_dir, exc.stdout, exc.stderr)
            raise
        _write_worker_logs(output_dir, completed.stdout, completed.stderr)
        completed.check_returncode()
        if checkout_state is not None and _git_state(sdk_checkout) != checkout_state:
            raise ValueError("SDK checkout changed during the run")
        if sha256_file(input_path) != input_hash:
            raise ValueError("Prepared suite changed during the run")
        if sha256_file(input_metadata_path) != input_metadata_hash:
            raise ValueError("Prepared suite metadata changed during the run")
        case_id = f"projected:{project_to}" if project_to is not None else "native"
        results = _validate_results(
            records,
            read_jsonl(results_path),
            adapter,
            case_id,
        )
        adapter_metadata = read_json(adapter_metadata_path)
    except BaseException:
        results_path.unlink(missing_ok=True)
        metadata_path(results_path).unlink(missing_ok=True)
        adapter_metadata_path.unlink(missing_ok=True)
        raise

    run_metadata = {
        "schema_version": 1,
        "adapter": adapter,
        "adapter_metadata": adapter_metadata,
        "input": str(input_path),
        "input_sha256": input_hash,
        "input_metadata_sha256": input_metadata_hash,
        "prepared_suite": prepared_metadata,
        "python": str(python),
        "sdk_checkout": str(sdk_checkout) if sdk_checkout is not None else None,
        "sdk_commit": checkout_state["commit"] if checkout_state else None,
        "rules_dir": str(rules_dir.resolve()) if rules_dir is not None else None,
        "project_to": project_to,
        "worker_timeout_seconds": timeout_seconds,
        "worker_sandboxed": False,
        "corpus_text_in_process_arguments": False,
        "result_count": len(results),
    }
    write_json(metadata_path(results_path), run_metadata)
    metrics = calculate_metrics(records, results)
    write_json(output_dir / "metrics.json", metrics)
    write_run_report(output_dir / "report.md", metrics, run_metadata)
    return results_path
