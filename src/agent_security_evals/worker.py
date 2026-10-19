"""Run one trusted analyzer adapter in an isolated process."""

from __future__ import annotations

import argparse
import time
from dataclasses import replace
from pathlib import Path

from agent_security_evals.adapters import (
    OPENHANDS_PROJECTABLE_SURFACES,
    AdapterOutcome,
    create_adapter,
)
from agent_security_evals.contracts import EvalRecord, EvalResult
from agent_security_evals.io import read_json, read_jsonl, write_json, write_jsonl


def _error(
    record: EvalRecord,
    adapter: str,
    case_id: str,
    attributes: dict[str, str],
    elapsed_ns: int,
    exc: Exception,
) -> EvalResult:
    return EvalResult.from_dict(
        {
            "schema_version": 1,
            "record_id": record.id,
            "text_sha256": record.text_sha256,
            "adapter": adapter,
            "case_id": case_id,
            "status": "error",
            "findings": [],
            "attributes": attributes,
            "elapsed_ns": elapsed_ns,
            "error": f"{type(exc).__module__}.{type(exc).__qualname__}",
        }
    )


def _result(
    record: EvalRecord,
    adapter: str,
    case_id: str,
    case_attributes: dict[str, str],
    outcome: AdapterOutcome,
    elapsed_ns: int,
) -> EvalResult:
    return EvalResult.from_dict(
        {
            "schema_version": 1,
            "record_id": record.id,
            "text_sha256": record.text_sha256,
            "adapter": adapter,
            "case_id": case_id,
            "status": outcome.status,
            "findings": [finding.to_dict() for finding in outcome.findings],
            "attributes": {**outcome.attributes, **case_attributes},
            "elapsed_ns": elapsed_ns,
            "error": None,
        }
    )


def run_worker(
    input_path: Path,
    output_path: Path,
    adapter_metadata_path: Path,
    config_path: Path,
) -> None:
    config = read_json(config_path)
    adapter_name = config.get("adapter")
    if not isinstance(adapter_name, str):
        raise ValueError("Worker config has no adapter name")
    project_to = config.get("project_to")
    if project_to is not None:
        if not adapter_name.startswith("openhands-"):
            raise ValueError("Only OpenHands adapters support projection")
        if (
            not isinstance(project_to, str)
            or project_to not in OPENHANDS_PROJECTABLE_SURFACES
        ):
            raise ValueError(f"Unsupported OpenHands projection surface: {project_to}")
    adapter = create_adapter(adapter_name, config)
    records = [EvalRecord.from_dict(value) for value in read_jsonl(input_path)]
    results: list[EvalResult] = []
    for record in records:
        evaluated_record = record
        case_id = "native"
        case_attributes: dict[str, str] = {}
        if project_to is not None:
            evaluated_record = replace(record, surface=project_to)
            case_id = f"projected:{project_to}"
            case_attributes = {
                "source_surface": record.surface,
                "evaluated_surface": project_to,
            }
        started = time.perf_counter_ns()
        try:
            outcome = adapter.evaluate(evaluated_record)
        except Exception as exc:
            elapsed = time.perf_counter_ns() - started
            results.append(
                _error(
                    record,
                    adapter_name,
                    case_id,
                    case_attributes,
                    elapsed,
                    exc,
                )
            )
            continue
        elapsed = time.perf_counter_ns() - started
        results.append(
            _result(
                record,
                adapter_name,
                case_id,
                case_attributes,
                outcome,
                elapsed,
            )
        )
    write_jsonl(output_path, (result.to_dict() for result in results))
    write_json(adapter_metadata_path, adapter.metadata())


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--adapter-metadata", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    args = parser.parse_args()
    run_worker(args.input, args.output, args.adapter_metadata, args.config)


if __name__ == "__main__":
    main()
