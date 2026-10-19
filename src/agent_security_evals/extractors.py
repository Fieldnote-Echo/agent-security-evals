"""Extract neutral records from pinned public datasets."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable, Mapping

from agent_security_evals.contracts import EvalRecord
from agent_security_evals.io import read_jsonl, sha256_text


_OPENHANDS_ORIGINS = {
    "agent": "agent",
    "human": "human",
    "user": "human",
}


def _source(spec: Mapping[str, Any], coordinates: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "dataset": spec["name"],
        "revision": spec["revision"],
        "homepage": spec["homepage"],
        "license": spec["license"],
        "coordinates": dict(coordinates),
    }


def _record_id(dataset: str, coordinates: Mapping[str, Any]) -> str:
    parts = [f"{key}={coordinates[key]}" for key in sorted(coordinates)]
    return f"{dataset}:" + ":".join(parts)


def _parquet_rows(
    files: Iterable[Path], columns: list[str]
) -> Iterable[tuple[Path, int, dict[str, Any]]]:
    try:
        import pyarrow.parquet as pq
    except ImportError as exc:
        raise RuntimeError(
            "Parquet support is not installed. Install the 'corpora' extra."
        ) from exc

    for path in files:
        row_index = 0
        parquet = pq.ParquetFile(path)
        for batch in parquet.iter_batches(columns=columns, batch_size=1024):
            for row in batch.to_pylist():
                yield path, row_index, row
                row_index += 1


def extract_vendored(
    spec: Mapping[str, Any], files: list[Path]
) -> Iterable[EvalRecord]:
    if len(files) != 1:
        raise ValueError(f"{spec['name']} must have one vendored record file")
    for value in read_jsonl(files[0]):
        record = EvalRecord.from_dict(value)
        if record.source["dataset"] != spec["name"]:
            raise ValueError(
                f"Vendored record {record.id} has the wrong source dataset"
            )
        if record.source["revision"] != spec["revision"]:
            raise ValueError(f"Vendored record {record.id} has the wrong revision")
        yield record


def extract_gandalf(spec: Mapping[str, Any], files: list[Path]) -> Iterable[EvalRecord]:
    for path, row_index, row in _parquet_rows(files, ["text", "similarity"]):
        text = row.get("text")
        if not isinstance(text, str):
            raise ValueError(f"Gandalf row {row_index} has no text")
        split = path.name.split("-", 1)[0]
        coordinates = {"split": split, "row": row_index}
        yield EvalRecord.create(
            record_id=_record_id(spec["name"], coordinates),
            text=text,
            surface="user_input",
            origin="human",
            group_id=None,
            source=_source(spec, coordinates),
            label={
                "value": "attack",
                "provenance": "source_embedding_filter",
                "confidence": "noisy",
            },
            metadata={"similarity": row.get("similarity")},
        )


def extract_notinject(
    spec: Mapping[str, Any], files: list[Path]
) -> Iterable[EvalRecord]:
    columns = ["prompt", "word_list", "category"]
    for path, row_index, row in _parquet_rows(files, columns):
        text = row.get("prompt")
        if not isinstance(text, str):
            raise ValueError(f"NotInject row {row_index} has no prompt")
        subset = path.name.split("-", 1)[0]
        coordinates = {"subset": subset, "row": row_index}
        yield EvalRecord.create(
            record_id=_record_id(spec["name"], coordinates),
            text=text,
            surface="user_input",
            origin="synthetic",
            group_id=subset,
            source=_source(spec, coordinates),
            label={
                "value": "benign",
                "provenance": "source",
                "confidence": "high",
            },
            metadata={
                "category": row.get("category"),
                "trigger_words": row.get("word_list"),
            },
        )


def extract_injecagent(
    spec: Mapping[str, Any], files: list[Path]
) -> Iterable[EvalRecord]:
    for path in files:
        values = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(values, list):
            raise ValueError(f"Expected a list in {path}")
        attack_family = "direct_harm" if "_dh_" in path.name else "data_stealing"
        for row_index, row in enumerate(values):
            if not isinstance(row, dict):
                raise ValueError(f"InjecAgent row {row_index} is not an object")
            text = row.get("Tool Response")
            instruction = row.get("Attacker Instruction")
            if not isinstance(text, str) or not isinstance(instruction, str):
                raise ValueError(f"InjecAgent row {row_index} is missing attack text")
            coordinates = {"family": attack_family, "row": row_index}
            yield EvalRecord.create(
                record_id=_record_id(spec["name"], coordinates),
                text=text,
                surface="tool_output",
                origin="synthetic",
                group_id=f"injecagent:{sha256_text(instruction)[:16]}",
                source=_source(spec, coordinates),
                label={
                    "value": "attack",
                    "provenance": "synthetic",
                    "confidence": "high",
                },
                metadata={
                    "attack_family": attack_family,
                    "attack_type": row.get("Attack Type"),
                    "user_tool": row.get("User Tool"),
                },
            )


def extract_openhands_feedback(
    spec: Mapping[str, Any], files: list[Path]
) -> Iterable[EvalRecord]:
    for _path, row_index, row in _parquet_rows(files, ["trajectory"]):
        for event_index, event in enumerate(row.get("trajectory") or []):
            if event.get("action") != "run":
                continue
            extras = json.loads(event["extras"])
            command = extras.get("command")
            if not isinstance(command, str):
                continue
            coordinates = {"row": row_index, "event": event_index}
            event_source = event.get("source")
            origin = _OPENHANDS_ORIGINS.get(event_source, "unknown")
            yield EvalRecord.create(
                record_id=_record_id(spec["name"], coordinates),
                text=command,
                surface="command",
                origin=origin,
                group_id=f"openhands_feedback:row={row_index}",
                source=_source(spec, coordinates),
                label={
                    "value": "operational",
                    "provenance": "source",
                    "confidence": "unknown",
                },
                metadata={
                    "event_id": event.get("id"),
                    "event_source": event_source,
                },
            )


def extract_data_agent_harbor(
    spec: Mapping[str, Any], files: list[Path]
) -> Iterable[EvalRecord]:
    columns = ["task_id", "source_agent", "messages"]
    for _path, row_index, row in _parquet_rows(files, columns):
        for message_index, encoded_message in enumerate(row.get("messages") or []):
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
                coordinates = {
                    "row": row_index,
                    "message": message_index,
                    "tool_call": call_index,
                }
                task_id = row.get("task_id")
                yield EvalRecord.create(
                    record_id=_record_id(spec["name"], coordinates),
                    text=command,
                    surface="command",
                    origin="agent",
                    group_id=f"data_agent_harbor:{task_id or row_index}",
                    source=_source(spec, coordinates),
                    label={
                        "value": "operational",
                        "provenance": "source",
                        "confidence": "unknown",
                    },
                    metadata={
                        "task_id": task_id,
                        "source_agent": row.get("source_agent"),
                    },
                )


EXTRACTORS = {
    "vendored": extract_vendored,
    "gandalf": extract_gandalf,
    "notinject": extract_notinject,
    "injecagent": extract_injecagent,
    "openhands_feedback": extract_openhands_feedback,
    "data_agent_harbor": extract_data_agent_harbor,
}
