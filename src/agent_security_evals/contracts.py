"""Versioned data contracts for evaluation records and results."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Mapping

from agent_security_evals.io import sha256_text


SCHEMA_VERSION = 1
LABEL_VALUES = frozenset({"attack", "benign", "operational", "unknown"})
LABEL_CONFIDENCE = frozenset({"high", "noisy", "unknown"})
ORIGINS = frozenset({"agent", "human", "synthetic", "mixed", "unknown"})
SURFACES = frozenset(
    {
        "action_argument",
        "command",
        "email",
        "reasoning_content",
        "retrieved_document",
        "summary",
        "thought",
        "tool_output",
        "user_input",
    }
)
RESULT_STATES = frozenset({"match", "no_match", "unknown", "error", "skipped"})
SEVERITIES = frozenset({"critical", "high", "medium", "low", "info", "unknown"})


def _mapping(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{name} must be an object")
    return dict(value)


def _string(value: Any, name: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a string")
    if not allow_empty and not value:
        raise ValueError(f"{name} must not be empty")
    return value


@dataclass(frozen=True)
class EvalRecord:
    """One immutable evaluation input."""

    id: str
    text: str
    text_sha256: str
    surface: str
    origin: str
    group_id: str | None
    source: dict[str, Any]
    label: dict[str, Any]
    metadata: dict[str, Any]

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> EvalRecord:
        raw = dict(value)
        if raw.get("schema_version") != SCHEMA_VERSION:
            raise ValueError(f"Unsupported record schema: {raw.get('schema_version')}")

        record_id = _string(raw.get("id"), "id")
        if "\n" in record_id or "\r" in record_id:
            raise ValueError("id must stay on one line")
        text = _string(raw.get("text"), "text", allow_empty=True)
        text_hash = _string(raw.get("text_sha256"), "text_sha256")
        if text_hash != sha256_text(text):
            raise ValueError(f"Record {record_id} has an invalid text hash")

        surface = _string(raw.get("surface"), "surface")
        if surface not in SURFACES:
            raise ValueError(
                f"Record {record_id} has an unsupported surface: {surface}"
            )
        origin = _string(raw.get("origin"), "origin")
        if origin not in ORIGINS:
            raise ValueError(f"Record {record_id} has an unsupported origin: {origin}")

        group_id = raw.get("group_id")
        if group_id is not None:
            group_id = _string(group_id, "group_id")

        source = _mapping(raw.get("source"), "source")
        for field in ("dataset", "revision", "homepage", "license"):
            _string(source.get(field), f"source.{field}")
        source["coordinates"] = _mapping(
            source.get("coordinates"), "source.coordinates"
        )

        label = _mapping(raw.get("label"), "label")
        label_value = _string(label.get("value"), "label.value")
        if label_value not in LABEL_VALUES:
            raise ValueError(
                f"Record {record_id} has an unsupported label: {label_value}"
            )
        confidence = _string(label.get("confidence"), "label.confidence")
        if confidence not in LABEL_CONFIDENCE:
            raise ValueError(
                f"Record {record_id} has unsupported confidence: {confidence}"
            )
        _string(label.get("provenance"), "label.provenance")

        metadata = _mapping(raw.get("metadata", {}), "metadata")
        return cls(
            id=record_id,
            text=text,
            text_sha256=text_hash,
            surface=surface,
            origin=origin,
            group_id=group_id,
            source=source,
            label=label,
            metadata=metadata,
        )

    @classmethod
    def create(
        cls,
        *,
        record_id: str,
        text: str,
        surface: str,
        origin: str,
        group_id: str | None,
        source: Mapping[str, Any],
        label: Mapping[str, Any],
        metadata: Mapping[str, Any] | None = None,
    ) -> EvalRecord:
        return cls.from_dict(
            {
                "schema_version": SCHEMA_VERSION,
                "id": record_id,
                "text": text,
                "text_sha256": sha256_text(text),
                "surface": surface,
                "origin": origin,
                "group_id": group_id,
                "source": dict(source),
                "label": dict(label),
                "metadata": dict(metadata or {}),
            }
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "id": self.id,
            "text": self.text,
            "text_sha256": self.text_sha256,
            "surface": self.surface,
            "origin": self.origin,
            "group_id": self.group_id,
            "source": self.source,
            "label": self.label,
            "metadata": self.metadata,
        }


@dataclass(frozen=True)
class Finding:
    """One normalized analyzer finding."""

    id: str
    severity: str
    field: str

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> Finding:
        raw = dict(value)
        finding_id = _string(raw.get("id"), "finding.id")
        severity = _string(raw.get("severity"), "finding.severity")
        if severity not in SEVERITIES:
            raise ValueError(f"Unsupported finding severity: {severity}")
        field = _string(raw.get("field"), "finding.field")
        return cls(id=finding_id, severity=severity, field=field)

    def to_dict(self) -> dict[str, str]:
        return {"id": self.id, "severity": self.severity, "field": self.field}


@dataclass(frozen=True)
class EvalResult:
    """One normalized analyzer result."""

    record_id: str
    text_sha256: str
    adapter: str
    case_id: str
    status: str
    findings: tuple[Finding, ...]
    attributes: dict[str, Any]
    elapsed_ns: int
    error: str | None

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> EvalResult:
        raw = dict(value)
        if raw.get("schema_version") != SCHEMA_VERSION:
            raise ValueError(f"Unsupported result schema: {raw.get('schema_version')}")
        record_id = _string(raw.get("record_id"), "record_id")
        text_hash = _string(raw.get("text_sha256"), "text_sha256")
        adapter = _string(raw.get("adapter"), "adapter")
        case_id = _string(raw.get("case_id"), "case_id")
        status = _string(raw.get("status"), "status")
        if status not in RESULT_STATES:
            raise ValueError(f"Unsupported result state: {status}")
        findings_raw = raw.get("findings")
        if not isinstance(findings_raw, list):
            raise ValueError("findings must be a list")
        findings = tuple(Finding.from_dict(item) for item in findings_raw)
        attributes = _mapping(raw.get("attributes", {}), "attributes")
        elapsed_ns = raw.get("elapsed_ns")
        if not isinstance(elapsed_ns, int) or elapsed_ns < 0:
            raise ValueError("elapsed_ns must be a non-negative integer")
        error = raw.get("error")
        if error is not None and not isinstance(error, str):
            raise ValueError("error must be a string or null")
        if status == "error" and not error:
            raise ValueError("An error result must include an error message")
        if status != "error" and error is not None:
            raise ValueError("Only an error result can include an error message")
        return cls(
            record_id=record_id,
            text_sha256=text_hash,
            adapter=adapter,
            case_id=case_id,
            status=status,
            findings=findings,
            attributes=attributes,
            elapsed_ns=elapsed_ns,
            error=error,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "record_id": self.record_id,
            "text_sha256": self.text_sha256,
            "adapter": self.adapter,
            "case_id": self.case_id,
            "status": self.status,
            "findings": [finding.to_dict() for finding in self.findings],
            "attributes": self.attributes,
            "elapsed_ns": self.elapsed_ns,
            "error": self.error,
        }

    def semantic_signature(self) -> str:
        material = {
            "status": self.status,
            "findings": [finding.to_dict() for finding in self.findings],
            "attributes": self.attributes,
            "error": self.error,
        }
        return json.dumps(material, sort_keys=True, separators=(",", ":"))
