"""Explicit adapters for supported security analyzers."""

from __future__ import annotations

import importlib.metadata
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from agent_security_evals.contracts import EvalRecord, Finding
from agent_security_evals.io import digest_tree


PUBLIC_ADAPTERS = (
    "atr-direct",
    "openhands-pattern",
    "openhands-policy-rails",
    "openhands-pattern-atr-high",
    "openhands-pattern-atr-all",
)
ALL_ADAPTERS = (*PUBLIC_ADAPTERS, "_self-test")
OPENHANDS_PROJECTABLE_SURFACES = (
    "action_argument",
    "command",
    "reasoning_content",
    "summary",
    "thought",
)


@dataclass(frozen=True)
class AdapterOutcome:
    status: str
    findings: tuple[Finding, ...] = ()
    attributes: dict[str, Any] = field(default_factory=dict)


class Adapter(Protocol):
    name: str

    def evaluate(self, record: EvalRecord) -> AdapterOutcome: ...

    def metadata(self) -> dict[str, Any]: ...


class SelfTestAdapter:
    name = "_self-test"

    def evaluate(self, record: EvalRecord) -> AdapterOutcome:
        if record.metadata.get("self_test_match") is True:
            return AdapterOutcome(
                status="match",
                findings=(
                    Finding(
                        id="self-test.marker",
                        severity="high",
                        field=record.surface,
                    ),
                ),
            )
        return AdapterOutcome(status="no_match")

    def metadata(self) -> dict[str, Any]:
        return {"purpose": "Harness tests only"}


class ATRAdapter:
    name = "atr-direct"

    def __init__(self, rules_dir: Path) -> None:
        try:
            from pyatr import ATREngine
        except ImportError as exc:
            raise RuntimeError(
                "ATR support is not installed. Install the 'atr' extra."
            ) from exc

        self._rules_dir = rules_dir.resolve()
        if not self._rules_dir.is_dir():
            raise ValueError(f"ATR rules directory does not exist: {rules_dir}")
        self._yaml_count = sum(
            1
            for path in self._rules_dir.rglob("*")
            if path.is_file() and path.suffix.casefold() in {".yaml", ".yml"}
        )
        self._engine = ATREngine()
        self._loaded_count = self._engine.load_rules_from_directory(self._rules_dir)
        self._rules_digest = digest_tree(self._rules_dir, (".yaml", ".yml"))
        self._has_known_invalid_condition = any(
            "ATR-2026-00290" in path.read_text(encoding="utf-8")
            for path in self._rules_dir.rglob("*")
            if path.is_file() and path.suffix.casefold() in {".yaml", ".yml"}
        )

    @staticmethod
    def _event(record: EvalRecord) -> Any:
        from pyatr import AgentEvent

        mapping = {
            "user_input": ("llm_input", "user_input"),
            "thought": ("llm_output", "agent_output"),
            "summary": ("llm_output", "agent_output"),
            "reasoning_content": ("llm_output", "agent_output"),
            "command": ("tool_call", "tool_args"),
            "action_argument": ("tool_call", "tool_args"),
            "tool_output": ("tool_response", "tool_response"),
            "retrieved_document": ("tool_response", "tool_response"),
            "email": ("tool_response", "tool_response"),
        }
        event_type, field_name = mapping[record.surface]
        return AgentEvent(
            content=record.text,
            event_type=event_type,
            fields={field_name: record.text},
            metadata={"source_surface": record.surface},
        )

    def evaluate(self, record: EvalRecord) -> AdapterOutcome:
        matches = self._engine.evaluate(self._event(record))
        findings = tuple(
            Finding(
                id=match.rule_id,
                severity=match.severity.casefold()
                if match.severity.casefold()
                in {"critical", "high", "medium", "low", "info"}
                else "unknown",
                field=record.surface,
            )
            for match in matches
        )
        return AdapterOutcome(
            status="match" if matches else "no_match",
            findings=findings,
            attributes={
                "matches": [
                    {
                        "rule_id": match.rule_id,
                        "title": match.title,
                        "severity": match.severity,
                        "confidence": match.confidence,
                        "matched_patterns": list(match.matched_patterns),
                    }
                    for match in matches
                ],
                "event_mapping": {
                    "email": "tool_response",
                    "retrieved_document": "tool_response",
                    "tool_output": "tool_response",
                    "user_input": "user_input",
                    "command": "tool_args",
                    "action_argument": "tool_args",
                    "thought": "agent_output",
                    "summary": "agent_output",
                    "reasoning_content": "agent_output",
                }[record.surface],
            },
        )

    def metadata(self) -> dict[str, Any]:
        # pyatr 0.3.1 has no public API for failed regex conditions.
        observed_failures = [
            {"rule_id": rule_id, "condition_index": index}
            for rule_id, index in sorted(self._engine._failed_regexes)
        ]
        known_failures = []
        if self._has_known_invalid_condition:
            known_failures.append(
                {
                    "rule_id": "ATR-2026-00290",
                    "condition_index": 3,
                    "reason": ("The v4.1.5 regex has a backreference without a group."),
                }
            )
        return {
            "pyatr_version": importlib.metadata.version("pyatr"),
            "rules_directory": str(self._rules_dir),
            "rules_sha256": self._rules_digest,
            "yaml_files": self._yaml_count,
            "loaded_rules": self._loaded_count,
            "unloaded_rule_files": self._yaml_count - self._loaded_count,
            "known_degraded_conditions": known_failures,
            "observed_regex_failures": observed_failures,
            "complete_rule_evaluation": not (
                known_failures
                or observed_failures
                or self._yaml_count != self._loaded_count
            ),
        }


class OpenHandsAdapter:
    _SUPPORTED_SURFACES = frozenset(OPENHANDS_PROJECTABLE_SURFACES)

    def __init__(self, name: str) -> None:
        if name not in PUBLIC_ADAPTERS or not name.startswith("openhands-"):
            raise ValueError(f"Unknown OpenHands adapter: {name}")
        self.name = name
        self._atr_patterns: list[tuple[tuple[str, str, str], str]] = []
        self._analyzer = self._create_analyzer()

    def _create_analyzer(self) -> Any:
        from openhands.sdk.security import (
            PatternSecurityAnalyzer,
            PolicyRailSecurityAnalyzer,
        )

        if self.name == "openhands-policy-rails":
            return PolicyRailSecurityAnalyzer()
        if self.name == "openhands-pattern":
            return PatternSecurityAnalyzer()

        from openhands.sdk.security.defense_in_depth.atr_patterns import (
            ATR_INJECTION_HIGH_PATTERNS,
            ATR_INJECTION_MEDIUM_PATTERNS,
        )
        from openhands.sdk.security.defense_in_depth.pattern import (
            DEFAULT_INJECTION_HIGH_PATTERNS,
            DEFAULT_INJECTION_MEDIUM_PATTERNS,
        )

        high = [*DEFAULT_INJECTION_HIGH_PATTERNS, *ATR_INJECTION_HIGH_PATTERNS]
        medium = list(DEFAULT_INJECTION_MEDIUM_PATTERNS)
        self._atr_patterns = [
            (pattern, "high") for pattern in ATR_INJECTION_HIGH_PATTERNS
        ]
        if self.name == "openhands-pattern-atr-all":
            medium.extend(ATR_INJECTION_MEDIUM_PATTERNS)
            self._atr_patterns.extend(
                (pattern, "medium") for pattern in ATR_INJECTION_MEDIUM_PATTERNS
            )
        return PatternSecurityAnalyzer(
            injection_high_patterns=high,
            injection_medium_patterns=medium,
        )

    def _matching_atr_findings(
        self, normalized: str, field: str
    ) -> tuple[Finding, ...]:
        return tuple(
            Finding(id=detector_id, severity=severity, field=field)
            for (pattern, _description, detector_id), severity in self._atr_patterns
            if re.search(pattern, normalized, re.IGNORECASE)
        )

    def _match_findings(
        self,
        risk_name: str,
        field: str,
        atr_findings: tuple[Finding, ...],
    ) -> tuple[Finding, ...]:
        family = "policy_rails" if self.name == "openhands-policy-rails" else "pattern"
        return (
            Finding(
                id=f"openhands.{family}.risk",
                severity=risk_name.casefold(),
                field=field,
            ),
            *atr_findings,
        )

    @staticmethod
    def _action(record: EvalRecord) -> Any:
        from openhands.sdk.event import ActionEvent
        from openhands.sdk.llm import MessageToolCall, TextContent

        tool_name = "fixture"
        arguments: dict[str, str] = {}
        thought: list[Any] = []
        summary = None
        reasoning_content = None
        if record.surface == "command":
            tool_name = "bash"
            arguments = {"command": record.text}
        elif record.surface == "action_argument":
            arguments = {"value": record.text}
        elif record.surface == "thought":
            thought = [TextContent(text=record.text)]
        elif record.surface == "summary":
            summary = record.text
        elif record.surface == "reasoning_content":
            reasoning_content = record.text
        else:
            raise ValueError(f"Unsupported OpenHands surface: {record.surface}")
        return ActionEvent(
            thought=thought,
            reasoning_content=reasoning_content,
            summary=summary,
            tool_name=tool_name,
            tool_call_id=record.id,
            tool_call=MessageToolCall(
                id=record.id,
                name=tool_name,
                arguments=json.dumps(arguments),
                origin="completion",
            ),
            llm_response_id=record.id,
        )

    def evaluate(self, record: EvalRecord) -> AdapterOutcome:
        if record.surface not in self._SUPPORTED_SURFACES:
            return AdapterOutcome(
                status="skipped",
                attributes={
                    "reason": "The ActionEvent analyzer has no native input field "
                    f"for {record.surface}."
                },
            )

        from openhands.sdk.security import ConfirmRisky
        from openhands.sdk.security.defense_in_depth.utils import (
            _extract_content,
            _normalize,
        )

        action = self._action(record)
        risk = self._analyzer.security_risk(action)
        if risk.name == "UNKNOWN":
            status = "unknown"
        elif risk.name == "LOW":
            status = "no_match"
        else:
            status = "match"

        findings: tuple[Finding, ...] = ()
        if self._atr_patterns:
            normalized = _normalize(_extract_content(action))
            findings = self._matching_atr_findings(normalized, record.surface)
        if status == "match":
            findings = self._match_findings(risk.name, record.surface, findings)
        return AdapterOutcome(
            status=status,
            findings=findings,
            attributes={
                "risk": risk.name,
                "should_confirm": ConfirmRisky().should_confirm(risk),
                "event_field": record.surface,
            },
        )

    def metadata(self) -> dict[str, Any]:
        try:
            version = importlib.metadata.version("openhands-sdk")
        except importlib.metadata.PackageNotFoundError:
            version = "source-checkout"
        metadata: dict[str, Any] = {
            "openhands_sdk_version": version,
            "supported_surfaces": sorted(self._SUPPORTED_SURFACES),
        }
        if self._atr_patterns:
            metadata["selected_atr_patterns"] = len(self._atr_patterns)
        return metadata


def create_adapter(name: str, config: dict[str, Any]) -> Adapter:
    if name == "_self-test":
        return SelfTestAdapter()
    if name == "atr-direct":
        rules_dir = config.get("rules_dir")
        if not isinstance(rules_dir, str):
            raise ValueError("atr-direct requires rules_dir")
        return ATRAdapter(Path(rules_dir))
    if name.startswith("openhands-"):
        return OpenHandsAdapter(name)
    raise ValueError(f"Unknown adapter: {name}")
