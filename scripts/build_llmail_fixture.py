"""Build the normalized LLMail fixture from pinned source files."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from agent_security_evals.contracts import EvalRecord
from agent_security_evals.io import sha256_file, write_jsonl


REVISION = "1063bdf01ec8762b812d5e06ee768a06faa5a6f7"
HOMEPAGE = "https://huggingface.co/datasets/microsoft/llmail-inject-challenge"
ATTACK_SHA256 = "f89af984e345430c3b357903890e30867bf4676f4ef10c138cc7bad218e890b8"
BENIGN_SHA256 = "4ddd950b5dbaa8548f5597c886d8e09a051ba07f80a9291fdcca9c2397d22abe"


def _source(kind: str, index: int) -> dict[str, object]:
    return {
        "dataset": "llmail_phase2",
        "revision": REVISION,
        "homepage": HOMEPAGE,
        "license": "MIT",
        "coordinates": {"kind": kind, "index": index},
    }


def build(attacks_path: Path, benign_path: Path) -> list[EvalRecord]:
    if sha256_file(attacks_path) != ATTACK_SHA256:
        raise ValueError("The LLMail attack source has an unexpected SHA-256")
    if sha256_file(benign_path) != BENIGN_SHA256:
        raise ValueError("The LLMail benign source has an unexpected SHA-256")

    attacks_raw = json.loads(attacks_path.read_text(encoding="utf-8"))
    benign_raw = json.loads(benign_path.read_text(encoding="utf-8"))
    if not isinstance(attacks_raw, dict) or not isinstance(benign_raw, list):
        raise ValueError("The LLMail source shape changed")

    attack_texts = sorted(
        text
        for text, outcome in attacks_raw.items()
        if isinstance(text, str)
        and isinstance(outcome, dict)
        and outcome.get("attack_attempt") == "True"
        and outcome.get("reason") == "api_triggered"
    )
    if len(attack_texts) != 3165:
        raise ValueError(
            f"Expected 3165 API-triggered records, found {len(attack_texts)}"
        )
    if len(set(attack_texts)) != len(attack_texts):
        raise ValueError("LLMail attack text must be unique")
    if len(benign_raw) != 203 or not all(isinstance(text, str) for text in benign_raw):
        raise ValueError("Expected 203 LLMail benign email strings")

    records: list[EvalRecord] = []
    for index, text in enumerate(attack_texts):
        records.append(
            EvalRecord.create(
                record_id=f"llmail_phase2:attack:index={index}",
                text=text,
                surface="email",
                origin="human",
                group_id=None,
                source=_source("attack", index),
                label={
                    "value": "attack",
                    "provenance": "source_outcome",
                    "confidence": "high",
                },
                metadata={"outcome": {"api_triggered": True}},
            )
        )
    for index, text in enumerate(benign_raw):
        records.append(
            EvalRecord.create(
                record_id=f"llmail_phase2:benign:index={index}",
                text=text,
                surface="email",
                origin="unknown",
                group_id=None,
                source=_source("benign", index),
                label={
                    "value": "benign",
                    "provenance": "source_control",
                    "confidence": "high",
                },
            )
        )
    return records


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--attacks", type=Path, required=True)
    parser.add_argument("--benign", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    records = build(args.attacks, args.benign)
    write_jsonl(args.output, (record.to_dict() for record in records))
    print(
        f"Wrote {len(records)} records with SHA-256 {sha256_file(args.output)}: "
        f"{args.output}"
    )


if __name__ == "__main__":
    main()
