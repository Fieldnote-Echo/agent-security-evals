"""Command-line interface for agent security evaluations."""

from __future__ import annotations

import argparse
import subprocess
from pathlib import Path

from agent_security_evals.adapters import (
    OPENHANDS_PROJECTABLE_SURFACES,
    PUBLIC_ADAPTERS,
)
from agent_security_evals.reports import compare_runs
from agent_security_evals.runner import run_adapter
from agent_security_evals.sources import load_manifest, prepare_suite


PACKAGE_ROOT = Path(__file__).resolve().parent
DEFAULT_MANIFEST = PACKAGE_ROOT / "data" / "manifest.json"
DEFAULT_DATA_DIR = Path("data")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Run non-executing security evaluations against pinned public data."
        )
    )
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--data-dir", type=Path, default=DEFAULT_DATA_DIR)
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("list", help="List the available suites and adapters.")

    prepare_parser = subparsers.add_parser(
        "prepare", help="Download, verify, and normalize one suite."
    )
    prepare_parser.add_argument("suite")

    run_parser = subparsers.add_parser(
        "run", help="Run one local analyzer adapter against a prepared suite."
    )
    run_parser.add_argument("suite")
    run_parser.add_argument("--adapter", required=True)
    run_parser.add_argument("--output", type=Path, required=True)
    run_parser.add_argument("--sdk-checkout", type=Path)
    run_parser.add_argument("--python", type=Path)
    run_parser.add_argument("--rules-dir", type=Path)
    run_parser.add_argument("--project-to", choices=OPENHANDS_PROJECTABLE_SURFACES)
    run_parser.add_argument("--timeout", type=int, default=600)

    compare_parser = subparsers.add_parser(
        "compare", help="Compare two result files without comparing runtime."
    )
    compare_parser.add_argument("base", type=Path)
    compare_parser.add_argument("candidate", type=Path)
    compare_parser.add_argument("--output", type=Path, required=True)
    compare_parser.add_argument("--stable-sample-size", type=int, default=20)
    return parser


def _results_path(path: Path) -> Path:
    return path / "results.jsonl" if path.is_dir() else path


def main() -> None:
    parser = _parser()
    args = parser.parse_args()
    try:
        manifest = load_manifest(args.manifest)
        if args.command == "list":
            print("Suites:")
            for name, sources in manifest.suites.items():
                print(f"  {name}: {', '.join(sources)}")
            print("Adapters:")
            for name in PUBLIC_ADAPTERS:
                print(f"  {name}")
            return

        if args.command == "prepare":
            output = prepare_suite(
                manifest=manifest,
                suite=args.suite,
                data_dir=args.data_dir,
                package_root=PACKAGE_ROOT,
            )
            print(f"Prepared {args.suite}: {output}")
            return

        if args.command == "run":
            input_path = args.data_dir / "processed" / f"{args.suite}.jsonl"
            results = run_adapter(
                input_path=input_path,
                output_dir=args.output,
                adapter=args.adapter,
                python=args.python,
                sdk_checkout=args.sdk_checkout,
                rules_dir=args.rules_dir,
                project_to=args.project_to,
                timeout_seconds=args.timeout,
            )
            print(f"Wrote results: {results}")
            return

        summary = compare_runs(
            base_path=_results_path(args.base),
            candidate_path=_results_path(args.candidate),
            output_dir=args.output,
            stable_sample_size=args.stable_sample_size,
        )
        print(
            f"Compared {summary['records']} records with "
            f"{summary['changed']} semantic changes: {args.output}"
        )
    except (OSError, RuntimeError, subprocess.SubprocessError, ValueError) as exc:
        parser.error(str(exc))
