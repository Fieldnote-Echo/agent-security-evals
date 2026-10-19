# Agent Security Evals

Agent Security Evals runs reproducible, non-executing checks for agent security
analyzers and rule sets. It normalizes pinned public datasets, runs a selected
local analyzer in a separate process, and writes reviewable JSON and Markdown
results.

This is an independent project. It is not an official OpenHands or Agent
Threat Rules project.

This project evaluates deterministic analyzers. Analyzer runs do not run a
language model, call an external analyzer API, or use credentials. The prepare
command can download pinned public data. The project never passes corpus text
to a shell or executes a command found in a dataset.

The project is an evaluation tool. It is not a sandbox or a security boundary.
Use only trusted local SDK checkouts and trusted rule files. The worker imports
their Python code with the permissions of the current user.

## What the project provides

- A versioned record and result schema.
- Pinned source revisions, byte counts, and SHA-256 digests.
- Deterministic normalization and stable record identifiers.
- Adapters for direct Agent Threat Rules (ATR) checks and OpenHands security
  analyzers.
- Reports that keep `unknown`, `skipped`, and `error` results separate.
- Semantic comparison that excludes runtime from change detection.

See [DATASETS.md](DATASETS.md) for source licenses, labels, and redistribution
rules. See [SECURITY.md](SECURITY.md) before you process untrusted content or
load a local checkout.

## Labels and metrics

The labels describe source provenance. They are not project judgments about
all behavior in a record.

- `attack` is an attack or attack outcome defined by the source dataset.
- `benign` is a benign control defined by the source dataset.
- `operational` is a command from an agent trace. It is not a benign label.
- `unknown` has no class claim.

The reports use attack recall, benign false-positive rate, and operational
alert rate when those labels are present. The project does not report an
overall accuracy value. These public datasets are not a held-out benchmark.

## Setup

Install Python 3.11 or later and
[`uv`](https://docs.astral.sh/uv/getting-started/installation/). Then run:

```bash
uv sync --frozen --all-extras
```

This command installs the locked development environment. The `corpora` extra
adds Parquet support. The `atr` extra installs `pyatr==0.3.1`.

You can also use `pip` for a local installation:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[atr,corpora]"
```

List the available suites and adapters:

```bash
uv run agent-security-evals list
```

## Prepare data

The `smoke` and `llmail_phase2` data files are included in the package. Other
sources are download-only. The prepare command verifies every file before it
creates the normalized suite.

```bash
uv run agent-security-evals prepare smoke
uv run agent-security-evals prepare labeled-core
```

Prepared data goes to `data/processed/<suite>.jsonl`. The companion metadata
file records the source revisions, counts, and output SHA-256 digest. Raw and
processed data under `data/` stays outside Git.

## Run an adapter

The public adapters are:

- `atr-direct`, which loads a supplied ATR rule directory with `pyatr`;
- `openhands-pattern`, which runs the default OpenHands pattern analyzer;
- `openhands-policy-rails`, which runs the OpenHands policy-rail analyzer;
- `openhands-pattern-atr-high`, which adds selected high-severity ATR patterns
  to the OpenHands pattern analyzer; and
- `openhands-pattern-atr-all`, which adds the selected high- and
  medium-severity ATR patterns.

The OpenHands ATR pattern adapters are selected pattern integrations. They are
not complete direct evaluation of an ATR release.

Run ATR rules directly:

```bash
uv run agent-security-evals run labeled-core \
  --adapter atr-direct \
  --rules-dir /path/to/agent-threat-rules/rules \
  --output runs/atr-direct
```

Run an OpenHands analyzer from a clean local SDK checkout:

```bash
uv run agent-security-evals run operational-shell \
  --adapter openhands-pattern \
  --sdk-checkout /path/to/software-agent-sdk \
  --python /path/to/software-agent-sdk/.venv/bin/python \
  --output runs/openhands-pattern
```

The selected Python environment must contain the dependencies of the analyzer.
The runner records the SDK commit, input digests, adapter metadata, and whether
the worker was sandboxed. The worker is not sandboxed.

OpenHands adapters support `action_argument`, `command`, `reasoning_content`,
`summary`, and `thought`. They mark other surfaces as `skipped`.
The `openhands-pattern-atr-high` and `openhands-pattern-atr-all` adapters need a
checkout that provides
`openhands.sdk.security.defense_in_depth.atr_patterns`.

Use an explicit projection when you want to test a pattern set against text
from a different source surface:

```bash
uv run agent-security-evals run labeled-core \
  --adapter openhands-pattern-atr-all \
  --project-to thought \
  --sdk-checkout /path/to/software-agent-sdk \
  --python /path/to/software-agent-sdk/.venv/bin/python \
  --output runs/openhands-pattern-atr-all
```

Projection does not change the source record. Each result uses a case ID such
as `projected:thought` and records both surfaces. A projected run measures
pattern behavior on the selected field. It does not measure native end-to-end
detection.

## Compare runs

```bash
uv run agent-security-evals compare \
  runs/base \
  runs/candidate \
  --output runs/comparison
```

The comparison checks that both runs used the same input content. It selects
semantic changes, matches, errors, and a deterministic sample of stable
`no_match` records for review. Latency does not affect semantic comparison.
Result and review files use record identifiers and text hashes. Review files
also include source names, surfaces, and labels. They do not copy source text.

## ATR v4.1.5 coverage limit

Direct evaluation of ATR v4.1.5 has reduced coverage with `pyatr==0.3.1`.
The fourth condition of `ATR-2026-00290`, at zero-based index 3, has a
backreference without a capture group. The condition does not compile. The
adapter records this limit in
`adapter.json` and sets `complete_rule_evaluation` to `false`. Do not describe
such a run as complete ATR v4.1.5 coverage.

## Development

Run the local checks:

```bash
uv run ruff check .
uv run ruff format --check .
uv run pytest
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution rules.

## License

Project code and documentation are available under either the MIT License or
the Apache License 2.0. You can select either license. See [LICENSE](LICENSE),
[LICENSE-MIT](LICENSE-MIT), and [LICENSE-APACHE](LICENSE-APACHE).

Third-party datasets keep their source licenses. The project license does not
replace them. See [DATASETS.md](DATASETS.md) and the notices under
`src/agent_security_evals/data/third_party/`.
