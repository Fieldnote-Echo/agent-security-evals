# Agent shell corpus

This local repository checks OpenHands security analyzers against shell commands
from public agent traces. The harness does not start a shell with corpus text.

The first two sources use the MIT license:

- [OpenHands feedback](https://huggingface.co/datasets/OpenHands/openhands-feedback)
- [Data Agent Harbor](https://huggingface.co/datasets/AdithyaSK/data_agent_harbor_train_sft)

`corpora.json` pins each source revision, file size, and SHA-256 digest. The raw
Parquet files and all generated results stay uncommitted under `data/` and
`runs/`.

## Setup

```bash
uv sync --frozen
```

## Fetch and extract

```bash
uv run python corpus_harness.py fetch
uv run python corpus_harness.py extract --output runs/sample/commands.jsonl
```

The default sample contains 100 OpenHands feedback shell-call records and 200
Data Agent Harbor shell-call records. Sampling is deterministic. The extractor
preserves every selected command string exactly.

## Compare two SDK checkouts

Use a Python environment that contains the SDK dependencies. The harness loads
SDK source from the selected checkout in a separate process.

Use only trusted local SDK checkouts. The worker imports Python code from the
selected checkout with the current user's file access. It uses a small explicit
environment, but it is not a sandbox.

```bash
uv run python corpus_harness.py analyze \
  --sdk-checkout /path/to/base \
  --python /path/to/sdk/.venv/bin/python \
  --input runs/sample/commands.jsonl \
  --output runs/sample/base.jsonl \
  --label base

uv run python corpus_harness.py analyze \
  --sdk-checkout /path/to/branch \
  --python /path/to/sdk/.venv/bin/python \
  --input runs/sample/commands.jsonl \
  --output runs/sample/branch.jsonl \
  --label branch

uv run python corpus_harness.py compare \
  --base runs/sample/base.jsonl \
  --candidate runs/sample/branch.jsonl \
  --review-output runs/sample/review.jsonl \
  --report runs/sample/report.md
```

The review set contains:

- all shell-call records with a changed result;
- all shell-call records with a `HIGH` result in either run;
- all analyzer errors;
- a deterministic sample of unchanged commands that stayed `LOW`.

The analyzer worker constructs `ActionEvent` values and calls only
`PatternSecurityAnalyzer.security_risk()` and
`PolicyRailSecurityAnalyzer.security_risk()`. It never starts a shell with a
corpus command.
