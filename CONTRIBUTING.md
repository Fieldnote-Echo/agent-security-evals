# Contributing

Thank you for improving Agent Security Evals. Keep each change small and easy
to review.

## Development setup

Install Python 3.11 or later and `uv`. Clone the repository. Then run:

```bash
uv sync --frozen --all-extras
```

Do not add model credentials, API keys, or cloud credentials. Development and
tests do not need them.

## Required checks

Run these commands before you open a pull request:

```bash
uv run ruff check .
uv run ruff format --check .
uv run pytest
```

Run the same local CLI smoke flow as CI:

```bash
work_dir="$(mktemp -d)"
uv run agent-security-evals list
uv run agent-security-evals --data-dir "$work_dir/data" prepare smoke
uv run agent-security-evals --data-dir "$work_dir/data" run smoke \
  --adapter _self-test \
  --output "$work_dir/run"
uv run agent-security-evals compare \
  "$work_dir/run" \
  "$work_dir/run" \
  --output "$work_dir/comparison"
```

The `_self-test` adapter is an internal contract check. Do not use it for an
analyzer evaluation.

CI runs these checks on Python 3.11 and Python 3.13.

## Change rules

- Keep corpus text as data. Never execute a command from a record.
- Do not add a model call, external analyzer API, or credential requirement.
- Keep result states such as `unknown`, `skipped`, and `error` visible.
- Do not describe operational trace records as benign.
- Do not add an overall accuracy claim for mixed public datasets.
- Preserve source labels and record their provenance and confidence.
- Add focused tests for changed behavior.
- Do not commit generated `data/` or `runs/` content.

## Add or update a dataset

Before you add a source, confirm that its license permits the planned use and
distribution. Prefer download-only integration when redistribution terms are
not clear.

Update `src/agent_security_evals/data/manifest.json` with:

- the stable source homepage;
- an immutable revision;
- the source license;
- the redistribution mode;
- the exact file size and SHA-256 digest;
- an HTTPS source URL or a safe packaged path; and
- the extractor name.

Add a deterministic extractor. Preserve the selected source text. Give each
record stable source coordinates and a stable identifier. Define the label,
label provenance, label confidence, origin, and input surface. Document the
source and license in `DATASETS.md`.

If you vendor third-party data, include its license and attribution beside the
data. Do not assume that the project license applies to third-party content.

## Analyzer changes

An adapter must return one validated result for every input record. It must not
execute record text. It must report unsupported input surfaces as `skipped`.
It must keep analyzer errors as `error` results.

An adapter can project a record only through an explicit CLI option. Keep the
source surface in the record. Record the evaluated surface and a distinct case
ID in the result. Do not describe a projected run as native end-to-end
detection.

Record adapter versions, rule digests, supported surfaces, and known coverage
limits in adapter metadata. A partial rule load or failed condition must remain
visible. For ATR v4.1.5, retain the recorded reduced coverage for zero-based
condition index 3 of `ATR-2026-00290` until the upstream condition and the
evaluated rules make that marker unnecessary.

## Pull requests

Explain the user-visible change and the checks that you ran. State any dataset,
license, schema, label, or coverage effect. Do not include raw sensitive data
or credentials in the pull request.

Report security problems through the private process in `SECURITY.md`.

## License of contributions

Unless you state otherwise, a contribution that you intentionally submit for
this project is available under both the MIT License and the Apache License
2.0. See `LICENSE`, `LICENSE-MIT`, and `LICENSE-APACHE`.
