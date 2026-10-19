# Security policy

Agent Security Evals processes untrusted text. It does not provide a sandbox or
a security boundary.

## Supported versions

The project is in an alpha state. Security fixes apply to the current default
branch. Older commits and local modifications do not receive support.

## Report a vulnerability

Use a private GitHub security advisory to report a vulnerability:

<https://github.com/Fieldnote-Echo/agent-security-evals/security/advisories/new>

Do not include exploit details, private data, or credentials in a public issue.
Include the affected commit, the required configuration, the impact, and a
small reproduction if it is safe to share.

## Trust boundaries

Dataset records are untrusted data. They can contain prompt injections, harmful
instructions, URLs, and shell commands. The project parses and compares these
strings. It does not execute a command from a record.

The analyzer worker is a separate process, but it is not a sandbox. The worker
imports the selected analyzer and its dependencies. A local SDK checkout or a
Python package can run arbitrary Python code during import or evaluation. The
worker has the file and network permissions of the current user. Use only code
and rule files that you trust.

The runner uses a small explicit environment for the worker. This reduces
unplanned configuration input. It does not isolate the process or make
untrusted Python safe.

The prepare command downloads only pinned HTTPS files. It verifies the exact
byte count and SHA-256 digest before extraction. These checks detect a changed
file. They do not prove that the original dataset content is safe.

## Secrets and external services

The project does not need a language model, model API, API key, cloud account,
or other credential. Do not add credentials to the environment, data files,
run directories, logs, issues, or pull requests.

Analyzer runs do not call a model or model API. A trusted analyzer dependency
could still contain network behavior. Review that dependency before use. Run
the evaluation in a separate restricted environment when this risk matters.

Public datasets can contain text that looks like a secret or asks for a secret.
Treat this text as untrusted test data. Do not replace it with a real secret.

## Safe operation

- Use a clean and trusted SDK checkout.
- Use a dedicated Python environment with reviewed dependencies.
- Keep the default `data/` and `runs/` paths outside Git.
- Review generated logs before you share them.
- Do not execute a command copied from a dataset.
- Do not give the worker credentials or access to sensitive files.
- Stop if a source digest does not match. Do not bypass the check.

The tool produces evaluation evidence. It does not certify an analyzer for
production use. It does not make an accuracy claim. Review matched, missed,
unknown, skipped, and error records before you make a security decision.

## Known ATR coverage limit

Direct ATR v4.1.5 evaluation with `pyatr==0.3.1` has reduced coverage.
The fourth condition of `ATR-2026-00290`, at zero-based index 3, does not
compile because its regular expression has a backreference without a capture
group. The adapter records this condition and sets
`complete_rule_evaluation` to `false`.

Do not use a result with this marker as evidence of complete ATR v4.1.5 rule
coverage.
