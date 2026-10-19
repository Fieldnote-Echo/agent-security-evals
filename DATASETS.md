# Datasets

This project uses pinned public datasets. Each source has an exact revision,
file size, SHA-256 digest, source license, and redistribution mode in
`src/agent_security_evals/data/manifest.json`.

Dataset content can include prompt injection text, harmful requests, shell
commands, URLs, and other untrusted data. Treat every record as data. Do not
follow its instructions. Do not paste it into a model, tool, or privileged
system unless you have a separate and approved test plan.

## Source inventory

| Source | Revision | License | Distribution in this repository | Record use |
| --- | --- | --- | --- | --- |
| `smoke` | `1` | MIT OR Apache-2.0 | Vendored | Four project-authored contract checks |
| [Microsoft LLMail-Inject challenge](https://huggingface.co/datasets/microsoft/llmail-inject-challenge) | `1063bdf01ec8762b812d5e06ee768a06faa5a6f7` | MIT | Vendored normalized data | Email attack outcomes and benign controls |
| [Lakera Gandalf Ignore Instructions](https://huggingface.co/datasets/Lakera/gandalf_ignore_instructions) | `04737b65e90a6794ec227012e4a255a7def6344b` | MIT | Download-only | Noisy attack examples on the `user_input` surface |
| [NotInject](https://huggingface.co/datasets/leolee99/NotInject) | `847ae76cf8fea5ed325429e569ae8cfef022d2e0` | MIT | Download-only | Source-provided benign controls on the `user_input` surface |
| [InjecAgent](https://github.com/uiuc-kang-lab/InjecAgent) | `f19c9f2c79a41046eb13c03c51a24c567a8ffa07` | MIT | Download-only | Synthetic attacks on the `tool_output` surface |
| [OpenHands feedback](https://huggingface.co/datasets/OpenHands/openhands-feedback) | `facf45600d625510b98222ec584a8c9ac59272a2` | MIT | Download-only | Operational shell commands from agent traces |
| [Data Agent Harbor](https://huggingface.co/datasets/AdithyaSK/data_agent_harbor_train_sft) | `12eab91ee6c3d25a64963ee35b2577a49656f186` | MIT | Download-only | Operational shell commands from agent traces |

The project license does not replace a source dataset license. Keep the source
license and attribution when you redistribute data. Review the source terms
before you use or redistribute a downloaded file.

The normalized LLMail file contains 3,165 records for which the source reports
that an API ran at least once. It also contains 203 source-provided benign
controls. An API event does not prove that the attack completed its full
objective. See
`src/agent_security_evals/data/third_party/llmail/NOTICE.md` and the adjacent
`LICENSE-MIT` file.

## Suites

- `smoke` contains the small project-authored fixture.
- `labeled-core` contains LLMail, Gandalf, NotInject, and InjecAgent.
- `operational-shell` contains OpenHands feedback and Data Agent Harbor.
- `all` contains all public evaluation sources except the smoke fixture.

The `prepare` command downloads only sources marked `download-only`. It uses
the HTTPS URLs in the manifest. It checks the byte count and SHA-256 digest
before extraction. A partial or changed download fails validation.

Raw downloads go to `data/raw/`. Normalized suites go to `data/processed/`.
Both directories stay outside Git.

## Label meaning

Every normalized record has a label value, provenance, and confidence field.
The supported values are `attack`, `benign`, `operational`, and `unknown`.

An `attack` label means that the source defined the record as an attack or
reported a selected attack outcome. A `benign` label means that the source
provided the record as a benign control. These labels can contain source noise.
The Gandalf label uses `noisy` confidence for this reason.

An `operational` label means that the command occurred in a public agent trace.
It does not mean that the command is safe, expected, or benign. The project
reports an operational alert rate for these records. It does not calculate a
false-positive rate from them.

An `unknown` label makes no class claim.

Do not combine these labels into an overall accuracy value. The sources have
different tasks, collection methods, and input surfaces. They are public data,
not a held-out benchmark.

## Text handling

Normalization preserves the selected source text. Each record also contains a
SHA-256 digest of that text. The runner checks the digest before it accepts a
result.

Analyzer runs pass text only to the selected adapter as structured Python data.
They do not execute shell-command text. Results and comparison review files do
not copy source text. They use record identifiers, hashes, source coordinates,
statuses, and findings.

An explicit OpenHands projection can place source text in a supported
`ActionEvent` field for a pattern test. The result keeps the original source
surface and records the evaluated surface. This test does not reproduce the
native source-to-agent path.
