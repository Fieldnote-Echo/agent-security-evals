# LLMail-Inject data notice

The normalized `llmail_core.jsonl` file contains selected records from the
[Microsoft LLMail-Inject challenge dataset](https://huggingface.co/datasets/microsoft/llmail-inject-challenge).

- Source revision: `1063bdf01ec8762b812d5e06ee768a06faa5a6f7`
- Attack source: `data/labelled_unique_submissions_phase2.json`
- Benign source: `data/emails_for_fp_tests.json`
- Source license: MIT
- Copyright: Microsoft Corporation

The file includes 3,165 records where the source reports that an API ran at
least once. It also includes 203 source-provided benign email controls. An API
event does not prove that an attack completed its full objective.

The project `MIT OR Apache-2.0` license does not apply to this third-party
data. The data stays under the source MIT license in `LICENSE-MIT`.
