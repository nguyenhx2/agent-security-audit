# Scanner smoke fixture - planted defects, on purpose

Everything under `tree/` is **deliberately vulnerable**. It is the input of
`scripts/smoke_scanners.py`, which proves that a scanner image (the pinned one, or a candidate
from `scripts/update_pins.py`) still finds a known defect before its pin moves. One defect is
planted per scanner; `expect.json` lists the rule ids each scanner must report.

| Scanner | Planted defect | Expected rule (any of) |
|---------|----------------|------------------------|
| gitleaks | fake GitHub token in the working tree, and another in a file deleted from history | `github-pat` |
| semgrep | Flask command injection, `os.system`, `yaml.load`, `eval`, MD5 | `subprocess-shell-true`, ... |
| trivy | lodash 4.17.4, requests 2.19.1; `FROM :latest`, `USER root` | `CVE-2021-23337`, ...; `DS002`, ... |
| osv-scanner | lodash 4.17.4, requests 2.19.1 | `GHSA-35jh-r3h4-6jhm`, ... |
| checkov | SSH open to 0.0.0.0/0, public-read S3 bucket | `CKV_AWS_24`, `CKV_AWS_20` |
| hadolint | `FROM ubuntu:latest`, unpinned apt, last `USER root` | `DL3007`, ... |
| zizmor | `pull_request_target` + checkout of the PR head, PR title in `run:` | `dangerous-triggers`, `template-injection` |
| mobsfscan | password logged, `java.util.Random`, SSL error ignored, MD5 | `android_logging`, ... |

## Why every file ends in `.fixture`

So nothing in this repository's own pipeline mistakes the fixture for real code:

- CodeQL (`.github/workflows/codeql.yml`) scans `*.py` and `.github/workflows/*.yml`; the
  fixture's Python and workflow are `*.fixture`, and the workflow sits under `_github/`.
- Dependabot and GitHub's dependency graph read `requirements.txt` and `package-lock.json` by
  exact name; the vulnerable lockfiles here are `*.fixture`.
- No secret is committed. The two token files hold a placeholder; `smoke_scanners.py` writes a
  well-formed but **fake** token (derived from a hash, never issued by GitHub) into a temporary
  copy at run time.

`smoke_scanners.py` copies `tree/` to a temporary directory, drops the `.fixture` suffix, renames
`_github` to `.github`, makes it a git repository (the history-only file is committed, then
deleted) and runs `security-audit/scripts/run_scanners.py` on it, exactly as the skill does.

Never copy anything from `tree/` into real code.
