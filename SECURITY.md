# Security policy

## Reporting a vulnerability

Please report a vulnerability in this repository privately, through GitHub's private vulnerability
reporting: the **Security** tab of https://github.com/nguyenhx2/agent-security-audit, then
**Report a vulnerability**. Do not open a public issue for it.

Include what you found, the file and version (the `VERSION` file inside an installed skill, or the
commit), how to reproduce it, and what an attacker gains. A proof of concept against a throwaway
repository is ideal.

This is maintained by one person. Expect an acknowledgement within a week; a fix is released as a
patch version with a **Fixed** entry in `security-audit/CHANGELOG.md` that names the failure mode,
and the advisory is published once the fix is out. Credit is given in the advisory unless you ask
otherwise.

## Scope

In scope - the skill and everything that runs on a user's machine or in this repository's CI:

- the scripts under `security-audit/scripts/` and `editions/ja/security-audit/scripts/` (for
  example: a hostile repository or a hostile advisory feed that makes a script execute code, write
  outside its work folder, leak a secret into a report, or reach the network when it should not)
- the subagent definitions and the skill instructions (for example: content in an audited
  repository that can steer the audit into editing code, running commands or exfiltrating data)
- the release workflows and tooling under `.github/` and `scripts/`, and the published zips

Out of scope:

- vulnerabilities in the repositories you audit with the skill - report those to their owners
- the deliberately insecure fixtures under `eval/fixtures/` (a root container, a `.env` under a web
  root, a hostile feed title): they exist to prove the detectors fire
- the third-party scanners the skill runs (Semgrep, Gitleaks, Trivy and others) and the advisory
  feeds it reads - report those upstream

## Supported versions

Only the latest release receives fixes. Upgrade by installing the newest zip or with
`/plugin update`.
