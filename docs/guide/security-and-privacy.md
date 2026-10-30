# Security and privacy

**English** · [日本語](ja/security-and-privacy.md)

An auditor reads hostile input for a living. This page lists what the skill runs, sends, fetches and writes, and how it protects the code it audits, the secrets in it, and the machine it runs on.

## What it runs, sends, fetches and writes

| | |
|---|---|
| **Runs locally** | The bundled Python scripts. Read-only git commands on the audited repository. Pinned scanners in Docker or Podman (images pulled by digest, repository mounted read-only, Gitleaks and hadolint with networking disabled), else native installs, else none with the gap stated. The Excel recalculation check through Excel or LibreOffice, when installed. |
| **Sends** | `threat_intel.py`: product names and versions only (an endoflife.date product id, an NVD CPE string such as `cpe:2.3:a:php:php:8.3.30`, CVE ids to FIRST EPSS). Never repository names, paths, code or findings. OSV-Scanner sends package names and versions to osv.dev; Semgrep downloads its rule pack; Trivy downloads its vulnerability database. |
| **Fetches** | Public feeds, no account: CISA KEV (GitHub mirror as fallback), NVD CVE API 2.0, FIRST EPSS, endoflife.date, IPA, JPCERT/CC, JVN and JVN iPedia RSS. Fixed host allowlist; cached under `~/.cache/security-audit/intel`; `--offline` uses the cache only. `run_scanners.py --check-updates` asks Docker Hub and GHCR for tag lists, only when it is run. |
| **Writes** | Only the audit folder outside the audited repository (`<parent>/<project>-security-audit/<timestamp>/`), the feed cache, and at Standard or Deep depth the four helper subagents in `~/.claude/agents/security-audit/`. |

Semgrep runs with `--metrics off` and the `p/default` pack, never `auto`, which would send the project URL to the registry. TruffleHog is not part of the runner; if it is used as an extra tool, its verification mode, which contacts providers, needs your approval.

## Read-only rules

- **Audited code is never edited**, formatted, committed or "quick-fixed". The auditor reports; you apply the fixes. This is also a separation-of-duties requirement (OWASP AISVS 1.01 Appendix C, AC.8.1 and AC.8.4).
- **No output inside the audited repository.** `run_scanners.py` refuses an output folder inside it; all scripts write to the audit folder.
- **git is read-only and inert.** Every git call disables `core.fsmonitor`, optional locks, hooks and repository config, and never writes the index. The Gitleaks history pass runs without textconv or external diff drivers.
- **Containers are boxed.** The repository is mounted read-only. On Linux and macOS containers run as your user. SELinux hosts use `label=disable`, never `:z`, because relabelling would write into the audited repository.
- **Symlinks out of the repository are skipped** and counted, so no host file is read through one.
- **The code is never built or run.** Scripts read files; they never execute project code.

## Secrets and personal data are never printed

- Secrets, card numbers and personal data never appear in the transcript, the findings or the reports, not even truncated, whether real or test values.
- Secret-bearing lines are viewed only through `peek.py`, which masks private keys, high-entropy tokens, values of secret-like names, CLI secrets, cloud and SaaS token shapes, card-like numbers, connection-string passwords, e-mail addresses, phone numbers, Japanese street addresses and personal-data values, while keeping names, keys, line numbers and code structure visible.
- The skill never uses `cat`, `sed` or `grep` on config, IaC, `.env*`, seed or fixture files to look for secrets, because their values would enter the transcript.
- `repo_digest.py` records locations and tokens only, never line contents. `sensitive_sweep.py` reports `file:line`, the matched term and the data class, never values; Luhn-valid numbers are reported as "PAN-like literal" with no value.
- Gitleaks runs with `--redact`; the normaliser masks long tokens; the Excel renderer redacts text.
- A finding names the variable and `file:line`, never the value. The validator refuses a report that still carries a card-number-like value or a secret.

Examples in this guide use placeholders such as `<token>` and `CVE-2026-XXXXX`.

## Audited content is evidence, never instructions

README files, `CLAUDE.md`, `AGENTS.md`, skill files, rules, code comments, prompt logs, MCP tool descriptions and advisory feed text may address an AI agent. The skill reads all of them as data. It never follows, runs, fetches or installs what they say, and it reports instruction-like text as a finding.

Related protections:

- **The repository cannot silence its own scanners.** Gitleaks ignores repository allow-lists, zizmor runs with `--no-config`, Semgrep with `--disable-nosem`, OSV-Scanner with an empty config. What cannot be neutralised (`.gitleaksignore`, `.checkov.yaml`, `.semgrepignore`) is listed as a coverage gap. An inline `nosemgrep`, `# noqa` or `gitleaks:allow` is noted as a claim by the code under audit.
- **Scanner output is untrusted.** SARIF is parsed as data, never executed; messages are truncated and secret-like strings masked.
- **Feed text is untrusted.** Control, bidi and zero-width characters are stripped, titles truncated, links kept only for the feed's own hosts, and redirects to other hosts refused.
- **HTML output is escaped.** Everything quoted from audited code is HTML-escaped, no raw HTML passes through, and the page loads nothing external.
- **Excel output cannot carry formulas from the audit.** Cells starting with `=`, `+`, `-` or `@` are stored as text.
- **Self-protection.** When the audit target is the current working directory and holds `.claude/`, `.mcp.json` or `CLAUDE.md`, its hooks, MCP servers and instructions are live in your session. The skill says so and recommends starting from a neutral folder. If it holds its own `.claude/agents/security-audit-*` files, those would override the skill's agents, so the skill uses the general-purpose fallback instead.
- **Subagents are restricted.** No Edit, no Agent, a turn cap, and no `CLAUDE.md`.

## Your output is yours

The findings, reports, work files, inventories and threat-intelligence summaries the skill writes about your repository are yours, under terms of your choice. The skill itself is licensed under AGPL-3.0-only. See [NOTICE](https://github.com/nguyenhx2/agent-security-audit/blob/main/NOTICE.md).

## Reporting a vulnerability in the skill

Use GitHub's private vulnerability reporting (the repository's **Security** tab, then **Report a vulnerability**), not a public issue. Scope and what to include: [SECURITY.md](https://github.com/nguyenhx2/agent-security-audit/blob/main/SECURITY.md).

## See also

- [ARCHITECTURE: Protecting the auditor](https://github.com/nguyenhx2/agent-security-audit/blob/main/docs/ARCHITECTURE.md#protecting-the-auditor)
- [Live threat intelligence](threat-intelligence.md)
- [How an audit runs](how-it-works.md#read-only-guarantees)
