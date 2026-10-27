# security-audit

Read-only security audit skill for Claude Code. It audits one or more repositories and writes
evidence-anchored findings plus Markdown, HTML and Excel reports in English or Japanese. It never
edits, builds or runs the audited code.

Usage: in Claude Code, ask "audit this repo" (or `/security-audit <repo-path> [quick|standard|deep]`).
The skill asks for depth, report language, focus and formats, then works through recon, scanners,
review lanes, verification and the report. Full procedure: `SKILL.md`; history: `CHANGELOG.md`.

## What it runs, sends and fetches

**Runs locally**
- Bundled Python scripts (stdlib; `openpyxl` only for Excel) under `scripts/`.
- Read-only git commands on the audited repo (hooks, fsmonitor and repo config disabled).
- Pinned scanners, in Docker or Podman when available, else native installs, else none (the gap is
  stated): Semgrep, Gitleaks, Trivy, OSV-Scanner, Checkov, zizmor, mobsfscan, hadolint. Container
  images are pulled by digest at run time from their public registries; the repo is mounted
  read-only, and tools that need no network (Gitleaks, hadolint) run with networking disabled.
- Excel recalculation check through Excel (Windows) or LibreOffice headless, when installed.

**Sends (network)**
- `threat_intel.py`: product names and versions only (an endoflife.date product id, an NVD CPE string
  such as `cpe:2.3:a:php:php:8.3.30`, CVE ids to FIRST EPSS). Never repo names, paths, code or findings.
- OSV-Scanner sends package names and versions to osv.dev; Semgrep downloads its rule pack from the
  Semgrep registry; Trivy downloads its vulnerability database (`--offline` keeps cached databases).

**Fetches (network, public, no account)**
- CISA KEV catalog (cisa.gov, GitHub mirror as fallback), NVD CVE API 2.0, FIRST EPSS API,
  endoflife.date API, IPA security alerts RSS, JPCERT/CC alerts RSS, JVN RSS, JVN iPedia RSS. Fixed
  host allowlist, cached under `~/.cache/security-audit/intel`. `--offline` uses the cache only.
- Feed and repository text is treated as data, never as instructions.

**Writes**
- Only to the audit folder outside the audited repo (`<parent>/<project>-security-audit/<ts>/`), the
  feed cache, and, at Standard / Deep depth, four helper subagents in `~/.claude/agents/security-audit/`.
