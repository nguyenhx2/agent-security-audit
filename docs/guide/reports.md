# Findings and reports

**English** · [日本語](ja/reports.md)

An audit produces one file per root-cause defect and one report set per language. The finding files and the Markdown report are the source of truth; HTML and Excel are rendered from them.

## Finding files

Path: `<audit_dir>/findings/<lang>/<repo>/find-<repo>-NNN.md`, with the id `FIND-<REPO>-NNN` in the frontmatter. The file name is the id in lowercase. Ids and anchors are the same in every language.

One finding is one root cause, deduplicated by remediation action: one package upgrade (twenty CVEs in one package are one finding), one missing check repeated across N controllers (with every site listed), one Dockerfile change that clears every CVE of a runtime version. Scanner hits are evidence attached to a root cause, not separate findings.

### Frontmatter

```yaml
---
id: FIND-SHOPAPI-001
repo: shop-api
severity: P1
confidence: confirmed
kind: security
standard: OWASP Top 10
standard_version: "2025"
requirement_id: A01
also_maps_to: "OWASP ASVS 5.0.0 V8.2; CWE-639"
cwe: CWE-639
confirmed_by: manual review
status: open
found: 2026-10-30
verified: n/a
---
```

| Field | Values |
|---|---|
| `id` | `FIND-<REPO>-NNN`, stable and unique within the audit |
| `repo` | The repository folder name, or `cross-repo` |
| `severity` | `P0`, `P1`, `P2`, `Info` |
| `confidence` | `confirmed`, `likely`, `needs-runtime-check` |
| `kind` | `security`, `sensitive-data-at-rest`, `secret`, `supply-chain`, `configuration`, `privacy`, `performance`, `quality` |
| `standard`, `standard_version`, `requirement_id` | A canonical standard name, its version, the requirement. See [the citation rule](standards-and-sectors.md#the-citation-rule). |
| `also_maps_to` | Optional further citations, each with a version |
| `cwe` | `CWE-NNN` or `n/a` |
| `shares_anchor_with` | Optional: other finding ids citing the same line for a different root cause |
| `confirmed_by` | Scanner and rule, `manual review`, or both, for example `semgrep <rule-id> + manual review` |
| `status` | `open` (default), `in-progress`, `closed`, `accepted-risk`, `false-positive` |
| `found` | Date found |
| `verified` | Date a re-scan confirmed the fix ([Phase 8](rescan.md)), else `n/a` |

Frontmatter values are always English codes; the reports show them in the report language.

### Severity

Severity is set by consequence and reachability, not by scanner wording.

| Severity | Meaning |
|---|---|
| **P0 / Blocker** | Direct, high-impact compromise reachable now: cardholder or special-category data exposure, credential compromise, unauthenticated access to sensitive data or admin functions, RCE, money theft. Ship-blocking. |
| **P1 / Major** | Serious weakness exploitable under realistic conditions (an authenticated attacker, one precondition), or a control believed to work that does not. |
| **P2 / Minor** | Real defect with limited blast radius or unlikely preconditions; defence-in-depth gaps. |
| **Info** | No direct security consequence: hardening, hygiene, coverage notes. |

Some conditions set a floor that cannot be argued down, for example: CVV or PIN stored after authorisation is P0 even if encrypted; plaintext card numbers at rest are P0; a live credential shipped in a client artifact is P0; an installed malicious dependency (`MAL-*`) is P0; a dead security control or a fail-open authorization path is at least P1. Every P0 to P2 states who gains what: `principal -> control crossed -> resource affected`. The full list: [`triage.md`](https://github.com/nguyenhx2/agent-security-audit/blob/main/security-audit/reference/method/triage.md).

### Confidence

| Confidence | Meaning |
|---|---|
| `confirmed` | The code path was read end to end: source to sink with no effective control |
| `likely` | The pattern is present and plausibly reachable; one link is not proven, and the finding says which |
| `needs-runtime-check` | Depends on deployment or runtime state a static audit cannot see; Verification names the one fact that decides it and who can check it |

### Body

The body has six sections, with localised headings:

| English | Japanese | Content |
|---|---|---|
| Location | 該当箇所 | Repository-relative `path:line` anchors with their role (source, sink, missing control, column). Never the data. |
| What it is | 内容 | The root cause, with every call site when many share it |
| Why it matters | 影響 | The consequence, who can exploit it, what is reached |
| Evidence | 根拠 | The trace from entry point to sink, scanner witnesses, the unproven link for `likely` |
| Remedy | 是正策 | The specific fix for this stack. The auditor does not patch. |
| Verification | 検証 | How this closes: the re-scan or re-read that proves the fix |

A committed secret's remedy is rotation at the provider, then history cleanup if wanted; deleting the file fixes nothing. Findings are written at defect and remedy level, never as exploit payloads.

## The Markdown report

`reports/md/security-audit-report_<project>_<ts>[_<lang>].md` is built by `build_report.py`. Tables and counts are generated from the finding files; only the narrative (executive summary, actions, cross-repo notes) is written by the model. Sections:

1. Executive summary
2. Scope and coverage gaps, including the AI and agent inventory and "Platform versions and threat intelligence" (components, advisory ids, feeds checked, feed gaps, feed date)
3. Findings, by severity, plus Refuted / false positives with a reason each
4. Sensitive data at rest (mandatory, present even when nothing was found)
5. Cross-repo findings
6. Performance and code quality
7. What the user must do, ordered, with sequencing
8. Method and limitations (mandatory)

The header records the skill version, the standards-verified date, the timestamp and the audited commit per repository. These are fixed at the first build, so rebuilds and translations never drift.

## The validator

`validate_findings.py` must exit 0 before anything is rendered. It checks:

- every finding file has complete frontmatter, with values from the allowed sets
- no bare requirement IDs: `standard_version` is present and not a placeholder; non-canonical standard names are warned
- every `path:line` anchor resolves to an existing file and a line within it (history-only secrets are marked `history:<commit>`)
- no unresolved `{{placeholders}}` anywhere
- no card-number-like (Luhn-valid 13-19 digit) values and no secrets in findings or report
- the report carries the mandatory sections and its severity counts and tables match the finding files
- no duplicate ids or duplicate (file:line, requirement) pairs
- in a Japanese (or Chinese or Korean) set, English prose in a finding is an error
- a known-exploited CVE or end-of-life deploy component from the advisory match that is in no finding and not refuted with a reason is a warning

The skill fixes every ERROR and re-runs until it passes; each WARN is fixed or explained.

## The HTML report

`render_html.py` writes one offline file to `reports/html/`: severity cards (click to filter), a findings explorer with full-text search across finding bodies, filters for severity, repository, kind, confidence and status, sortable columns, expandable rows, `#FIND-ID` deep links, CSV export of the filtered view, and the full report with a table of contents. Light and dark, print-friendly. Everything from the audit is HTML-escaped, nothing external is loaded, and a strict content security policy applies.

![HTML report: severity cards, filters and the findings table](../assets/screens/html-report.png)

![HTML report: an expanded finding](../assets/screens/html-finding.png)

## The Excel workbook

`render_xlsx.py` writes `reports/xlsx/` with four sheets:

| Sheet | Content |
|---|---|
| Summary | Project information, statistics (COUNTIFS formulas, so they follow your edits) and four charts: by severity, repository by severity, by kind, by status |
| Findings | One row per finding; dropdowns for Severity, Confidence, Status, Kind, Repo and Standard; Owner, Due date and Notes columns for tracking; filters and a frozen header |
| Coverage | Scanners per repository (status, image, digest, seconds), coverage gaps, sweep statistics |
| Master | The value lists behind every dropdown, as named ranges |

Text is redacted, and cells that start with `=`, `+`, `-` or `@` are stored as text, never as formulas. `--verify` recalculates the workbook in Excel (Windows) or LibreOffice and fails on a formula error or a total that does not match the finding files; with neither installed it prints `VERIFY SKIPPED` and the reply says the workbook was not recalculated. Needs `openpyxl`.

![Excel workbook: Summary sheet with four charts](../assets/screens/excel-summary.png)

The screenshots come from a real Quick audit of DVWA, a deliberately vulnerable practice app, in the benchmark.

## Translation

Findings are written once, as `work/findings.json` and `work/narrative.json`, in one source language: English at Standard and Deep unless exactly one report language was chosen (then that language). Each other chosen language is produced by a `report-translator` subagent from those two files, while the source-language report is being built. `new_finding.py --source` copies every code, id and `path:line` from the source, so only prose changes. Each language set is then built, validated and rendered on its own. With a single report language, the verifier drafts directly in it and no translator runs.

## Cleaning up work/

`prune_work.py` runs last, once every language and format is built and validated. By default it deletes intermediates nothing reads after the run (raw scanner output, lane packs, lane notes, digests, route maps, recon notes) and keeps what a rebuild, a later translation and a [Phase 8 re-scan](rescan.md) need (`findings*.json`, `narrative*.json`, `report-settings.json`, `profile.md`, `scanners.json`, `sweep.json`, `platform.json`, `intel.json`, `lanes/candidates.md`, `lanes/verifier.md`). Typically 3 MB becomes 0.4 MB. Unknown files are never touched.

| Switch | Effect |
|---|---|
| `--keep-work` | Keep everything (investigation, skill debugging) |
| `--purge-work` | Delete the whole `work/` folder. Reports can no longer be rebuilt or translated, and Phase 8 becomes a new audit. |
| `--dry-run` | List what would be deleted |

Pass `--keep-work` or `--purge-work` on the `/security-audit` command line to choose.

## See also

- [Standards and industry sectors](standards-and-sectors.md)
- [Re-scan and fix verification](rescan.md)
- [`finding.md.template`](https://github.com/nguyenhx2/agent-security-audit/blob/main/security-audit/templates/finding.md.template) and [`audit-report.md.template`](https://github.com/nguyenhx2/agent-security-audit/blob/main/security-audit/templates/audit-report.md.template)
