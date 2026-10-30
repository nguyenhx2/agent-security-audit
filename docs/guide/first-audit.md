# Your first audit

**English** · [日本語](ja/first-audit.md)

## Start it

Ask in plain words, or call the skill by name. Any of these starts an audit:

```text
audit this repo
security review before launch
check for leaked credentials
are we storing card data correctly
OWASP / PCI / ASVS check
are we affected by this CVE
セキュリティ監査
脆弱性診断
注意喚起の影響確認
```

The explicit form takes paths, a depth and two switches:

```text
/security-audit [repo-path ...] [quick|standard|deep] [--yes] [--keep-work|--purge-work]
```

| Argument | Effect |
|---|---|
| `repo-path ...` | One or more repositories. With none, the current repository. Several repositories make one audit with one report. |
| `quick`, `standard`, `deep` | The depth. Given here, the depth question is not asked. |
| `--yes` | Skip every question and use the defaults (see below). Use it for unattended runs. |
| `--keep-work` / `--purge-work` | What to do with the intermediate `work/` folder at the end (see [Findings and reports](reports.md#cleaning-up-work)). |

Examples:

```text
/security-audit ../shop-api deep
/security-audit ../shop-api ../shop-web standard
/security-audit C:/src/shop-api quick --yes
```

**Start from a neutral folder.** If the repository you audit is the current working directory and contains `.claude/`, `.mcp.json` or `CLAUDE.md`, its hooks, MCP servers and instructions are live in your Claude Code session. The skill tells you and recommends starting the audit from a folder outside the repository, for example its parent.

## The Phase 0 questions

The skill fingerprints the repositories first (`detect_stack.py`), then asks up to five questions in one or two prompts, in the language you wrote in. A question your request already answered is dropped.

| Question | Choices | Default when not asked |
|---|---|---|
| **Depth** | Deep (recommended), Standard, Quick. The question shows the repository size. | The argument, else Deep |
| **Report language(s)** | English, 日本語, or Other (any language). Several allowed. | The language of your request |
| **Focus** | Application security, Secrets and supply chain, Sensitive data, Performance and quality. A detected AI scope or mobile app gets its own option. Use Other to add an industry the code does not show. | All detected lanes |
| **Formats** | HTML, Excel. Markdown is always produced. The question shows the output folder; pick Other to change it. | Markdown, HTML and Excel |
| **Jurisdiction** (only when personal, payment, health or financial data is detected) | GDPR (EU/UK), Japan APPI, Vietnam PDPL, US (CCPA, HIPAA) | None: privacy obligations are cited generically and the report says so |

A focus area you deselect is listed as a coverage gap, not silently dropped. An industry you state ("we are a bank", "this is for a city office") is added even when the code does not show it.

Once these are answered, or skipped with `--yes`, the skill runs through to the report without stopping to ask again. A headless run (`claude -p`) therefore always ends with findings and a report.

## Depths

| Depth | What runs | Typical use |
|---|---|---|
| **Quick** | All scripts and scanners, then up to three review lanes inline in the main session: `authz-logic`, the main lane for the repository type, `injection-dataflow`. The lead re-checks every P0 and P1 itself. No subagents. | A first look, a small repository, "are we affected by this CVE?" |
| **Standard** | All scripts and scanners, `recon-mapper` (Sonnet, medium), lane-reviewer groups in parallel (Sonnet: high on design lanes, medium on the rest), `finding-verifier` on P0 and P1 (Sonnet, high). | A routine audit |
| **Deep** (default) | As Standard, with Opus (high) on the design lanes `authz-logic`, `sensitive-data` and `ai-agentic`, Sonnet (high) on the other lanes, and the verifier on Opus (high) covering P0 to P2. Every row of the coverage checklist is walked. | Before a launch, a regulated system |

Every depth runs the platform inventory, live threat intelligence, the sensitive-data sweep and the scanners. What changes is how many review lanes run, which model reads the code, and how far adversarial verification reaches. `perf-quality` runs only at Standard and Deep; at Quick it is a stated gap. Details: [Models and cost](models.md).

### Cost and time

| Depth | Measured |
|---|---|
| Quick | The live benchmark measured a mean of US$<!--n:bench_cost_usd-->2.52<!--/n--> and <!--n:bench_minutes-->8<!--/n--> minutes per audit on three deliberately vulnerable projects ([benchmark/RESULTS.md](https://github.com/nguyenhx2/agent-security-audit/blob/main/benchmark/RESULTS.md)). The depth question describes Quick as about 5-10 minutes. |
| Standard, Deep | Not benchmarked. They run more subagents and stronger models, so expect more time and cost than Quick. |

Inside any audit: scanners take about 1-5 minutes per repository with images cached (the first image pull adds 1-5 minutes), and the advisory match takes 10-90 seconds (longer without an `NVD_API_KEY`). Both run in the background while recon and the sweep continue.

## Report languages and formats

- **English and Japanese** are fully localised: headings, labels, prose and the HTML and Excel interfaces.
- **Any other language** (Other): prose in that language, labels in English.
- **Several languages:** each gets its own complete set of findings and reports. The second language is a translation of the findings data, never a second audit, so ids, severities and anchors are the same in every language.
- The **conversation language** (questions, progress, the final reply) follows the language you write in and is independent of the report language.

| Format | Always? | What it is |
|---|---|---|
| Markdown | yes | The validated source of truth |
| HTML | if chosen | One offline file with search, filters, sortable columns and expandable findings |
| Excel | if chosen | A tracking workbook with charts, dropdowns and Owner / Due date / Notes columns. Needs `openpyxl`. |

See [Findings and reports](reports.md).

## Where the output goes

Everything goes to a timestamped folder beside the repository, never inside it:

```text
<parent-of-repo>/<project>-security-audit/<YYYY-MM-DD_HHMM>/
  reports/md/    security-audit-report_<project>_<ts>[_<lang>].md   always, validated
  reports/html/  ..._<ts>[_<lang>].html                             when chosen
  reports/xlsx/  ..._<ts>[_<lang>].xlsx                             when chosen
  findings/<lang>/<repo>/find-<repo>-001.md                         one file per root cause
  work/                                                             intermediate, pruned at the end
```

`<project>` is the product name you gave, else the repository name, else the repository names joined with `-`. File names are lowercase. A re-run never overwrites: a new timestamp makes a new folder (two runs in the same minute get `_2`). The `_<lang>` suffix appears only when you chose more than one report language. With several repositories, the folder sits in their common parent.

You can also give another output folder in the Formats question.

## Worked example

You want a routine audit of a Node.js API in `C:/src/shop-api` before a release, with an English report for the team and a Japanese one for a partner.

1. Open Claude Code in `C:/src` (the parent, not the repository) and type:

   ```text
   /security-audit shop-api standard
   ```

2. The skill runs `env_check.py` and `detect_stack.py`, then asks the remaining questions. You pick **English** and **日本語**, keep all focus areas, keep HTML and Excel. Because the API stores customer accounts, it also asks the jurisdiction; you pick **Japan APPI**.
3. Scanners start in the background, followed by the platform inventory and the live advisory match. Recon, the sensitive-data sweep and the review lanes run while they finish.
4. The verifier tries to refute each P0 and P1 candidate. Survivors become finding files, the report is built, validated and rendered, and a translator subagent produces the Japanese set from the same data.
5. The final reply is short: P0 and P1 counts, the top three to five findings with `file:line`, the first thing to do, the coverage gaps, and the report paths, for example:

   ```text
   C:/src/shop-api-security-audit/2026-10-30_1015/reports/html/security-audit-report_shop-api_2026-10-30_1015_en.html
   C:/src/shop-api-security-audit/2026-10-30_1015/reports/html/security-audit-report_shop-api_2026-10-30_1015_ja.html
   ```

Open the HTML report, sort by severity, assign owners in the Excel workbook, and fix. When the fixes are in, ask "re-scan to verify the fixes" ([Re-scan and fix verification](rescan.md)).

For a real result, the README shows screenshots of a Quick audit of DVWA, a deliberately vulnerable practice app, with 19 findings ([README: What the reports look like](https://github.com/nguyenhx2/agent-security-audit/blob/main/README.md#what-the-reports-look-like)).

## See also

- [How an audit runs](how-it-works.md)
- [Findings and reports](reports.md)
- [Troubleshooting and FAQ](troubleshooting.md)
