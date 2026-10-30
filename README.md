<p align="center">
  <img src="docs/assets/readme-banner.png" alt="Agent Security Audit - read-only security audits, checked against today's advisories" width="100%">
</p>

<p align="center"><b>Audit a repository without touching it, against the advisories published today.</b></p>

<p align="center"><b>English</b> · <a href="README.ja.md">日本語</a></p>

<p align="center">
  <a href="https://github.com/nguyenhx2/agent-security-audit/releases/latest"><img src="https://img.shields.io/github/v/release/nguyenhx2/agent-security-audit?display_name=tag&sort=semver" alt="Latest release"></a>
  <a href="LICENSE.md"><img src="https://img.shields.io/badge/license-AGPL--3.0-blue.svg" alt="License: AGPL-3.0"></a>
  <a href="https://github.com/nguyenhx2/agent-security-audit/actions/workflows/ci.yml"><img src="https://github.com/nguyenhx2/agent-security-audit/actions/workflows/ci.yml/badge.svg" alt="CI workflow"></a>
  <a href="https://github.com/nguyenhx2/agent-security-audit/actions/workflows/codeql.yml"><img src="https://github.com/nguyenhx2/agent-security-audit/actions/workflows/codeql.yml/badge.svg" alt="CI: CodeQL"></a>
  <a href="#proof-you-can-run"><img src="https://img.shields.io/badge/selftest-194%2F194%20per%20edition-brightgreen.svg" alt="Self-test: 194 of 194 checks pass, in each edition"></a>
  <a href="eval/README.md"><img src="https://img.shields.io/badge/eval-75%2F75-brightgreen.svg" alt="Offline eval: 75 of 75 checks pass"></a>
  <a href="#industry-sectors"><img src="https://img.shields.io/badge/industry%20sectors-9%20signals%2C%206%20modules-blue.svg" alt="Industry sectors: 9 sector signals mapped to 6 sector modules"></a>
  <a href="#live-threat-intelligence"><img src="https://img.shields.io/badge/advisory%20feeds-8%20global%20%2B%20Japan-blue.svg" alt="8 advisory feeds, global and Japanese"></a>
  <a href="#tools-that-keep-up"><img src="https://img.shields.io/badge/pinned%20scanners-8-blue.svg" alt="8 pinned scanners"></a>
  <a href="#tools-that-keep-up"><img src="https://img.shields.io/badge/scanner%20updates-weekly%2C%20reviewed-blue.svg" alt="Scanner updates: weekly, reviewed before merge"></a>
</p>

A security review before launch tends to fail in the same places. The scanner reports a hundred
dependency CVEs and nothing about the admin route anyone can call. The lockfile is clean while the
Dockerfile still deploys a PHP build that is on this week's exploited list. Card numbers sit in a
JSON column nobody thought of as storage. The agent config grants itself every permission. And the
report is a PDF that nobody can filter, assign or re-check after the fixes.

`security-audit` is a **read-only security audit skill for Claude Code**, built for teams who ship
web and API back ends, mobile apps, infrastructure as code, CI/CD pipelines and AI agents, in Japan
and anywhere else. Ask "audit this repo" and it fingerprints the stack and the industry, runs
pinned scanners, matches what you deploy against live advisories, has models hunt what scanners
cannot see, tries to refute every finding, and writes one validated source of truth in Markdown,
HTML and Excel, in English and Japanese.

**It never edits, builds or runs the code it audits.**

- **Threat intelligence that is current at audit time.** `platform_inventory` reads what the repo
  actually deploys (base images, runtimes, servers, datastores, admin tools), and `threat_intel`
  matches it, at the moment the audit runs, against <!--n:feeds-->8<!--/n--> global and Japanese feeds (CISA KEV, NVD,
  FIRST EPSS, endoflife.date, IPA, JPCERT/CC, JVN, JVN iPedia). This week's incident is covered
  without anyone naming it. A feed that fails is a stated gap in the report, never a pass.
  [How it works](#live-threat-intelligence)
- **Scanners that update on a schedule, safely.** A weekly workflow finds new scanner releases,
  waits until they have been public for 7 days, proves each one still catches a planted defect, and
  opens a pull request for a maintainer to review. Nothing merges or switches on its own, and a
  failed run opens an issue. Audits always run the digest-pinned images, so a fix is checked by the
  same rules that found the defect. [How it works](#tools-that-keep-up)
- **Many domains, many industries.** Web and API, mobile, cloud and IaC, CI/CD and supply chain,
  AI, LLM, agents and MCP (including AI coding-agent configs), sensitive data at rest; plus medical,
  finance and crypto, e-commerce, public sector, education, IoT, OT and vehicles, with Japanese, US,
  EU and Vietnamese rules.
- **Output that fits the reader.** Markdown as the validated source of truth, an interactive HTML
  report, an Excel workbook for tracking, in English and Japanese from one source, one finding file
  per root cause.
- **The right model for each task.** Quick runs inline; Standard and Deep hand recon, review lanes,
  adversarial verification and translation to named subagents with their own model and effort.
  Deterministic scripts do the discovery, so model turns go to judgement.

## Install

**From a release** (offline, no plugin system needed): download
`security-audit-1.15.1.zip` from the
[latest release](https://github.com/nguyenhx2/agent-security-audit/releases/latest) and unzip it
into your skills folder:

```bash
unzip security-audit-1.15.1.zip -d ~/.claude/skills/
```

```powershell
Expand-Archive security-audit-1.15.1.zip -DestinationPath $HOME\.claude\skills\
```

**As a Claude Code plugin:**

```text
/plugin marketplace add nguyenhx2/agent-security-audit
/plugin install security-audit@agent-security-audit
```

Then, in Claude Code:

```text
audit this repo                                     # asks depth, language, focus and formats
/security-audit ../shop-api ../shop-web deep        # several repos, one audit, no questions on depth
```

Requirements: Claude Code, Python 3.9+ (standard library; `openpyxl` only for Excel), and Docker or
Podman for the scanners (native installs work too; with neither, the audit runs reading-only and
states the gap). Windows, macOS and Linux, including WSL.

**Which zip?** The English edition (`security-audit-1.15.1.zip`) is recommended for everyone: it
writes reports in English, Japanese or both. `security-audit-ja-1.15.1.zip` is the same skill with
Japanese instructions and reference prose, for teams that want to read and maintain the skill
itself in Japanese. Both install as `security-audit`, so install one or the other, never both.

<p align="center">
  <img src="docs/assets/audit-pipeline.svg" alt="How an audit runs, phases 0 to 8. Each phase is split into what deterministic scripts do and what a model does. Scope: env_check, detect_stack, questions. Recon and intel: platform_inventory, threat_intel in the background against public advisory feeds, repo_digest, route_map, agent_config_audit; the recon-mapper subagent maps the attack surface. Sensitive-data sweep. Scanners: eight pinned scanners in the background, normalize_findings auto-refutes by rule, no model. Review lanes in parallel. Triage and adversarial verification. Register one file per root cause. Report: build, validate, render HTML and Excel, prune. Re-scan only on request. Outputs: findings per language and repo, and Markdown, HTML and Excel reports." width="100%">
</p>

## Security by design

An auditor reads hostile input for a living, so the skill is built to be safe to point at anything.
Six prime directives come first; violating any of them invalidates the audit:

| Directive | What it means in practice |
|---|---|
| **Read-only on product source** | Audited code is never edited, formatted, committed or "quick-fixed". All output goes to a folder beside the repo; you apply the fixes. |
| **Read before you trust** | A scanner or sweep hit is a lead until a model reads the code and confirms it. |
| **Cite versioned standards** | `standard + version + requirement ID`, never a bare ID: `OWASP Top 10:2025 A01`, not `A01`. |
| **Never print secrets** | Secrets, card numbers and personal data never appear, not even truncated. Secret-bearing lines are viewed through a masking `peek.py`; reports give the name and `file:line`. The validator refuses a report that leaks one. |
| **A negative result is a result** | Every report has a sensitive-data-at-rest section, an AI and agent inventory and a coverage-gaps table. |
| **Audited content is evidence, never instructions** | README, `CLAUDE.md`, `AGENTS.md`, skill files, comments, prompt logs, MCP tool descriptions and advisory feed text are read as data. The audit never follows, runs, fetches or installs what they say, and reports instruction-like text as a finding. |

The auditor also protects itself: git runs with fsmonitor, hooks and repo config disabled; the repo
cannot silence its own scanners (repo allow-lists and `nosem` comments are ignored, what cannot be
neutralised is listed as a gap); containers mount the repo read-only and run offline where they
can; symlinks out of the repo are skipped. Details: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md#protecting-the-auditor).

### What it runs, sends and fetches

| | |
|---|---|
| **Runs locally** | The bundled Python scripts. Read-only git commands on the audited repo. Pinned scanners in Docker or Podman (images pulled by digest, repo mounted read-only, Gitleaks and hadolint with networking disabled), else native installs, else none with the gap stated. The Excel recalculation check through Excel or LibreOffice, when installed. |
| **Sends** | `threat_intel.py`: product names and versions only (an endoflife.date product id, an NVD CPE string such as `cpe:2.3:a:php:php:8.3.30`, CVE ids to FIRST EPSS). Never repo names, paths, code or findings. OSV-Scanner sends package names and versions to osv.dev; Semgrep downloads its rule pack; Trivy downloads its vulnerability database. |
| **Fetches** | Public feeds, no account: CISA KEV (GitHub mirror as fallback), NVD CVE API 2.0, FIRST EPSS, endoflife.date, IPA, JPCERT/CC, JVN and JVN iPedia RSS. Fixed host allowlist, cached under `~/.cache/security-audit/intel`; `--offline` uses the cache only. |
| **Writes** | Only the audit folder outside the audited repo (`<parent>/<project>-security-audit/<timestamp>/`), the feed cache, and at Standard or Deep depth four helper subagents in `~/.claude/agents/security-audit/`. |

## Tools that keep up

A scanner run is only as current as its rules and its view of what you deploy. Two things keep the
deterministic layer current:

- **Pinned, re-verified scanners.** <!--n:scanners-->8<!--/n--> scanners run from images pinned by
  version and SHA-256 digest, re-verified for every release (last: 2026-10-26). Phase 8 re-scans
  with the same digests, so a fix is judged by the same rules that found the defect, and a finding
  closes only when it no longer reproduces and its rule still fires.

  | Scanner | Covers |
  |---|---|
  | Semgrep 1.181.0 | code patterns (SAST) |
  | Gitleaks 8.30.1 | secrets, including full git history |
  | Trivy 0.76.1 | dependencies, images, IaC misconfiguration |
  | OSV-Scanner 2.7.0 | dependencies against OSV, including malicious packages |
  | Checkov 3.3.29 | Terraform, CloudFormation, Kubernetes, Helm |
  | zizmor 1.31.1 | GitHub Actions workflows |
  | mobsfscan 1.0.1 | Android and iOS source |
  | hadolint 2.15.1 | Dockerfiles |

  New scanner versions arrive by review, never on their own. A weekly workflow finds releases that
  have been public for at least 7 days, proves each one still finds a planted defect, and opens a
  pull request for a maintainer to merge; a failed run opens an issue instead. When you run an
  audit, `run_scanners.py --check-updates` tells you whether newer versions exist without changing
  any pin, and `--pin tool=image:tag@sha256:...` tries one on purpose. Details:
  [Scanner pin updates](docs/RELEASING.md#scanner-pin-updates).

  <p align="center">
    <img src="docs/assets/scanner-update-flow.svg" alt="Scanner pin update flow. Every Monday at 02:17 UTC, or on a manual run, update_pins.py --check asks Docker Hub and GHCR for each scanner's newest stable tag and its index digest, proposing a tag only after a 7-day cooldown and never as a downgrade; when every pin is current the run ends quietly. smoke_scanners.py runs each candidate image on a fixture with one planted defect per scanner, eight scanners, and it must still find it, in a read-only job that never sees the write token. update_pins.py --write then moves the pins and the gates run (both selftests, eval, edition parity, versions). The result is one pull request from bot/scanner-pins, labelled scanner-pins, with release-notes links, a draft CHANGELOG and the smoke-test table, CI on three operating systems; a maintainer reviews and merges it, it is never auto-merged, and a z release ships the pins. Any failure opens one issue update-pins failed that the next success closes. During an audit the pins never move: images are fixed by digest, run_scanners.py --check-updates only reports newer versions, and --pin tries one on purpose." width="100%">
  </p>

- **What the repo deploys, not only what it imports.** `platform_inventory.py` finds versions where
  lockfile scanners never look: Dockerfile `FROM` and `ARG` defaults (multi-stage builds included),
  compose, Kubernetes and Helm, `.tool-versions` and `.nvmrc`, CI setup steps, serverless runtimes.
  It records each pin's precision (exact, floating tag, range, distro, managed) and context (deploy,
  build, CI, dev), plus exposure signals: `.env` or dumps under a web root, `phpinfo()`, admin and
  BI tool images, published datastore ports, root containers, download tools in a runtime image,
  open egress, no base-image update automation.

## Live threat intelligence

`threat_intel.py` runs in the background on every audit, at every depth, and matches the inventory
against <!--n:feeds-->8<!--/n--> public advisory feeds fetched at that moment:

<p align="center">
  <img src="docs/assets/threat-intel-flow.svg" alt="Live threat intelligence flow. The repos' version pins feed platform_inventory.py, which writes platform.json with each component's version, precision, context and exposure signals, without network. threat_intel.py matches it in the background against global feeds (CISA KEV, NVD, FIRST EPSS, endoflife.date) and Japanese feeds (IPA, JPCERT/CC, JVN, JVN iPedia), sending only product names and versions. A failed feed becomes a stated gap, never a pass. intel.json sorts components into act-now, review and update; the supply-chain-infra lane triages with severity floors; the report's section 2 lists versions, advisory ids, the feed date and gaps." width="100%">
</p>

| Feed | Scope | What it answers |
|---|---|---|
| CISA KEV | global | exploited in the wild, used in ransomware |
| NVD CVE API 2.0 | global | which CVEs affect this exact version (CPE + version) |
| FIRST EPSS | global | likelihood of exploitation in the next 30 days |
| endoflife.date | global | support and security cycles, latest patch per cycle |
| IPA security alerts | Japan | emergency measures the national agency asks for |
| JPCERT/CC alerts | Japan | 注意喚起, weekly reports, campaign indicators |
| JVN | Japan | coordinated vendor advisories (JVN#, JVNVU#) |
| JVN iPedia | Japan | the wider vulnerability database |

A KEV or nationally alerted CVE on an exact, internet-facing deploy pin is **act-now**, with a
severity floor of P0 or P1. One finding per remediation ("upgrade the runtime in the Dockerfile,
rebuild, redeploy") lists every CVE it clears. Feed text is sanitised and treated as data, the
report states the feed date, and the validator warns when a known-exploited CVE ends up in no
finding. Ask "are we affected by this CVE?" or "注意喚起の影響確認" and the same machinery answers
it. The rules: [`threat-intel.md`](security-audit/reference/method/threat-intel.md).

## What it checks

Modules load from what the code shows and from what you say ("we are a bank"); every finding cites
`standard + version + requirement ID`. The standards baseline was verified against the issuing
bodies on 2026-10-26, and past 90 days the skill re-verifies the rows in scope before citing them.

<p align="center">
  <img src="docs/assets/coverage-map.svg" alt="Coverage map. Technical domains: web and API (OWASP Top 10:2025, ASVS 5.0.0, API Security Top 10 2023, CWE Top 25 2025, IPA How to Secure Your Web Site); mobile (MASVS 2.1.0, MASTG 2.0.0, Mobile Top 10 2024); cloud and IaC (CIS benchmarks, OWASP Kubernetes Top 10 2025); CI/CD and supply chain (OWASP CI/CD Top 10, SLSA v1.2, SSDF v1.1, Non-Human Identities Top 10 2025); AI, LLM, agents and MCP (LLM Top 10 2026, Agentic Top 10 2026, MCP Top 10 beta, AISVS 1.01) and AI coding-agent configs; sensitive data at rest and payments (PCI DSS v4.0.1); privacy (GDPR, APPI, Vietnam PDPL, CCPA, HIPAA, EU CRA, EU AI Act). Industry sectors with Japanese, US, EU and Vietnamese rules: medical, finance and crypto assets, e-commerce, public sector, education, IoT, OT and vehicles." width="100%">
</p>

Beyond the standards, review lanes hunt the defect classes scanners cannot see: broken object and
function authorization, the one unscoped query, routes the UI hides but the API serves, trusted
identity headers, dead security controls, non-atomic refunds without idempotency keys, card and
personal data at rest, prompt injection into tools, and risky agent setups. For AI coding agents
(Claude Code, Cursor, Copilot, Codex, Gemini and others), `agent_config_audit.py` inventories
permissions, hooks, exec settings, MCP servers, subagents, skills, instruction files, CI agent
actions, prompt logs in git history and hidden Unicode.

## Industry sectors

`detect_stack.py` reads <!--n:sectors-->9<!--/n--> sector signals from dependencies and identifiers,
Japanese romaji included (`karte`, `monshin`, `kanja`, `zengin`, `furikomi`), and maps them to six
sector modules. A detected sector also asks for the jurisdiction.

| Sector module | Signals | Japan | US, EU, global | Vietnam |
|---|---|---|---|---|
| Medical | medical | MHLW Medical Information Security Guidelines 7.0, MIC/METI Provider Guidelines 2.0 | HIPAA; GDPR Art. 9 | PDPL |
| Finance and crypto assets | finance, crypto | FISC Security Guidelines (14th), FSA Cybersecurity Guidelines; crypto-asset custody checks | GLBA Safeguards Rule, NYDFS 23 NYCRR 500 | Circulars 09/2020 and 50/2024 |
| E-commerce | ecommerce | Credit Card Security Guidelines 6.1 | PCI DSS v4.0.1 | E-commerce Law 122/2025, Decree 248/2026 |
| Public sector | government | Government Unified Standards, ISMAP, Active Cyber Defense Act | - | Decree 85/2016, Cybersecurity Law 116/2025 |
| Education | education | MEXT Education Information Security Guidelines | FERPA, COPPA | - |
| IoT, OT and vehicles | iot, ot, automotive | JC-STAR | ETSI EN 303 645, EU CRA, IEC 62443, UN R155 / R156 | - |

Japanese clients also get the IPA guide "How to Secure Your Web Site" cited next to OWASP, and
Japan APPI first among the privacy laws, with its article map (security control measures, breach
reports and their deadlines, transfers abroad).

## Outputs

Every audit writes to `<parent-of-repo>/<project>-security-audit/<timestamp>/`, beside the repo.

| Format | What you get |
|---|---|
| **Findings** | `findings/<lang>/<repo>/find-<repo>-001.md`: one file per root cause, deduplicated by remediation action, with location, what it is, why it matters, evidence, remedy and verification. Same ids and anchors in every language. |
| **Markdown report** | The validated source of truth. `validate_findings.py` resolves every `path:line` anchor, blocks secrets, card numbers and leftover placeholders, and checks every table against the finding files. |
| **HTML report** | One offline file: severity cards, full-text search, filters, sortable columns, expandable findings, `#FIND-ID` deep links, CSV export, and the full report with a table of contents. |
| **Excel workbook** | Summary with four charts, Findings with dropdowns and Owner / Due date / Notes columns for tracking, Coverage, and Master lists. `--verify` recalculates it and fails on a formula error or a total that does not match. |

Reports come in English, Japanese or both, from one canonical source: the second language is a
translation of the findings data, never a second audit. Any other language gets prose in that
language with English labels.

### What the reports look like

From a real Quick audit of [DVWA](https://github.com/digininja/DVWA), a deliberately vulnerable
practice app, taken from the benchmark (19 findings).

**HTML report:** severity cards, filters and the findings explorer.

![HTML report: severity cards, filters and the findings table](docs/assets/screens/html-report.png)

**HTML report, one finding expanded:** location, what it is, why it matters, evidence and remedy.

![HTML report: an expanded finding](docs/assets/screens/html-finding.png)

**Excel workbook, Summary sheet** (as exported to PDF by `render_xlsx.py --pdf`).

![Excel workbook: Summary sheet with four charts](docs/assets/screens/excel-summary.png)

## Models per task

<p align="center">
  <img src="docs/assets/model-allocation.svg" alt="Model allocation per depth. Recon: the lead inline at Quick, recon-mapper on Sonnet medium at Standard and Deep. Design lanes (authz-logic, sensitive-data, ai-agentic): lead at Quick, Sonnet high at Standard, Opus high at Deep. Other lanes: lead at Quick, Sonnet medium at Standard, Sonnet high at Deep. Verifier: the lead re-checks P0 and P1 at Quick, Sonnet high on P0 and P1 at Standard, Opus high on P0 to P2 at Deep. Translator, only with two or more report languages: Sonnet medium. Below: the scripts that do discovery without a model, and the rules every subagent runs under." width="100%">
</p>

| Depth | How it runs | Typical use |
|---|---|---|
| **Quick** | Scripts plus up to three review lanes inline in the main session; the lead re-checks every P0/P1 | A first look, a small repo, "are we affected by this CVE" |
| **Standard** | Named subagents on Sonnet: `recon-mapper` (medium), `lane-reviewer` groups in parallel (high on design lanes, medium on the rest), `finding-verifier` on P0/P1 (high) | A routine audit |
| **Deep** (default) | As Standard, with **Opus / high** on the design lanes (authz-logic, sensitive-data, ai-agentic) and on the verifier, which covers P0 to P2 | Before a launch, a regulated system |

With two or more report languages, one `report-translator` (Sonnet / medium) per extra language
runs while the source-language report is built. Every subagent has a read-only tool allowlist (no
Edit, no Agent), a turn cap, and does not load `CLAUDE.md`; Haiku is not used for security
judgement. Scripts hand each lane a digest, a route map, the platform inventory, the advisory match
and a redacted pack of code excerpts, which replace its first 20-40 Read and Grep turns. Lanes
reading the same files of a small repo share one subagent. The matrix:
[`orchestration.md`](security-audit/reference/method/orchestration.md).

<!-- BENCHMARK -->
## Measured, not modelled

Real, headless Claude Code audits (CLI 2.1.310 for the 1.13.0 runs, 2.1.311 for 1.15.0) of three deliberately
vulnerable projects pinned to exact commits (DVWA, NodeGoat, OWASP Juice Shop), 1.13.0 against
1.15.0, the same prompt, depth (Quick) and per-run budget,
18 runs in total, US$41.71 in total. Recall is scored by script
against ten documented vulnerability classes per project, never by a model.

| Measure | 1.13.0 | 1.15.0 | Change |
|---|---:|---:|---:|
| Ground-truth classes found (recall) | <!--n:bench_recall_pct_baseline-->88<!--/n-->% | <!--n:bench_recall_pct-->97<!--/n-->% | +9 pt |
| Outdated or end-of-life runtime found (DVWA, NodeGoat) | 4/6 | 6/6 | +2 |
| Threat-intelligence section produced | 0/9 | 9/9 | +9 |
| Findings per audit | 20.4 | 22.3 | +1.9 |
| Audits whose findings pass the validator | 9/9 | 9/9 | +0 |
| Cost per audit (USD) | <!--n:bench_cost_usd_baseline-->2.27<!--/n--> | <!--n:bench_cost_usd-->2.36<!--/n--> | +4% |
| Wall-clock time per audit (minutes) | <!--n:bench_minutes_baseline-->11<!--/n--> | <!--n:bench_minutes-->7<!--/n--> | -30% |

1.15.0 found more of the known classes on DVWA and Juice Shop, and named the end-of-life runtime in
every DVWA and NodeGoat audit, at about the same cost. Time is the weakest figure: the first two
1.13.0 runs took 26 and 18 minutes while three audits shared the machine, and the medians are 8.2
against 6.9 minutes. Three projects and three runs per cell are a small sample, and one run per
version is not a verdict; per-run numbers and the history are in
[`benchmark/RESULTS.md`](benchmark/RESULTS.md).
Precision is not measured: these projects have more bugs than their documentation lists, so a
finding outside the ten classes is not necessarily a false positive. Method and limits:
[`benchmark/README.md`](benchmark/README.md).
<!-- /BENCHMARK -->

## Proof you can run

```bash
python security-audit/tests/selftest.py               # every script behaves as tested (English edition)
python editions/ja/security-audit/tests/selftest.py   # the same checks, Japanese edition
python eval/run_eval.py                               # offline eval: detection, platform, threat intel
python scripts/check_numbers.py                       # every figure in these docs matches its source
python benchmark/bench.py fetch                       # live benchmark: clone the pinned fixtures,
python benchmark/bench.py run --help                  #   then run real audits (costs money, never in CI)
```

The self-test runs offline in about a minute: <!--n:selftest_checks-->194<!--/n--> checks per
edition, with the same count in both, on Windows, macOS and Linux under Python 3.9 and 3.13 in CI.
The offline eval (<!--n:eval_passed-->75<!--/n-->/<!--n:eval_total-->75<!--/n--> checks) needs no
API key, network or Docker: it proves each industry sector is detected from real-looking fixtures
(and that an Azure SDK full of `Sku` is not e-commerce), that deployed versions and exposure
signals are found where lockfile scanners do not look, that a KEV entry plus a national alert on the
deployed PHP version ranks "act now", that a feed answering with an HTML error page is a gap and not
a pass, and that hostile feed text is sanitised. Cases: [`eval/README.md`](eval/README.md).

## Go deeper

```mermaid
flowchart TD
    subgraph U["Understand"]
        A["ARCHITECTURE<br/>phases, data flow, models"]
        S["SKILL.md<br/>the full procedure"]
    end
    subgraph R["Reference"]
        ST["standards index<br/>versions, citation"]
        TI["threat-intel<br/>feeds, severity floors"]
        OR["orchestration<br/>model matrix"]
    end
    subgraph T["Trust"]
        E["eval<br/>offline proof"]
        B["benchmark<br/>live audits"]
        C["CHANGELOG<br/>what changed"]
    end

    classDef art fill:#16365C,stroke:#0B1F33,stroke-width:1px,color:#FFFFFF

    class A,S,ST,TI,OR,E,B,C art
```

| To learn | Read |
|---|---|
| How an audit runs: phases, data flow, model allocation, auditor safety | [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) |
| The full procedure the skill follows | [`security-audit/SKILL.md`](security-audit/SKILL.md) |
| Every standard, its version and how to cite it | [`reference/standards/index.md`](security-audit/reference/standards/index.md) |
| Feeds, version precision and severity floors | [`reference/method/threat-intel.md`](security-audit/reference/method/threat-intel.md) |
| The model and effort matrix and prompts | [`reference/method/orchestration.md`](security-audit/reference/method/orchestration.md) |
| What each release changed | [`security-audit/CHANGELOG.md`](security-audit/CHANGELOG.md), [`CHANGELOG.md`](CHANGELOG.md) |
| How the claims are measured | [`eval/README.md`](eval/README.md), [`benchmark/README.md`](benchmark/README.md) |
| How a release is cut | [`docs/RELEASING.md`](docs/RELEASING.md) |
| Reporting a vulnerability in this repository | [`SECURITY.md`](SECURITY.md) |

Set up the harness this audit runs before and after: [agent-harness-bootstrap](https://github.com/nguyenhx2/agent-harness-bootstrap).

## Credits

Cloudflare's [security-audit-skill](https://github.com/cloudflare/security-audit-skill) (MIT)
inspired several of the coverage classes this skill hunts for. The live threat intelligence stands
on the public work of the
feed operators: CISA, NIST's National Vulnerability Database, FIRST, the endoflife.date
contributors, IPA, JPCERT/CC and the JVN team. None of them endorse this project. More in
[NOTICE](NOTICE.md).

## Contributing

Issues and pull requests are welcome. The bar is "does it still find what it claims, and only
that", and the gates that answer it are automated: [`CONTRIBUTING.md`](CONTRIBUTING.md).

## License

**[GNU AGPL-3.0-only](LICENSE.md)**, licensor **Hoàng Xuân Nguyên** (`nguyenhx2`). Free for any use,
commercial included; distribute or serve a modified version and you publish your changes under the
same licence. The findings and reports the skill writes about *your* repository are yours, under
terms of your choice: see [NOTICE](NOTICE.md).
