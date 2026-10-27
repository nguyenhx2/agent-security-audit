# Changelog - security-audit

## Versioning rules

Version = `1.y.z`. The major number stays **1**.

| Part | Bump when | Examples |
|------|-----------|----------|
| `y` (big update) | A new capability, output format, or workflow change that users notice | new report format, new language, depth modes, subagent orchestration |
| `z` (small change) | Fixes, refinements, wording, standards/scanner data updates, new checks inside an existing capability | redaction fix, new sweep pattern, re-verified standard versions, new self-test case |

Reset `z` to 0 when `y` increases. Every release gets a dated entry here, newest first, headed
`## [X.Y.Z] - YYYY-MM-DD` (Keep a Changelog), with the same sub-headings (Added / Changed / Fixed / Removed - omit empty ones). On release, update all three together:
this file, `metadata.version` in `SKILL.md`, and the "Skill v..." line at the top of `SKILL.md`.
When standards or scanner pins are re-verified, also update `metadata.standards-verified` /
`scanner-pins-verified`, the table in `reference/standards/index.md`, and `PINS_VERIFIED` in
`scripts/run_scanners.py` - that is a `z` bump unless a module is added or removed (then `y`).

## [1.15.0] - 2026-10-26

Industry sectors and Japanese standards, a full re-verification of the standards baseline, and
current scanner pins.

### Added
- Industry sector detection in `detect_stack.py`: `sectors` (medical, finance, crypto, ecommerce,
  government, education, iot, ot, automotive) from dependencies (FHIR / HL7, Plaid, Zengin, wallet and
  chain libraries, EC platforms, LTI, MQTT / IoT SDKs, Modbus / OPC UA / S7 / BACnet, CAN / UDS) and
  keyword files (incl. Japanese romaji identifiers such as `karte`, `monshin`, `kanja`, `zengin`,
  `furikomi`, `kouza`). Each sector adds a standards module; the profile prints them; the Focus question
  names them (en / ja) and a detected sector triggers the jurisdiction question. Thresholds avoid known
  false positives (no bare `sku` / `coupon`: cloud SDKs use SKUs).
- Sector modules, each with code-evidenced checks, severity and citation notes:
  - `reference/standards/medical.md` (M01-M07): MHLW Medical Information Security Guidelines 7.0
    (2026-06-29; five parts incl. the new 保守委託機関編) and MIC/METI Medical Service Provider
    Guidelines 2.0 (2025-03-28), with item numbers verified against the published texts (システム運用編
    14.1.1, 14.2, 13.1-13.3, 7.2, 12.2, 17.1; MIC/METI 5.1.4, 5.1.5, 別紙2); HIPAA, GDPR Art. 9 and PDPL
    pointers. Written for any health system; app-specific names are examples only.
  - `reference/standards/finance.md` (F01-F10, C01-C06): FISC Security Guidelines 14th (2026-03; cited by
    part 統制 / 実務 / 設備 / 監査基準, item numbers unverified because the text is paid), FSA Cybersecurity
    Guidelines (2024-10-04, items from 別紙18), crypto-asset custody (hot / cold separation, no single
    signer, key storage, withdrawal controls, lessons of the 2024 DMM Bitcoin case), GLBA Safeguards
    Rule, NYDFS 23 NYCRR 500, Vietnam Circulars 09/2020 and 50/2024.
  - `reference/standards/ecommerce.md` (E01-E11): Japan Credit Card Security Guidelines 6.1
    (2026-03-11): card non-retention, checkout script integrity, the five EC-site vulnerability measures,
    card-testing limits, EMV 3-D Secure, login-fraud controls at registration / login / attribute change;
    Vietnam E-commerce Law 122/2025 + Decree 248/2026.
  - `reference/standards/public-sector.md` (G01-G08): Japan Government Unified Standards 令和7年度版
    (patch-management revision 2026-06-12), ISMAP / ISMAP-LIU, the Japan Active Cyber Defense Act
    (reporting duties from 2026-10-01, secondary source), Vietnam Decree 85/2016 (with the caveat that its
    parent law was replaced) and Cybersecurity Law 116/2025.
  - `reference/standards/education.md` (D01-D08): MEXT Education Information Security Guidelines
    (2025-03), FERPA, COPPA (2025 amendments, compliance from 2026-04-22).
  - `reference/standards/iot-ot.md` (T01-T11): JC-STAR, ETSI EN 303 645 V3.1.3, EU CRA, IEC 62443
    (3-3, 4-1, 4-2), UN R155 / R156.
- `owasp-web.md` Part E: IPA "How to Secure Your Web Site" (改訂第7版 第4刷, 2021-03-31) items 1.1-1.11
  mapped to OWASP Top 10:2025, ASVS 5.0.0 and CWE; root fix vs mitigation.
- `privacy.md`: Japan APPI article map (Art. 20(2) consent for special care-required information,
  Art. 23 security control measures, Art. 24-25 supervision, Art. 26 breach reports with the Enforcement
  Rules Art. 8 deadlines and the PPC guideline 3-5-3-3 for "roughly 3-5 days", Art. 27-28 provision and
  transfer abroad); Japan My Number Act; the external transmission rule of the Telecommunications
  Business Act (2023-06-16).
- Canonical standard names (validator, report): Japan My Number Act, IPA How to Secure Your Web Site,
  MHLW Medical Information Security Guidelines, MIC/METI Medical Service Provider Guidelines, FISC
  Security Guidelines, Japan Credit Card Security Guidelines, FSA Cybersecurity Guidelines, Japan
  Government Unified Standards, ISMAP, Japan Active Cyber Defense Act, MEXT Education Information
  Security Guidelines, JC-STAR, Japan Telecommunications Business Act, ETSI EN 303 645, IEC 62443,
  UN R155, UN R156, FERPA, COPPA, GLBA Safeguards Rule, NYDFS 23 NYCRR 500, Vietnam Decree 85/2016,
  Vietnam Circulars 09/2020 and 50/2024, Vietnam E-commerce Law; Japanese and common aliases
  (3省2ガイドライン, 安全なウェブサイトの作り方, FISC Safety Standards, 個人情報保護法, 番号法 ...).
- Coverage checklist: "Industry sectors" walk; lane-reviewer: which sector rows each lane covers.
- Evals 18 (Japanese clinic API) and 19 (Japanese online shop); selftest for sector detection,
  sector-to-module files, Japanese canonical names and the Focus question.

### Changed
- Standards baseline re-verified on 2026-10-26 (every row): OWASP Top 10:2025 final (RC label removed
  2025-12-24); ASVS 5.0.0 dated 2025-05-30; MASVS 2.1.0 dated 2024-01-18 (was given as 2026-06), MASTG
  2.0.0 2026-06-30, MASWE 1.0.0 added (2026-08-17); AISVS 1.01 released 2026-10-16; LLM Top 10 2026
  dated 2026-08-03; PCI DSS v4.0.1 with a note on the 2026 request for comments; SSDF v1.2 still a draft.
  Japanese and sector rows added. `standards-verified` is 2026-10-26.
- Scanner pins verified 2026-10-26: semgrep 1.181.0, trivy 0.76.1 (security fix for the eMudhra CA key
  compromise; taken although only 5 days old), checkov 3.3.29, zizmor 1.31.1 (now flags `issue_comment`
  as a dangerous trigger; 1.31.0 skipped); gitleaks, osv-scanner, hadolint and mobsfscan unchanged
  (digests re-checked). Native install pins in `env_check.py` and `platforms.md` follow.
- SKILL.md description names industry detection and sector rules (1016 characters).
- The author line is removed from SKILL.md, CHANGELOG and README; authorship and the AGPL-3.0-only
  licence live in the repository (github.com/nguyenhx2/agent-security-audit) and its plugin manifest.
- CHANGELOG headings follow Keep a Changelog: `## [X.Y.Z] - YYYY-MM-DD`.

### Fixed
- FISC is cited as the 14th edition (2026-03), by part only, never by item numbers that cannot be checked.
- MHLW 7.0 is described with its five parts, including the new part for maintenance contractors.
- APPI security control measures are cited as Art. 23 (Art. 20 is proper acquisition).
- The verification caveats in `privacy.md` (secondary sources, Vietnam Decree 85, HIPAA proposed rule)
  are kept, and only rows actually re-checked carry the new verified date.
- No bare `ipa` alias: IPA alerts are evidence, not the IPA web-site guideline.
- Clickjacking mapped to Top 10:2025 A02 (misconfiguration) in the IPA table.
- Keyword signals in `detect_stack.py` treat `_` as a word separator: snake_case identifiers such as
  `patient_id`, `kanja_id` or `bank_account_id` were missed by `\b...\b` patterns. The IoT signal no
  longer fires on `firmware_version` / `secure_boot` (server inventories and cloud VM settings); it needs
  firmware update / image terms, an RTOS, MQTT, CoAP or an IoT SDK. Both found by the offline eval.
- SKILL.md "Finish the run": after Phase 0 the audit goes through Phase 7 without pausing to ask. Found by
  the live benchmark: one headless Quick run stopped before writing findings and left no report.

## [1.14.0] - 2026-10-26

Live threat intelligence and incident-driven coverage: the audit now checks what the repos deploy
(runtimes, servers, datastores, base images, admin tools, frameworks) against public advisory feeds
fetched at audit time, global and Japanese, and hunts the exposure and blast-radius classes behind
recent incident reports, without depending on anyone naming the incident.

### Added
- `scripts/platform_inventory.py` (Phase 1, every depth, no network): versions pinned in Dockerfiles
  (incl. `ARG` defaults and multi-stage builds), compose / Kubernetes / Helm files, version files
  (`.tool-versions`, `.nvmrc`, `.php-version`, ...), `composer.json` / `package.json` / `pyproject.toml`
  constraints, CI setup steps, serverless runtimes and framework lockfile entries, with precision
  (exact / minor / range / floating / distro / managed) and context (deploy / build / ci / dev /
  declared). Exposure and hardening signals: sensitive files under a web root, `phpinfo()`, directory
  listing, risky `php.ini` settings, admin / BI tool images, published datastore ports, actuator and
  Tomcat manager exposure, root containers, download tools in the runtime image, remote `ADD`,
  unpinned base images, no NetworkPolicy, security-group egress to anywhere, no base-image update
  automation.
- `scripts/threat_intel.py` (background, one per audit): matches the inventory against CISA KEV (GitHub
  mirror as fallback), NVD CVE API 2.0 (CPE + version), FIRST EPSS, endoflife.date and the IPA, JPCERT/CC,
  JVN and JVN iPedia RSS feeds. Sends product names and versions only; host allowlist, no foreign
  redirects, size and time limits; feed text sanitised (control, bidi and zero-width characters
  removed) and treated as data; responses cached with a TTL per feed and reused when a feed is down;
  `--offline` uses the cache only. A failed or suspended feed is a stated gap. Priorities: act-now
  (KEV or nationally alerted CVE on the pinned version), review (EOL, alert without a version match,
  critical CVEs), update (behind the latest patch).
- `reference/method/threat-intel.md`: feed catalogue, version-precision rules (floating tags, distro
  backports, managed runtimes, ranges), severity floors, proactive checks that do not need an
  advisory (patch readiness, exposure, blast radius, detection, data minimisation).
- Report section 2 "Platform versions and threat intelligence" (en / ja) from `intel.json`: components
  with a support or advisory issue, advisory ids, feeds checked and the feed date, unavailable feeds.
- `validate_findings.py` warns when a KEV or nationally alerted CVE, or an end-of-life deployed
  component, is in no finding and not listed under Refuted.
- Coverage checklist: new section "Exposure, patch level and blast radius" (patch level, EOL, patch
  readiness, web-root files, management planes, admin / BI tools, upload-to-execution, build context,
  post-compromise blast radius, forensic readiness) and new rows for token validity oracles,
  rate-limit key and coverage, client-IP header trust, long-lived tokens, spoofable gateway identity,
  insecure config fallbacks, account linking, MFA bypass, SAML, scope-bypassing data access, signed
  URLs, search indexes, revocation, unreferenced privileged routes, NoSQL operator injection,
  export / import scope, queue consumers, decompression bombs, pre-auth cost, shared-cache leakage,
  request smuggling, browser messaging, CI cache poisoning, native code.
- Evals 16-17 (live advisory triage, Japanese alert check at Standard).

### Changed
- Triage: severity floors for KEV / national-alert runtime CVEs and for exposed admin tools and web-root
  secrets; a boundary line (principal -> control crossed -> resource affected) on every P0-P2
  candidate, otherwise it is a hardening note (Info); `needs-runtime-check` names the deciding
  deployment fact; variant sweep after a P0/P1; weakest door to the same effect; national alerts in
  the dependency order.
- Lanes get `platform=` and `intel=`; the supply-chain-infra group owns runtime and exposure findings
  (the lead when that lane is not run); lane blocks carry `boundary:` and lanes list `## Hardening` and
  `## Reviewed`; work is ordered so a cut-off lane still covered the riskiest surfaces. Recon diffs routes
  against client calls and does a literal pass for debug switches and security TODOs.
- `collect_lanes.py`: boundary column and a Hardening section; the verifier downgrades candidates whose
  boundary does not hold and lists hardening notes.
- Standards modules: management / debug planes, web-root exposure, config fallbacks, runtime patch level,
  NoSQL operator injection, forensic readiness (owasp-web); rate-limit key and coverage (owasp-api);
  exposure, blast radius and image patch level (cloud-iac); runtime and product patch level outside
  lockfiles (supply-chain); five design-flaw hunts (hidden routes, the one unscoped query, trusted
  identity headers, weakest door, revocation).
- `prune_work.py` also deletes `platform.md` and `work/intel.md`; `platform.json` and `intel.json` are
  kept (the report and validator read them).
- SKILL.md description names the advisory feeds (1015 characters) and states what is not in scope.

## [1.13.0] - 2026-10-14

Fewer AI turns and tokens per audit: scripts now hand subagents what they used to discover with
Read/Grep, scanner false positives are refuted by rule, and a one-language audit drafts directly in
that language.

### Added
- `scripts/route_map.py` - static endpoint map (FastAPI, Flask, Django/DRF, Express/Koa/Fastify,
  NestJS, Spring, Laravel, Rails): method, full path with router prefixes, handler `file:line`, auth
  markers, global auth, routes with no auth marker (leads), unparsed frameworks as gaps. Writes
  `routes.md` + `routes.json`; recon and the authz lane start from it.
- `scripts/lane_pack.py` - one redacted code-excerpt pack per lane group within a byte budget
  (secret-bearing files by name only, a "Left out" list); lanes read it first and Read/Grep only for
  what it lacks.
- `repo_digest.py --json` - the digest index as JSON for lane_pack.
- Rule-based auto-refute in `normalize_findings.py`: placeholder secret values, vendored docs and
  production-only SAST rules in test files are marked `auto_refuted`, listed in the summary
  ("auto-refuted N") and in `lanes/candidates.md`, not assigned to lanes; the verifier copies them into
  Refuted. Never applied to history-only hits, real key formats or high-entropy values
  (`reference/method/triage.md`). Calibrated on a real audit: 33 of 37 refuted candidates
  auto-refuted, 0 of 38 registered findings affected.
- `validate_findings.py --lang <code>` - the English-prose check for a ja (zh, ko) set runs without
  `--report`; the verifier's self-check passes it.

### Changed
- One report language: the verifier drafts findings directly in it (`lang=`), that draft is the
  canonical source, and no translator runs. Translators run only for two or more report languages.
- `prune_work.py` also deletes `packs/`, `digest.json`, `routes.md` and `routes.json` (the report
  does not read them).
- Standards re-verified 2026-10-13 (all current); eval citations updated to LLM Top 10 2026.

## [1.12.0] - 2026-10-01

Full re-audit of the skill (code, instructions, standards), plus
cross-platform support. A Japanese edition of this release ships separately (same version).

### Added
- `scripts/env_check.py` - first step of Phase 0 on every OS: detects Windows / macOS / Linux / WSL,
  the Python command to use (`py -3`, `python3`, `python`, probed for >= 3.9 and openpyxl), shells,
  Docker or Podman and whether it answers, SELinux, native scanners, the Excel verify method and git,
  and prints `choices` (script prefix, scanner mode, wait loop, path format, install routes per OS).
- `reference/tooling/platforms.md` - per-OS alternatives for every tool the skill uses.
- `run_scanners.py --engine auto|docker|podman`; on Linux / macOS containers run as the current user
  (no root-owned output), Podman with `--userns=keep-id`, SELinux hosts with `label=disable` (never
  `:z` - relabelling would write into the audited repo); leftover root-owned files are handed back.
- `render_xlsx.py --verify` with LibreOffice headless (throw-away profile) where Excel is not
  available; `--verify-with excel|libreoffice`; "VERIFY SKIPPED" (exit 0) when neither exists.
- `scripts/safegit.py` - one read-only git helper for every script.
- `scanners.json` records the audited commit at scan time, the engine / user / SELinux decisions, and
  repo files that can suppress scanner results (`repo_scanner_configs`).

### Fixed
- Security of the auditor: git ran `core.fsmonitor` commands from the audited repo's `.git/config`
  and `git status` rewrote its index - all git calls now disable fsmonitor and optional locks and
  never write. The gitleaks history pass no longer runs repo textconv / external diff drivers
  (`--no-textconv --no-ext-diff`); gitleaks and hadolint containers run with `--network none`.
- Repo-provided scanner configs can no longer silence results: gitleaks uses a runtime default config
  and ignores repo allow-lists, zizmor `--no-config`, semgrep `--disable-nosem`, osv-scanner an empty
  config, native tools run outside the repo. What cannot be neutralised (`.gitleaksignore`,
  `.checkov.yaml`, `.semgrepignore`) is listed as a coverage gap.
- Masking: CLI secrets (`--password=`, `-pSecret`, `-u user:pass`, `--token`), `*_KEY` / `*_PIN`
  values, unquoted personal data in YAML / CSV / properties (birth dates, kana names, Japanese
  addresses) and YAML block scalars are masked; the delivery gate checks the same shapes. Evidence
  (paths, `path:line`, code, types) stays readable.
- Symlinks pointing outside the audited repo are skipped and counted (no host files read).
- UTF-8 output on every console and pipe (cp932 / cp1252); config files with a BOM, UTF-16 or JSONC
  are parsed instead of silently dropped (a missed `bypassPermissions` setting); unparseable files are
  listed for manual review.
- Report rebuilds keep the audit's skill version, standards date, timestamp and commit
  (`report-settings.json`; `--refresh-meta` to re-derive); the report location column reads only the
  Location section; `|` in titles no longer breaks tables; paths with spaces are accepted everywhere.
- Sweep summary no longer hides lead counts when the repo holds committed data files.
- Prompt logs deleted from history are found when their names are non-ASCII.
- Excel and HTML pick the same findings language for an unsuffixed report; coverage-gap texts and
  Excel validation messages are localised in Japanese reports.
- `prune_work.py` reports files it cannot delete (e.g. root-owned) with the fix command, and deletes
  agent `scratch/` folders.
- Instructions: translator start (Phase 7 step 2b), source-language-not-chosen builds,
  `--lang-suffix`, rebuild with `--force --fill`, Phase 8 re-scan procedure (where to update status,
  `--offline` limits), recon delegation at Standard/Deep, scratch folders, stale paths in references,
  templates and evals, finding template frontmatter order, eval 14 path escape.

### Changed
- `allowed-tools`: PowerShell rules removed (not substituted by Claude Code; scripts run through the
  Bash tool); Podman read-only commands added. `compatibility` states Claude Code only and the
  supported OSes. Description shortened (992 characters).

## [1.11.0] - 2026-09-30

### Added
- `scripts/prune_work.py` - Phase 7 cleans up `work/` after the report set is built and validated.
  Default: deletes only intermediates nothing reads after the run (`raw/`, `candidates.jsonl`, lane
  notes, `findings.draft.json`, digest, recon, scanner summary) and keeps what a rebuild, a later
  translation and a Phase 8 re-scan need - about 3 MB -> 0.4 MB on a medium repo. `--keep-work`
  keeps everything; `--purge-work` deletes `work/`. Refuses to run before a report exists; unknown
  files are never touched.
- Author in `SKILL.md` metadata and in this file.

### Fixed
- `build_report.py`: the report date comes from the audit timestamp, so a rebuild days later keeps the
  audit date; a `<ts>_2` folder (two runs in one minute) keeps its timestamp in the report name.

### Changed
- Standards and scanner pins verified 2026-09-30.

## [1.10.0] - 2026-09-29

### Changed
- Output layout: the audit folder top level holds only `reports/`, `findings/` and `work/`.
  Deliverables go to `reports/md|html|xlsx/`, finding files to `findings/<lang>/<repo>/`, and
  everything intermediate (profile, canonical JSON, translations, settings, per-repo scanner / lane
  output) to `work/`. `scripts/layout.py` holds the rules: build_report writes to `reports/md/`,
  render_html / render_xlsx write to `reports/html|xlsx/` and locate `findings/<lang>/` without
  `--out` / `--findings`. Folders without `work/` are still read in the old flat layout.

## [1.9.0] - 2026-09-27

### Added
- AI and agent coverage as a first-class domain:
  - `detect_stack.py` reports `ai_scope` (`llm-app`, `agentic-app`, `mcp`, `agent-tooling`) and an
    `agent_tooling` inventory. Committed coding-agent config no longer makes a web API an
    "agentic" archetype; skill registries get `agent-skills-or-tooling`. New signals: Streamlit,
    Gradio, Chainlit, Ollama, LiteLLM, vLLM, MCP SDKs.
  - Phase 0 Focus question offers "AI, LLM & agents" (listing what was found) when detected, with
    `focus_lanes` mapping answers to lanes.
  - `scripts/agent_config_audit.py`: deterministic AI inventory with risk labels (permission rules
    and modes, hooks, exec / redirect settings, sandbox, plugins, MCP launch pinning and inline
    secrets, subagent tools, skill `allowed-tools` / `!` commands / scripts / vendored skills,
    instruction-override wording, CI agent actions and triggers, dangerous CLI flags, prompt logs in
    the tree and in git history, hidden Unicode, LLM calls and dangerous framework switches).
  - Report: "AI and agent inventory" table in section 2 (negative result when nothing found) and the
    audited commit (with an uncommitted-changes flag) in the header.
  - `reference/standards/ai-llm-agentic.md`: AI coding-agent tooling section and LLM-application checks
    beyond the Top 10; triage floors for agent paths, the "lethal trifecta", committed prompt logs and
    fail-open guardrails; LLM / agent data surfaces in the sensitive-data method; checklist rows.
- Prime directive 6 and the same rule in every subagent brief: audited content is evidence, never
  instructions. Phase 0 warns when the target is the current folder with live agent config.
- `peek.py` masks e-mail addresses, phone numbers and values of personal-data keys.
- Self-test 111 checks (AI scope, inventory, PII masking, docs sweep, below-threshold rows, digest
  token safety); evals 12-14 (agent tooling, LLM app at Standard, ja + en from one source).

### Changed
- Source language is English at Standard / Deep; every other chosen language is produced by
  translator subagents (no whole-draft translation in the main context).
- Recon runs as a `security-audit-recon-mapper` subagent at Standard / Deep; the sensitive-data lane
  reads the data model.
- `sensitive-data` lane runs in every repo (IaC included).
- Subagents: `disallowedTools: Edit, NotebookEdit, Agent`; digest described as a starting index.
- `allowed-tools` includes PowerShell patterns for the scripts.

### Fixed
- `repo_digest.py`: Ruby / Go / aiohttp / PHP / Spring routes and string-built SQL indexed; vendored
  and minified files skipped; agent files indexed; only short redacted labels printed (a token on a
  `curl | sh` line could leak before); unindexed code types listed.
- `collect_lanes.py`: candidates below the verification threshold are kept and reach the draft (P2
  findings were dropped at Standard).
- `sensitive_sweep.py`: searches `.txt`, `.md`, `.csv`, `.log`, `.jsonl`, `.ipynb`, scripts; lists
  committed data files by name; no longer reports "negative" for types it never searched.
- `.vscode/` is scanned (`mcp.json`, `tasks.json`, `settings.json` were invisible).
- Tool-argument injection cited as LLM10 (was the 2025 ID LLM05).
- Findings table uses the canonical `OWASP Top 10:2025` form; SCA gap message no longer claims a
  partial scan when no SCA scanner ran; mount check fallback uses a pinned image.
- Found in the live run on a FastAPI repo with committed agent tooling:
  - `validate_findings.py` crashed on an anchor that is a directory (symlinked vendored skill) - now a
    WARN; unreadable files are WARNs too.
  - `new_finding.py --source <findings.json>`: translated files take every code field and anchor
    from the canonical source, so source edits after translation cannot drift.
  - Japanese reports localise the AI inventory surfaces and risk labels (no English in ja output).
  - Sweep leads: prompt logs and product code first; vendored skill docs and rules last.
  - `agent_config_audit.py` flags commands / skills that pre-approve exec, network or write
    commands (`curl:*`, `docker compose:*`, `sed:*`).
  - Verifier brief: run `validate_findings.py --repo` on the draft (full repo-relative anchors).

## [1.8.0] - 2026-09-25

### Added
- `scripts/repo_digest.py`: one shared repo map per audit (inventory with line counts, sink/source
  index as `path:line` + token, secret-bearing file names; never line contents). Recon and every lane
  start from it instead of re-discovering the repo with Glob/Grep.
- `scripts/collect_lanes.py`: merges all lane files into `lanes/candidates.md` (one row per
  candidate, cross-lane duplicate groups, lane refutations / open questions) - the verifier reads
  this (~5x smaller than the lane files on the first real run) instead of every lane file.
- `scripts/install_agents.py`: installs the briefs as named subagents in
  `~/.claude/agents/security-audit/` (`security-audit-recon-mapper`, `-lane-reviewer`,
  `-finding-verifier`, `-report-translator`) with own tool lists, `maxTurns`, `omitClaudeMd`;
  `--check` / `--uninstall`; never overwrites files it did not write. General-purpose fallback kept.
- `agents/report-translator.md` (translator brief, previously an inline prompt).
- `tests/package.py`: self-test, then the release zip without `tests/` or caches.

### Changed
- Lane subagents are grouped by repo size (`detect_stack.py` `lane_groups`): small repos 3
  subagents, medium ~5, large one per lane - lanes that read the same files share one subagent.
- Verifier writes `findings.draft.json` (new_finding.py schema, validated) next to `verifier.md`;
  Phase 6 edits the draft instead of writing every finding again in the main context.
- Lane brief: digest first, one block per defect in the lane that owns the remedy (cross-lane
  pointers instead of duplicates), primary anchor = sink, lane notes in English.
- `tests/` is development-only and not part of the release zip.

## [1.7.2] - 2026-09-24

### Fixed
- Report-language question text (en / ja) no longer says findings are authored in the first language;
  it now matches the one-canonical-source flow (every selected language gets a full set, identical
  findings).

## [1.7.1] - 2026-09-23

### Changed
- Multi-language flow uses one canonical `findings.json` + `narrative.json` written in the source
  language (the lane-note language, or the only report language); every other language is translated
  from it in parallel. No author-then-translate-back round trip.
- `build_report.py` remembers depth / project / language / suffix per findings folder
  (`report-settings.json`), so `--force --fill` rebuilds need no repeated flags.

### Removed
- Vietnamese localisation. Report and interface languages are **English and Japanese**; other
  languages still work through "Other" (prose in that language, English labels). Vietnam PDPL stays in
  the privacy module as a jurisdiction, and Vietnamese PII keywords stay in the sensitive-data sweep.

### Fixed
- Lane brief forbids severities outside P0 / P1 / P2 / Info (lanes had invented "P3").
- Validator accepts the `_<lang>` report-name suffix.

## [1.7.0] - 2026-09-21

### Added
- Report language question (multiSelect: English / Japanese / Other); one report set per language
  (`findings-<lang>/`, `..._<ts>_<lang>.*`) with a translator subagent role.
- `build_report.py --findings-dir / --lang-suffix`; unknown language codes fall back to English labels.
- Conversation language auto-detected (`scripts/questions.py`): Phase 0 questions are generated in the
  user's language from their message; user instructions (CLAUDE.md) override via `--lang`.

### Changed
- Default depth is **Deep** (question default and `--yes` default); `detect_stack.py` reports a repo
  `size` hint instead of choosing a smaller depth.
- Questions are asked in one call of four (Depth, Language, Focus, Formats) plus a second call for
  Jurisdiction only when personal / payment / health / financial data is detected.

## [1.6.1] - 2026-09-19

### Fixed
- Sensitive-data sweep: client credential storage (SharedPreferences / UserDefaults / localStorage),
  credentials embedded in URLs, seeded users (`INSERT [OR IGNORE] INTO users`), Terraform / config file
  types; UUIDs (e.g. `yor_trace`) no longer flagged as card numbers; "fingerprint" no longer biometric.
- `peek.py` masks Terraform / HCL secret variable defaults while keeping names readable.
- Offline OSV-Scanner reported as a stated gap instead of a false "clean".
- `detect_stack.py`: `.claude/agents|hooks|skills`, `SKILL.md`, MCP configs mark a repo agentic;
  `httprouter` / chi recognised; manifests in fixture / sample folders ignored.
- Normalizer collapses test / vendor / log noise into one line; redacts only real secret shapes.
- Validator: lockfile anchors are not dedupe candidates; readable secret labels; fewer false positives.

### Changed
- `SKILL.md`: multi-repo naming rule, `<ts>` collision rule, Windows `py -3` note at the top, waiting
  for background scans, "never cat secret-bearing files", quick lanes per repo, one finding per
  remediation action, dependency anchors in the lockfile, primary-standard rule for LLM-reached bugs.

## [1.6.0] - 2026-09-18

### Added
- `scripts/new_finding.py`: findings from one JSON list - checks codes and canonical standard names,
  writes localised headings, names files by id, supports history-only secret anchors.
- `build_report.py --fill` / `--list-placeholders` with named placeholders (`{{key: hint}}`).
- Validator stale-table check: report rows must match the finding files (severity and anchor).
- `tests/selftest.py`: offline self-test of every script; scripts set `sys.dont_write_bytecode`, so
  the installed skill never gets a `__pycache__`.

## [1.5.1] - 2026-09-17

### Fixed
- Excel: Master lists are dynamic named ranges (OFFSET / COUNTA) - a value typed below a list joins
  every dropdown; empty rows are not pre-ruled (conditional borders rule a row once it has content),
  so Page Break Preview shows only real content.
- Localised Excel sheet names, dropdown values, and Coverage texts; HTML column wrapping.

## [1.5.0] - 2026-09-16

### Added
- Shared localisation (`scripts/i18n.py`) for the report scaffold, HTML interface, Excel labels,
  displayed status / confidence / kind, and finding section headings.
- Validator language-consistency gate (English prose inside a Japanese audit fails).
- Canonical standard names, enforced by the validator.

## [1.4.0] - 2026-09-14

### Added
- Excel output (`scripts/render_xlsx.py`): Summary (COUNTIFS statistics + 4 charts), Findings register
  with dropdowns fed by a Master sheet, Owner / Due date / Notes for remediation tracking, Coverage,
  Master. Business-document layout (Meiryo, ruled tables, no zebra, gutter, Page Break Preview), no
  logo. `--verify` recalculates in real Excel and checks totals and formula errors.
- Report formats are a multiSelect question (HTML, Excel); Markdown is always produced.
- Finding status `in-progress`.

## [1.3.1] - 2026-09-12

### Fixed
- HTML: data JSON escapes `<` / `>`, CSP uses a sha256 script hash (no inline-script allowance), CSV
  formula-injection guard, protocol-relative links rejected.

## [1.3.0] - 2026-09-11

### Added
- Interactive HTML report (`scripts/render_html.py`): severity cards, full-text search, filters,
  sortable columns, expandable findings, deep links, CSV export, table of contents.
- `scripts/build_report.py`: report scaffold filled from finding files, `scanners.json`, `sweep.json`.

### Changed
- File naming: lowercase, timestamped (`security-audit-report_<project>_<ts>.*`, `find-<repo>-NNN.md`);
  templates renamed to lowercase.

## [1.2.1] - 2026-09-09

### Fixed
- Secret redaction unified in `scripts/peek.py`; the sweep no longer leaks secrets into `sweep.json`;
  normalizer and validator use the same detection; subagent briefs must use `peek.py`.
- `allowed-tools` patterns match the quoted `python "${CLAUDE_SKILL_DIR}/..."` commands.
- Scanner pins carry `@sha256` digests; cached images are not re-pulled; `--offline` never pulls.

### Changed
- Standards corrected after independent review: OWASP Top 10 for LLM Applications 2026 (IDs
  renumbered), AISVS 1.01 and its separation-of-duties citation (Appendix C AC.4.1 / AC.8.1 / AC.8.4),
  MCP Top 10 (beta), OWASP Non-Human Identities Top 10 2025, CIS EKS / AKS / GKE, PCI DSS 3.3.1.x /
  6.3.3 / 6.4.1-2 / 8.4.2 / 8.6.2 scope, RFC 9700 / RFC 8725 / WebAuthn, GraphQL / WebSocket / gRPC.
- Method: abuse-case step in recon, dependency prioritisation (MAL > KEV > EPSS > CVSS v4, reachability,
  minimal fixed version), client-artifact override narrowed to credentials.
- `reference/` reorganised into `standards/`, `method/`, `tooling/`; subagent orchestration moved to
  `reference/method/orchestration.md`.

## [1.2.0] - 2026-09-07

### Added
- Depth modes (Quick / Standard / Deep) and subagent briefs (`agents/recon-mapper.md`,
  `lane-reviewer.md`, `finding-verifier.md`) with a model / effort matrix.
- AskUserQuestion scoping (depth, focus, formats, jurisdiction) with a `--yes` bypass.
- Adversarial finding verifier and a confidence axis (confirmed / likely / needs-runtime-check).
- `evals/evals.json` with scenario evals across project types.

## [1.1.1] - 2026-09-05

### Fixed
- Git-Bash `/c/...` paths resolved wrongly on Windows Python - all scripts normalise them and fail
  loudly on a missing `--repo`.
- Sweep catches plain `password TEXT` columns and inline `CREATE TABLE` schemas.
- Validator resolves extensionless anchors (`Dockerfile:1`).
- Version and verified dates shown in the `SKILL.md` body (frontmatter is not visible at run time).
- Background scans use the tool's `run_in_background` (a shell `&` job was killed).

## [1.1.0] - 2026-09-03

### Added
- Deterministic script layer: `detect_stack.py` (repo fingerprint -> standards modules, scanners,
  lanes, gaps), `sensitive_sweep.py` (locations-only leads + negative-result record),
  `run_scanners.py` (pinned Docker scanners with native fallback, read-only mounts, mount check,
  digests, parallel tools), `normalize_findings.py` (SARIF -> deduplicated candidates),
  `validate_findings.py` (delivery gate).
- Per-module standards references with requirement-level checks.

### Changed
- Standards baseline re-verified: OWASP Top 10 2025, ASVS 5.0.0, SLSA v1.2, CIS AWS v7.1.0 (+ Azure
  v6.0.0, GCP v5.0.0), Agentic Top 10 2026, OWASP K8s Top 10 2025, Mobile Top 10 2024, CWE Top 25 2025,
  NIST SP 800-63-4, privacy and sector law updates.
- Scanner pins updated (Semgrep 1.180.0, Gitleaks 8.30.1 `git` / `dir`, Trivy 0.75.0, OSV-Scanner
  v2.7.0, Checkov 3.3.28, zizmor 1.30.1, hadolint 2.15.1, mobsfscan 1.0.1).
- harness-bootstrap is optional (used when present, not required).

## [1.0.0] - 2026-09-01

### Added
- Initial skill: phases 0-8, knowledge layer (standards table, sensitive data at rest, scanner matrix,
  triage, what scanners cannot see, coverage checklist), finding and report templates.
