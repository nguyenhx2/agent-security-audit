# Trigger cases - security-audit

Re-run whenever the skill's description changes. Each case states what should load, what must stay
quiet, and how the result is judged. Behavioural expectations per run are in `evals/evals.json`.

## positive-discovery

The skill should trigger.

- Request: "Audit this repo before we launch - we store customer cards and use an LLM for support replies."
- Repo state: a Node.js API with `package-lock.json`, migrations, a Stripe integration and an OpenAI client; no prior audit folder.
- Expected skills: security-audit
- Not expected: security-review (no diff was asked about), harness-bootstrap
- Success criteria: Phase 0 questions are asked once; the audit folder is created outside the repo; validate_findings.py exits 0; the report has the sensitive-data-at-rest, AI inventory, platform / threat-intelligence and coverage-gap sections.

## negative-discovery

A request that sounds close but belongs elsewhere. The skill must not trigger.

- Request: "Review the security of the changes on this branch before I open the PR."
- Repo state: a feature branch with three changed files.
- Expected skills: security-review
- Not expected: security-audit
- Success criteria: only the diff is reviewed; no audit folder, scanners or report set are produced.

## edge-case

The skill should trigger and cope with a target that has no application code and no scanner engine.

- Request: "セキュリティ監査して。Docker は入っていない。"
- Repo state: Terraform and Kubernetes manifests only; no container engine and no native scanners; JVN iPedia feed suspended.
- Expected skills: security-audit
- Not expected: harness-bootstrap
- Success criteria: env_check offers the per-OS options, the audit continues reading-only with every missing scanner and the failed feed stated as gaps (never as clean), and the report is in Japanese with no English prose.

## conflict-composition

Several skills look relevant; routing must be explicit.

- Request: "Set up the Claude harness for this repo and check it is safe before and after."
- Repo state: an existing app with a committed `.claude/settings.json` and hooks.
- Expected skills: harness-bootstrap leads the setup; security-audit runs before it (baseline) and after it (re-scan of the agent-tooling scope)
- Not expected: security-review
- Success criteria: security-audit never edits the repo or the harness files; harness-bootstrap writes them; the second audit reports the agent permissions and hooks the harness added, and findings close only on re-scan.

## execution-quality

The skill measurably improves the result.

- Request: "Is our PHP app affected by the emergency PHP advisories this week?"
- Repo state: `Dockerfile` with `FROM php:8.3.30-fpm`, `composer.json` with `"php": "^8.1"`, a `public/` folder holding `info.php`.
- Expected skills: security-audit
- Not expected: security-review
- Success criteria: platform_inventory finds the exact deployed version; threat_intel matches it to the KEV / IPA / JPCERT/CC alerted CVEs and the EOL cycle allowed by the range; one upgrade finding lists every CVE and pin; the web-root `phpinfo()` is triaged; validate_findings.py prints no `intel:` warning.
- Baseline (without the skill): a general answer about the advisory without reading the repo's pins, no version comparison, and no check of the web root or the range constraint.

## efficiency

The skill loads only what it needs.

- Request: "Quick security check of this small Flask API, English report only."
- Repo state: about 40 Python files, `requirements.txt`, no mobile, IaC or AI components.
- Expected skills: security-audit
- Not expected: security-review
- Success criteria: Quick depth runs lanes inline with no subagents; mobile, ai-llm-agentic, pci-dss and cloud-iac references stay unread; the reply is short (counts, top findings, first action, gaps, paths).
