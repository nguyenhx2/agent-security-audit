# Finding triage - severity, confidence, dedupe, verification, anchoring

Back to procedure: `SKILL.md` Phases 5-6. Finding shape: `templates/finding.md.template`.

## Contents
- Severity by consequence
- Overrides that cannot be argued down
- Confidence (separate axis from severity)
- Adversarial verification (the false-positive filter)
- Deduplicate by root cause
- Anchoring
- Committed secrets: compromised, not exposed
- Separation of duties and lifecycle

## Severity by consequence

| Severity | Definition (by consequence if exploited) |
|----------|------------------------------------------|
| **P0 / Blocker** | Direct, high-impact compromise reachable now: cardholder/special-category data exposure, credential compromise, unauthenticated access to sensitive data or admin functions, RCE, money theft. Ship-blocking |
| **P1 / Major** | Serious weakness exploitable under realistic conditions (authenticated attacker, one precondition), or a control believed to work that does not |
| **P2 / Minor** | Real defect with limited blast radius or unlikely preconditions; defense-in-depth gaps |
| **Info** | No direct security consequence: hardening, hygiene, coverage notes |

Rate by consequence and reachability, not scanner wording. Scanner "critical" on a dev-only
dependency is often P2; a silent schema column holding CVVs is P0.

## Overrides that cannot be argued down

| Condition | Floor | Why |
|-----------|-------|-----|
| SAD (CVV / track / PIN) stored after authorization | **P0**, even if encrypted | PCI DSS v4.0.1 Req 3.3.1 - encryption does not redeem never-store |
| Plaintext PAN at rest | **P0** | PCI DSS v4.0.1 Req 3.5.1 |
| Live credential that authenticates to a server-side or third-party resource, shipped in a client artifact (mobile bundle, `NEXT_PUBLIC_*`, `EXPO_PUBLIC_*`, JS bundle) | **P0** | Public by definition; no server-side mitigation downgrades it. A hard-coded *local* encryption key is MASVS-CRYPTO-2 / CWE-321 - severity by consequence (usually P1) |
| Known-malicious dependency (OSV `MAL-*`) installed | **P0** | Assume the install executed; rotate what it could reach |
| Dead security control (verify/validate/authz that cannot fail) | **at least P1** | The belief that it works is the vulnerability |
| Fail-open on exception in an authz/verify/payment path | **at least P1** | OWASP Top 10:2025 A10 |
| Untrusted content (document, web page, issue / MR text, tool output) reaches a pre-approved write / exec / publish action of an agent | **at least P1** (P0 with deploy secrets or money) | OWASP Top 10 for Agentic Applications 2026 ASI01 / ASI02 |
| One agent or tool set holding private data + untrusted content + an exfiltration channel ("lethal trifecta") | **at least P1** (P0 with write or money) | Exfiltration needs no further bug; LLM Top 10 2026 LLM01 / LLM02 |
| Committed prompt / transcript log containing secrets or personal data | **at least P1** | Treat like a committed secret: rotate, then purge history |
| Agent guardrail, hook or deny rule that fails open | **at least P1** | Dead control (row above) |
| Deployed runtime / server / product version affected by a CISA KEV CVE or by a CVE an IPA / JPCERT/CC alert asks to fix now, reachable from the internet | **P0** for pre-auth RCE / auth bypass, else **at least P1** | Exploitation is in progress somewhere; `reference/method/threat-intel.md` |
| Admin / BI / management console or datastore reachable from outside without auth, or a secret-bearing file under a served web root | **at least P1** (P0 with data or code execution) | Mass-scanned initial access in national CERT campaign alerts |
| Perf claim with neither a measurement nor a structural argument | **not a finding** | Info at most |
| Missing best practice with no lower-trust principal who gains anything (no boundary line, see below) | **Info** (`kind: configuration`, "hardening") | A hardening note is not a vulnerability; P2 only when it widens a confirmed P0/P1 |

Secrets in git history that are demonstrably test/demo values (sample apps, documented fixtures)
are still reported, with severity by what the credential could reach - state the reasoning.

## Confidence (separate axis from severity)

| Confidence | Meaning | Required evidence |
|-----------|---------|-------------------|
| `confirmed` | Read the code path end to end: source -> sink with no effective control | file:line of source, sink, and the missing/broken control |
| `likely` | Pattern present and plausibly reachable, one link not proven (e.g. middleware order, config at runtime) | state the unproven link |
| `needs-runtime-check` | Depends on deployment/runtime state a static audit cannot see | state exactly what to check |

Never report a P0 at `needs-runtime-check` without saying so in the title line of the report table.
A `needs-runtime-check` finding names the blocker (the one deployment fact that decides it, e.g. "is
port 3000 of the metabase service published by the production compose file") and who can check it,
in Verification - the owner gets a checklist, not a guess.

**Boundary line.** Every P0-P2 candidate states `principal -> control crossed -> resource affected`
("unauthenticated internet user -> missing authz on PUT /users/{id}/role -> any account's role"). A
candidate that cannot fill all three is a hardening note (Info) or not a finding.
A scanner hit nobody read is not a finding at all - it stays a candidate.

## Adversarial verification (the false-positive filter)

Before registering any P0/P1 (and any P2 in Deep mode), try to **refute** it:
1. Is the input actually attacker-controlled at this point? Trace back to the entry point.
2. Is there a control elsewhere - middleware, framework default (ORM parameterization, template
   auto-escaping), gateway, schema validation - that neutralises it? Read it, don't assume it.
3. Is the code reachable in production (not dead, not test-only, not behind a disabled flag)?
4. Does the claimed consequence follow, given the data actually involved?
If refuted -> drop or downgrade with the reason recorded. If it survives -> `confirmed` or `likely`.
In Standard/Deep mode this is delegated to the verifier subagent (`agents/finding-verifier.md`).

**Auto-refuted by rule (before the lanes).** `normalize_findings.py` marks a scanner candidate
`auto_refuted: <reason>` only when it is almost surely not real: a secret hit at HEAD whose matched
value (read in-process, never printed) is a placeholder (`dummy`, `example`, `sample`, `test`,
`fake`, `changeme`, `your_*_here`, `xxx`, `<...>`, `${...}`, `{{...}}`, `***`, one repeated
character), or weaker placeholder words in documentation/example files; a short, low-entropy value
in vendored third-party docs (`.agents/skills/`, `node_modules/`, `vendor/`, `third_party/`);
production-only SAST rules (CORS, CSRF, debug, cookie flags, bind-all, healthcheck, missing USER,
security headers, TLS verification, weak random, temp files) in test files or vendored code. Lanes
and the verifier skip them; the report lists them under Refuted. **Never auto-refuted:** secrets that
exist only in git history, private keys, values with a real key format anywhere on the matched lines
(`AKIA...`, `ghp_...`, `xox...`, `sk_live_` / `sk_test_` / `sk_prod_`, `AIza...`, `glpat-`), cloud,
card or JWT rules, long high-entropy values, unreadable lines, and every other rule or category.

## Dependency prioritisation
Order: OSV `MAL-*` (malicious) > listed in CISA KEV (https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
> named in a national CERT alert (IPA, JPCERT/CC) > EPSS >= 0.1 (FIRST EPSS) > CVSS v4.0 base >= 7 (v3.1
if v4 absent) > the rest. Runtimes, servers and products outside lockfiles come from `intel.md`
(`reference/method/threat-intel.md`). Downgrade only with
a reachability argument: call-graph evidence (govulncheck, OSV-Scanner call analysis) or a manual
trace that the vulnerable function / import is never on a production path (dev-only, test-only,
optional platform dependency, sample folder not built). Record not-affected decisions with the reason
(optionally as OpenVEX / CycloneDX VEX in `<audit_dir>/work/<repo>/vex.json`). Every dependency finding
names the minimal fixed version per package.

## Deduplicate by root cause

Two scanners on one committed key = one finding. Three rule IDs on one missing authz check = one
finding. Twenty CVEs in one outdated package = one finding (the upgrade). One vulnerable helper called
from ten routes = one finding listing the call sites. Scanner hits are evidence attached to a root
cause, not separate findings. Assign severity once, at triage. A runtime upgrade is one finding too:
"PHP 8.3.30 -> 8.3.36 and rebuild" lists every CVE and every pin it changes.

**Variant sweep.** After confirming a P0/P1, grep the same root cause's lexical and structural variants
(the same helper, the same missing guard on sibling routes, the same pattern in another service) and
add the sites to that finding before closing the lane. **Weakest door:** for each sensitive effect
(role change, payout, export, delete, MFA reset), list every path that produces it (UI route, API,
mobile endpoint, batch job, import, retry, admin tool) and compare their controls; the weakest path is
the finding.

## Anchoring

Each finding carries: `file:line` (source and sink where they differ; column + migration for
data-at-rest - never the data); `standard + version + requirement ID` (`reference/standards/index.md`); CWE when one
fits; `confirmed_by` (scanner+rule, `manual review`, or both - manual-only is fully valid).
`scripts/validate_findings.py --repo name=path` checks anchors resolve.

## Committed secrets: compromised, not exposed

Remedy is **rotation at the provider**, then history cleanup if desired - deleting the file fixes
nothing. A secret finding states: which console rotates it; what breaks at rotation (consumers to
update/redeploy); whether it is in history (`history-only` flag from the normalizer); whether it
shipped in a client artifact (P0 override). Never paste the value - gitleaks output is redacted.

## Separation of duties and lifecycle

The auditor never modifies or merges audited code (OWASP AISVS 1.01 Appendix C AC.4.1 / AC.8.1 / AC.8.4). The user fixes.
```
open -> (user fixes) -> re-scan with same pinned image digests + ruleset (+ re-read for manual findings)
     -> reproduces? yes -> stays open
                    no  -> catching rule still present? (rule out drift) -> closed
accepted-risk / false-positive: only with the user's recorded decision and reason
```
