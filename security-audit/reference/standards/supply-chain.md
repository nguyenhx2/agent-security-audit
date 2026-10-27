# Module: supply-chain - CICD-SEC, SLSA v1.2, NIST SSDF v1.1, OWASP NHI Top 10 2025, SBOM, Scorecard

Apply when the repo has CI/CD config, lockfiles, release automation, or container builds. Cite
`OWASP Top 10 CI/CD Security Risks CICD-SEC-<n>`, `SLSA v1.2 Build L<n>` / `Source L<n>`,
`NIST SSDF SP 800-218 v1.1 <practice>` (e.g. PS.1, PW.4, RV.1), `OWASP Top 10:2025 A03`.

## Contents
- Lesson from 2026: tags are not pins
- CICD-SEC 1-10 checks
- SLSA v1.2 levels (what to claim)
- SSDF practices a code audit can evidence
- Dependency findings: how to register them

## Lesson from 2026: tags are not pins
March 2026: a malicious Trivy v0.69.4 release binary/image was published and the `trivy-action`
(0.0.1-0.34.2) and `setup-trivy` tags were force-pushed to malicious commits (CVE-2026-33634).
Consumers pinned by tag ran malware; consumers pinned by digest / commit SHA did not. Apply to the
audited repo: GitHub Actions `uses:` must pin a full commit SHA; container `FROM` should pin
`@sha256:`; install scripts should verify checksums/signatures (cosign). Same rule binds this skill's
own scanners (`reference/tooling/scanners.md`).

## CICD-SEC 1-10

| ID | Risk | What to verify | Where |
|----|------|----------------|-------|
| CICD-SEC-1 | Insufficient Flow Control Mechanisms | Branch protection / required reviews for deploy branches; no direct push-to-prod path; manual approval for prod | workflow triggers (`push: main` -> deploy), environments with reviewers |
| CICD-SEC-2 | Inadequate Identity and Access Management | Least-privilege CI identities; no personal tokens; stale accounts | `secrets.*_TOKEN` usage, `permissions:` blocks |
| CICD-SEC-3 | Dependency Chain Abuse | Lockfiles committed; private registry scoping (dependency confusion); install scripts disabled where possible (`--ignore-scripts`); no unpinned `npx pkg@latest` | lockfiles, `.npmrc`, `pip install` without hashes |
| CICD-SEC-4 | Poisoned Pipeline Execution (PPE) | Untrusted PR code never runs with secrets: no `pull_request_target`/`workflow_run` that checks out PR head; no `${{ github.event.* }}` interpolated into `run:` (script injection) | `.github/workflows/*.yml` (zizmor catches most) |
| CICD-SEC-5 | Insufficient PBAC | Per-job `permissions:` minimal (`contents: read` default); self-hosted runners not shared with untrusted workflows | `permissions: write-all`, missing `permissions:`, `runs-on: self-hosted` on public repos |
| CICD-SEC-6 | Insufficient Credential Hygiene | OIDC federation instead of long-lived cloud keys; secrets not echoed; masked; scoped per environment | `AWS_ACCESS_KEY_ID` in secrets, `set -x` with secrets, `aws-actions/configure-aws-credentials` with keys |
| CICD-SEC-7 | Insecure System Configuration | Runners/build images patched and pinned; artifact storage private | runner images, build containers |
| CICD-SEC-8 | Ungoverned Usage of 3rd Party Services | Third-party actions/apps reviewed and SHA-pinned; marketplace apps with org-wide write limited | `uses: someone/action@v1` |
| CICD-SEC-9 | Improper Artifact Integrity Validation | Artifacts signed (Sigstore/cosign), provenance generated (SLSA), verified before deploy | release workflows, `actions/attest-build-provenance` |
| CICD-SEC-10 | Insufficient Logging and Visibility | CI audit logs retained; deploy events attributable | org settings (usually out of static scope - state it) |

## OWASP Non-Human Identities Top 10 2025 (service accounts, CI tokens, API keys, agent identities)
Cite `OWASP Non-Human Identities Top 10 2025 NHIx`. Check in code/CI/IaC:
| ID | Risk | What to verify |
|----|------|----------------|
| NHI1 | Improper Offboarding | Keys/SAs for retired services, ex-vendors, old pipelines still referenced or provisioned |
| NHI2 | Secret Leakage | Committed / logged / client-shipped secrets (gitleaks, peek.py) |
| NHI3 | Vulnerable Third-Party NHI | Third-party apps/actions holding broad tokens to repos or cloud |
| NHI4 | Insecure Authentication | Static long-lived keys where OIDC/workload identity is available |
| NHI5 | Overprivileged NHI | Wildcard IAM, org-wide PATs, `cluster-admin` service accounts |
| NHI6 | Insecure Cloud Deployment Configurations | CI-to-cloud trust without audience/subject constraints (OIDC `sub` wildcard) |
| NHI7 | Long-Lived Secrets | No expiry/rotation on keys and tokens |
| NHI8 | Environment Isolation | Same credential used across dev/staging/prod |
| NHI9 | NHI Reuse | One identity shared by many services/agents - no attribution |
| NHI10 | Human Use of NHI | Developers using service credentials interactively |

## Runtime, image and product patch level (outside lockfiles)
Interpreters, servers, datastores, base images, admin tools and frameworks are pinned in Dockerfiles,
compose / manifests, version files, CI and serverless config - lockfile SCA never sees them.
`platform_inventory.py` lists them and `threat_intel.py` matches them against CISA KEV, NVD, EPSS,
endoflife.date and IPA / JPCERT/CC / JVN alerts. Method, precision rules and severity floors:
`reference/method/threat-intel.md`. Cite `OWASP Top 10:2025 A03` (+ `PCI DSS v4.0.1 Req 6.3.3` in
card scope); CWE-1104 for EOL, CWE-1395 for a vulnerable third-party component.

## SLSA v1.2 - what to claim
- Build L1: provenance exists. L2: hosted build platform + signed provenance. L3: hardened, isolated
  builds; provenance unforgeable by tenants.
- Source track (new in v1.2): version-controlled history, protected branches, two-party review at
  higher levels.
Report the *observed* level with evidence (e.g. "no provenance generated -> Build L0"). Never claim
a level from config alone if signing/verification cannot be seen.

## SSDF practices a code audit can evidence
PO.3 (toolchains), PS.1 (protect code from unauthorized change - branch protection, signed commits),
PS.2 (release integrity - signatures), PS.3 (archive + provenance), PW.4 (reuse well-secured
components - dependency hygiene), PW.7 (code review/analysis - SAST in CI), RV.1 (vuln
identification - SCA in CI). NIST SP 800-218A adds GenAI-specific practices (cite when training/
fine-tuning models). SSDF Rev 1 (v1.2) is a draft - do not cite as final.

## Dependency findings: how to register them
- **Root cause = the package you must upgrade**, not each CVE. State the minimal fixed version
  (Trivy `Fixed Version`, OSV advisory `affected.ranges`); "see advisory" is not a remedy. One finding per upgrade action
  (`scripts/normalize_findings.py` already groups this way); list CVEs inside it.
- Severity: reachable from production code paths and exploitable in this context -> keep scanner
  severity; dev-only / test-only / unreachable -> downgrade with a stated reason. Known-malicious
  (OSV `MAL-*`) -> P0, rotate anything the install could have touched.
- Transitive vulns: name the direct dependency that pulls them in and the minimal upgrade.
- SBOM: recommend CycloneDX 1.7 / SPDX 3.0.1 generation in CI (PCI DSS v4.0.1 6.3.2 inventory).
- OpenSSF Scorecard (v5.x) can grade repo hygiene for critical third-party dependencies - suggest,
  do not run against third parties without the user asking.
