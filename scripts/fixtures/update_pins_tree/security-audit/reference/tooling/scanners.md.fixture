# Scanner operations - the deterministic layer

Back to procedure: `SKILL.md` Phase 3. Scanners find the mechanical, the many, and the
regression-checkable; they cannot see design-level defects (`reference/method/design-flaws.md`).

## Contents
- Run it: `scripts/run_scanners.py`
- Tool matrix (pins verified 2026-10-26)
- Mode resolution and fallbacks
- Rules the runner enforces (and why)
- Reading the output: `scripts/normalize_findings.py`
- Ruleset drift and re-scan discipline
- Language coverage gaps

## Run it

See SKILL.md Phase 3 for the exact commands (`--out <audit_dir>/work/<repo>`, always in the
background, then `normalize_findings.py ... --summary-out`). Per-OS Python command, wait loop, path
format, container engine and install routes: run `scripts/env_check.py` and follow its `choices`
(`reference/tooling/platforms.md`).

`--out` must be OUTSIDE the audited repo (the runner refuses otherwise). Tools run in parallel
(`--jobs 3`). Typical wall time on a 100-300 file repo: 1-3 min with images cached; first pull adds
1-5 min. `--offline`: no DB updates for trivy/zizmor; osv-scanner is skipped (re-run it online for
OSV / `MAL-*` findings); semgrep `p/default` is still fetched, so rules may drift - check that the
finding's rule id is still emitted.

## Tool matrix

| Tool | Image (pinned) | Role | Run when |
|------|----------------|------|----------|
| gitleaks | `ghcr.io/gitleaks/gitleaks:v8.30.1` | Secrets: `git` mode (full history, `--log-opts=--all`) + `dir` mode (working tree incl. untracked) | always |
| semgrep | `semgrep/semgrep:1.181.0` | SAST, `--config p/default --metrics off` (no login, no telemetry) | any supported language |
| trivy | `aquasec/trivy:0.76.1` | Dependency CVEs, IaC/Dockerfile misconfig (license scan off - enable only for a license policy) | lockfiles or containers |
| osv-scanner | `ghcr.io/google/osv-scanner:v2.7.0` | Lockfile-precise CVEs + malicious-package (`MAL-*`) advisories | lockfiles |
| checkov | `bridgecrew/checkov:3.3.29` | IaC: Terraform, CFN, K8s, Helm, Dockerfile, GH Actions | IaC or containers |
| hadolint | `hadolint/hadolint:v2.15.1` | Dockerfile lint + ShellCheck | Dockerfiles |
| zizmor | `ghcr.io/zizmorcore/zizmor:1.31.1` | GitHub Actions security (offline audits) | `.github/workflows` |
| mobsfscan | `opensecurity/mobsfscan:1.0.1` | Android/iOS source SAST | mobile |

Pins are `image:tag@sha256:digest` - the tag for humans, the digest for reproducibility (a re-pointed
tag cannot change what runs). `python run_scanners.py --list` prints them. If `PINS_VERIFIED` is
older than ~90 days, check for newer tags and pass `--pin tool=image:tag`; the runner refuses
`:latest` and untagged pins. `python run_scanners.py --check-updates` asks Docker Hub / GHCR for the
newest stable tag of each pin and prints current / newer available / lookup failed (`--json PATH`
for a file, `--offline` = no lookup). It only reports: it never pulls, never changes a pin and exits 0;
the default pins stay the verified ones, and a newer tag is tried deliberately with
`--pin tool=image:tag@sha256:...`. Images already cached are not re-pulled; with `--offline` a missing
image is skipped (stated as a gap), never pulled. Digests are recorded per run in `scanners.json`.

Optional extras (not wired into the runner; run manually when the stack calls for it and state them
in the coverage table): TruffleHog `trufflesecurity/trufflehog` (secret *verification* - contacts
providers; use `--no-verification` unless the user approves), Bandit (Python), gosec / govulncheck
(Go, reachability-aware), Brakeman (Rails), KICS (IaC alternative), Grype + Syft (SBOM),
OWASP Dependency-Check 13 (needs NVD API key). Betterleaks is the announced successor to Gitleaks
(Gitleaks is security-fix-only) - acceptable substitute if the user prefers.

## Mode resolution and fallbacks

`--mode auto`: a container engine answers (`--engine auto` = docker, else podman) -> container;
else native binaries on PATH -> `native`; a tool with neither is `skipped` and listed under
`coverage_gaps`. Never report "clean" for a skipped tool. `--mode container` (alias `docker`) requires
an engine (exit 3 otherwise). `scanners.json` -> `container` records engine, runtime, the uid the
containers ran as, SELinux handling and any ownership fix-up (Linux/macOS: no root-owned output).

When an engine is installed but not running (`env_check` -> `engine_installed_not_running`), tell the
user and offer: (a) start it and re-run (Docker Desktop / OrbStack / `colima start` / `podman machine
start` / `sudo systemctl start docker`), (b) install native tools - the per-OS commands are in
`env_check` -> `choices.install` and `reference/tooling/platforms.md`, or (c) continue
knowledge-layer-only and state every scanner as a gap. Installing software is the user's call - ask.

## Rules the runner enforces (and why)

| Rule | Why |
|------|-----|
| Source mounted `:ro`; `--out` outside the repo | Auditor is read-only on product source (AISVS 1.01 AC.8.1/AC.8.4) |
| SELinux / podman: `label=disable`, never `:z`/`:Z` | Relabelling would write xattrs into the audited repo |
| Containers run as your uid (Linux/macOS), podman `--userns=keep-id` | Root-owned output blocks cleanup (`prune_work.py`) |
| Mount verified (`find /src -type f | wc -l` > 0) before any scan | Zero findings on an empty mount is the classic false "clean" (Windows paths, engine file sharing on macOS / Colima / podman machine) |
| Python `subprocess` (no shell) builds `docker -v` | Git Bash MSYS path conversion silently rewrites `/src` and `C:\...` arguments |
| Full git history for secrets; shallow clone / no `.git` recorded as a gap | Deleted credentials stay in every clone; HEAD-only scans miss the compromised ones |
| `safe.directory=*` via `GIT_CONFIG_*` env | Read-only mounts owned by another UID trip git's "dubious ownership" and silently scan nothing |
| `--redact` on gitleaks; normalizer masks long tokens | Secrets never enter the transcript or the report |
| Semgrep `--metrics off`, `p/default` (not `auto`) | `auto` sends the project URL to the registry |
| Pinned tags + recorded digests; no `:latest` | Trivy 2026 compromise shipped through re-pointed tags |

## Reading the output

`normalize_findings.py` parses SARIF as data (never executes it), clusters hits by location across
tools ("multi-tool" = independent witnesses, higher confidence), groups dependencies by
package@version (one upgrade = one root cause), separates test/vendor/example/doc paths, flags
history-only secrets and `MAL-*` packages, and omits license notices. It writes `candidates.jsonl`
(each with a `cid`) for grep/jq follow-up. Read the summary, not the raw SARIF - raw files are often
1-5 MB.

Scanner output is untrusted: an inline `nosemgrep` / `# noqa` / `gitleaks:allow` is a claim by the
code under audit - note it, assign severity yourself.

## Ruleset drift and re-scan discipline
Rule packs (`p/default`), vuln DBs (Trivy, OSV), and Checkov policies update independently of image
tags. For a Phase 8 re-scan: same pinned images (compare digests in `scanners.json`) AND `--offline`
with the same cached DBs where possible (see the `--offline` caveats above). A finding that
disappears: confirm the catching rule id is still emitted before calling it fixed.

## Language coverage gaps
`detect_stack.py` emits `sast_coverage_gaps`. Weak/no Semgrep CE coverage: Dart (Flutter), Lua,
Clojure, Objective-C, Erlang, Perl, VB.NET, F#, Groovy, PowerShell, Razor/JSP templates. Memory-safety
CWEs in C/C++ need dedicated tools. For each gap: manual review in the relevant lane, or state "not
covered". A scanner's silence on a language it does not cover means nothing.
