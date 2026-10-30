# Scanners

**English** · [日本語](ja/scanners.md)

Scanners find the mechanical, the many and the regression-checkable. They cannot see design-level defects; the review lanes do that. Every scanner hit is a lead until a model reads the code and confirms it.

## The pinned scanners

The skill runs <!--n:scanners-->8<!--/n--> pinned scanners. `detect_stack.py` decides which ones apply to each repository.

| Scanner | Image | Covers | Runs when |
|---|---|---|---|
| Gitleaks | `ghcr.io/gitleaks/gitleaks` | Secrets: full git history (all refs) and the working tree, including untracked files | Always |
| Semgrep | `semgrep/semgrep` | Code patterns (SAST), rule pack `p/default`, metrics off | Any supported language |
| Trivy | `aquasec/trivy` | Dependency CVEs, images, IaC and Dockerfile misconfiguration | Lockfiles or containers |
| OSV-Scanner | `ghcr.io/google/osv-scanner` | Lockfile-precise CVEs and malicious-package (`MAL-*`) advisories | Lockfiles |
| Checkov | `bridgecrew/checkov` | Terraform, CloudFormation, Kubernetes, Helm, Dockerfile, GitHub Actions | IaC or containers |
| hadolint | `hadolint/hadolint` | Dockerfile lint and ShellCheck | Dockerfiles |
| zizmor | `ghcr.io/zizmorcore/zizmor` | GitHub Actions workflow security | `.github/workflows` |
| mobsfscan | `opensecurity/mobsfscan` | Android and iOS source | Mobile apps |

The versions change with each pin update, so this guide does not repeat them. The current versions are in the [README scanner table](https://github.com/nguyenhx2/agent-security-audit/blob/main/README.md#tools-that-keep-up), and `run_scanners.py --list` prints the exact `image:tag@sha256:digest` pins of your installed copy and the date they were verified.

`detect_stack.py` also reports SAST coverage gaps by language. Semgrep CE has weak or no coverage for Dart (Flutter), Lua, Clojure, Objective-C, Erlang, Perl, VB.NET, F#, Groovy, PowerShell and Razor or JSP templates; those are covered by manual review in the relevant lane or stated as "not covered". A scanner's silence on a language it does not cover means nothing.

## Container, native or none

`run_scanners.py --mode auto` (the default) picks a mode:

1. **Container.** If a container engine answers (`--engine auto` tries Docker, then Podman), every scanner runs from its pinned image, with the repository mounted read-only.
2. **Native.** Otherwise, scanners found on `PATH` run natively.
3. **None.** A scanner with neither is `skipped` and listed under coverage gaps. A skipped scanner is never reported as clean.

`--mode container` requires an engine and exits 3 when none answers. `--engine docker|podman` forces one.

What the runner enforces:

| Rule | Why |
|---|---|
| Source mounted read-only; `--out` must be outside the repository | The auditor is read-only on product source |
| The mount is verified (file count above 0) before any scan | Zero findings on an empty mount is the classic false "clean" |
| SELinux and Podman: `label=disable`, never `:z` or `:Z` | Relabelling would write extended attributes into the audited repository |
| Linux and macOS: containers run as your user; rootless Podman uses `--userns=keep-id` | No root-owned output that blocks cleanup |
| Gitleaks and hadolint run with networking disabled | They need no network |
| The repository's own scanner configs are ignored (Gitleaks allow-lists, `nosem` comments, zizmor config, osv-scanner config) | The repository cannot silence its own scanners. What cannot be neutralised (`.gitleaksignore`, `.checkov.yaml`, `.semgrepignore`) is listed as a coverage gap. |
| Semgrep with `--metrics off` and `p/default` (not `auto`) | `auto` sends the project URL to the registry |
| Gitleaks with `--redact`; long tokens masked in normalised output | Secrets never enter the transcript or the report |
| Pinned tags plus recorded digests; `:latest` refused | A re-pointed tag cannot change what runs |
| Python `subprocess` without a shell builds the container command | Git Bash path conversion cannot rewrite the mount paths |

The run writes `work/<repo>/raw/<tool>.(sarif|json)` and `work/<repo>/scanners.json`, which records the mode, engine, image digests or native versions, the audited commit and the coverage gaps. Then `normalize_findings.py` merges everything into `candidates.jsonl` and `summary.md`.

## Why pins are digests

Each pin is `image:tag@sha256:digest`: the tag for humans, the digest for reproducibility. Rule packs and vulnerability databases still update on their own, but the scanner binary and its built-in rules do not change between two runs. That matters most for [Phase 8](rescan.md): a re-scan uses the same digests (`--pin tool=<image:tag@sha256 from scanners.json>`), so a fix is judged by the same rules that found the defect, and a finding closes only when it no longer reproduces and its rule still fires.

## Checking for newer scanners

```bash
py -3 <skill_dir>/scripts/run_scanners.py --check-updates [--json PATH] [--offline]
```

It asks Docker Hub and GHCR for the newest stable tag of each pinned image and prints, per scanner, current, newer available, or lookup failed. It only reports: it never pulls an image, never changes a pin, and exits 0. In Phase 0, when the scanner pins are more than 90 days old, the skill may run it and tell you in one line which scanners have newer tags; the audit still uses the verified pins.

To try a newer version on purpose, for one run only:

```bash
py -3 <skill_dir>/scripts/run_scanners.py <repo> --out <work>/<repo> --pin trivy=aquasec/trivy:<tag>@sha256:<digest>
```

The runner refuses `:latest` and untagged pins.

## The weekly update-pins workflow

Pins move only through the repository, in a pull request a maintainer reviews. The `update-pins` workflow prepares it every Monday at 02:17 UTC.

![Scanner updates on a schedule, proven and reviewed. Weekly on Monday 02:17 UTC or by hand: update_pins.py --check asks Docker Hub and GHCR for the newest stable tag, public for 7 days first, never a downgrade, no rc, beta or latest tags. smoke_scanners.py runs each candidate image on a fixture with one planted defect per scanner and it must still find it. update_pins.py --write moves the pins in both editions and runs the gates. One pull request on branch bot/scanner-pins, label scanner-pins, with release notes links, a draft CHANGELOG and the smoke test table; a maintainer reviews and merges by hand, never auto-merged; then a z release. Any failure opens one issue update-pins failed. During an audit the pins never move on their own: run_scanners.py --check-updates only reports, --pin tries one version for that run only.](../assets/scanner-update-flow.svg)

1. **Check.** `update_pins.py --check` asks each registry for a newer stable tag. A tag is proposed only once it has been public for 7 days (the cooldown): a compromised image pushed to a registry is usually noticed and pulled within days, and the cooldown keeps the repository out of that window. Release candidates, betas and `latest` are never proposed, nor is a downgrade. A failed registry lookup fails the run, so an outage never reads as "everything is current".
2. **Smoke test.** `smoke_scanners.py` runs every candidate image on a fixture with a planted defect for that scanner. A new version that no longer finds its defect, or crashes, stops the run.
3. **Write and gate.** `update_pins.py --write` updates the pins in both editions; then both self-tests, the offline eval, the edition check, the plugin manifest check, the figures check and the release validator run on the result.
4. **Pull request.** The change goes to the branch `bot/scanner-pins` as one pull request labelled `scanner-pins` (or updates the open one). The title lists each move, for example `scanner pins: trivy <old> -> <new>, ...`; the body has release notes links, a draft CHANGELOG entry and the smoke test table. It is **never merged automatically**.
5. **Failure issue.** When any step fails, the run opens one issue, `update-pins failed`, labelled `scanner-pins`, with the failed stage, the run link and what to do next. A later failure comments on it; the next successful run closes it. Nothing is merged either way.

A merged pin update is released as a `z` version; the new pins reach you only with that release. Running the workflow by hand, local commands and exit codes: [Scanner pin updates](https://github.com/nguyenhx2/agent-security-audit/blob/main/docs/RELEASING.md#scanner-pin-updates).

## Optional extra tools

Not wired into the runner; run them yourself when the stack calls for it and the auditor states them in the coverage table: TruffleHog (secret verification, which contacts providers; use `--no-verification` unless you approve), Bandit (Python), gosec and govulncheck (Go), Brakeman (Rails), KICS (IaC), Grype and Syft (SBOM), OWASP Dependency-Check (needs an NVD API key).

## See also

- [`scanners.md`](https://github.com/nguyenhx2/agent-security-audit/blob/main/security-audit/reference/tooling/scanners.md): the tool matrix and runner rules
- [`platforms.md`](https://github.com/nguyenhx2/agent-security-audit/blob/main/security-audit/reference/tooling/platforms.md): engines and native installs per OS
- [Re-scan and fix verification](rescan.md)
- [Troubleshooting and FAQ](troubleshooting.md)
