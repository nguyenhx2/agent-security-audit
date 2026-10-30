# Releasing

**English** · [日本語](RELEASING.ja.md)

The skill ships in two editions, English (`security-audit/`, the master) and Japanese
(`editions/ja/security-audit/`), released together under one version and one tag, `vX.Y.Z`. The
release is CHANGELOG-driven: the GitHub release body is generated from the skill CHANGELOG by
`scripts/release_notes.py`, never typed by hand.

```mermaid
flowchart TD
    subgraph LOCAL["On your machine"]
        direction LR
        B["Bump version<br/>both editions"] --> C["Write CHANGELOGs"]
        C --> P["Rebuild plugin<br/>manifests"]
        P --> V{"Gates<br/>green?"}
        V -->|"no"| C
    end
    subgraph CI["CI, on the tag"]
        direction LR
        G["Re-run gates"] --> Z["Build both zips"]
        Z --> N["Write notes"]
        N --> R(["Publish"])
    end
    LOCAL -->|"push tag"| CI
```

## Version numbers

Versions are `1.y.z`; the major number stays 1. The rules are at the top of
[`security-audit/CHANGELOG.md`](../security-audit/CHANGELOG.md):

| Part | Bump when | Examples |
|---|---|---|
| `y` | A new capability, output format or workflow change that users notice | a new report format, a new language, a new standards module |
| `z` | Fixes, refinements, wording, standards or scanner data updates, new checks inside an existing capability | a redaction fix, a new sweep pattern, re-verified standard versions |

Reset `z` to 0 when `y` increases. The repository version is the skill version: tag `v1.15.0`
releases skill 1.15.0.

## Where the version lives

| File | Why it matters | Checked by |
|---|---|---|
| `security-audit/SKILL.md` (`metadata.version`, and the "Skill vX.Y.Z" line under the title) | An installed skill identifies itself | `validate_release.py`, `package.py --check` |
| `editions/ja/security-audit/SKILL.md` (same two places) | The Japanese edition is the same release | `validate_release.py`, `check_editions.py` |
| `security-audit/CHANGELOG.md`, `editions/ja/security-audit/CHANGELOG.md` (`## [X.Y.Z] - YYYY-MM-DD` at the top) | The release body is generated from it | `validate_release.py X.Y.Z` |
| `CHANGELOG.md` (repo root, `## vX.Y.Z`) | The narrative of what the repository release contains | `validate_release.py X.Y.Z`, `package.py --check` |
| `.claude-plugin/marketplace.json`, `security-audit/.claude-plugin/plugin.json` (generated) | `/plugin update` reads these; Claude Code prefers plugin.json's version | `build_plugins.py --check`, `validate_release.py` |
| `eval/results/latest.json` (generated), `docs/numbers.json` (generated) | Figures the README quotes | `check_numbers.py`, CI's freshness check |

When standards or scanner pins are re-verified, the skill CHANGELOG's rules also apply:
`metadata.standards-verified` / `scanner-pins-verified`, the table in
`reference/standards/index.md` and `PINS_VERIFIED` in `scripts/run_scanners.py`, in both editions.
Scanner pins usually arrive through the weekly pull request described in
[Scanner pin updates](#scanner-pin-updates).

## Procedure

1. **Bump the version** in both `SKILL.md` files (`metadata.version`, `metadata.updated` and the
   "Skill v..." line).
2. **Write the CHANGELOG entries.** `## [X.Y.Z] - YYYY-MM-DD` at the top of both skill CHANGELOGs
   (Keep a Changelog, newest first; Added / Changed / Fixed / Removed, omitting empty ones), the
   Japanese one in Japanese with the same content. Then a `## vX.Y.Z` section in the root
   `CHANGELOG.md`. Write for the person on the release page: what changed and why it matters to
   them. A Fixed entry names the failure mode, not the patch. No em-dashes.
3. **Regenerate the generated files:**

   ```bash
   python scripts/build_plugins.py
   python eval/run_eval.py
   python scripts/check_numbers.py --write
   ```

4. **Run the gates.** All must pass:

   ```bash
   python scripts/validate_release.py X.Y.Z
   python scripts/package.py --version X.Y.Z --check
   python scripts/check_editions.py
   python scripts/build_plugins.py --check
   python scripts/check_numbers.py
   python scripts/check_mermaid.py
   python scripts/check_svg.py
   python scripts/release_notes.py X.Y.Z
   ```

   `python scripts/package.py --version X.Y.Z` builds the zips into `dist/` locally if you want to
   inspect them; CI builds its own.
5. **Rehearse (optional).** Run the `release` workflow by hand (workflow_dispatch) with the version:
   it runs every gate and builds every artifact, and publishes nothing.
6. **Tag and push.**

   ```bash
   git tag -a vX.Y.Z -m "vX.Y.Z"
   git push origin vX.Y.Z
   ```

7. **CI publishes.** The `release` workflow re-runs the gates (validate_release, package preflight,
   plugin manifests and icon, the full offline eval, check_numbers), builds both zips, generates the
   body with `release_notes.py`, and publishes with these assets: `security-audit-X.Y.Z.zip`,
   `security-audit-ja-X.Y.Z.zip`, their unversioned aliases, `SHA256SUMS`, `eval-results.json` and
   `.md`, and `benchmark-results.md` / `.json` when `benchmark/RESULTS.md` and
   `benchmark/results/results.json` exist at the tag.
8. **Check what was published:** `gh release view vX.Y.Z --json assets -q '.assets[].name'`.

The live benchmark (`benchmark/bench.py`) is not part of the release gates: it costs money and
needs Claude. Re-run it when a change could move cost or recall, and commit its results before the
tag.

## Scanner pin updates

The skill runs eight scanner images, each pinned by tag and digest. An audit never changes a scanner
on its own: the digest stays fixed, so the Phase 8 re-scan that verifies a fix runs exactly the
rules of the first scan, and two audits of the same code on different days agree. Pins move only
through this repository, in a pull request a maintainer reviews.

The `update-pins` workflow (`.github/workflows/update-pins.yml`) prepares that pull request every
Monday:

1. **Check.** `scripts/update_pins.py --check` asks each registry for a newer tag. A tag is proposed
   only once it has been public for 7 days (the cooldown). A compromised image pushed to a registry is
   usually noticed and pulled within days; the cooldown keeps this repository out of that window. A
   failed registry lookup fails the run, so an outage never reads as "everything is current".
2. **Smoke test.** `scripts/smoke_scanners.py` runs every candidate image, with docker, on a fixture
   with a planted defect for that scanner. A new version that no longer finds its defect, or crashes,
   stops the run: the pin only moves when detection still works.
3. **Write and gate.** `update_pins.py --write` updates the pins in both editions, then both
   selftests, the offline eval, `check_editions.py`, `build_plugins.py --check`, `check_numbers.py`
   and `validate_release.py` run on the result.
4. **Pull request.** The change is force-pushed to the branch `bot/scanner-pins` and opened as one
   pull request labelled `scanner-pins`, or the open one is updated. The title lists each move
   (`scanner pins: trivy 0.76.1 -> 0.77.0, ...`); the body has the release notes links, a draft
   CHANGELOG entry and the smoke test table. It is **never merged automatically**.

A pull request opened with `GITHUB_TOKEN` does not start other workflows, so the gates above run
inside `update-pins` itself, and it then dispatches `ci.yml` on `bot/scanner-pins` for the full
operating system matrix. If that CI run is missing from the pull request, start it by hand:
`gh workflow run ci.yml --ref bot/scanner-pins`.

**Run it by hand.** Start the workflow from the Actions tab or with
`gh workflow run update-pins.yml -f cooldown_days=7 -f tools="trivy semgrep"` (both inputs optional;
an empty `tools` means all eight). Run from any branch other than the default one it is a dry run:
everything up to the patch, no branch pushed, no pull request. Locally, without the workflow:

```bash
python scripts/update_pins.py --check --json pins.json --pr-body body.md
python scripts/smoke_scanners.py --pins-json pins.json   # needs docker or podman
python scripts/update_pins.py --write
```

`--check` exits 0 when nothing is new, 10 when updates are available and 2 when a lookup failed.

**Release the result.** A pin update is a `z` release. Review and merge the pull request, then follow
the [procedure](#procedure): bump the version, and write the CHANGELOG entries in both editions and
the root, starting from the draft in the pull request body. The merged pins reach users only with
that release.

## What enforces this

| Rule | Enforced by |
|---|---|
| Both editions' `metadata.version` and newest CHANGELOG entry equal the tag | `validate_release.py X.Y.Z` (release gate) |
| The editions agree with each other and with the plugin manifests, on every push | `validate_release.py`, `build_plugins.py --check` (`ci.yml`) |
| The Japanese edition is the same code | `check_editions.py` (`ci.yml`, and inside `run_eval.py`) |
| The root `CHANGELOG.md` has a `## vX.Y.Z` section | `package.py --check`, `validate_release.py X.Y.Z` |
| Every archive has only `security-audit/` at its root, a correct `VERSION`, no `tests/` | `package.py` verifies what it built |
| The release body comes from the CHANGELOG | `release_notes.py`; exits non-zero when either edition lacks the entry |
| No em-dash, no CRLF | `validate_release.py` |
| The README figures match the code and the eval of this commit | `check_numbers.py` after `run_eval.py` |
| A re-run does not fail on an existing release | `gh release edit` and `gh release upload --clobber` |
| A scanner pin moves only after the cooldown, a passing smoke test and the gates, through a reviewed pull request | `update-pins.yml` (`update_pins.py`, `smoke_scanners.py`) |

## Withdrawing a release

```bash
gh release delete vX.Y.Z --yes --cleanup-tag
```

Then record it, with the reason, under **Removed** in both skill CHANGELOGs.
