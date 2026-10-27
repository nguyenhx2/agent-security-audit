#!/usr/bin/env python3
"""Release-consistency gate. Run by CI on every push and before a tag is published.

Checks (all cheap, all deterministic):
  1. both editions (security-audit/, editions/ja/security-audit/) have SKILL.md with a
     `metadata.version`, and a CHANGELOG.md whose entries are `## [X.Y.Z] - YYYY-MM-DD`,
     newest-first, without duplicates
  2. each edition's newest CHANGELOG entry equals its SKILL.md metadata.version, and the two
     editions agree - they are one skill in two languages, released together; a Japanese edition
     one version behind is a release that tells Japanese users something different
  3. the generated plugin manifests (.claude-plugin/marketplace.json, security-audit/.claude-plugin/
     plugin.json) carry that version and the licence LICENSE.md actually states
  4. no em-dash (U+2014) and no CRLF in any text file the repo ships or publishes - the house style
     is a plain hyphen, and a CRLF file diffs on every line between the editions
  5. the vendored harness skill linter (eval/vendor/skill-check.py --published) passes on the
     English edition

With a version argument (the release gate), additionally:
  6. both editions' SKILL.md metadata.version == that version, and both CHANGELOGs' newest entry
     is that version - so a tag can never ship a stale skill or a placeholder body
  7. the repo-root CHANGELOG.md has a `## v<version>` section

Exit 0 = clean (prints one summary line). Exit 1 = problems (one per line).

    python scripts/validate_release.py            # structure + sync
    python scripts/validate_release.py 1.15.0     # plus: everything says 1.15.0
"""
from __future__ import annotations

import json
import pathlib
import re
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True

ROOT = pathlib.Path(__file__).resolve().parent.parent
SKILLS = ("security-audit",)
EDITIONS = (("en", ROOT / "security-audit"), ("ja", ROOT / "editions" / "ja" / "security-audit"))
LINTER = ROOT / "eval" / "vendor" / "skill-check.py"

sys.path.insert(0, str(ROOT / "scripts"))
from package import skill_md_version  # noqa: E402

ENTRY = re.compile(r"^##\s*\[(\d+\.\d+\.\d+)\]\s*-\s*(\d{4}-\d{2}-\d{2})\s*$", re.M)
# Any bracketed version heading, valid or not. The delta against ENTRY is a malformed heading
# (usually a bad date) that release_notes.py would still extract; caught here with a clear message.
LOOSE_ENTRY = re.compile(r"^##\s*\[(\d+\.\d+\.\d+)\][^\n]*$", re.M)

EM_DASH = chr(0x2014)  # spelled as a code point so this file passes its own check
TEXT_SUFFIX = {".py", ".md", ".json", ".yml", ".yaml", ".template", ".svg", ".txt", ".toml",
               ".ini", ".rdf", ".sql", ".cfg", ".html", ".js", ".ts", ".php", ".conf", ".xml",
               ".tf", ".gitattributes", ".gitignore"}
TEXT_NAMES = {"Dockerfile", ".gitattributes", ".gitignore", ".nvmrc", ".env", "LICENSE"}
SKIP_DIRS = {".git", "dist", "__pycache__", "node_modules"}
# Third-party clones and scratch output: not ours, not shipped.
SKIP_PREFIX = ("benchmark/fixtures/", "benchmark/runs/", "eval/results/tmp/")


def ver_tuple(v: str) -> tuple:
    return tuple(int(x) for x in v.split("."))


def changelog_problems(rel: str, text: str) -> tuple[list[str], list[str]]:
    """(problems, versions newest-first) for one skill CHANGELOG."""
    errs: list[str] = []
    strict = [v for v, _ in ENTRY.findall(text)]
    for v in LOOSE_ENTRY.findall(text):
        if v not in strict:
            errs.append(f"{rel}: heading for {v} is malformed - the form is '## [X.Y.Z] - YYYY-MM-DD'")
    seen: set[str] = set()
    for v in strict:
        if v in seen:
            errs.append(f"{rel}: duplicate entry for {v} - merge the two sections; release notes "
                        "would silently use only the first")
        seen.add(v)
    if not strict:
        errs.append(f"{rel}: no '## [X.Y.Z] - YYYY-MM-DD' entry found")
    elif [ver_tuple(v) for v in strict] != sorted((ver_tuple(v) for v in strict), reverse=True):
        errs.append(f"{rel}: entries are not newest-first")
    return errs, strict


def text_files() -> list[pathlib.Path]:
    out = []
    for p in ROOT.rglob("*"):
        rel = p.relative_to(ROOT)
        if not p.is_file() or SKIP_DIRS & set(rel.parts[:-1]) or rel.as_posix().startswith(SKIP_PREFIX):
            continue
        if p.suffix.lower() in TEXT_SUFFIX or p.name in TEXT_NAMES:
            out.append(p)
    return sorted(out)


def style_problems(paths: list[pathlib.Path]) -> list[str]:
    errs = []
    for p in paths:
        raw = p.read_bytes()
        rel = p.relative_to(ROOT).as_posix() if p.is_relative_to(ROOT) else p.name
        if b"\r\n" in raw:
            errs.append(f"{rel}: CRLF line endings - the repo is LF everywhere (.gitattributes)")
        text = raw.decode("utf-8", errors="replace")
        if EM_DASH in text:
            line = text[:text.index(EM_DASH)].count("\n") + 1
            errs.append(f"{rel}:{line}: em-dash - use a plain hyphen")
    return errs


def licence_id() -> str | None:
    lic = ROOT / "LICENSE.md"
    if not lic.is_file():
        return None
    head = lic.read_text(encoding="utf-8", errors="replace")[:400]
    return ("AGPL-3.0-only" if "GNU AFFERO GENERAL PUBLIC LICENSE" in head
            else "MIT" if "MIT License" in head else None)


def self_test() -> list[str]:
    """Every detector must fire on a mutant and stay quiet on a sound input."""
    dead = []
    good = "## [1.2.0] - 2026-01-02\n\nx\n\n## [1.1.0] - 2026-01-01\n"
    if changelog_problems("t", good)[0]:
        dead.append("a sound CHANGELOG is reported")
    for label, text in (("malformed heading", "## [1.2.0] 2026-01-02\n"),
                        ("duplicate", good + "## [1.1.0] - 2026-01-01\n"),
                        ("out of order", "## [1.1.0] - 2026-01-01\n## [1.2.0] - 2026-01-02\n")):
        if not changelog_problems("t", text)[0]:
            dead.append(f"CHANGELOG detector misses: {label}")
    with tempfile.TemporaryDirectory() as td:
        ok, crlf, dash = (pathlib.Path(td) / n for n in ("ok.md", "crlf.md", "dash.md"))
        ok.write_bytes(b"plain - hyphen\n")
        crlf.write_bytes(b"line\r\n")
        dash.write_bytes(("a " + EM_DASH + " b\n").encode("utf-8"))
        if style_problems([ok]):
            dead.append("a sound file is reported by the style check")
        if not style_problems([crlf]):
            dead.append("CRLF is not reported")
        if not style_problems([dash]):
            dead.append("an em-dash is not reported")
    return dead


def main() -> int:
    required = sys.argv[1].lstrip("vV") if len(sys.argv) > 1 else None
    if required and not re.fullmatch(r"\d+\.\d+\.\d+", required):
        print(f"usage error: '{sys.argv[1]}' is not a semver version (X.Y.Z)")
        return 1

    dead = self_test()
    if dead:
        print("DEAD CHECK - these detectors would pass anything:")
        for d in dead:
            print(f"  - {d}")
        return 1

    errs: list[str] = []
    skill_v: dict[str, str] = {}
    newest: dict[str, str] = {}
    for ed, base in EDITIONS:
        rel = base.relative_to(ROOT).as_posix()
        v = skill_md_version(base / "SKILL.md")
        if v is None:
            errs.append(f"{rel}/SKILL.md is missing or has no metadata.version")
        else:
            skill_v[ed] = v
        ch = base / "CHANGELOG.md"
        if not ch.is_file():
            errs.append(f"{rel}/CHANGELOG.md is missing")
            continue
        found, versions = changelog_problems(f"{rel}/CHANGELOG.md", ch.read_text(encoding="utf-8"))
        errs += found
        if versions:
            newest[ed] = versions[0]
            if v is not None and v != versions[0]:
                errs.append(f"{rel}: CHANGELOG newest entry is {versions[0]} but SKILL.md "
                            f"metadata.version is {v} - bump one to match the other")
            if required and versions[0] != required:
                errs.append(f"{rel}/CHANGELOG.md: newest entry is {versions[0]}, the release is "
                            f"{required} - add '## [{required}] - YYYY-MM-DD' at the top")
        if required and v is not None and v != required:
            errs.append(f"{rel}/SKILL.md metadata.version is {v}, the release is {required}")
        # The visible "Skill vX.Y.Z" line under the H1 is the third place the version lives; the
        # skill CHANGELOG's own rules say all three move together.
        if v is not None and (base / "SKILL.md").is_file():
            m = re.search(r"Skill v(\d+\.\d+\.\d+)", (base / "SKILL.md").read_text(encoding="utf-8"))
            if m and m.group(1) != v:
                errs.append(f"{rel}/SKILL.md says 'Skill v{m.group(1)}' in its body but "
                            f"metadata.version is {v}")

    if len(set(skill_v.values())) > 1:
        errs.append(f"editions disagree on SKILL.md metadata.version ({skill_v}) - they release together")
    if len(set(newest.values())) > 1:
        errs.append(f"editions disagree on the newest CHANGELOG entry ({newest})")

    if required:
        root_ch = ROOT / "CHANGELOG.md"
        if not root_ch.is_file():
            errs.append("CHANGELOG.md (repo root) is missing")
        elif not re.search(rf"^## v{re.escape(required)}\b", root_ch.read_text(encoding="utf-8"), re.M):
            errs.append(f"CHANGELOG.md (repo root) has no '## v{required}' section")

    # The plugin manifests are the place a `/plugin update` reads, and Claude Code prefers
    # plugin.json's version over the marketplace entry's. A release that bumps SKILL.md but not
    # these ships an update plugin users never receive.
    expected_v = required or (next(iter(skill_v.values())) if len(set(skill_v.values())) == 1 else None)
    lic = licence_id()
    if lic is None:
        errs.append("LICENSE.md does not name a licence this check knows - teach it the new one")
    mkt = ROOT / ".claude-plugin" / "marketplace.json"
    try:
        entries = json.loads(mkt.read_text(encoding="utf-8")).get("plugins", []) if mkt.is_file() else None
    except ValueError as e:
        entries = []
        errs.append(f".claude-plugin/marketplace.json does not parse: {e}")
    if entries is None:
        errs.append(".claude-plugin/marketplace.json is missing - run scripts/build_plugins.py")
    else:
        for e in entries:
            if expected_v and e.get("version") != expected_v:
                errs.append(f".claude-plugin/marketplace.json: `{e.get('name')}` is {e.get('version')}, "
                            f"expected {expected_v} - run scripts/build_plugins.py")
    for s in SKILLS:
        man = ROOT / s / ".claude-plugin" / "plugin.json"
        if not man.is_file():
            errs.append(f"{s}/.claude-plugin/plugin.json is missing - run scripts/build_plugins.py")
            continue
        try:
            body = json.loads(man.read_text(encoding="utf-8"))
        except ValueError as e:
            errs.append(f"{s}/.claude-plugin/plugin.json does not parse: {e}")
            continue
        if expected_v and body.get("version") != expected_v:
            errs.append(f"{s}/.claude-plugin/plugin.json is {body.get('version')}, expected "
                        f"{expected_v} - Claude Code reads this version first")
        if lic and body.get("license") != lic:
            errs.append(f"{s}/.claude-plugin/plugin.json says license {body.get('license')!r} but "
                        f"LICENSE.md is {lic}")

    errs += style_problems(text_files())

    # The harness skill linter: frontmatter limits, listing cap, when / not-when, references,
    # trigger cases. --published because the skill is invoked by its own description, not wired
    # into a harness. The Japanese edition is NOT linted: its description is Japanese, and the
    # linter's when / exclusion detectors match English phrasing only.
    if LINTER.is_file():
        r = subprocess.run([sys.executable, "-B", str(LINTER), "--published", "--skill",
                            str(ROOT / "security-audit")], capture_output=True, text=True,
                           encoding="utf-8", errors="replace")
        if r.returncode != 0:
            tail = [ln.strip() for ln in r.stdout.splitlines() if "FAIL" in ln or ln.strip().startswith("[")]
            errs.append("skill-check failed on security-audit: " + ("; ".join(tail[:6]) or r.stdout[-300:]))
    else:
        errs.append("eval/vendor/skill-check.py is missing - the skill linter cannot run")

    if errs:
        print(f"VALIDATION FAILED ({len(errs)} problem(s)):")
        for e in errs:
            print("  - " + e)
        return 1
    print(f"ok: 2 editions valid, version {expected_v}, plugin manifests in sync, "
          f"no em-dash or CRLF, skill-check clean")
    return 0


if __name__ == "__main__":
    sys.exit(main())
