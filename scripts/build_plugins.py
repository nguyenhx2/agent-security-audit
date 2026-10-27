#!/usr/bin/env python3
"""Generate the Claude Code plugin manifests from the skill, so they cannot drift from it.

Two files, both generated, both committed:

    .claude-plugin/marketplace.json            the marketplace `/plugin marketplace add
                                               nguyenhx2/agent-security-audit` reads
    security-audit/.claude-plugin/plugin.json  the plugin manifest inside the skill folder

WHY THE SKILL FOLDER IS THE PLUGIN ROOT
---------------------------------------
Claude Code loads a folder with SKILL.md at its root as a single-skill plugin, so the marketplace
entry points straight at `./security-audit`. Claude Code does not strictly need plugin.json, but the
Claude plugin directory refuses a submission without it, and with it `/plugin update` is driven by
the manifest's version instead of only the marketplace entry's. Claude Code reads the manifest's
version FIRST, so a manifest that lags the release keeps plugin users on the old build silently.

WHY ONLY THE ENGLISH EDITION
----------------------------
The Japanese edition is the same skill (`name: security-audit`) with Japanese prose. Two plugins
with one name would collide on install, so the Japanese edition ships only as the release zip
`security-audit-ja-<ver>.zip`.

WHERE EACH FIELD COMES FROM
---------------------------
  version      `metadata.version` in security-audit/SKILL.md (the one place a release bumps)
  description  the FIRST SENTENCE of the SKILL.md description. The full description is a trigger
               carpet written for a model (~1000 characters); its first sentence is the reviewed
               one-line summary, and taking it from there means one wording, not two.
  license      the SPDX id of LICENSE.md (validate_release.py re-checks it against the file)

    python scripts/build_plugins.py            # write both files
    python scripts/build_plugins.py --check    # fail when the committed files differ (CI)
"""
from __future__ import annotations

import json
import pathlib
import re
import sys
import tempfile

sys.dont_write_bytecode = True

ROOT = pathlib.Path(__file__).resolve().parent.parent
SKILLS = ("security-audit",)
REPO = "agent-security-audit"
OWNER = "nguyenhx2"
REPO_URL = f"https://github.com/{OWNER}/{REPO}"
# SPDX id for LICENSE.md. A manifest that misstates the licence is the copy a user installs.
LICENSE_ID = "AGPL-3.0-only"
KEYWORDS = ["security", "audit", "owasp", "asvs", "pci-dss", "sast", "threat-intelligence",
            "compliance", "japan"]

sys.path.insert(0, str(ROOT / "scripts"))
from package import skill_md_version  # noqa: E402


def frontmatter_description(skill_md: pathlib.Path) -> str:
    """The folded `description: >-` block of SKILL.md, joined into one line."""
    text = skill_md.read_text(encoding="utf-8")
    fm = re.match(r"---\n(.*?)\n---", text, re.S)
    if not fm:
        sys.exit(f"{skill_md} has no frontmatter")
    m = re.search(r"^description:\s*>-?\s*\n((?:[ \t]+.*\n?)+)", fm.group(1) + "\n", re.M)
    if m:
        return " ".join(line.strip() for line in m.group(1).splitlines() if line.strip())
    m = re.search(r"^description:\s*[\"']?(.+?)[\"']?\s*$", fm.group(1), re.M)
    if not m:
        sys.exit(f"{skill_md} has no description")
    return m.group(1).strip()


def blurb(skill: str) -> str:
    """First sentence of the description: up to the first full stop followed by a space.

    "Read-only security audit of one or more repositories: evidence-anchored findings, Markdown,
    HTML and Excel reports." The colon inside it is why the split is on '. ', not on ':'.
    """
    desc = frontmatter_description(ROOT / skill / "SKILL.md")
    first = re.split(r"(?<=\.)\s", desc, maxsplit=1)[0]
    if len(first) > 200:
        sys.exit(f"{skill}: the first sentence of the description is {len(first)} characters; "
                 "a plugin browser needs a short one")
    return first


def version(skill: str) -> str:
    v = skill_md_version(ROOT / skill / "SKILL.md")
    if not v:
        sys.exit(f"{skill}/SKILL.md has no metadata.version")
    return v


def plugin_manifest(skill: str) -> dict:
    return {
        "name": skill,
        "version": version(skill),
        "description": blurb(skill),
        "author": {"name": OWNER, "url": f"https://github.com/{OWNER}"},
        "homepage": REPO_URL,
        "repository": REPO_URL,
        "license": LICENSE_ID,
        "keywords": KEYWORDS,
    }


def marketplace() -> dict:
    return {
        "name": REPO,
        "owner": {"name": OWNER},
        "description": "Claude Code plugin for the security-audit skill: read-only, evidence-anchored "
                       "security audits with live threat intelligence and industry standards.",
        "plugins": [
            {"name": s, "source": f"./{s}", "description": blurb(s), "version": version(s)}
            for s in SKILLS
        ],
    }


def dump(body: dict) -> str:
    return json.dumps(body, indent=2, ensure_ascii=False) + "\n"


def targets() -> dict[pathlib.Path, str]:
    out = {ROOT / ".claude-plugin" / "marketplace.json": dump(marketplace())}
    for s in SKILLS:
        out[ROOT / s / ".claude-plugin" / "plugin.json"] = dump(plugin_manifest(s))
    return out


def same(have: str, want: str) -> bool:
    """Content equality that ignores CRLF vs LF: a Windows checkout with core.autocrlf would
    otherwise turn this gate red on a contributor's machine and green in CI."""
    return have.replace("\r\n", "\n") == want.replace("\r\n", "\n")


def self_test() -> list[str]:
    """The drift comparison must report a real edit and must not report a newline-only change."""
    dead = []
    if not same("a\n", "a\r\n"):
        dead.append("a CRLF-only difference is reported as drift")
    if same('{"version": "1.0.0"}\n', '{"version": "1.0.1"}\n'):
        dead.append("a version change is not reported")
    with tempfile.TemporaryDirectory() as td:
        f = pathlib.Path(td) / "SKILL.md"
        f.write_text("---\nname: x\ndescription: >-\n  One thing: done well. Second sentence.\n"
                     "metadata:\n  version: \"2.0.0\"\n---\n", encoding="utf-8")
        if frontmatter_description(f) != "One thing: done well. Second sentence.":
            dead.append("the folded description is not read")
    return dead


def main() -> int:
    check = "--check" in sys.argv[1:]
    dead = self_test()
    if dead:
        print("  DEAD CHECK - the drift detector cannot report drift:")
        for d in dead:
            print(f"    {d}")
        return 1

    want = targets()
    if not check:
        for path, body in want.items():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(body, encoding="utf-8", newline="\n")
            print(f"  wrote {path.relative_to(ROOT).as_posix()}")
        return 0

    problems = []
    for path, body in want.items():
        rel = path.relative_to(ROOT).as_posix()
        if not path.is_file():
            problems.append(f"{rel} is missing")
        elif not same(path.read_text(encoding="utf-8"), body):
            problems.append(f"{rel} differs from what the skill implies")
    if problems:
        print("  FAIL  the plugin manifests do not match the skill:")
        for p in problems:
            print(f"    {p}")
        print("\n  Run `python scripts/build_plugins.py` and commit the result.")
        return 1
    print(f"  ok    plugin manifests match the skill ({len(want)} files, "
          f"v{version(SKILLS[0])})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
