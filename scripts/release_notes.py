#!/usr/bin/env python3
"""Assemble the GitHub release body for a version from the skill's CHANGELOG.

The skill's own CHANGELOG.md (security-audit/CHANGELOG.md, the English master) is the single source
of truth for what changed - not a hand-written release description. This extracts its
`## [X.Y.Z] - YYYY-MM-DD` section, demotes its Added / Changed / Fixed headings one level (so they
read as children of the skill heading instead of siblings of it), and wraps it in a short header:

    - install lines for both archives (English and Japanese edition)
    - where the evidence is: the offline eval result attached to the release, and the live
      benchmark write-up in benchmark/RESULTS.md at the tag
    - one line on the Japanese edition, whose CHANGELOG carries the same entry in Japanese

The Japanese CHANGELOG must have the same version entry (validate_release.py enforces that), so the
note can say so truthfully; this script refuses to write a body when either entry is missing,
because publishing a placeholder body is exactly the failure a generated body replaces.

    python scripts/release_notes.py 1.15.0            # -> stdout
    python scripts/release_notes.py 1.15.0 -o notes.md
"""
from __future__ import annotations

import argparse
import pathlib
import re
import sys

sys.dont_write_bytecode = True

ROOT = pathlib.Path(__file__).resolve().parent.parent
SKILL = "security-audit"
EN = ROOT / SKILL / "CHANGELOG.md"
JA = ROOT / "editions" / "ja" / SKILL / "CHANGELOG.md"
REPO_URL = "https://github.com/nguyenhx2/agent-security-audit"


def section(changelog: pathlib.Path, version: str) -> str | None:
    """The body of a `## [version] - DATE` entry, or None if the file or the entry is missing."""
    if not changelog.is_file():
        return None
    text = changelog.read_text(encoding="utf-8")
    pat = re.compile(rf"^##\s*\[{re.escape(version)}\][^\n]*\n(.*?)(?=^##\s|\Z)", re.M | re.S)
    m = pat.search(text)
    return m.group(1).strip() if m else None


def build(version: str) -> str | None:
    body = section(EN, version)
    if body is None or section(JA, version) is None:
        return None
    # The skill name is an H3 below, so its ### Added / ### Changed must drop to H4.
    body = re.sub(r"^###\s", "#### ", body, flags=re.M)
    tag = f"v{version}"
    header = "\n".join([
        f"`security-audit` {version}: read-only, evidence-anchored security audits for Claude Code, "
        "in English and Japanese.",
        "",
        "**Install** (one edition; both unzip to `security-audit/`, the second replaces the first)",
        "",
        f"- English: `unzip security-audit-{version}.zip -d ~/.claude/skills/`",
        f"- Japanese: `unzip security-audit-ja-{version}.zip -d ~/.claude/skills/`",
        "- Plugin (English): `/plugin marketplace add nguyenhx2/agent-security-audit`, then "
        "`/plugin install security-audit@agent-security-audit`",
        "- Verify the download with `sha256sum -c SHA256SUMS`",
        "",
        "**Evidence**",
        "",
        "- `eval-results.json` / `eval-results.md` (attached): the offline eval of this exact commit - "
        "selftest of both editions, edition parity, skill linter, detection precision and recall, "
        "threat intel against offline feeds.",
        f"- [`benchmark/RESULTS.md`]({REPO_URL}/blob/{tag}/benchmark/RESULTS.md): the live benchmark "
        "(real audits of pinned public fixtures, cost, time and recall against a fixed ground truth).",
    ])
    ja_note = ("The Japanese edition (`security-audit-ja`) has identical code and the same entry, in "
               "Japanese, in [`editions/ja/security-audit/CHANGELOG.md`]"
               f"({REPO_URL}/blob/{tag}/editions/ja/security-audit/CHANGELOG.md).")
    return f"{header}\n\n---\n\n### `{SKILL}`\n\n{body}\n\n---\n\n{ja_note}"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("version", help="semver, with or without a leading v")
    ap.add_argument("-o", "--out", help="write the notes to this file instead of stdout")
    a = ap.parse_args()

    version = a.version.lstrip("vV")
    notes = build(version)
    if notes is None:
        print(f"ERROR: no '## [{version}] - YYYY-MM-DD' entry in {EN.relative_to(ROOT).as_posix()} "
              f"and {JA.relative_to(ROOT).as_posix()} - add both before releasing.", file=sys.stderr)
        return 1

    if a.out:
        pathlib.Path(a.out).write_text(notes + "\n", encoding="utf-8", newline="\n")
        print(f"notes -> {a.out}")
    else:
        # Windows consoles default to a non-UTF-8 code page; the CHANGELOG carries Japanese text.
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stdout.write(notes + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
