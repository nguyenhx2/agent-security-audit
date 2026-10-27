#!/usr/bin/env python3
"""Package the skill into release artifacts.

Produces, under dist/:

    security-audit-<X.Y.Z>.zip       the English edition (the master)
    security-audit-ja-<X.Y.Z>.zip    the Japanese edition
    security-audit.zip               unversioned alias of the English zip
    security-audit-ja.zip            unversioned alias of the Japanese zip
    SHA256SUMS

The unversioned aliases exist because GitHub's permanent download URL
(/releases/latest/download/<NAME>) needs an exact filename and cannot carry a version.

Both editions are the SAME skill (`name: security-audit`, identical code, prose in a different
language), so both archives have the same root folder, `security-audit/`. A user installs one or
the other into ~/.claude/skills/, never both: installing is an unzip, and the second one replaces
the first. That is also why only the English edition is a marketplace entry.

Every archive carries a VERSION file inside `security-audit/`, so a skill on disk can be traced
back to the release it came from, plus LICENSE.md and NOTICE.md, because the zip is the copy a user
actually receives and the AGPL travels with the code.

Excluded from both archives: `tests/` (selftest.py and the old per-skill packager are development
tools, not part of an installed skill), `__pycache__/`, `*.pyc`, OS and editor junk. The English
edition's `.claude-plugin/` (plugin.json, icon.png) IS shipped, following the harness repo: it is
harmless in ~/.claude/skills/ and makes the unzipped folder a complete plugin.

Usage:
    python scripts/package.py --version 1.15.0
    python scripts/package.py --version 1.15.0 --check   # preflight only, write nothing
"""

from __future__ import annotations

import argparse
import hashlib
import pathlib
import re
import shutil
import sys
import zipfile

sys.dont_write_bytecode = True

ROOT = pathlib.Path(__file__).resolve().parent.parent
SKILLS = ("security-audit",)
# (archive stem, source folder). The folder inside every archive is the skill name.
EDITIONS = (("security-audit", ROOT / "security-audit"),
            ("security-audit-ja", ROOT / "editions" / "ja" / "security-audit"))
SKILL = SKILLS[0]
DIST = ROOT / "dist"

SEMVER = re.compile(r"^\d+\.\d+\.\d+$")
ENTRY = re.compile(r"^##\s*\[(\d+\.\d+\.\d+)\]\s*-\s*\d{4}-\d{2}-\d{2}\s*$", re.M)

EXCLUDE_DIRS = {"tests", "__pycache__", ".git", ".pytest_cache", "node_modules", ".vscode", ".idea"}
EXCLUDE_NAMES = {".DS_Store", "Thumbs.db", "desktop.ini"}
EXCLUDE_SUFFIX = {".pyc", ".pyo", ".zip"}


def skill_md_version(path: pathlib.Path) -> str | None:
    """`metadata.version` from SKILL.md frontmatter.

    The version lives under `metadata:` (the Agent Skills spec keeps the top level for a closed
    set of keys), so a top-level `^version:` search - what the harness repo uses - finds nothing
    here. The frontmatter is read, then the indented `version:` under `metadata:`.
    """
    if not path.is_file():
        return None
    text = path.read_text(encoding="utf-8")
    m = re.match(r"---\n(.*?)\n---", text, re.S)
    if not m:
        return None
    meta = re.search(r"^metadata:\s*\n((?:[ \t]+.*\n?)+)", m.group(1) + "\n", re.M)
    if not meta:
        return None
    v = re.search(r"^[ \t]+version:\s*[\"']?([^\"'\s]+)[\"']?\s*$", meta.group(1), re.M)
    return v.group(1).lstrip("vV") if v else None


def wanted(rel: pathlib.Path) -> bool:
    if any(part in EXCLUDE_DIRS for part in rel.parts):
        return False
    return rel.name not in EXCLUDE_NAMES and rel.suffix not in EXCLUDE_SUFFIX


def edition_files(src: pathlib.Path) -> list[pathlib.Path]:
    return sorted(p for p in src.rglob("*") if p.is_file() and wanted(p.relative_to(src)))


def preflight(version: str) -> list[str]:
    problems: list[str] = []
    if not SEMVER.match(version):
        problems.append(f"version '{version}' is not semver (X.Y.Z)")

    for stem, src in EDITIONS:
        rel = src.relative_to(ROOT).as_posix()
        # The version must be bumped inside the skill file itself, not only in the VERSION file
        # the packager injects: a skill installed on its own then carries its release number in
        # its frontmatter, and a forgotten bump fails the release instead of shipping stale.
        v = skill_md_version(src / "SKILL.md")
        if v is None:
            problems.append(f"{rel}/SKILL.md has no metadata.version in its frontmatter")
        elif v != version:
            problems.append(f"{rel}/SKILL.md metadata.version '{v}' != release '{version}' - bump it")
        ch = src / "CHANGELOG.md"
        if not ch.is_file():
            problems.append(f"{rel}/CHANGELOG.md is missing")
        elif version not in ENTRY.findall(ch.read_text(encoding="utf-8")):
            problems.append(f"{rel}/CHANGELOG.md has no '## [{version}] - YYYY-MM-DD' section")
        if not edition_files(src):
            problems.append(f"{rel} has no files")

    ch = ROOT / "CHANGELOG.md"
    if not ch.is_file():
        problems.append("CHANGELOG.md is missing")
    elif not re.search(rf"^## v{re.escape(version)}\b", ch.read_text(encoding="utf-8"), re.M):
        problems.append(f"CHANGELOG.md has no '## v{version}' section")
    for f in ("LICENSE.md", "NOTICE.md"):
        if not (ROOT / f).is_file():
            problems.append(f"{f} is missing - it ships inside every archive")
    return problems


def add_edition(zf: zipfile.ZipFile, src: pathlib.Path, version: str) -> None:
    """Everything sits under `security-audit/`. These archives extract straight into
    ~/.claude/skills/, so a file at the archive root would land loose in the user's skills folder."""
    for f in edition_files(src):
        zf.write(f, f"{SKILL}/{f.relative_to(src).as_posix()}")
    zf.writestr(f"{SKILL}/VERSION", f"{version}\n")
    zf.write(ROOT / "LICENSE.md", f"{SKILL}/LICENSE.md")
    zf.write(ROOT / "NOTICE.md", f"{SKILL}/NOTICE.md")


def build(version: str) -> list[pathlib.Path]:
    if DIST.exists():
        shutil.rmtree(DIST)
    DIST.mkdir(parents=True)

    written: list[pathlib.Path] = []
    for stem, src in EDITIONS:
        out = DIST / f"{stem}-{version}.zip"
        with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
            add_edition(zf, src, version)
        written.append(out)
        alias = DIST / f"{stem}.zip"
        shutil.copyfile(out, alias)
        written.append(alias)

    sums = DIST / "SHA256SUMS"
    sums.write_text("".join(f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n"
                            for p in written), encoding="utf-8", newline="\n")
    written.append(sums)
    return written


def verify_zip(p: pathlib.Path, version: str) -> list[str]:
    """Checked rather than trusted: nothing at the archive root, no directory but `security-audit/`,
    a correct VERSION, a SKILL.md, and none of the excluded paths inside."""
    bad: list[str] = []
    with zipfile.ZipFile(p) as zf:
        names = zf.namelist()
        loose = sorted(n for n in names if "/" not in n.rstrip("/"))
        stray = sorted({n.split("/", 1)[0] for n in names} - {SKILL})
        if loose or stray:
            bad.append(f"{p.name}: loose at root={loose} unexpected dirs={stray}")
        stamp = zf.read(f"{SKILL}/VERSION").decode().strip() if f"{SKILL}/VERSION" in names else None
        if stamp != version:
            bad.append(f"{p.name}: VERSION {stamp!r} != {version}")
        if f"{SKILL}/SKILL.md" not in names:
            bad.append(f"{p.name}: no {SKILL}/SKILL.md")
        leaked = [n for n in names if not wanted(pathlib.PurePosixPath(n.split("/", 1)[-1]))]
        if leaked:
            bad.append(f"{p.name}: excluded paths inside: {leaked[:5]}")
    return bad


def self_test() -> list[str]:
    """Prove the archive verifier can fail before it passes the real archives. A verifier that
    returns nothing looks exactly like a clean build."""
    import tempfile
    dead: list[str] = []
    with tempfile.TemporaryDirectory() as td:
        def mk(name: str, entries: dict) -> pathlib.Path:
            z = pathlib.Path(td) / name
            with zipfile.ZipFile(z, "w") as zf:
                for k, v in entries.items():
                    zf.writestr(k, v)
            return z
        good = {f"{SKILL}/SKILL.md": "x", f"{SKILL}/VERSION": "1.0.0\n"}
        if verify_zip(mk("good.zip", good), "1.0.0"):
            dead.append("a sound archive is reported as broken")
        for label, entries in (("loose root file", {**good, "README.md": "x"}),
                               ("wrong VERSION", {**good, f"{SKILL}/VERSION": "0.9.0\n"}),
                               ("tests/ shipped", {**good, f"{SKILL}/tests/selftest.py": "x"}),
                               ("pyc shipped", {**good, f"{SKILL}/scripts/a.pyc": "x"}),
                               ("stray top dir", {**good, "other/x.md": "x"})):
            if not verify_zip(mk("bad.zip", entries), "1.0.0"):
                dead.append(f"verifier does not catch: {label}")
    for text, want in (("---\nname: x\nmetadata:\n  version: \"1.2.3\"\n---\n", "1.2.3"),
                       ("---\nname: x\nversion: 1.2.3\n---\n", None)):
        with tempfile.TemporaryDirectory() as td:
            f = pathlib.Path(td) / "SKILL.md"
            f.write_text(text, encoding="utf-8")
            if skill_md_version(f) != want:
                dead.append(f"metadata.version reader returned {skill_md_version(f)!r}, want {want!r}")
    return dead


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--version", required=True, help="semver, e.g. 1.15.0 (no leading v)")
    ap.add_argument("--check", action="store_true", help="preflight only, write nothing")
    a = ap.parse_args()
    version = a.version.lstrip("vV")

    dead = self_test()
    if dead:
        print("DEAD CHECK - the archive verifier cannot fail:", file=sys.stderr)
        for d in dead:
            print(f"  - {d}", file=sys.stderr)
        return 1

    problems = preflight(version)
    if problems:
        print("preflight FAILED:", file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        return 1
    print(f"preflight ok for {version} (both editions, CHANGELOGs, root CHANGELOG)")
    if a.check:
        return 0

    written = build(version)
    print(f"\nwrote {len(written)} files to dist/:")
    for p in written:
        print(f"  {p.name:<34} {p.stat().st_size:>9,} bytes")

    print("\nverifying:")
    bad: list[str] = []
    for p in written:
        if p.suffix == ".zip":
            found = verify_zip(p, version)
            bad += found
            with zipfile.ZipFile(p) as zf:
                n = len(zf.namelist())
            print(f"  {'FAIL' if found else 'ok  '}  {p.name:<34} {n} files, VERSION {version}")
    if bad:
        for b in bad:
            print(f"  - {b}", file=sys.stderr)
        print("\npackaging failed its own checks. Nothing here is safe to release.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
