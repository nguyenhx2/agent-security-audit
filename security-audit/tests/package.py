#!/usr/bin/env python3
"""
Build the release zip of the skill (development tool - this `tests/` folder is not shipped).

1. Runs tests/selftest.py (skip with --no-test); stops on failure.
2. Zips the skill folder as `security-audit/...` WITHOUT `tests/`, `__pycache__/`, `*.pyc`,
   OS junk, or editor folders, and checks the result (SKILL.md present, no excluded path inside).

Usage:
  python tests/package.py [--out <file.zip>] [--no-test]
Default output: <skills folder>/security-audit.zip (next to the other skill zips).
"""
from __future__ import annotations

import sys
sys.dont_write_bytecode = True

import argparse
import re
import subprocess
import zipfile
from pathlib import Path

SKILL = Path(__file__).resolve().parent.parent
EXCLUDE_DIRS = {"tests", "__pycache__", ".git", ".vscode", ".idea", ".pytest_cache"}
EXCLUDE_FILES = {".DS_Store", "Thumbs.db", "desktop.ini"}


def included(rel: Path) -> bool:
    return (not any(part in EXCLUDE_DIRS for part in rel.parts) and rel.name not in EXCLUDE_FILES
            and rel.suffix not in (".pyc", ".pyo", ".zip"))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default=str(SKILL.parent / f"{SKILL.name}.zip"))
    ap.add_argument("--no-test", action="store_true")
    a = ap.parse_args()
    if not a.no_test:
        r = subprocess.run([sys.executable, "-B", str(SKILL / "tests" / "selftest.py")], capture_output=True,
                           text=True, encoding="utf-8", errors="replace")
        print(r.stdout.strip().splitlines()[-1] if r.stdout.strip() else r.stderr[-500:])
        if r.returncode != 0:
            print("self-test failed - not packaging", file=sys.stderr)
            return 1
    files = sorted(p for p in SKILL.rglob("*") if p.is_file() and included(p.relative_to(SKILL)))
    out = Path(a.out)
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for p in files:
            z.write(p, (Path(SKILL.name) / p.relative_to(SKILL)).as_posix())
    names = zipfile.ZipFile(out).namelist()
    bad = [n for n in names if not included(Path(n).relative_to(SKILL.name))]
    ver = re.search(r'(?m)^\s+version:\s*"?([\d.]+)', (SKILL / "SKILL.md").read_text(encoding="utf-8"))
    if bad or f"{SKILL.name}/SKILL.md" not in names:
        print(f"error: bad package content: {bad[:5]}", file=sys.stderr)
        return 1
    print(f"wrote {out} - v{ver.group(1) if ver else '?'}, {len(names)} files, {out.stat().st_size // 1024} KB "
          f"(excluded: tests/, caches)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
