#!/usr/bin/env python3
"""Clean up <audit_dir>/work/ after the report set is finished (Phase 7, last step).

Default: delete only intermediates nothing reads after the run, and keep what a report rebuild
(`build_report.py --force --fill`), a later translation, and a Phase 8 re-scan still need.

  deleted  <repo>/raw/  packs/  scratch/  candidates.jsonl  findings.draft.json  digest.md  digest.json
           routes.md  routes.json  recon.md  summary.md  agent-config.md  platform.md  lanes/*.md (lane
           notes); work/intel.md (build_report reads none of them)
  kept     profile.md  findings.json  findings_<L>.json  narrative*.json  report-settings.json
           <repo>/scanners.json (image pins for Phase 8)  sweep.json  agent-config.json  platform.json  vex.json
           intel.json (report section 2, validate_findings)
           lanes/candidates.md  lanes/verifier.md (why each candidate was kept or refuted)
  Unknown files are never touched.

  --keep-work    keep everything (investigation, skill debugging)
  --purge-work   delete the whole work/ folder - reports can no longer be rebuilt or translated,
                 and Phase 8 becomes a full re-audit

Refuses to run unless <audit_dir> holds reports/md/*.md (the run is finished).
Files it cannot delete (root-owned scanner output on Linux, read-only or locked files on Windows) are
skipped and listed with the exact fix command for this OS; exit 1 in that case.

Usage:
  python prune_work.py <audit_dir> [--keep-work | --purge-work] [--dry-run]
"""
from __future__ import annotations

import sys
sys.dont_write_bytecode = True  # keep the installed skill free of __pycache__
for _s in (sys.stdout, sys.stderr):  # UTF-8 output even on cp932 / cp1252 consoles and pipes
    if hasattr(_s, "reconfigure"):
        _s.reconfigure(encoding="utf-8", errors="replace")

import argparse
import os
import shutil
import stat
from pathlib import Path

REPO_FILES = ("candidates.jsonl", "findings.draft.json", "digest.md", "digest.json", "routes.md",
              "routes.json", "recon.md", "summary.md", "agent-config.md", "platform.md")
REPO_DIRS = ("raw", "packs", "scratch")
LANES_KEEP = ("candidates.md", "verifier.md")


def size(p: Path) -> int:
    try:
        if p.is_file():
            return p.stat().st_size
        return sum(f.stat().st_size for f in p.rglob("*") if f.is_file())
    except OSError:  # unreadable (foreign-owned) subfolder: size is informative only
        return 0


def remove(p: Path, failed: list) -> None:
    """Delete a file or tree; whatever cannot be deleted is appended to `failed`, the rest still goes."""
    if p.is_dir() and not p.is_symlink():
        try:
            children = list(p.iterdir())
        except OSError:
            failed.append(p)
            return
        for c in children:
            remove(c, failed)
        try:
            p.rmdir()
        except OSError:
            if not any(f == p or p in f.parents for f in failed):
                failed.append(p)
        return
    try:
        p.unlink()
    except OSError:
        try:  # Windows read-only attribute (git objects, copied files)
            os.chmod(p, stat.S_IWRITE)
            p.unlink()
        except OSError:
            failed.append(p)


def fix_hint(work: Path) -> str:
    """Exact command for this OS to make the leftovers deletable."""
    if os.name == "nt":
        return (f'close programs using files in "{work}" (editor, Excel, a running scanner), then run: '
                f'attrib -R "{work}\\*" /S /D  - or, if access is denied: icacls "{work}" /grant '
                f'"{os.environ.get("USERNAME", "%USERNAME%")}":F /T')
    ug = f"{os.getuid()}:{os.getgid()}"
    lines = [f"sudo chown -R {ug} '{work}'"]
    try:
        from run_scanners import IMAGES  # an already-pinned image; no new pull for the one-shot chown
        eng = shutil.which("docker") and "docker" or shutil.which("podman") and "podman"
        if eng:
            lines.insert(0, f"{eng} run --rm --user 0:0 --network none --security-opt label=disable "
                            f"-v '{work}:/fix' --entrypoint chown {IMAGES['gitleaks']} -R {ug} /fix")
    except Exception:  # noqa: BLE001 - the sudo line is always printed
        pass
    return "\n  or: ".join(lines)


def targets(work: Path) -> list[Path]:
    out: list[Path] = []
    for repo in sorted(p for p in work.iterdir() if p.is_dir()):
        if not ((repo / "scanners.json").exists() or (repo / "sweep.json").exists()):
            continue  # not a repo work folder written by this skill
        out += [repo / d for d in REPO_DIRS if (repo / d).is_dir()]
        out += [repo / n for n in REPO_FILES if (repo / n).is_file()]
        lanes = repo / "lanes"
        if lanes.is_dir():
            out += sorted(f for f in lanes.glob("*.md") if f.name not in LANES_KEEP)
    if (work / "intel.md").is_file() and any((d / "scanners.json").exists() or (d / "sweep.json").exists()
                                             for d in work.iterdir() if d.is_dir()):
        out.append(work / "intel.md")
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("audit_dir")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--keep-work", action="store_true", help="keep everything")
    g.add_argument("--purge-work", action="store_true", help="delete the whole work/ folder")
    ap.add_argument("--dry-run", action="store_true", help="list what would be deleted")
    a = ap.parse_args()

    root = Path(a.audit_dir).resolve()
    work = root / "work"
    if not work.is_dir():
        print(f"error: {work} not found (legacy flat layout or already purged) - nothing done", file=sys.stderr)
        return 2
    if not any((root / "reports" / "md").glob("*.md")):
        print(f"error: no report in {root / 'reports' / 'md'} - finish Phase 7 before cleaning up", file=sys.stderr)
        return 2
    if a.keep_work:
        print(f"work/ kept as is ({size(work) / 1e6:.1f} MB)")
        return 0

    todo = [work] if a.purge_work else targets(work)
    freed = sum(size(p) for p in todo)
    failed: list[Path] = []
    for p in todo:
        rel = p.relative_to(root).as_posix() + ("/" if p.is_dir() else "")
        if a.dry_run:
            print(f"would delete {rel}")
            continue
        remove(p, failed)
    if failed:
        print(f"error: {len(failed)} item(s) could not be deleted (permission denied / in use):", file=sys.stderr)
        for f in failed[:15]:
            print(f"  {f.relative_to(root).as_posix() if root in f.parents else f}", file=sys.stderr)
        if len(failed) > 15:
            print(f"  ... and {len(failed) - 15} more", file=sys.stderr)
        print(f"fix (then re-run prune_work.py):\n  {fix_hint(work)}", file=sys.stderr)
        return 1
    verb = "would free" if a.dry_run else "freed"
    if a.purge_work:
        print(f"work/ {'would be ' if a.dry_run else ''}deleted - {verb} {freed / 1e6:.1f} MB. Reports can no longer "
              f"be rebuilt or translated; a re-scan needs a new audit.")
    else:
        left = size(work) if work.exists() else 0
        print(f"pruned {len(todo)} intermediate item(s) - {verb} {freed / 1e6:.1f} MB; work/ keeps "
              f"{(left - (freed if a.dry_run else 0)) / 1e6:.1f} MB for rebuilds, translation and re-scan")
    return 0


if __name__ == "__main__":
    sys.exit(main())
