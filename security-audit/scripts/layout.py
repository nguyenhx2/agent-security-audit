"""Audit folder layout shared by the report scripts.

    <audit_dir>/
      reports/md|html|xlsx/   security-audit-report_<project>_<ts>[_<lang>].<ext>   (deliverables)
      findings/<lang>/<repo>/find-<repo>-NNN.md                                   (one file per finding)
      work/                   profile.md, findings.json, narrative*.json, report-settings.json,
                              <repo>/ (scanners.json, raw/, sweep.json, digest.md, lanes/ ...)
                              (prune_work.py removes the intermediates after the run)

A folder without `work/` is read in the legacy flat layout (everything at the top level).
"""
from __future__ import annotations

import sys
sys.dont_write_bytecode = True  # keep the installed skill free of __pycache__

import re
from pathlib import Path


def work_dir(root: Path) -> Path:
    return root / "work" if (root / "work").is_dir() else root


def is_new(root: Path) -> bool:
    return (root / "work").is_dir()


def root_of_report(report: Path) -> Path:
    p = report.resolve().parent
    return p.parent.parent if p.name == "md" and p.parent.name == "reports" else p


def findings_dir(root: Path, lang: str) -> Path:
    """findings/<lang> (new), findings-<lang> or findings (legacy). The root findings/ is used only when it
    holds no per-language subfolders - otherwise it would mix the languages."""
    per_lang = (root / "findings").is_dir() and any(d.is_dir() and re.fullmatch(r"[a-z]{2}(?:-[A-Za-z]{2,4})?", d.name)
                                                    for d in (root / "findings").iterdir())  # ISO 639-1 codes
    for c in (root / "findings" / lang, root / f"findings-{lang}", root / "findings"):
        if c == root / "findings" and per_lang:
            continue
        if c.is_dir() and any(c.rglob("*.md")):
            return c
    return root / "findings" / lang if is_new(root) or per_lang else root / "findings"


def report_out(root: Path, name: str) -> Path:
    if is_new(root):
        (root / "reports" / "md").mkdir(parents=True, exist_ok=True)
        return root / "reports" / "md" / name
    return root / name


def format_out(report: Path, ext: str) -> Path:
    """reports/md/x.md -> reports/<ext>/x.<ext>; legacy: beside the report."""
    rp = report.resolve()
    if rp.parent.name == "md" and rp.parent.parent.name == "reports":
        d = rp.parent.parent / ext
        d.mkdir(parents=True, exist_ok=True)
        return d / (rp.stem + "." + ext)
    return rp.with_suffix("." + ext)
