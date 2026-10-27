"""報告書スクリプトが共有する監査フォルダの構成。

    <audit_dir>/
      reports/md|html|xlsx/   security-audit-report_<project>_<ts>[_<lang>].<ext>   （成果物）
      findings/<lang>/<repo>/find-<repo>-NNN.md                                   （指摘事項 1 件につき 1 ファイル）
      work/                   profile.md, findings.json, narrative*.json, report-settings.json,
                              <repo>/ (scanners.json, raw/, sweep.json, digest.md, lanes/ ...)
                              （実行後に prune_work.py が中間ファイルを削除する）

`work/` のないフォルダは旧来のフラットな構成（すべて最上位に置く）として読み込む。
"""
from __future__ import annotations

import sys
sys.dont_write_bytecode = True  # インストール済みスキルに __pycache__ を作らない

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
    """findings/<lang>（新構成）、findings-<lang> または findings（旧構成）。最上位の findings/ は
    言語別サブフォルダを含まない場合に限り使う（含む場合は言語が混在するため）。"""
    per_lang = (root / "findings").is_dir() and any(d.is_dir() and re.fullmatch(r"[a-z]{2}(?:-[A-Za-z]{2,4})?", d.name)
                                                    for d in (root / "findings").iterdir())  # ISO 639-1 コード
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
    """reports/md/x.md -> reports/<ext>/x.<ext>。旧構成では報告書の隣に置く。"""
    rp = report.resolve()
    if rp.parent.name == "md" and rp.parent.parent.name == "reports":
        d = rp.parent.parent / ext
        d.mkdir(parents=True, exist_ok=True)
        return d / (rp.stem + "." + ext)
    return rp.with_suffix("." + ext)
