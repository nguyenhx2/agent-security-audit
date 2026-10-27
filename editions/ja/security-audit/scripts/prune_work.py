#!/usr/bin/env python3
"""報告書一式の完成後に <audit_dir>/work/ を整理する（Phase 7、最終ステップ）。

既定：実行後に何も読まない中間ファイルだけを削除し、報告書の再ビルド（`build_report.py --force --fill`）、
後からの翻訳、Phase 8 の再スキャンに必要なものは残す。

  削除     <repo>/raw/  packs/  scratch/  candidates.jsonl  findings.draft.json  digest.md  digest.json
           routes.md  routes.json  recon.md  summary.md  agent-config.md  platform.md  lanes/*.md（レーンの
           メモ）、work/intel.md（build_report はこれらをいずれも読まない）
  保持     profile.md  findings.json  findings_<L>.json  narrative*.json  report-settings.json
           <repo>/scanners.json（Phase 8 用のイメージのピン）  sweep.json  agent-config.json  platform.json  vex.json
           intel.json（報告書の第2節、validate_findings）
           lanes/candidates.md  lanes/verifier.md（各候補を残した / 反証した理由）
  不明なファイルには決して触れない。

  --keep-work    すべて残す（調査、スキルのデバッグ用）
  --purge-work   work/ フォルダ全体を削除する - 報告書の再ビルドや翻訳はできなくなり、
                 Phase 8 は監査のやり直しになる

<audit_dir> に reports/md/*.md がない（実行が完了していない）場合は実行を拒否する。
削除できないファイル（Linux では root 所有のスキャナ出力、Windows では読み取り専用またはロックされたファイル）は
スキップし、この OS 用の正確な対処コマンドとともに一覧表示する。その場合は exit 1。

使い方：
  python prune_work.py <audit_dir> [--keep-work | --purge-work] [--dry-run]
"""
from __future__ import annotations

import sys
sys.dont_write_bytecode = True  # インストール済みスキルに __pycache__ を残さない
for _s in (sys.stdout, sys.stderr):  # cp932 / cp1252 のコンソールやパイプでも UTF-8 で出力する
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
    except OSError:  # 読めない（他者所有の）サブフォルダ：サイズは参考値にすぎない
        return 0


def remove(p: Path, failed: list) -> None:
    """ファイルまたはツリーを削除する。削除できないものは `failed` に追加し、残りは引き続き削除する。"""
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
        try:  # Windows の読み取り専用属性（git オブジェクト、コピーしたファイル）
            os.chmod(p, stat.S_IWRITE)
            p.unlink()
        except OSError:
            failed.append(p)


def fix_hint(work: Path) -> str:
    """残ったファイルを削除可能にする、この OS 用の正確なコマンド。"""
    if os.name == "nt":
        return (f'"{work}" 内のファイルを使用しているプログラム（エディタ、Excel、実行中のスキャナ）を閉じてから実行: '
                f'attrib -R "{work}\\*" /S /D  - アクセスが拒否される場合は: icacls "{work}" /grant '
                f'"{os.environ.get("USERNAME", "%USERNAME%")}":F /T')
    ug = f"{os.getuid()}:{os.getgid()}"
    lines = [f"sudo chown -R {ug} '{work}'"]
    try:
        from run_scanners import IMAGES  # 固定済みのイメージ。一度きりの chown のために新たな pull はしない
        eng = shutil.which("docker") and "docker" or shutil.which("podman") and "podman"
        if eng:
            lines.insert(0, f"{eng} run --rm --user 0:0 --network none --security-opt label=disable "
                            f"-v '{work}:/fix' --entrypoint chown {IMAGES['gitleaks']} -R {ug} /fix")
    except Exception:  # noqa: BLE001 - sudo の行は常に表示される
        pass
    return "\n  または: ".join(lines)


def targets(work: Path) -> list[Path]:
    out: list[Path] = []
    for repo in sorted(p for p in work.iterdir() if p.is_dir()):
        if not ((repo / "scanners.json").exists() or (repo / "sweep.json").exists()):
            continue  # このスキルが書き出したリポジトリの作業フォルダではない
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
    g.add_argument("--keep-work", action="store_true", help="すべて残す")
    g.add_argument("--purge-work", action="store_true", help="work/ フォルダ全体を削除する")
    ap.add_argument("--dry-run", action="store_true", help="削除対象を一覧表示する（削除はしない）")
    a = ap.parse_args()

    root = Path(a.audit_dir).resolve()
    work = root / "work"
    if not work.is_dir():
        print(f"error: {work} が見つからない（旧来のフラットな構成か、既に削除済み）- 何もしていない", file=sys.stderr)
        return 2
    if not any((root / "reports" / "md").glob("*.md")):
        print(f"error: {root / 'reports' / 'md'} に報告書がない - 整理の前に Phase 7 を完了すること", file=sys.stderr)
        return 2
    if a.keep_work:
        print(f"work/ はそのまま残した（{size(work) / 1e6:.1f} MB）")
        return 0

    todo = [work] if a.purge_work else targets(work)
    freed = sum(size(p) for p in todo)
    failed: list[Path] = []
    for p in todo:
        rel = p.relative_to(root).as_posix() + ("/" if p.is_dir() else "")
        if a.dry_run:
            print(f"削除予定: {rel}")
            continue
        remove(p, failed)
    if failed:
        print(f"error: {len(failed)} 項目を削除できなかった（権限がない / 使用中）:", file=sys.stderr)
        for f in failed[:15]:
            print(f"  {f.relative_to(root).as_posix() if root in f.parents else f}", file=sys.stderr)
        if len(failed) > 15:
            print(f"  ... ほか {len(failed) - 15} 項目", file=sys.stderr)
        print(f"対処（その後 prune_work.py を再実行する）:\n  {fix_hint(work)}", file=sys.stderr)
        return 1
    verb = "解放予定" if a.dry_run else "解放"
    if a.purge_work:
        print(f"work/ を削除{'する予定' if a.dry_run else 'した'} - {verb} {freed / 1e6:.1f} MB。報告書の再ビルドや翻訳は"
              f"できなくなる。再スキャンには新しい監査が必要。")
    else:
        left = size(work) if work.exists() else 0
        print(f"中間ファイル {len(todo)} 項目を整理 - {verb} {freed / 1e6:.1f} MB。work/ には再ビルド、翻訳、再スキャン用に "
              f"{(left - (freed if a.dry_run else 0)) / 1e6:.1f} MB を残す")
    return 0


if __name__ == "__main__":
    sys.exit(main())
