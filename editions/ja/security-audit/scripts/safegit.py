#!/usr/bin/env python3
"""
監査対象リポジトリ向けの読み取り専用 git。リポジトリで git を実行するスクリプトはすべてここを経由する。

zip で受け取ったリポジトリ（または共有マシン上のリポジトリ）は独自の `.git/config` を持ち込む。素の
`git status` / `ls-files` はその `core.fsmonitor` コマンドを実行してしまい、`git status` は
`.git/index` を書き換える。以下のオプションで両方を無効にする。`--no-optional-locks` は git による
インデックスの更新を防ぐ。`git log -p` の呼び出し側は `--no-textconv --no-ext-diff` も渡すこと
（リポジトリ定義の diff ドライバ対策）。出力は UTF-8 として置換付きでデコードし（cp932 コンソール対策）、
パスは `-z` を使わない限り C 形式でクォートされる。

ほかに：Windows で書かれたリポジトリ設定ファイルのデコード（UTF-8 BOM、PowerShell 5 のリダイレクトによる
UTF-16）、JSONC の解析（VS Code / devcontainer 形式）、ファイル走査処理が使うシンボリックリンク脱出の判定。
"""
from __future__ import annotations

import sys
sys.dont_write_bytecode = True  # インストール済みスキルに __pycache__ を作らない

import json
import os
import re
import subprocess
from pathlib import Path

SAFE_OPTS = ["-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false", "-c", "core.quotePath=true",
             "--no-optional-locks"]


def cmd(root, *args: str) -> list[str]:
    return ["git", *SAFE_OPTS, "-C", str(root), *args]


def run(root, *args: str, timeout: int = 120) -> subprocess.CompletedProcess:
    """`root` で git を読み取り専用で実行する。subprocess.run と同様に OSError / SubprocessError を送出する。"""
    return subprocess.run(cmd(root, *args), capture_output=True, encoding="utf-8", errors="replace",
                          timeout=timeout, env={**os.environ, "GIT_OPTIONAL_LOCKS": "0"})


def out(root, *args: str, timeout: int = 120) -> str:
    """成功した git 呼び出しの stdout。それ以外は ""（git なし、リポジトリでない、タイムアウト）。"""
    try:
        r = run(root, *args, timeout=timeout)
        return r.stdout if r.returncode == 0 else ""
    except (OSError, subprocess.SubprocessError):
        return ""


def head_dirty(root) -> tuple[str, bool | None]:
    """（短縮 HEAD、追跡ファイルの変更有無）。変更判定は stat 情報に対する `diff-index` で行う。
    インデックスへの書き込みも clean フィルタの実行も一切しない（git status / git diff は両方行い得る）。
    そのため、コピーしたチェックアウト（mtime が新しい）は変更ありと判定され得る。参考情報にすぎない。None = 不明。"""
    head = out(Path(root), "rev-parse", "--short=12", "HEAD", timeout=30).strip()
    if not head:
        return "", None
    try:
        r = run(root, "diff-index", "--quiet", "HEAD", "--", timeout=60)
    except (OSError, subprocess.SubprocessError):
        return head, None
    return head, {0: False, 1: True}.get(r.returncode)


def decode(raw: bytes) -> str:
    """リポジトリ内ファイルのテキスト：UTF-8（BOM 除去）または BOM 付き UTF-16。デコードできないバイトは置換する。"""
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return raw.decode("utf-16", "replace")
    return raw.decode("utf-8-sig", "replace")


def read_text(p: Path) -> str:
    return decode(Path(p).read_bytes())


_JSONC_COMMENT = re.compile(r'("(?:\\.|[^"\\])*")|//[^\n]*|/\*.*?\*/', re.S)
_JSONC_COMMA = re.compile(r'("(?:\\.|[^"\\])*")|,(\s*[}\]])')


def loads_jsonc(text: str):
    """// と /* */ のコメントおよび末尾のカンマも受け付ける json.loads（文字列内は変更しない）。"""
    try:
        return json.loads(text)
    except ValueError:
        pass
    t = _JSONC_COMMENT.sub(lambda m: m.group(1) or " ", text)
    return json.loads(_JSONC_COMMA.sub(lambda m: m.group(1) or m.group(2), t))


def escapes(root: Path, p: Path) -> bool:
    """`p` が（パス上のいずれかのシンボリックリンク経由で）`root`（解決済みの絶対パス）の外に解決される場合 True。"""
    try:
        rp = Path(p).resolve()
    except (OSError, RuntimeError):
        return True
    return rp != root and root not in rp.parents
