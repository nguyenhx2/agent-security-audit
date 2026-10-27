#!/usr/bin/env python3
"""
スキルのサブエージェント定義を、名前付きの正式なエージェントとしてインストールする（Phase 0、標準 / 詳細）。

スキルは自らサブエージェントを登録できない。Claude Code は `~/.claude/agents/`（ユーザー）、
`.claude/agents/`（プロジェクト）またはプラグインから読み込む。本スクリプトは `{skill_dir}` を解決したうえで
`agents/*.md` を `~/.claude/agents/security-audit/` にコピーする。これにより Agent ツールから
`security-audit-lane-reviewer`、`security-audit-finding-verifier`、`security-audit-recon-mapper`、
`security-audit-report-translator` を直接呼び出せる：独自のツール許可リスト（Agent/Edit なし）、`maxTurns`、
`omitClaudeMd`（各サブエージェントのコンテキストに CLAUDE.md を入れない）、タスク一覧での読みやすい名前。

書き込むのは自身が所有するファイルのみ（各ファイルに `installed-by: security-audit` のスタンプを付ける）。
自身が書いていない同名ファイルは変更せずに報告する。Claude Code は既存の agents フォルダの変更を数秒で
反映するが、セッション中に作成したフォルダは再起動が必要。

使い方：
  python install_agents.py            インストールまたは更新（冪等）
  python install_agents.py --check    exit 0 = インストール済みで最新、1 = 未インストール / 古い
  python install_agents.py --uninstall
  [--dest DIR]                         既定値 ~/.claude/agents/security-audit
"""
from __future__ import annotations

import sys
sys.dont_write_bytecode = True  # インストール済みスキルに __pycache__ を作らない
for _s in (sys.stdout, sys.stderr):  # cp932 / cp1252 のコンソールやパイプでも UTF-8 で出力する
    if hasattr(_s, "reconfigure"):
        _s.reconfigure(encoding="utf-8", errors="replace")

import argparse
import hashlib
import json
import re
from pathlib import Path

SKILL = Path(__file__).resolve().parent.parent
STAMP = "installed-by: security-audit"


def version() -> str:
    m = re.search(r'(?m)^\s+version:\s*"?([\d.]+)', (SKILL / "SKILL.md").read_text(encoding="utf-8"))
    return m.group(1) if m else "0"


def render(src: Path) -> str:
    text = src.read_text(encoding="utf-8").replace("{skill_dir}", SKILL.as_posix())
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()[:12]
    # 先頭の '---' の次の行に YAML コメントとしてスタンプを付ける
    return text.replace("---\n", f"---\n# {STAMP} {version()} ({digest}) - do not edit; re-run install_agents.py\n", 1)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dest", default=str(Path.home() / ".claude" / "agents" / "security-audit"))
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--check", action="store_true")
    g.add_argument("--uninstall", action="store_true")
    a = ap.parse_args()
    dest = Path(a.dest)
    sources = sorted((SKILL / "agents").glob("*.md"))
    status = {"dest": dest.as_posix(), "version": version(), "agents": {}}
    names = {}
    for src in sources:
        m = re.search(r"(?m)^name:\s*(\S+)", src.read_text(encoding="utf-8"))
        names[src.name] = m.group(1) if m else src.stem

    if a.uninstall:
        removed = []
        for src in sources:
            t = dest / src.name
            if t.exists() and STAMP in t.read_text(encoding="utf-8", errors="replace"):
                t.unlink()
                removed.append(t.name)
        if dest.exists() and not any(dest.iterdir()):
            dest.rmdir()
        print(json.dumps({"removed": removed}))
        return 0

    agents_root_existed = dest.parent.exists()
    ok = True
    for src in sources:
        want = render(src)
        t = dest / src.name
        have = t.read_text(encoding="utf-8", errors="replace") if t.exists() else None
        if have is not None and STAMP not in have:
            status["agents"][names[src.name]] = "foreign file - left untouched"
            ok = False
            continue
        state = "current" if have == want else ("outdated" if have else "missing")
        if not a.check and state != "current":
            dest.mkdir(parents=True, exist_ok=True)
            t.write_text(want, encoding="utf-8")
            state = "installed"
        status["agents"][names[src.name]] = state
        ok = ok and state in ("current", "installed")
    if not a.check and not agents_root_existed:
        status["note"] = ("agents folder was created now - restart Claude Code to load the agents; "
                          "until then use general-purpose with the brief path")
    print(json.dumps(status, indent=1))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
