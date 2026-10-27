#!/usr/bin/env python3
"""
Install the skill's subagent definitions as real named agents (Phase 0, Standard / Deep).

A skill cannot register subagents itself; Claude Code loads them from `~/.claude/agents/` (user),
`.claude/agents/` (project) or a plugin. This copies `agents/*.md` to
`~/.claude/agents/security-audit/` with `{skill_dir}` resolved, so the Agent tool can call
`security-audit-lane-reviewer`, `security-audit-finding-verifier`, `security-audit-recon-mapper`
and `security-audit-report-translator` directly: own tool allow-list (no Agent/Edit), `maxTurns`,
`omitClaudeMd` (no CLAUDE.md in every subagent's context), and a readable name in the task list.

Writes only files it owns (each carries an `installed-by: security-audit` stamp); a file with
the same name that it did not write is left alone and reported. Claude Code picks up changes in
an existing agents folder within seconds; a folder created during the session needs a restart.

Usage:
  python install_agents.py            install or update (idempotent)
  python install_agents.py --check    exit 0 = installed and current, 1 = missing / outdated
  python install_agents.py --uninstall
  [--dest DIR]                         default ~/.claude/agents/security-audit
"""
from __future__ import annotations

import sys
sys.dont_write_bytecode = True  # keep the installed skill free of __pycache__
for _s in (sys.stdout, sys.stderr):  # UTF-8 output even on cp932 / cp1252 consoles and pipes
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
    # stamp as a YAML comment on the line after the opening '---'
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
