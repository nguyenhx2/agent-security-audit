#!/usr/bin/env python3
"""
Read-only git for audited repos. Every script that runs git on a repo goes through here.

A repo handed over as a zip (or sitting on a shared machine) brings its own `.git/config`. Plain
`git status` / `ls-files` would run its `core.fsmonitor` command, and `git status` rewrites
`.git/index`. These options switch both off; `--no-optional-locks` keeps git from refreshing the index.
`git log -p` callers must also pass `--no-textconv --no-ext-diff` (repo-defined diff drivers).
Output is decoded as UTF-8 with replacement (cp932 consoles), paths are C-quoted unless `-z` is used.

Also: decoding of repo config files written on Windows (UTF-8 BOM, UTF-16 from PowerShell 5 redirects),
JSONC parsing (VS Code / devcontainer style), and the symlink-escape test used by the file walkers.
"""
from __future__ import annotations

import sys
sys.dont_write_bytecode = True  # keep the installed skill free of __pycache__

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
    """Run git read-only on `root`; raises OSError / SubprocessError like subprocess.run."""
    return subprocess.run(cmd(root, *args), capture_output=True, encoding="utf-8", errors="replace",
                          timeout=timeout, env={**os.environ, "GIT_OPTIONAL_LOCKS": "0"})


def out(root, *args: str, timeout: int = 120) -> str:
    """stdout of a successful git call, else "" (no git, not a repo, timeout)."""
    try:
        r = run(root, *args, timeout=timeout)
        return r.stdout if r.returncode == 0 else ""
    except (OSError, subprocess.SubprocessError):
        return ""


def head_dirty(root) -> tuple[str, bool | None]:
    """(short HEAD, tracked files changed?). The dirty check is `diff-index` on stat data: it never
    writes the index and never runs clean filters (git status / git diff can do both). A copied
    checkout (new mtimes) can therefore read as dirty; it is informative only. None = unknown."""
    head = out(Path(root), "rev-parse", "--short=12", "HEAD", timeout=30).strip()
    if not head:
        return "", None
    try:
        r = run(root, "diff-index", "--quiet", "HEAD", "--", timeout=60)
    except (OSError, subprocess.SubprocessError):
        return head, None
    return head, {0: False, 1: True}.get(r.returncode)


def decode(raw: bytes) -> str:
    """Text of a repo file: UTF-8 (BOM stripped) or UTF-16 with a BOM; undecodable bytes replaced."""
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return raw.decode("utf-16", "replace")
    return raw.decode("utf-8-sig", "replace")


def read_text(p: Path) -> str:
    return decode(Path(p).read_bytes())


_JSONC_COMMENT = re.compile(r'("(?:\\.|[^"\\])*")|//[^\n]*|/\*.*?\*/', re.S)
_JSONC_COMMA = re.compile(r'("(?:\\.|[^"\\])*")|,(\s*[}\]])')


def loads_jsonc(text: str):
    """json.loads that also accepts // and /* */ comments and trailing commas (strings untouched)."""
    try:
        return json.loads(text)
    except ValueError:
        pass
    t = _JSONC_COMMENT.sub(lambda m: m.group(1) or " ", text)
    return json.loads(_JSONC_COMMA.sub(lambda m: m.group(1) or m.group(2), t))


def escapes(root: Path, p: Path) -> bool:
    """True if `p` (via a symlink anywhere on its path) resolves outside `root` (an absolute, resolved path)."""
    try:
        rp = Path(p).resolve()
    except (OSError, RuntimeError):
        return True
    return rp != root and root not in rp.parents
