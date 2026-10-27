#!/usr/bin/env python3
"""The Japanese edition must behave exactly like the English master. This proves it mechanically.

The two editions are one skill: same name, same scripts, same outputs; only the prose a human reads
(comments, docstrings, help text, console messages, SKILL.md and reference text) is translated.
A translation pass that "improves" a regex, drops an argument or reorders a branch would make the
Japanese edition audit differently while every Japanese reader assumes it is the same tool. Four
checks, each one a failure that a careful human review would not reliably catch:

  1. code parity   every Python file (scripts/*.py, tests/*.py) has an IDENTICAL abstract syntax
                   tree once every string literal, f-string, docstring and argparse help text is
                   masked. Comments do not survive parsing, so they are free to differ. Any change
                   to logic, names, constants that are not strings, call order or structure fails.
                   Machine-read string outputs (JSON keys, finding headings) are not masked away
                   unchecked: the selftest of each edition asserts them.
  2. file tree     the same set of files, except README.ja.md (the English edition carries both
                   READMEs; the Japanese edition's README.md IS the Japanese one) and the generated
                   plugin files (.claude-plugin/), which only the English edition ships because the
                   Japanese edition is not a marketplace entry.
  3. versions      SKILL.md metadata.version, the metadata dates, and the newest CHANGELOG entry
                   are equal in both editions.
  4. machine-read  agents/*.md frontmatter (name, tools, model, effort, maxTurns ... everything but
     metadata      the description) and the evals.json structure (eval ids, fixtures) are equal:
                   these are read by Claude Code and the benchmark, not by a person.

Ported from the AST comparison used while building the 1.15.0 Japanese edition.

    python scripts/check_editions.py
"""
from __future__ import annotations

import ast
import json
import pathlib
import re
import sys
import tempfile

sys.dont_write_bytecode = True

ROOT = pathlib.Path(__file__).resolve().parent.parent
EN = ROOT / "security-audit"
JA = ROOT / "editions" / "ja" / "security-audit"
EN_ONLY = {"README.ja.md", ".claude-plugin/plugin.json", ".claude-plugin/icon.png"}
SKIP_PARTS = {"__pycache__"}
SKIP_SUFFIX = {".pyc", ".pyo"}
HELP_KW = {"help", "description", "epilog"}
META_KEYS = ("version", "updated", "standards-verified", "scanner-pins-verified")


class _Mask(ast.NodeTransformer):
    def visit_JoinedStr(self, node):  # f-strings: segmentation differs between languages
        return ast.copy_location(ast.Constant(value="<STR>"), node)

    def visit_Constant(self, node):
        if isinstance(node.value, str):
            node.value = "<STR>"
        return node


def norm(src: str) -> str:
    """The AST with every string masked, as a comparable dump (no line numbers)."""
    tree = _Mask().visit(ast.parse(src))
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node.body:
            first = node.body[0]
            if isinstance(first, ast.Expr) and isinstance(getattr(first, "value", None), ast.Constant) \
                    and isinstance(first.value.value, str):
                first.value.value = "<DOC>"
        if isinstance(node, ast.keyword) and node.arg in HELP_KW and isinstance(node.value, ast.Constant):
            node.value.value = "<HELP>"
    return ast.dump(tree, include_attributes=False)


def first_diff(a: str, b: str) -> str:
    i = next((k for k in range(min(len(a), len(b))) if a[k] != b[k]), min(len(a), len(b)))
    return f"...{a[max(0, i - 100):i + 100]!r}\n          vs ...{b[max(0, i - 100):i + 100]!r}"


def tree(base: pathlib.Path) -> set[str]:
    return {p.relative_to(base).as_posix() for p in base.rglob("*")
            if p.is_file() and not SKIP_PARTS & set(p.relative_to(base).parts)
            and p.suffix not in SKIP_SUFFIX}


def frontmatter(text: str) -> str:
    m = re.match(r"---\n(.*?)\n---", text.replace("\r\n", "\n"), re.S)
    return m.group(1) if m else ""


def metadata(skill_md: pathlib.Path) -> dict[str, str]:
    fm = frontmatter(skill_md.read_text(encoding="utf-8"))
    block = re.search(r"^metadata:\s*\n((?:[ \t]+.*\n?)+)", fm + "\n", re.M)
    out = {}
    for k in META_KEYS:
        m = re.search(rf"^[ \t]+{re.escape(k)}:\s*[\"']?([^\"'\n]+?)[\"']?\s*$", block.group(1) if block else "", re.M)
        out[k] = m.group(1) if m else None
    return out


def agent_meta(text: str) -> list[str]:
    """Frontmatter lines minus the (translated) description, which may be folded over lines."""
    out, in_desc = [], False
    for line in frontmatter(text).splitlines():
        if line.startswith("description:"):
            in_desc = True
            continue
        if in_desc and line.startswith((" ", "\t")):
            continue
        in_desc = False
        out.append(line.rstrip())
    return out


def evals_shape(path: pathlib.Path) -> object:
    d = json.loads(path.read_text(encoding="utf-8"))
    evals = d.get("evals", [])
    return {"skill_name": d.get("skill_name"),
            "fixtures": sorted(json.dumps(f, sort_keys=True) for f in d.get("fixtures", []))
            if isinstance(d.get("fixtures"), list) else sorted(d.get("fixtures") or {}),
            "eval_ids": [e.get("id") for e in evals]}


def newest_entry(changelog: pathlib.Path) -> str | None:
    m = re.search(r"^##\s*\[(\d+\.\d+\.\d+)\]", changelog.read_text(encoding="utf-8"), re.M)
    return m.group(1) if m else None


def compare(en: pathlib.Path, ja: pathlib.Path) -> tuple[list[str], int]:
    """(problems, python files compared)."""
    problems: list[str] = []
    t_en, t_ja = tree(en), tree(ja)
    for rel in sorted(t_en - t_ja - EN_ONLY):
        problems.append(f"tree: {rel} is in the English edition only")
    for rel in sorted(t_ja - t_en):
        problems.append(f"tree: {rel} is in the Japanese edition only")
    for rel in sorted(EN_ONLY & t_ja):
        problems.append(f"tree: {rel} must not be in the Japanese edition")

    py = sorted(r for r in t_en & t_ja if r.endswith(".py"))
    for rel in py:
        try:
            a = norm((en / rel).read_text(encoding="utf-8"))
            b = norm((ja / rel).read_text(encoding="utf-8"))
        except SyntaxError as e:
            problems.append(f"code: {rel} does not parse: {e}")
            continue
        if a != b:
            problems.append(f"code: {rel} differs once strings are masked:\n          {first_diff(a, b)}")

    if (en / "SKILL.md").is_file() and (ja / "SKILL.md").is_file():
        me, mj = metadata(en / "SKILL.md"), metadata(ja / "SKILL.md")
        for k in META_KEYS:
            if me[k] != mj[k]:
                problems.append(f"version: SKILL.md metadata.{k} is {me[k]!r} (en) vs {mj[k]!r} (ja)")
    if (en / "CHANGELOG.md").is_file() and (ja / "CHANGELOG.md").is_file():
        ve, vj = newest_entry(en / "CHANGELOG.md"), newest_entry(ja / "CHANGELOG.md")
        if ve != vj:
            problems.append(f"version: newest CHANGELOG entry is {ve} (en) vs {vj} (ja)")

    for rel in sorted(r for r in t_en & t_ja if r.startswith("agents/") and r.endswith(".md")):
        a = agent_meta((en / rel).read_text(encoding="utf-8"))
        b = agent_meta((ja / rel).read_text(encoding="utf-8"))
        if a != b:
            problems.append(f"agents: {rel} frontmatter differs beyond the description: "
                            f"{sorted(set(a) ^ set(b))}")
    if "evals/evals.json" in t_en & t_ja:
        try:
            if evals_shape(en / "evals/evals.json") != evals_shape(ja / "evals/evals.json"):
                problems.append("evals: evals/evals.json ids or fixtures differ between editions")
        except ValueError as e:
            problems.append(f"evals: evals/evals.json does not parse: {e}")
    return problems, len(py)


def self_test() -> list[str]:
    """Build a sound pair and one mutant per detector; every mutant must be reported and the sound
    pair must not. A parity check that never fails is indistinguishable from parity."""
    dead: list[str] = []
    code = 'import sys\n"""Doc."""\ndef f(x):\n    """Doc."""\n    print("hello", x)  # comment\n    return x + 1\n'
    code_ja = code.replace("Doc.", "説明。").replace('"hello"', '"こんにちは"').replace("# comment", "# 注釈")
    skill = ("---\nname: s\nmetadata:\n  version: \"1.0.0\"\n  updated: \"2026-01-01\"\n---\n# S\n")
    agent = "---\nname: a\ndescription: Does a.\ntools: Read\nmodel: sonnet\n---\nbody\n"
    agent_ja = agent.replace("Does a.", "A を行う。")
    evals = json.dumps({"skill_name": "s", "fixtures": [], "evals": [{"id": 1}]})
    base = {"scripts/x.py": (code, code_ja), "SKILL.md": (skill, skill),
            "CHANGELOG.md": ("## [1.0.0] - 2026-01-01\n", "## [1.0.0] - 2026-01-01\n"),
            "agents/a.md": (agent, agent_ja), "evals/evals.json": (evals, evals),
            "README.ja.md": ("ja", None)}
    mutants = {
        "logic change": {"scripts/x.py": (code, code_ja.replace("x + 1", "x + 2"))},
        "renamed call": {"scripts/x.py": (code, code_ja.replace("print(", "repr("))},
        "file only in ja": {"scripts/y.py": (None, "pass\n")},
        "file only in en": {"scripts/y.py": ("pass\n", None)},
        "version drift": {"SKILL.md": (skill, skill.replace("1.0.0", "1.0.1"))},
        "changelog drift": {"CHANGELOG.md": ("## [1.0.0] - 2026-01-01\n", "## [0.9.0] - 2026-01-01\n")},
        "agent model drift": {"agents/a.md": (agent, agent_ja.replace("sonnet", "opus"))},
        "evals drift": {"evals/evals.json": (evals, evals.replace('"id": 1', '"id": 2'))},
    }
    with tempfile.TemporaryDirectory() as td:
        def build(files: dict) -> tuple[pathlib.Path, pathlib.Path]:
            root = pathlib.Path(tempfile.mkdtemp(dir=td))
            en, ja = root / "en", root / "ja"
            for rel, (a, b) in files.items():
                for d, txt in ((en, a), (ja, b)):
                    if txt is not None:
                        (d / rel).parent.mkdir(parents=True, exist_ok=True)
                        (d / rel).write_text(txt, encoding="utf-8")
            return en, ja
        found, _ = compare(*build(base))
        if found:
            dead.append(f"the sound pair is reported: {found}")
        for label, change in mutants.items():
            found, _ = compare(*build({**base, **change}))
            if not found:
                dead.append(f"not detected: {label}")
    return dead


def main() -> int:
    dead = self_test()
    if dead:
        print("DEAD CHECK - edition parity would pass a broken edition:")
        for d in dead:
            print(f"  - {d}")
        return 1
    problems, n = compare(EN, JA)
    if problems:
        print(f"FAIL  editions differ ({len(problems)} problem(s)):")
        for p in problems:
            print(f"  - {p}")
        return 1
    print(f"ok: editions match - {n} Python files identical with strings masked, same file tree, "
          f"same versions, same agent and eval metadata")
    return 0


if __name__ == "__main__":
    sys.exit(main())
