#!/usr/bin/env python3
"""Render every mermaid block in the repo and fail on any that does not draw.

GitHub renders mermaid server-side and shows "Unable to render rich display" when a block does not
parse. That message says nothing about which line is wrong, so the only way to find out is to render
the block yourself. This does that, with the same engine GitHub uses.

Needs node (it shells out to `npx @mermaid-js/mermaid-cli`). Without npx the static checks (fence
placement, tag-shaped labels, semicolons) still run and the render step is SKIPPED with a warning -
locally only. In CI (`CI` set, as GitHub Actions does) a missing npx is a failure, because a gate
that silently skips on the one machine that is supposed to enforce it enforces nothing.

    python scripts/check_mermaid.py          # check every .md
    python scripts/check_mermaid.py README.md docs/RELEASING.md
"""

from __future__ import annotations

import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent


def find_blocks(text: str) -> list[tuple[str, bool]]:
    """Return (source, closing_on_own_line) for every ```mermaid block.

    A closing fence must sit on a line by itself (CommonMark). mermaid-cli does not care - it splits
    on the ``` wherever it is - but GitHub does: a fence glued to the last content line
    (`    class A art` + ```` ``` ````) never closes the block, so GitHub pulls the following prose
    into the diagram and fails to parse it. That exact bug shipped once and rendered fine locally.
    """
    lines = text.splitlines()
    blocks: list[tuple[str, bool]] = []
    i = 0
    while i < len(lines):
        if lines[i].rstrip() == "```mermaid":
            body: list[str] = []
            j, closing_ok = i + 1, False
            while j < len(lines):
                line = lines[j]
                if re.match(r"^\s*```\s*$", line):          # proper closing fence, own line
                    closing_ok = True
                    break
                if line.rstrip().endswith("```"):           # fence glued to content
                    body.append(line.rstrip()[:-3])
                    closing_ok = False
                    break
                body.append(line)
                j += 1
            blocks.append(("\n".join(body), closing_ok))
            i = j + 1
        else:
            i += 1
    return blocks


# A label containing a tag-shaped token - "<name>", "<slug>", "<T>" - is parsed as HTML by the
# renderer. mermaid-cli silently EATS it: the diagram still renders, the text is just gone. GitHub's
# sanitiser is stricter and fails the whole block with "Unable to render rich display", naming
# neither the file nor the line. So this is checked before rendering, because rendering will not
# catch it. <br/> is the one tag a label may legitimately carry.
# The lookahead requires a letter or a slash right after the "<", so mermaid's own bidirectional
# arrows (<-->, <==>, <-.->) are not mistaken for tags.
TAGLIKE = re.compile(r"<(?!br\s*/?>)(?=[A-Za-z/])[^<>\n]{1,30}>")


def lint(src: str) -> list[str]:
    problems = []
    for n, line in enumerate(src.splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith(("%%", "classDef", "class ", "style ")):
            continue
        for m in TAGLIKE.finditer(line):
            problems.append(f"line {n}: '{m.group(0)}' is parsed as an HTML tag and the text is "
                            f"dropped. Rewrite the label without angle brackets.")
        # ';' ends a statement in mermaid, so one inside a message truncates the line.
        if ";" in stripped and not stripped.startswith(("classDef", "class ", "style ")):
            if re.match(r"\s*(Note (over|right of|left of)|[\w-]+\s*-?-?>>?)", line):
                problems.append(f"line {n}: ';' ends a mermaid statement. Use a comma or a hyphen.")
    return problems


def render(src: str) -> tuple[bool, str]:
    with tempfile.TemporaryDirectory() as td:
        t = pathlib.Path(td)
        mmd, out = t / "d.mmd", t / "d.svg"
        mmd.write_text(src, encoding="utf-8")

        # mermaid-cli drives a headless Chrome through puppeteer. In a container without a user
        # namespace (GitHub Actions, most CI images) Chrome's sandbox cannot start, and it fails
        # with "Failed to launch the browser process: Code: null" - which looks exactly like a
        # broken diagram. Disable the sandbox: the input is our own repo, not untrusted content.
        cfg = t / "puppeteer.json"
        cfg.write_text('{"args": ["--no-sandbox", "--disable-setuid-sandbox"]}', encoding="utf-8")

        r = subprocess.run(
            ["npx", "-y", "@mermaid-js/mermaid-cli@11.17.0",
             "-i", str(mmd), "-o", str(out), "-q", "-p", str(cfg)],
            capture_output=True, text=True, shell=(sys.platform == "win32"),
        )
        if r.returncode == 0 and out.is_file() and out.stat().st_size > 0:
            return True, ""
        err = (r.stderr or r.stdout).strip().splitlines()
        # keep the lines that actually name the problem
        useful = [l for l in err if any(k in l.lower() for k in
                                        ("error", "expecting", "got '", "parse"))]
        return False, " | ".join(useful[:3]) or "render produced nothing"


def main() -> int:
    args = sys.argv[1:]
    files = [ROOT / a for a in args] if args else sorted(ROOT.rglob("*.md"))
    # Cloned benchmark fixtures and audit runs are third-party content, not this repo's diagrams.
    skip = {".git", "node_modules", "dist", "fixtures", "runs", "tmp"}
    files = [f for f in files if not (skip & set(f.relative_to(ROOT).parts))]

    can_render = shutil.which("npx") is not None
    if not can_render:
        if os.environ.get("CI"):
            print("  FAIL  npx is not on PATH - CI must render every mermaid block (install Node)")
            return 1
        print("  warn  npx not found: static checks only, the render step is skipped (CI renders)")

    total = failed = 0
    for f in files:
        blocks = find_blocks(f.read_text(encoding="utf-8"))
        for i, (b, closing_ok) in enumerate(blocks, 1):
            total += 1
            rel = f.relative_to(ROOT).as_posix()

            if not closing_ok:
                failed += 1
                print(f"  FAIL  {rel} block {i}: closing ``` is glued to the last line. Put it on "
                      f"its own line, or GitHub will not close the block.")
                continue

            issues = lint(b)
            if issues:
                failed += 1
                print(f"  FAIL  {rel} block {i}:")
                for p in issues:
                    print(f"          {p}")
                continue

            if not can_render:
                print(f"  ok    {rel} block {i} (static checks; not rendered)")
                continue
            ok, err = render(b)
            if ok:
                print(f"  ok    {rel} block {i}")
            else:
                failed += 1
                print(f"  FAIL  {rel} block {i}: {err}")

    print(f"\n  {total - failed}/{total} mermaid blocks render.")
    return 1 if failed else 0


def self_test() -> list[str]:
    """The static detectors must fire on the failures that shipped before, and stay quiet on a sound
    block. They are the only part that runs without Node, so they are proven every run."""
    nl = chr(10)
    fence = "`" * 3
    dead = []
    good = nl.join([fence + "mermaid", "flowchart LR", "  A[Scan] --> B[Report]", fence, ""])
    blocks = find_blocks(good)
    if len(blocks) != 1 or not blocks[0][1] or lint(blocks[0][0]):
        dead.append("a sound block is reported")
    glued = find_blocks(nl.join([fence + "mermaid", "flowchart LR", "  A --> B" + fence, "prose", ""]))
    if not glued or glued[0][1]:
        dead.append("a closing fence glued to the last line is not reported")
    if not lint(nl.join(["flowchart LR", "  A[<name>] --> B"])):
        dead.append("a tag-shaped label is not reported")
    if not lint(nl.join(["sequenceDiagram", "  A->>B: one; two"])):
        dead.append("a semicolon inside a message is not reported")
    return dead


if __name__ == "__main__":
    _dead = self_test()
    if _dead:
        print("  DEAD CHECK - the mermaid linter cannot fail:")
        for _d in _dead:
            print(f"    {_d}")
        sys.exit(1)
    sys.exit(main())
