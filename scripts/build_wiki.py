#!/usr/bin/env python3
"""
Build the GitHub Wiki from the user guide in docs/guide/ (English) and docs/guide/ja/ (Japanese).

The guide is written once, in the repository, where pull requests and CI check it. The Pages site
(mkdocs.yml) and the Wiki are both generated from it; nobody edits the Wiki by hand (the sync
workflow overwrites it). The Wiki is flat, so this script:
  - names each page after its file: index.md -> Home, first-audit.md -> First-audit,
    ja/first-audit.md -> JA-First-audit (ja/index.md -> JA-Home);
  - rewrites links between guide pages to Wiki page names (anchors kept);
  - rewrites images under docs/assets/ to raw.githubusercontent.com URLs on the default branch;
  - rewrites any other relative link to the file's GitHub URL;
  - writes _Sidebar.md (both languages, in the order of mkdocs.yml's nav when it lists the page)
    and _Footer.md (where the source lives).

Usage:
  python scripts/build_wiki.py --out WIKI_DIR     # writes *.md into WIKI_DIR (removes stale *.md)
  python scripts/build_wiki.py --check            # builds into a temp dir, fails on a broken link
Stdlib only.
"""
from __future__ import annotations

import argparse
import posixpath
import re
import shutil
import sys
import tempfile
from pathlib import Path

sys.dont_write_bytecode = True
for _s in (sys.stdout, sys.stderr):
    if hasattr(_s, "reconfigure"):
        _s.reconfigure(encoding="utf-8", errors="replace")

ROOT = Path(__file__).resolve().parent.parent
GUIDE = ROOT / "docs" / "guide"
REPO = "nguyenhx2/agent-security-audit"
BLOB = f"https://github.com/{REPO}/blob/main/"
TREE = f"https://github.com/{REPO}/tree/main/"
RAW = f"https://raw.githubusercontent.com/{REPO}/main/"
LINK = re.compile(r"(!?)\[([^\]]*)\]\(([^)\s]+)(\s+\"[^\"]*\")?\)")
IMG_SRC = re.compile(r"(<img\b[^>]*\bsrc=\")([^\"]+)(\")", re.I)
NAV_ORDER = ["index", "install", "first-audit", "how-it-works", "threat-intelligence", "scanners",
             "standards-and-sectors", "reports", "models", "rescan", "security-and-privacy",
             "troubleshooting", "contributing"]


def page_name(rel: str) -> str:
    """docs/guide-relative path (posix) -> Wiki page name."""
    ja = rel.startswith("ja/")
    stem = Path(rel).stem
    base = "Home" if stem == "index" else stem[:1].upper() + stem[1:]
    return ("JA-" + base) if ja else base


def title_of(path: Path) -> str:
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("# "):
            return line[2:].strip()
    return path.stem


def rewrite(src_rel: str, text: str, pages: set, errors: list) -> str:
    here = posixpath.dirname("docs/guide/" + src_rel)

    def target(url: str, image: bool) -> str:
        if re.match(r"^[a-z][a-z0-9+.-]*:", url, re.I) or url.startswith("#"):
            return url
        path, _, frag = url.partition("#")
        full = posixpath.normpath(posixpath.join(here, path))
        if full.startswith("docs/guide/") and full.endswith(".md"):
            rel = full[len("docs/guide/"):]
            if rel not in pages:
                errors.append(f"{src_rel}: link to missing guide page {url}")
            return page_name(rel) + (("#" + frag) if frag else "")
        if full.startswith(".."):
            errors.append(f"{src_rel}: link leaves the repository: {url}")
            return url
        if not (ROOT / full).exists():
            errors.append(f"{src_rel}: link to missing file {url}")
        if image or full.startswith("docs/assets/"):
            return RAW + full
        return (TREE if (ROOT / full).is_dir() else BLOB) + full + (("#" + frag) if frag else "")

    out, in_code = [], False
    for line in text.splitlines():
        if line.lstrip().startswith("```"):
            in_code = not in_code
        if not in_code:
            line = LINK.sub(lambda m: f"{m.group(1)}[{m.group(2)}]({target(m.group(3), bool(m.group(1)))}"
                                      f"{m.group(4) or ''})", line)
            line = IMG_SRC.sub(lambda m: m.group(1) + target(m.group(2), True) + m.group(3), line)
        out.append(line)
    return "\n".join(out) + "\n"


def build(out: Path) -> list:
    if not GUIDE.is_dir():
        return [f"missing {GUIDE}"]
    files = sorted(p for p in GUIDE.rglob("*.md"))
    pages = {p.relative_to(GUIDE).as_posix() for p in files}
    errors: list = []
    for old in out.glob("*.md"):
        old.unlink()
    for p in files:
        rel = p.relative_to(GUIDE).as_posix()
        text = rewrite(rel, p.read_text(encoding="utf-8"), pages, errors)
        (out / f"{page_name(rel)}.md").write_bytes(text.encode("utf-8"))

    def ordered(prefix: str):
        rels = [r for r in pages if r.startswith(prefix) and r.count("/") == prefix.count("/")]
        key = {s: i for i, s in enumerate(NAV_ORDER)}
        return sorted(rels, key=lambda r: (key.get(Path(r).stem, 99), r))

    side = ["**English**", ""]
    side += [f"- [{title_of(GUIDE / r)}]({page_name(r)})" for r in ordered("")]
    side += ["", "**日本語**", ""]
    side += [f"- [{title_of(GUIDE / r)}]({page_name(r)})" for r in ordered("ja/")]
    side += ["", f"[Repository](https://github.com/{REPO}) · [Releases](https://github.com/{REPO}/releases)"]
    (out / "_Sidebar.md").write_bytes(("\n".join(side) + "\n").encode("utf-8"))
    foot = (f"Generated from [`docs/guide/`]({TREE}docs/guide) by `scripts/build_wiki.py`. Edit the source "
            f"there through a pull request; changes made here are overwritten. / このWikiは `docs/guide/` から"
            f"自動生成しています。編集はリポジトリ側で行ってください。")
    (out / "_Footer.md").write_bytes((foot + "\n").encode("utf-8"))
    return errors


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--out", help="Wiki working copy to write into")
    g.add_argument("--check", action="store_true", help="build into a temp dir and report broken links")
    a = ap.parse_args()
    if a.check:
        tmp = Path(tempfile.mkdtemp())
        try:
            errors = build(tmp)
            n = len(list(tmp.glob("*.md")))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
    else:
        out = Path(a.out)
        out.mkdir(parents=True, exist_ok=True)
        errors = build(out)
        n = len(list(out.glob("*.md")))
    for e in errors:
        print(f"  BROKEN  {e}")
    print(f"{n} wiki page(s), {len(errors)} broken link(s)")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
