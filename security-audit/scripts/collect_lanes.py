#!/usr/bin/env python3
"""
Collect lane results into one compact candidate table for the verifier (Phase 5).

Parses every `lanes/<lane>.md` (the lane-reviewer block format: `### title`, `- severity: ...
confidence: ...`, `- standard: ...`, `- location: ...`), and writes `lanes/candidates.md`:
  - one row per candidate (cid, lane, severity, confidence, title, first anchor, standard);
  - possible duplicates: candidates from different lanes that share an anchor (same file name,
    lines within 6) - verify each group once;
  - scanner candidates auto-refuted by normalize_findings.py (`../candidates.jsonl`), one line per
    reason + rule, so the verifier does not re-verify them;
  - the lanes' Refuted / Open questions / Not covered bullets, prefixed with the lane.
The verifier reads this file instead of every lane file and opens a lane block only for detail.

Usage:
  python collect_lanes.py <audit_dir>/<repo>/lanes [--out <lanes>/candidates.md] [--min P2]
Exit 1 when no candidate block was found (a lane file in the wrong format).
"""
from __future__ import annotations

import sys
sys.dont_write_bytecode = True  # keep the installed skill free of __pycache__
for _s in (sys.stdout, sys.stderr):  # UTF-8 output even on cp932 / cp1252 consoles and pipes
    if hasattr(_s, "reconfigure"):
        _s.reconfigure(encoding="utf-8", errors="replace")

import argparse
import json
import re
from pathlib import Path

SEV_ORDER = {"P0": 0, "P1": 1, "P2": 2, "Info": 3}
SKIP = {"verifier.md", "candidates.md"}
# `path:line`; inside backticks the path may contain spaces (`src/My Component/form.tsx:10`)
ANCHOR = re.compile(r"`([^`\n]*?(?:[\w-]\.[\w]+|Dockerfile|Makefile|Jenkinsfile)):(\d+)"
                    r"|([\w./\\-]*[\w-]\.[\w]+|Dockerfile|Makefile|Jenkinsfile):(\d+)")
SECTIONS = ("Refuted", "Hardening", "Open questions", "Not covered")
# fixed, stable lane prefixes (a lane group file "x+y" gets the prefixes joined)
PREFIX = {"authz-logic": "a", "injection-dataflow": "i", "sensitive-data": "d", "ai-agentic": "g",
          "supply-chain-infra": "s", "mobile": "m", "perf-quality": "p"}


def host_path(p: str) -> str:
    m = re.match(r"^/([a-zA-Z])/(.*)$", p)
    return f"{m.group(1).upper()}:/{m.group(2)}" if m and sys.platform == "win32" else p


def parse(path: Path, prefix: str):
    text = path.read_text(encoding="utf-8", errors="replace")
    cands, extras = [], {s: [] for s in SECTIONS}
    blocks = re.split(r"(?m)^(#{2,3} .+)$", text)
    for i in range(1, len(blocks), 2):
        head, body = blocks[i], blocks[i + 1]
        if head.startswith("## "):
            name = head[3:].strip()
            for s in SECTIONS:
                if name.lower().startswith(s.lower()):
                    extras[s] += [ln.strip()[2:].strip() for ln in body.splitlines() if ln.strip().startswith("- ")]
            continue
        sev = re.search(r"severity:\s*\**(P0|P1|P2|Info)\b", body)
        if not sev:
            continue
        conf = re.search(r"confidence:\s*\**([a-z-]+)", body)
        std = re.search(r"(?m)^- standard:\s*(.+)$", body)
        loc = re.search(r"(?m)^- location:\s*(.+)$", body)
        bnd = re.search(r"(?m)^- boundary:\s*(.+)$", body)
        anchors = [(Path(f.replace("\\", "/")).name, int(n), f) for f, n in ((a or c, b or d) for a, b, c, d in ANCHOR.findall(loc.group(1) if loc else ""))]
        title = re.sub(r"^###\s*(\d+\.\s*)?", "", head).strip()
        cands.append({"cid": f"{prefix}{len(cands) + 1}", "lane": path.stem, "sev": sev.group(1),
                      "conf": conf.group(1) if conf else "?", "title": title,
                      "anchor": f"{anchors[0][2]}:{anchors[0][1]}" if anchors else "-",
                      "anchors": anchors, "std": (std.group(1).strip() if std else "-"),
                      "boundary": bnd.group(1).strip() if bnd else "-"})
    return cands, extras


def dup_groups(cands):
    """Group candidates from different lanes whose PRIMARY anchors (first `path:line`, normally the
    sink) are in the same file within 6 lines. Secondary anchors are context and would chain
    unrelated findings together, so they are not used."""
    groups: list[list[int]] = []
    for i, c in enumerate(cands):
        if not c["anchors"]:
            continue
        f, ln, _ = c["anchors"][0]
        for g in groups:
            gf, gl, _ = cands[g[0]]["anchors"][0]
            if gf == f and abs(gl - ln) <= 6 and c["lane"] not in {cands[k]["lane"] for k in g}:
                g.append(i)
                break
        else:
            groups.append([i])
    return [g for g in groups if len(g) > 1]


def cell(s: str, n: int = 110) -> str:
    s = s.replace("|", "/").replace("\n", " ")
    return s if len(s) <= n else s[: n - 3] + "..."


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("lanes_dir")
    ap.add_argument("--out")
    ap.add_argument("--min", default="P2", choices=["P0", "P1", "P2", "Info"],
                    help="lowest severity listed in the table (Deep: P2, Standard: P1)")
    a = ap.parse_args()
    d = Path(host_path(a.lanes_dir))
    files = sorted(f for f in d.glob("*.md") if f.name not in SKIP)
    cands, extras_all, prefixes = [], [], {}
    for f in files:
        p = "".join(PREFIX.get(x, x[:1]) for x in f.stem.split("+"))
        while p in prefixes.values():
            p += "x"
        prefixes[f.stem] = p
        c, ex = parse(f, p)
        cands += c
        extras_all.append((f.stem, ex))
    if not cands:
        print(f"error: no candidate blocks found in {d}", file=sys.stderr)
        return 1
    limit = SEV_ORDER[a.min]
    listed = [c for c in cands if SEV_ORDER[c["sev"]] <= limit]
    listed.sort(key=lambda c: (SEV_ORDER[c["sev"]], c["anchor"]))
    counts = {s: sum(1 for c in cands if c["sev"] == s) for s in SEV_ORDER}
    out = [f"# Lane candidates ({len(cands)} blocks from {len(files)} lanes: "
           + ", ".join(f"{k} {v}" for k, v in counts.items()) + ")", "",
           f"Rows: {a.min} and above. Detail: `{d.as_posix()}/<lane>.md`, block with the same title. "
           "Lane prefixes: " + ", ".join(f"{p} = {s}" for s, p in prefixes.items()), "",
           "| cid | lane | sev | conf | title | first anchor | standard | boundary |",
           "|-----|------|-----|------|-------|--------------|----------|----------|"]
    for c in listed:
        out.append(f"| {c['cid']} | {c['lane']} | {c['sev']} | {c['conf']} | {cell(c['title'])} | "
                   f"`{cell(c['anchor'], 80)}` | {cell(c['std'], 90)} | {cell(c.get('boundary', '-'), 90)} |")
    groups = [g for g in dup_groups(listed)]
    out += ["", "## Possible duplicates (shared anchors across lanes - verify once, merge by remedy)"]
    out += [f"- {', '.join(listed[i]['cid'] for i in g)}: `{listed[g[0]]['anchor']}`" for g in groups] or ["- none detected"]
    below = [c for c in cands if limit < SEV_ORDER[c["sev"]] < 3]
    if below:
        out += ["", f"## Below verification threshold ({len(below)}) - not verified; the verifier copies them "
                "into the draft as written (confidence as given), the report states they were not verified",
                "", "| cid | lane | sev | conf | title | first anchor | standard | boundary |",
                "|-----|------|-----|------|-------|--------------|----------|----------|"]
        out += [f"| {c['cid']} | {c['lane']} | {c['sev']} | {c['conf']} | {cell(c['title'])} | "
                f"`{cell(c['anchor'], 80)}` | {cell(c['std'], 90)} | {cell(c.get('boundary', '-'), 90)} |" for c in below]
    if any(c["sev"] == "Info" for c in cands) and limit < 3:
        out += ["", "Info candidates (not verified): " + "; ".join(
            f"{c['cid']} {cell(c['title'], 70)}" for c in cands if c["sev"] == "Info")]
    jl = d.parent / "candidates.jsonl"  # scanner candidates refuted by rule in normalize_findings.py
    auto = [json.loads(ln) for ln in jl.read_text(encoding="utf-8").splitlines() if '"auto_refuted"' in ln] \
        if jl.is_file() else []
    if auto:
        grp: dict = {}
        for c in auto:
            grp.setdefault((c["auto_refuted"], c["witnesses"][0]), []).append(c)
        out += ["", f"## Auto-refuted scanner candidates ({len(auto)}) - refuted by rule before the lanes; do not "
                "re-verify, copy each line into Refuted (`auto_refuted` in candidates.jsonl)"]
        out += [f"- {rule} x{len(cs)} - {why}: {cell(', '.join(sorted({c['file'] for c in cs})), 120)} "
                f"({', '.join(c['cid'] for c in cs[:3])}{' ...' if len(cs) > 3 else ''})"
                for (why, rule), cs in sorted(grp.items(), key=lambda kv: -len(kv[1]))]
    for s in SECTIONS:
        rows = [f"- [{lane}] {cell(x, 220)}" for lane, ex in extras_all for x in ex[s]]
        if rows:
            out += ["", f"## {s} (from lanes)"] + rows
    target = Path(host_path(a.out)) if a.out else d / "candidates.md"
    target.write_text("\n".join(out) + "\n", encoding="utf-8")
    print(f"wrote {target} - {len(listed)} rows, {len(groups)} duplicate groups")
    return 0


if __name__ == "__main__":
    sys.exit(main())
