#!/usr/bin/env python3
"""Assert the figures quoted in the README and docs match reality.

"No invented numbers": a badge or a sentence that says "9 industry sectors" or "eval 67/67" is a
claim, and a claim nobody checks drifts the first time the code moves. The sibling harness repo
found its own docs quoting stale figures in several files at once before this kind of gate existed.

Reality is computed, never typed:

  version              security-audit/SKILL.md metadata.version
  selftest_checks      checks in tests/selftest.py, from eval/results/latest.json (both editions equal)
  eval_passed/_total   eval/run_eval.py summary, from eval/results/latest.json
  detect_precision_pct / detect_recall_pct
                       sector detection, micro precision / recall over the eval fixtures, in %
  sectors              industry sectors detect_stack.py can report - derived twice (the
                       recommendation code and the signal tables) and the two must agree
  feeds                advisory feeds threat_intel.py reads (FEED_NAMES)
  standards            canonical standard names the validator accepts (validate_findings.CANON)
  standards_modules    reference/standards/*.md modules (index.md excluded)
  scanners             pinned scanner images (run_scanners.IMAGES)
  bench_*              live benchmark headline, from benchmark/results/results.json (bench.py
                       report), only when that file exists: for the current skill version
                       (bench_recall_pct, bench_cost_usd, bench_minutes, bench_runs) and the
                       baseline it was compared with (the same keys with _baseline)

`--write` stores these in docs/numbers.json for anyone who wants to quote them; the default run
also fails when docs/numbers.json exists and is stale.

Where claims are found (README.md, README.ja.md, docs/**/*.md, eval/README*.md, benchmark/*.md;
never a CHANGELOG, whose figures are a record of their own release):

  1. shields.io badges, by label: `img.shields.io/badge/<label>-<message>-<colour>`
       selftest-184%2F184   eval-67%2F67   sectors-9   advisory%20feeds-8   standards-59
       scanners-8   version-v1.15.0   recall-NN%25 (benchmark)   detection-100%25 (sector recall)
     Japanese labels are accepted too (業種, 基準, フィード, セルフテスト, 評価).
  2. inline markers, for any key, in prose or tables: `<!--n:sectors-->9<!--/n-->`
  3. common English and Japanese phrasings: "9 industry sectors", "8 advisory feeds",
     "59 standards", "15 standards modules", "8 pinned scanners", "184 self-test checks",
     "eval 67/67", "9 業種", "8 つのフィード", "59 の基準".

A missing README is a warning, not a failure, so the docs can land after the tooling.

    python scripts/check_numbers.py            # check
    python scripts/check_numbers.py --write    # also (re)write docs/numbers.json
    python scripts/check_numbers.py --print    # print the computed numbers as JSON
"""
from __future__ import annotations

import ast
import json
import pathlib
import re
import sys
import urllib.parse

sys.dont_write_bytecode = True
for _s in (sys.stdout, sys.stderr):
    if hasattr(_s, "reconfigure"):
        _s.reconfigure(encoding="utf-8", errors="replace")

ROOT = pathlib.Path(__file__).resolve().parent.parent
SKILL = ROOT / "security-audit"
LATEST = ROOT / "eval" / "results" / "latest.json"
BENCH = ROOT / "benchmark" / "results" / "results.json"
NUMBERS = ROOT / "docs" / "numbers.json"

sys.path.insert(0, str(ROOT / "scripts"))
from package import skill_md_version  # noqa: E402


# ------------------------------------------------------------------ reality

def _literal(rel: str, name: str):
    """A module-level literal (dict / list / set) from a skill script, read with ast - the script is
    never imported, so nothing runs and no bytecode lands in the skill folder."""
    tree = ast.parse((SKILL / rel).read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name for t in node.targets):
            return ast.literal_eval(node.value)
    sys.exit(f"{rel} no longer defines {name}, so its published figure cannot be checked")


def sectors() -> list[str]:
    """Sector names detect_stack.py can report, derived two ways that must agree:
    (a) the recommendation code: keys of `sector_files` plus every `sectors["x"] =` assignment;
    (b) the signal tables: `sector_<x>` keyword signals plus `sector:<x>` dependency signals."""
    src = (SKILL / "scripts" / "detect_stack.py").read_text(encoding="utf-8")
    m = re.search(r"sector_files\s*=\s*(\{[^}]*\})", src)
    a = set(ast.literal_eval(m.group(1))) if m else set()
    a |= set(re.findall(r'sectors\["(\w+)"\]\s*=', src))
    b = set(re.findall(r'"sector_(\w+)":\s*re\.compile', src))
    b |= set(re.findall(r'\("sector:(\w+)"', src))
    if a != b:
        sys.exit(f"detect_stack.py: the recommendation code knows sectors {sorted(a)} but the signal "
                 f"tables know {sorted(b)} - one of them is a sector that can never be reported")
    return sorted(a)


def bench_numbers(version: str) -> dict:
    if not BENCH.is_file():
        return {}
    data = json.loads(BENCH.read_text(encoding="utf-8"))
    groups = data.get("groups", [])
    tag = "v" + version.replace(".", "")  # 1.15.2 -> v1152, the bench.py install name (sa-v1152)
    by_skill: dict[str, list] = {}
    for g in groups:
        by_skill.setdefault(g.get("skill", ""), []).append(g)
    cur = next((s for s in by_skill if s.endswith(tag)), None)
    out: dict = {}

    def mean(gs: list, field: str) -> float | None:
        xs = [(g.get(field) or {}).get("mean") for g in gs]
        xs = [x for x in xs if isinstance(x, (int, float))]
        return sum(xs) / len(xs) if xs else None

    for name, suffix in ((cur, ""), (next((s for s in by_skill if s != cur), None), "_baseline")):
        if not name:
            continue
        gs = by_skill[name]
        r, c, w = mean(gs, "recall"), mean(gs, "cost_usd"), mean(gs, "wall_s")
        if r is not None:
            out[f"bench_recall_pct{suffix}"] = round(r * 100)
        if c is not None:
            out[f"bench_cost_usd{suffix}"] = round(c, 2)
        if w is not None:
            out[f"bench_minutes{suffix}"] = round(w / 60)
        out[f"bench_runs{suffix}"] = sum(g.get("runs", 0) for g in gs)
    return out


def numbers() -> dict:
    version = skill_md_version(SKILL / "SKILL.md")
    n: dict = {"version": version}
    if LATEST.is_file():
        ev = json.loads(LATEST.read_text(encoding="utf-8"))
        st = ev.get("selftest", {})
        en, ja = st.get("selftest_en", {}), st.get("selftest_ja", {})
        if en.get("total") and en.get("total") == ja.get("total"):
            n["selftest_checks"] = en["total"]
        n["eval_passed"] = ev["summary"]["passed"]
        n["eval_total"] = ev["summary"]["total"]
        micro = ev.get("detection", {}).get("sectors", {}).get("micro", {})
        if micro:
            n["detect_precision_pct"] = round(micro["precision"] * 100)
            n["detect_recall_pct"] = round(micro["recall"] * 100)
    n["sectors"] = len(sectors())
    n["feeds"] = len(_literal("scripts/threat_intel.py", "FEED_NAMES"))
    n["standards"] = len(_literal("scripts/validate_findings.py", "CANON"))
    n["standards_modules"] = len([p for p in (SKILL / "reference" / "standards").glob("*.md") if p.name != "index.md"])
    n["scanners"] = len(_literal("scripts/run_scanners.py", "IMAGES"))
    n.update(bench_numbers(version or "0.0.0"))
    return n


# ------------------------------------------------------------------ claims

# badge label (lowercase, decoded) -> key. A pair key "a/b" means the message is "X/Y".
BADGE_LABELS = {
    "selftest": "selftest_checks/selftest_checks", "self-test": "selftest_checks/selftest_checks",
    "セルフテスト": "selftest_checks/selftest_checks",
    "eval": "eval_passed/eval_total", "offline eval": "eval_passed/eval_total", "評価": "eval_passed/eval_total",
    "sectors": "sectors", "industry sectors": "sectors", "業種": "sectors",
    "feeds": "feeds", "advisory feeds": "feeds", "threat intel feeds": "feeds", "フィード": "feeds",
    "standards": "standards", "基準": "standards",
    "standards modules": "standards_modules",
    "scanners": "scanners", "pinned scanners": "scanners",
    "version": "version", "release": "version",
    "recall": "bench_recall_pct", "benchmark recall": "bench_recall_pct", "benchmark": "bench_recall_pct",
    "detection": "detect_recall_pct", "sector detection": "detect_recall_pct",
}
BADGE = re.compile(r"img\.shields\.io/badge/([^)\s\"'<>?]+)")

MARKER = re.compile(r"<!--\s*n:([a-z_]+)\s*-->\s*([^<]*?)\s*<!--\s*/n\s*-->")

# (key, pattern with ONE numeric group, or two for a pair)
PROSE = [
    ("standards_modules", r"\b(\d+) standards modules?\b"),
    ("sectors", r"\b(\d+) (?:industry |industrial )?sectors\b"),
    ("feeds", r"\b(\d+) (?:live |public |national |global )?(?:advisory |threat[- ]intel(?:ligence)? )feeds\b"),
    ("standards", r"\b(\d+) (?:canonical |versioned )?standards\b(?! modules?)"),
    ("scanners", r"\b(\d+) pinned scanners\b"),
    ("selftest_checks", r"\b(\d+) self-?test checks\b"),
    ("eval_passed/eval_total", r"\beval (\d+) ?/ ?(\d+)\b"),
    ("sectors", r"(?<![\d.])(\d+) ?(?:の|つの)?業種"),
    ("feeds", r"(?<![\d.])(\d+) ?(?:の|つの)(?:勧告)?フィード"),
    ("standards", r"(?<![\d.])(\d+) ?(?:の|件の)基準"),
]


def claim_files() -> list[pathlib.Path]:
    files = [ROOT / "README.md", ROOT / "README.ja.md"]
    files += sorted((ROOT / "docs").rglob("*.md")) if (ROOT / "docs").is_dir() else []
    files += sorted((ROOT / "eval").glob("README*.md")) + sorted((ROOT / "benchmark").glob("*.md"))
    return [f for f in files if f.is_file() and "CHANGELOG" not in f.name]


def badge_parts(path: str) -> tuple[str, str] | None:
    """shields.io static badge path -> (label, message). '-' separates; '--' is a literal dash,
    '__' a literal underscore, '_' a space."""
    raw = path.split("?")[0]
    parts = re.split(r"(?<!-)-(?!-)", raw)
    if len(parts) < 2:
        return None
    label, message = (parts[0], parts[1]) if len(parts) >= 3 else (parts[0], parts[1])

    def dec(s: str) -> str:
        s = urllib.parse.unquote(s).replace("--", "-").replace("__", "\0").replace("_", " ").replace("\0", "_")
        return s.strip()
    return dec(label).lower(), dec(message)


def compare(key: str, said: list[str], n: dict) -> str | None:
    """None when the claim matches reality (or reality is unknown), else a reason."""
    keys = key.split("/")
    if any(k not in n for k in keys):
        return "SKIP"
    want = [str(n[k]) for k in keys]
    got = [s.lstrip("vV").rstrip("%") for s in said]
    if key == "version":
        got = [said[0].lstrip("vV")]
    return None if got == want else f"says {'/'.join(said)}, reality is {'/'.join(want)}"


def scan_text(text: str, n: dict) -> list[tuple[int, str, str]]:
    """(line, key, problem) for every claim in text that contradicts n. 'SKIP' problems are claims
    whose reality is not available here (no benchmark results yet)."""
    out = []
    raw = text
    for m in BADGE.finditer(raw):
        bp = badge_parts(m.group(1))
        if not bp or bp[0] not in BADGE_LABELS:
            continue
        key = BADGE_LABELS[bp[0]]
        nums = re.findall(r"v?\d+(?:\.\d+)*%?", bp[1])
        if not nums:
            continue
        said = nums[:2] if "/" in key else nums[:1]
        r = compare(key, said, n)
        if r:
            out.append((raw[:m.start()].count("\n") + 1, f"badge {bp[0]!r}", r))
    for m in MARKER.finditer(raw):
        key, val = m.group(1), m.group(2)
        nums = re.findall(r"v?\d+(?:\.\d+)*", val.replace(",", ""))
        if key not in n:
            out.append((raw[:m.start()].count("\n") + 1, f"marker {key}",
                        "SKIP" if key.startswith("bench_") else f"unknown key {key!r}"))
            continue
        r = compare(key, nums[:1] or [val], n)
        if r:
            out.append((raw[:m.start()].count("\n") + 1, f"marker {key}", r))
    # Prose: inline code is a quotation, not a claim - blank it, keeping offsets.
    prose = re.sub(r"`[^`\n]*`", lambda m: " " * len(m.group(0)), raw).replace("*", " ")
    for key, pat in PROSE:
        for m in re.finditer(pat, prose, re.I):
            said = [g for g in m.groups() if g]
            r = compare(key, said, n)
            if r:
                out.append((prose[:m.start()].count("\n") + 1, key, r))
    return out


def self_test(n: dict) -> list[str]:
    """Every pattern must catch a wrong figure and pass the right one; a pattern that never
    matches would let any number through."""
    dead = []
    probe = {"version": "1.15.0", "selftest_checks": 184, "eval_passed": 67, "eval_total": 67,
             "sectors": 9, "feeds": 8, "standards": 59, "standards_modules": 15, "scanners": 8,
             "bench_recall_pct": 90, "detect_recall_pct": 100}
    right = ("![s](https://img.shields.io/badge/selftest-184%2F184-green) "
             "![e](https://img.shields.io/badge/eval-67%2F67-green) "
             "![x](https://img.shields.io/badge/sectors-9-blue) "
             "![f](https://img.shields.io/badge/advisory%20feeds-8-blue) "
             "![st](https://img.shields.io/badge/standards-59-blue) "
             "![v](https://img.shields.io/badge/version-v1.15.0-blue) "
             "![r](https://img.shields.io/badge/recall-90%25-green)\n"
             "It knows 9 industry sectors, 8 advisory feeds, 59 standards, 15 standards modules, "
             "8 pinned scanners and passes 184 self-test checks and eval 67/67. 9 業種、8 つのフィード、59 の基準。"
             " <!--n:scanners-->8<!--/n--> `12 sectors` is a quotation.\n")
    if scan_text(right, probe):
        dead.append(f"correct figures are reported: {scan_text(right, probe)}")
    wrong = {
        "selftest badge": "![s](https://img.shields.io/badge/selftest-183%2F184-green)",
        "eval badge": "![e](https://img.shields.io/badge/eval-66%2F67-green)",
        "sectors badge": "![x](https://img.shields.io/badge/sectors-8-blue)",
        "feeds badge": "![f](https://img.shields.io/badge/advisory%20feeds-7-blue)",
        "standards badge": "![st](https://img.shields.io/badge/standards-58-blue)",
        "version badge": "![v](https://img.shields.io/badge/version-v1.14.0-blue)",
        "recall badge": "![r](https://img.shields.io/badge/recall-80%25-green)",
        "sectors prose": "covers 8 industry sectors",
        "feeds prose": "reads 9 advisory feeds",
        "standards prose": "cites 60 standards",
        "modules prose": "ships 14 standards modules",
        "scanners prose": "runs 7 pinned scanners",
        "selftest prose": "183 self-test checks",
        "eval prose": "eval 66/67",
        "sectors ja": "10 業種",
        "feeds ja": "7 つのフィード",
        "standards ja": "58 の基準",
        "marker": "<!--n:sectors-->8<!--/n-->",
    }
    for label, text in wrong.items():
        if not [p for p in scan_text(text, probe) if p[2] != "SKIP"]:
            dead.append(f"{label}: a wrong figure is not reported")
    if n.get("sectors", 0) < 2 or n.get("feeds", 0) < 2 or n.get("standards", 0) < 10:
        dead.append(f"a computed figure is implausibly small: {n}")
    return dead


def main() -> int:
    n = numbers()
    if "--print" in sys.argv:
        print(json.dumps(n, indent=1, ensure_ascii=False))
        return 0
    print("  computed (from the code and the committed results):")
    for k, v in n.items():
        print(f"    {k:<24} {v}")
    if not LATEST.is_file():
        print("  warn  eval/results/latest.json is missing - run eval/run_eval.py; eval and selftest "
              "figures cannot be checked")
    dead = self_test(n)
    if dead:
        print("\n  DEAD CHECKS - these would pass any figure:")
        for d in dead:
            print(f"    {d}")
        return 1

    bad = 0
    if "--write" in sys.argv:
        NUMBERS.parent.mkdir(parents=True, exist_ok=True)
        NUMBERS.write_text(json.dumps(n, indent=1, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")
        print(f"  wrote {NUMBERS.relative_to(ROOT).as_posix()}")
    elif NUMBERS.is_file():
        have = json.loads(NUMBERS.read_text(encoding="utf-8"))
        stale = {k: (have.get(k), v) for k, v in n.items() if have.get(k) != v}
        if stale:
            bad += 1
            print(f"  MISMATCH  docs/numbers.json is stale: {stale} - run with --write")

    files = claim_files()
    if not (ROOT / "README.md").is_file():
        print("  warn  README.md does not exist yet - nothing to check there (skipped)")
    print("\n  documents:")
    skipped = 0
    for f in files:
        rel = f.relative_to(ROOT).as_posix()
        for line, what, why in scan_text(f.read_text(encoding="utf-8"), n):
            if why == "SKIP":
                skipped += 1
                print(f"    skip      {rel}:{line}  {what}: no benchmark results to check it against")
                continue
            bad += 1
            print(f"    MISMATCH  {rel}:{line}  {what}: {why}")
    if bad:
        print(f"\n  {bad} figure(s) contradict reality. Fix the doc, or the code if the doc is right.")
        return 1
    print(f"    {len(files)} document(s) checked, every figure matches"
          + (f" ({skipped} benchmark claim(s) skipped)" if skipped else "") + ".")
    return 0


if __name__ == "__main__":
    sys.exit(main())
