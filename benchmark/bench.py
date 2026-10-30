#!/usr/bin/env python3
"""
Live benchmark for the security-audit skill: runs real headless Claude Code audits of public,
deliberately vulnerable repositories with two skill versions and measures cost, time, turns, findings
and recall against a fixed ground truth (CWE groups). Costs real money; never runs in CI.

Each run gets its own copy of the fixture, so concurrent runs never share an audit folder. The skill
versions are installed side by side under distinct names (sa-v1150, sa-v1152) and invoked by slash
command, so the prompt is identical apart from the name.

The fixtures are pinned: benchmark/fixtures.json names each repository and the exact commit the
published results were measured on, and `fetch` clones them at that commit. A fixture at any other
commit is a different benchmark, so `run` refuses one whose HEAD does not match the pin.

Usage:
  python benchmark/bench.py fetch   (clone the pinned fixtures into benchmark/fixtures/, gitignored)
  python benchmark/bench.py run --skill sa-v1150=<dir> --skill sa-v1152=<dir> --fixtures DVWA NodeGoat juice-shop
                      --reps 2 --parallel 3 [--depth quick] [--budget 10]
  python benchmark/bench.py report  (aggregate runs/*/result.json into results/results.json)

Requires: git, and the `claude` CLI logged in (run). Writes only under benchmark/ and installs the
compared skill versions under ~/.claude/skills/<name> for the duration of the run.
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import datetime as dt
import json
import os
import re
import shutil
import stat
import statistics as st
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
FIX = HERE / "fixtures"
RUNS = HERE / "runs"
RESULTS = HERE / "results"
PINS = HERE / "fixtures.json"
SKILLS_DIR = Path.home() / ".claude" / "skills"
# The findings of every run are validated with THIS checkout's validator, not whatever happens to be
# installed under ~/.claude/skills, so a result says the same thing on every machine.
VALIDATOR = HERE.parent / "security-audit" / "scripts" / "validate_findings.py"

# ground truth: each item is satisfied by a finding whose CWE list intersects the group
TRUTH = {
    "DVWA": {
        "SQL injection": {89}, "OS command injection": {78, 77}, "XSS": {79}, "unrestricted upload": {434},
        "CSRF": {352}, "file inclusion / traversal": {98, 22, 73}, "brute force / weak login": {307, 1390, 521, 799},
        "default or hard-coded credentials": {798, 259, 1392, 1393, 521}, "weak session id": {330, 331, 340, 384},
        "outdated / EOL runtime or image": {1104, 1395, 937},
    },
    "NodeGoat": {
        "server-side JS injection (eval)": {94, 95}, "NoSQL injection": {943}, "XSS": {79}, "SSRF": {918},
        "open redirect": {601}, "IDOR / missing authz": {639, 862, 863, 285}, "CSRF": {352},
        "ReDoS": {1333, 400, 185}, "weak password storage": {916, 256, 257, 328, 759},
        "outdated / EOL runtime or image": {1104, 1395, 937},
    },
    "juice-shop": {
        "SQL injection": {89}, "XSS": {79}, "NoSQL injection": {943}, "hard-coded secret / key": {798, 321, 547},
        "XXE": {611}, "path traversal": {22, 23}, "SSRF": {918}, "broken access control": {639, 862, 863, 285},
        "weak password hashing": {916, 328, 759}, "open redirect": {601},
    },
}


def rmtree(p: Path) -> None:
    """shutil.rmtree that also removes read-only files (git packs on Windows)."""
    def clear(func, path, _exc):
        os.chmod(path, stat.S_IWRITE)
        func(path)
    if sys.version_info >= (3, 12):
        shutil.rmtree(p, onexc=clear)
    else:
        shutil.rmtree(p, onerror=clear)


def install(name: str, src: Path) -> None:
    dst = SKILLS_DIR / name
    if dst.exists():
        rmtree(dst)
    shutil.copytree(src, dst, ignore=shutil.ignore_patterns("tests", "__pycache__", "*.pyc"))
    sk = dst / "SKILL.md"
    t = sk.read_text(encoding="utf-8")
    sk.write_text(re.sub(r"(?m)^name: .*$", f"name: {name}", t, count=1), encoding="utf-8", newline="\n")


def one(run_id: str, skill: str, fixture: str, depth: str, budget: float) -> dict:
    d = RUNS / run_id
    if (d / "result.json").exists():
        done = json.loads((d / "result.json").read_text(encoding="utf-8"))
        if done.get("cost_usd") is not None and not done.get("is_error"):  # killed or aborted run: redo it
            return done
    if d.exists():
        rmtree(d)
    d.mkdir(parents=True)
    repo = d / fixture
    shutil.copytree(FIX / fixture, repo)
    prompt = (f"/{skill} {repo.as_posix()} {depth} --yes\n"
              "Report language: English. Formats: Markdown only.")
    t0 = time.time()
    p = subprocess.run(["claude", "-p", prompt, "--output-format", "json", "--permission-mode",
                        "bypassPermissions", "--max-budget-usd", str(budget)], cwd=d, capture_output=True,
                       text=True, encoding="utf-8", errors="replace", timeout=5400)
    wall = time.time() - t0
    (d / "claude.json").write_text(p.stdout, encoding="utf-8")
    (d / "claude.err").write_text(p.stderr[-20000:], encoding="utf-8")
    try:
        cj = json.loads(p.stdout)
    except ValueError:
        cj = {}
    if cj.get("total_cost_usd") is None or cj.get("is_error"):  # killed, aborted or crashed: no result.json,
        raise RuntimeError(f"claude exited {p.returncode} ({cj.get('subtype')}) after {round(wall)}s")  # retried next time
    res = {"run": run_id, "skill": skill, "fixture": fixture, "depth": depth, "rc": p.returncode,
           "wall_s": round(wall), "cost_usd": cj.get("total_cost_usd"), "turns": cj.get("num_turns"),
           "duration_ms": cj.get("duration_ms"), "is_error": cj.get("is_error"),
           "usage": cj.get("usage"), "model_usage": cj.get("modelUsage")}
    res.update(analyse(d, fixture))
    (d / "result.json").write_text(json.dumps(res, indent=1), encoding="utf-8")
    return res


def analyse(d: Path, fixture: str) -> dict:
    # only the timestamped audit folders (YYYY-MM-DD_HHMM): a run may leave a helper folder beside them
    # (a "snapshot-..." copy of the repo), which sorts after them and holds no findings
    audits = sorted(p for p in d.glob("*-security-audit/*/") if re.match(r"\d{4}-\d{2}-\d{2}_\d{4}", p.name))
    out = {"audit_dir": audits[-1].relative_to(HERE).as_posix() if audits else None}
    if not audits:
        return out | {"findings": 0}
    a = audits[-1]
    files = [f for f in a.rglob("findings/**/*.md")]
    sev, cwes, titles = {}, [], []
    for f in files:
        t = f.read_text(encoding="utf-8", errors="replace")
        m = re.search(r"(?m)^severity:\s*(\S+)", t)
        sev[m.group(1) if m else "?"] = sev.get(m.group(1) if m else "?", 0) + 1
        cw = {int(x) for x in re.findall(r"CWE-(\d+)", t.split("\n## ")[0])}
        cwes.append(cw)
        h = re.search(r"(?m)^# (.+)$", t)
        titles.append(h.group(1) if h else f.stem)
    hit = {k: any(g & c for c in cwes) for k, g in TRUTH.get(fixture, {}).items()}
    rep = sorted(a.glob("reports/md/*.md"))
    rtxt = rep[-1].read_text(encoding="utf-8", errors="replace") if rep else ""
    work = a / "work"
    v = None
    if rep:
        vp = subprocess.run([sys.executable, "-B", str(VALIDATOR),
                             str(a / "findings" / "en"), "--report", str(rep[-1])], capture_output=True, text=True,
                            encoding="utf-8", errors="replace")
        v = vp.returncode
    return out | {
        "findings": len(files), "severity": sev, "titles": titles,
        "truth_hits": hit, "recall": round(sum(hit.values()) / len(hit), 3) if hit else None,
        "report": bool(rep), "validate_rc": v,
        "intel_section": "Platform versions and threat intelligence" in rtxt,
        "platform_json": any(work.rglob("platform.json")) if work.exists() else False,
        "intel_json": (work / "intel.json").exists(),
    }


def pins() -> dict:
    return json.loads(PINS.read_text(encoding="utf-8"))["fixtures"]


def head(repo: Path) -> str:
    r = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"], capture_output=True, text=True)
    return r.stdout.strip() if r.returncode == 0 else ""


def cmd_fetch(a) -> int:
    """Clone each pinned fixture and check out its commit. Idempotent: a fixture already at its pin
    is left alone; one at another commit is re-checked-out."""
    FIX.mkdir(parents=True, exist_ok=True)
    bad = 0
    for name, pin in pins().items():
        dest = FIX / name
        if not dest.exists():
            print(f"clone {name} <- {pin['url']}", flush=True)
            r = subprocess.run(["git", "clone", "--quiet", "--no-checkout", pin["url"], str(dest)])
            if r.returncode != 0:
                print(f"FAILED to clone {name}", flush=True)
                bad += 1
                continue
        if head(dest) != pin["commit"]:
            subprocess.run(["git", "-C", str(dest), "fetch", "--quiet", "origin", pin["commit"]])
            subprocess.run(["git", "-C", str(dest), "-c", "advice.detachedHead=false", "checkout",
                            "--quiet", "--force", pin["commit"]])
        ok = head(dest) == pin["commit"]
        bad += not ok
        print(f"{'ok  ' if ok else 'FAIL'}  {name} @ {head(dest)[:12] or '?'} (pin {pin['commit'][:12]})", flush=True)
    return 1 if bad else 0


def cmd_run(a) -> int:
    pinned = pins()
    for fx in a.fixtures:
        if fx not in pinned:
            print(f"error: {fx} is not in benchmark/fixtures.json", file=sys.stderr)
            return 2
        if head(FIX / fx) != pinned[fx]["commit"]:
            print(f"error: benchmark/fixtures/{fx} is not at its pinned commit - run `bench.py fetch`",
                  file=sys.stderr)
            return 2
    skills = dict(s.split("=", 1) for s in a.skill)
    for name, src in skills.items():
        install(name, Path(src))
    jobs = [(f"{name}_{fx}_{r}", name, fx) for r in range(1, a.reps + 1) for fx in a.fixtures for name in skills]
    print(f"{len(jobs)} runs, {a.parallel} in parallel", flush=True)
    with cf.ThreadPoolExecutor(a.parallel) as ex:
        futs = {ex.submit(one, rid, sk, fx, a.depth, a.budget): rid for rid, sk, fx in jobs}
        for f in cf.as_completed(futs):
            try:
                r = f.result()
                print(f"done {r['run']}: ${r.get('cost_usd')} {r.get('turns')} turns {r['wall_s']}s "
                      f"findings={r.get('findings')} recall={r.get('recall')}", flush=True)
            except Exception as e:  # noqa: BLE001
                print(f"FAILED {futs[f]}: {e!r}", flush=True)
    if not a.keep_installed:
        for name in skills:
            shutil.rmtree(SKILLS_DIR / name, ignore_errors=True)
    return 0


def agg(xs):
    xs = [x for x in xs if isinstance(x, (int, float))]
    if not xs:
        return None
    return {"mean": round(st.mean(xs), 3), "sd": round(st.stdev(xs), 3) if len(xs) > 1 else 0.0,
            "min": min(xs), "max": max(xs), "n": len(xs)}


def cmd_report(a) -> int:
    rs = [json.loads(p.read_text(encoding="utf-8")) for p in sorted(RUNS.glob("*/result.json"))]
    groups = {}
    for r in rs:
        groups.setdefault((r["skill"], r["fixture"]), []).append(r)
    table = []
    for r in rs:  # re-score with the current ground truth (only where the audit output is present)
        d = RUNS / r["run"]
        if any(d.glob("*-security-audit/*/")):
            r.update(analyse(d, r["fixture"]))
        (d / "result.json").write_text(json.dumps(r, indent=1), encoding="utf-8")
    for (sk, fx), g in sorted(groups.items(), key=lambda kv: (kv[0][1], kv[0][0])):
        hits = {}
        for r in g:
            for k, v in (r.get("truth_hits") or {}).items():
                hits[k] = hits.get(k, 0) + (1 if v else 0)
        table.append({"skill": sk, "fixture": fx, "runs": len(g), "cost_usd": agg([r.get("cost_usd") for r in g]),
                      "wall_s": agg([r.get("wall_s") for r in g]), "turns": agg([r.get("turns") for r in g]),
                      "findings": agg([r.get("findings") for r in g]), "recall": agg([r.get("recall") for r in g]),
                      "validate_ok": sum(1 for r in g if r.get("validate_rc") == 0),
                      "intel_section": sum(1 for r in g if r.get("intel_section")),
                      "truth_hit_counts": hits})
    RESULTS.mkdir(parents=True, exist_ok=True)
    (RESULTS / "results.json").write_text(json.dumps({"generated": dt.date.today().isoformat(),
                                                      "fixtures": pins(), "groups": table, "runs": rs},
                                                     indent=1), encoding="utf-8", newline="\n")
    print(f"wrote {(RESULTS / 'results.json').relative_to(HERE.parent).as_posix()}", file=sys.stderr)
    print(json.dumps(table, indent=1))
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("--skill", action="append", required=True)
    r.add_argument("--fixtures", nargs="+", default=list(TRUTH))
    r.add_argument("--reps", type=int, default=2)
    r.add_argument("--parallel", type=int, default=3)
    r.add_argument("--depth", default="quick")
    r.add_argument("--budget", type=float, default=10.0)
    r.add_argument("--keep-installed", action="store_true")
    sub.add_parser("report")
    sub.add_parser("fetch")
    a = ap.parse_args()
    return {"run": cmd_run, "report": cmd_report, "fetch": cmd_fetch}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())
