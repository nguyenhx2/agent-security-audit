#!/usr/bin/env python3
"""Offline eval suite for the security-audit skill. No API key, no network, no Docker: runs in CI.

The live benchmark (benchmark/bench.py) answers "does a real audit find the real bugs, and at what
cost". It needs Claude, money and an hour, so it cannot gate a pull request. This answers the
question CI CAN answer on every push: do the deterministic parts the audit stands on still do what
the skill says they do? Every part is a claim the README or SKILL.md makes.

  gates      selftest of both editions (each prints "N/M checks passed"; both must be complete),
             edition parity (scripts/check_editions.py), and the harness skill linter
             (eval/vendor/skill-check.py --published) on the English edition
  detect     detect_stack.py on small synthetic repositories, one per industry sector plus
             negatives that use sector-like words (an Azure SDK full of `Sku`, a plain API). The
             expected sector set must match EXACTLY - a false sector adds a standards module and
             questions the user did not need. Scored as precision and recall per sector.
  platform   platform_inventory.py on synthetic deployments: a PHP version pinned through a
             Dockerfile ARG, an admin tool and a published datastore port in compose, a .env and
             phpinfo() under the web root, a serverless runtime, and a hardened negative on which no
             exposure signal may fire. Scored per signal class.
  intel      threat_intel.py against offline copies of every advisory feed (eval/fixtures/feeds/),
             one of them answering with an HTML error page and one carrying hostile text: the KEV +
             national-alert match on the exact deployed version, end-of-life cycles, a failed feed
             reported as a gap, hostile feed text sanitised, and an offline run with an empty cache
             that must still exit 0 with every feed a gap.

Expectations live in eval/cases.json, written as what is TRUE of each fixture. Fixtures are copied
to a temporary folder before scanning, so neither the enclosing git repository nor this checkout's
state can change what the scripts see.

Writes eval/results/latest.json (deterministic: no timestamps, no paths) and prints a summary
ending in "eval N/M". Exit 0 only when every check passes.

    python eval/run_eval.py                  # everything (about 2-4 minutes, the selftests dominate)
    python eval/run_eval.py --no-selftest    # skip the two selftests; results go to eval/results/tmp/
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
for _s in (sys.stdout, sys.stderr):
    if hasattr(_s, "reconfigure"):
        _s.reconfigure(encoding="utf-8", errors="replace")

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent
FIX = HERE / "fixtures"
EN = ROOT / "security-audit"
JA = ROOT / "editions" / "ja" / "security-audit"
S = EN / "scripts"
PY = sys.executable
BIDI = chr(0x202E) + chr(0x200B)  # right-to-left override + zero-width space, injected at copy time
SELFTEST_LINE = re.compile(r"^(\d+)/(\d+) checks passed", re.M)

CHECKS: list[dict] = []


def check(part: str, name: str, ok: bool, detail: str = "") -> bool:
    CHECKS.append({"part": part, "name": name, "ok": bool(ok), "detail": "" if ok else detail[:400]})
    print(f"  {'PASS' if ok else 'FAIL'}  [{part}] {name}" + ("" if ok or not detail else f"  -- {detail[:300]}"))
    return bool(ok)


def run(args: list, timeout: int = 900) -> subprocess.CompletedProcess:
    env = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONDONTWRITEBYTECODE="1")
    return subprocess.run([PY, "-B", *map(str, args)], capture_output=True, text=True, encoding="utf-8",
                          errors="replace", env=env, timeout=timeout)


def copy_fixture(rel: str, dest: pathlib.Path) -> pathlib.Path:
    out = dest / rel.replace("/", "__")
    shutil.copytree(FIX / rel, out)
    return out


# ------------------------------------------------------------------ gates

def selftest(edition: str, skill: pathlib.Path) -> dict:
    r = run([skill / "tests" / "selftest.py"], timeout=1800)
    m = SELFTEST_LINE.search(r.stdout)
    passed, total = (int(m.group(1)), int(m.group(2))) if m else (0, 0)
    failed = [ln[6:].strip() for ln in r.stdout.splitlines() if ln.startswith("FAIL")]
    return {"edition": edition, "passed": passed, "total": total, "rc": r.returncode,
            "failed": failed[:10], "tail": (r.stdout + r.stderr)[-400:]}


def gates(do_selftest: bool) -> dict:
    out: dict = {}
    if do_selftest:
        with cf.ThreadPoolExecutor(2) as ex:
            res = list(ex.map(lambda a: selftest(*a), (("en", EN), ("ja", JA))))
        for r in res:
            out[f"selftest_{r['edition']}"] = {"passed": r["passed"], "total": r["total"]}
            check("gates", f"selftest {r['edition']}: {r['passed']}/{r['total']} checks passed",
                  r["rc"] == 0 and r["total"] > 0 and r["passed"] == r["total"],
                  f"rc={r['rc']} failed={r['failed']} {r['tail']}")
        check("gates", "selftest: both editions run the same number of checks",
              res[0]["total"] == res[1]["total"], f"en={res[0]['total']} ja={res[1]['total']}")
    r = run([ROOT / "scripts" / "check_editions.py"])
    check("gates", "edition parity (check_editions.py)", r.returncode == 0, r.stdout[-400:])
    r = run([HERE / "vendor" / "skill-check.py", "--published", "--skill", EN])
    m = re.search(r"(\d+) finding\(s\)", r.stdout)
    check("gates", "skill linter (skill-check.py --published) on the English edition",
          r.returncode == 0 and m is not None and m.group(1) == "0", r.stdout[-400:])
    return out


# ------------------------------------------------------------------ scoring

def score(per_case: list[tuple[set, set]], universe: set) -> dict:
    """Micro and per-class precision / recall over (expected, predicted) pairs, restricted to the
    classes the cases state an expectation about."""
    cls = {c: {"tp": 0, "fp": 0, "fn": 0} for c in sorted(universe)}
    for expected, predicted in per_case:
        for c in universe:
            e, p = c in expected, c in predicted
            if e and p:
                cls[c]["tp"] += 1
            elif p:
                cls[c]["fp"] += 1
            elif e:
                cls[c]["fn"] += 1

    def pr(tp: int, fp: int, fn: int) -> dict:
        return {"precision": round(tp / (tp + fp), 3) if tp + fp else 1.0,
                "recall": round(tp / (tp + fn), 3) if tp + fn else 1.0, "tp": tp, "fp": fp, "fn": fn}
    tot = {k: sum(v[k] for v in cls.values()) for k in ("tp", "fp", "fn")}
    return {"micro": pr(**tot), "classes": {c: pr(**v) for c, v in cls.items()}}


# ------------------------------------------------------------------ detect

def detect(cases: list[dict], tmp: pathlib.Path) -> dict:
    pairs = []
    universe: set = set()
    for c in cases:
        repo = copy_fixture(c["fixture"], tmp)
        r = run([S / "detect_stack.py", repo, "--format", "json"])
        try:
            rec = json.loads(r.stdout)[0]["recommendations"]
        except (ValueError, IndexError, KeyError):
            rec = {"sectors": {}, "standards_modules": []}
            check("detect", f"{c['fixture']}: detect_stack.py ran", False, r.stderr[-300:])
        got = set(rec.get("sectors", {}))
        want = set(c.get("sectors", []))
        universe |= want | got
        pairs.append((want, got))
        name = c["fixture"].split("/", 1)[1]
        check("detect", f"{name}: sectors {sorted(want) or 'none'}", got == want,
              f"got {sorted(got)} ({c.get('why', '')})")
        mods = set(rec.get("standards_modules", []))
        for m in c.get("modules", []):
            check("detect", f"{name}: module {m} selected", m in mods, f"modules {sorted(mods)}")
        for m in c.get("absent_modules", []):
            check("detect", f"{name}: module {m} not selected", m not in mods, f"modules {sorted(mods)}")
    return score(pairs, universe)


# ------------------------------------------------------------------ platform

def platform(cases: list[dict], tmp: pathlib.Path) -> dict:
    pairs = []
    universe: set = set()
    comp_hit = comp_total = 0
    for c in cases:
        repo = copy_fixture(c["fixture"], tmp)
        out = tmp / ("out-" + repo.name) / "platform.md"
        r = run([S / "platform_inventory.py", repo, "--out", out])
        try:
            pj = json.loads((out.parent / "platform.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            pj = {}
            check("platform", f"{c['fixture']}: platform_inventory.py ran", False, r.stderr[-300:])
        comps = {(x["product"], x["version"], x["context"]) for x in pj.get("components", [])}
        sigs = {x["id"] for x in pj.get("signals", [])}
        name = c["fixture"].split("/", 1)[1]
        for prod, ver, ctx in c.get("components", []):
            comp_total += 1
            ok = check("platform", f"{name}: component {prod} {ver} ({ctx})", (prod, ver, ctx) in comps,
                       f"components {sorted(comps)}")
            comp_hit += ok
        want = set(c.get("signals", []))
        absent = set(c.get("absent_signals", []))
        for s in sorted(want):
            check("platform", f"{name}: signal {s}", s in sigs, f"signals {sorted(sigs)}")
        for s in sorted(absent):
            check("platform", f"{name}: no signal {s}", s not in sigs, f"signals {sorted(sigs)}")
        scope = want | absent
        universe |= scope
        pairs.append((want, sigs & scope))
    res = score(pairs, universe)
    res["components"] = {"recall": round(comp_hit / comp_total, 3) if comp_total else 1.0,
                         "found": comp_hit, "expected": comp_total}
    return res


# ------------------------------------------------------------------ intel

def intel(spec: dict, tmp: pathlib.Path) -> None:
    repo = copy_fixture(spec["fixture"], tmp)
    feeds = tmp / "feeds"
    feeds.mkdir()
    for f in sorted((FIX / spec["feeds"]).iterdir()):
        (feeds / f.name).write_text(f.read_text(encoding="utf-8").replace("{BIDI}", BIDI),
                                    encoding="utf-8", newline="\n")
    work = tmp / "intel-work"
    r = run([S / "platform_inventory.py", repo, "--out", work / "app" / "platform.md"])
    check("intel", "platform inventory of the deployment", r.returncode == 0, r.stderr[-300:])
    r = run([S / "threat_intel.py", "--platform", work / "app" / "platform.json", "--out", work / "intel.md",
             "--feeds-dir", feeds, "--today", spec["today"]])
    try:
        ij = json.loads((work / "intel.json").read_text(encoding="utf-8"))
        md = (work / "intel.md").read_text(encoding="utf-8")
    except (OSError, ValueError):
        ij, md = {}, ""
    check("intel", "threat_intel.py exits 0 with offline feeds", r.returncode == 0 and bool(ij), r.stderr[-300:])
    comps = ij.get("components", [])
    php = next((c for c in comps if c.get("product") == "php" and c.get("version") == "8.3.30"), {})
    cves = php.get("cves", [])
    check("intel", "php 8.3.30: KEV + national alert on the exact deployed version -> act-now",
          php.get("priority") == "act-now" and php.get("status") == "behind", json.dumps(php)[:300])
    check("intel", "php 8.3.30: KEV CVE ranked first, with its EPSS score",
          [x.get("id") for x in cves][:2] == ["CVE-2026-0001", "CVE-2026-0002"]
          and bool(cves) and cves[0].get("kev") and cves[0].get("epss") == 0.97, json.dumps(cves)[:300])
    check("intel", "php 8.3.30: CVEs outside the window are counted, not listed",
          php.get("cve_total") == 3 and all(x.get("id") != "CVE-2025-0003" for x in cves), json.dumps(php)[:300])
    my = next((c for c in comps if c.get("product") == "mysql"), {})
    check("intel", "mysql 5.7: end of life", my.get("status") == "eol", json.dumps(my)[:200])
    rng = next((c for c in comps if c.get("version") == "^8.1"), {})
    check("intel", "php ^8.1 constraint: judged by its lowest cycle (range allows EOL)",
          rng.get("status") == "range-allows-eol" and "CVE-2026-0001" in (rng.get("alert_cves_unconfirmed") or []),
          json.dumps(rng)[:300])
    fs = {f.get("name"): f.get("status") for f in ij.get("feeds", [])}
    check("intel", "an HTML error page from a feed is a stated gap, never a pass",
          fs.get("jvndb") == "failed" and any("JVN iPedia" in g for g in ij.get("gaps", [])), json.dumps(fs))
    check("intel", "healthy feeds parsed (KEV, IPA, JPCERT/CC)",
          fs.get("kev") == "ok" and fs.get("ipa") == "ok" and fs.get("jpcert") == "ok", json.dumps(fs))
    check("intel", "hostile feed text sanitised: no bidi / zero-width characters, no foreign links",
          bool(md) and chr(0x202E) not in md and chr(0x200B) not in md and "evil.example" not in md)
    check("intel", "alert window applied (the 2025 alert is dropped) and feed text marked untrusted",
          bool(md) and "very old" not in md and "untrusted data" in md.lower())
    check("intel", "dependency named in KEV matched (guzzle)",
          any(d.get("dep") == "guzzle" for d in ij.get("dependency_alerts", [])),
          json.dumps(ij.get("dependency_alerts", []))[:200])
    r = run([S / "threat_intel.py", "--platform", work / "app" / "platform.json", "--out",
             tmp / "offline" / "intel.md", "--offline", "--cache-dir", tmp / "empty-cache"])
    try:
        oj = json.loads((tmp / "offline" / "intel.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        oj = {}
    failed = sum(1 for f in oj.get("feeds", []) if f.get("status") == "failed")
    check("intel", "offline with an empty cache: exit 0, every feed a stated gap, no network",
          r.returncode == 0 and failed >= 5 and all(f.get("status") in ("failed", "skipped")
                                                    for f in oj.get("feeds", [])), r.stdout[-200:])


# ------------------------------------------------------------------ main

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--no-selftest", action="store_true", help="skip both selftests (results go to eval/results/tmp/)")
    ap.add_argument("--out", help="results file (default eval/results/latest.json)")
    a = ap.parse_args()
    cases = json.loads((HERE / "cases.json").read_text(encoding="utf-8"))

    print("gates")
    selftests = gates(not a.no_selftest)
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="sa-eval "))  # a space in the path on purpose
    try:
        print("detect")
        det = detect(cases["detect"], tmp)
        print("platform")
        plat = platform(cases["platform"], tmp)
        print("intel")
        intel(cases["intel"], tmp)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    parts: dict = {}
    for c in CHECKS:
        p = parts.setdefault(c["part"], {"passed": 0, "total": 0})
        p["total"] += 1
        p["passed"] += c["ok"]
    passed = sum(1 for c in CHECKS if c["ok"])
    total = len(CHECKS)
    results = {
        "skill_version": _skill_version(),
        "summary": {"passed": passed, "total": total},
        "parts": parts,
        "selftest": selftests,
        "detection": {"sectors": det, "platform_signals": {k: v for k, v in plat.items() if k != "components"},
                      "platform_components": plat["components"]},
        "fixtures": {"detect": len(cases["detect"]), "platform": len(cases["platform"]), "intel": 1},
        "checks": CHECKS,
    }
    default = HERE / "results" / ("tmp" if a.no_selftest else "") / "latest.json"
    out = pathlib.Path(a.out) if a.out else default
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(results, indent=1, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")

    sm, sg = det["micro"], plat["micro"]
    print(f"\n  detection  sectors: precision {sm['precision']:.0%} recall {sm['recall']:.0%} "
          f"({len(det['classes'])} classes, {len(cases['detect'])} fixtures)")
    print(f"             platform signals: precision {sg['precision']:.0%} recall {sg['recall']:.0%}; "
          f"components {plat['components']['found']}/{plat['components']['expected']}")
    for k, v in selftests.items():
        print(f"  {k.replace('_', ' ')}: {v['passed']}/{v['total']}")
    print("  " + ", ".join(f"{k} {v['passed']}/{v['total']}" for k, v in parts.items()))
    print(f"  results -> {out.relative_to(ROOT).as_posix() if out.is_relative_to(ROOT) else out}")
    print(f"\neval {passed}/{total}")
    return 0 if passed == total else 1


def _skill_version() -> str | None:
    sys.path.insert(0, str(ROOT / "scripts"))
    from package import skill_md_version  # noqa: E402
    return skill_md_version(EN / "SKILL.md")


if __name__ == "__main__":
    sys.exit(main())
