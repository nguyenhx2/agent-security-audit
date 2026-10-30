#!/usr/bin/env python3
"""Smoke-test the scanner images: each one must still find the defect planted for it.

A scanner pin decides which rules every audit runs. Before a pin moves (scripts/update_pins.py,
the weekly update-pins workflow), the candidate image has to prove two things on a fixture whose
defects are known: it still runs end to end through the skill's own runner, and it still reports
the planted defect. A new release that renames a rule, drops a check, changes its output format or
crashes on start-up fails here, not in someone's audit.

What it does:

  1. Copies eval/fixtures/scanners/tree/ into a temporary directory: drops the `.fixture` suffix,
     renames `_github` to `.github`, writes a well-formed but FAKE GitHub token (derived from a
     hash, never issued) where the placeholders are, and makes it a git repository. The files
     listed under `history_only` in expect.json are committed and then deleted, so only a history
     scan can find them.
  2. Runs security-audit/scripts/run_scanners.py (the English edition) on it in container mode,
     as the skill does, with `--pin tool=image:tag@sha256:...` for each candidate from --pins-json,
     then normalize_findings.py on the result.
  3. Checks every requested scanner against eval/fixtures/scanners/expect.json: it ran (status ok
     in scanners.json), its exit code is one that means "ran normally", its SARIF parses, and it
     reported one of the accepted rule ids (or CVE / GHSA ids) for the planted defect.

--pins-json takes the update_pins.py --json output: {"updates": [{"tool", "image", "new_tag",
"new_digest"}, ...]} (a bare list of updates is accepted too). Each becomes
`--pin tool=image:new_tag@new_digest`; tools without an update run their current pin.

Exit codes:
  0  every requested scanner ran and found its planted defect
  1  a scanner did not run, crashed, produced unparseable output or missed its defect; or the
     pins file, the fixture or the normalizer failed
  2  no container engine answers (docker / podman), or a usage error. CI treats this as failure:
     a smoke test that could not run proves nothing.

Usage:
  python scripts/smoke_scanners.py [--pins-json PATH] [--tool NAME ...] [--json OUT] [--keep]
        [--timeout 900]

  python scripts/smoke_scanners.py                          # current pins, all eight scanners
  python scripts/smoke_scanners.py --tool trivy --tool zizmor
  python scripts/smoke_scanners.py --pins-json pins.json --json smoke.json

Unit tests (offline, no container engine): python scripts/test_smoke_scanners.py
"""
from __future__ import annotations

import sys

sys.dont_write_bytecode = True
for _s in (sys.stdout, sys.stderr):
    if hasattr(_s, "reconfigure"):
        _s.reconfigure(encoding="utf-8", errors="replace")

import argparse
import ast
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import string
import subprocess
import tempfile
from pathlib import Path, PurePosixPath
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parent.parent
SKILL_SCRIPTS = ROOT / "security-audit" / "scripts"
RUN_SCANNERS = SKILL_SCRIPTS / "run_scanners.py"
NORMALIZE = SKILL_SCRIPTS / "normalize_findings.py"
FIXTURE = ROOT / "eval" / "fixtures" / "scanners"
TREE = FIXTURE / "tree"
EXPECT = FIXTURE / "expect.json"

EXIT_PASS, EXIT_FAIL, EXIT_NO_ENGINE = 0, 1, 2
FIXTURE_SUFFIX = ".fixture"
DIR_RENAMES = {"_github": ".github"}
TOKEN_PLACEHOLDER = re.compile(r"@@FAKE_GITHUB_TOKEN_([A-Z]+)@@")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
TAG = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}")  # OCI tag grammar
IMAGE = re.compile(r"[a-z0-9]+(?:[._:/-][a-z0-9]+)*")  # registry[:port]/path, lower case
GIT_DATE = "2020-01-01T00:00:00+00:00"  # fixed, so the fixture commits are reproducible


class PinError(ValueError):
    """The pins file is malformed or proposes a pin the runner must not use."""


# ------------------------------------------------------------------ the runner's own tables

def runner_literal(name: str, path: Path = RUN_SCANNERS):
    """A module-level literal from run_scanners.py, read with ast (never imported, nothing runs)."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name for t in node.targets):
            return ast.literal_eval(node.value)
    raise SystemExit(f"{path.name} no longer defines {name}; update smoke_scanners.py")


# ------------------------------------------------------------------ --pins-json -> --pin

def pins_from_updates(data, known_tools) -> dict:
    """update_pins.py --json output (or its bare `updates` list) -> {tool: image:tag@sha256:...}."""
    updates = data.get("updates") if isinstance(data, dict) else data
    if not isinstance(updates, list):
        raise PinError("pins file: expected {\"updates\": [...]} or a list of updates")
    pins: dict = {}
    for i, u in enumerate(updates):
        if not isinstance(u, dict):
            raise PinError(f"pins file: update #{i + 1} is not an object")
        tool, image, tag, digest = (u.get(k) for k in ("tool", "image", "new_tag", "new_digest"))
        where = f"pins file: update #{i + 1} ({tool!r})"
        if tool not in known_tools:
            raise PinError(f"{where}: unknown tool; known: {', '.join(sorted(known_tools))}")
        if not isinstance(image, str) or not IMAGE.fullmatch(image) or "@" in image:
            raise PinError(f"{where}: image must be a bare image name without tag or digest, got {image!r}")
        if ":" in image.rsplit("/", 1)[-1]:
            raise PinError(f"{where}: image {image!r} already carries a tag; give it in new_tag")
        if not isinstance(tag, str) or not TAG.fullmatch(tag) or tag == "latest":
            raise PinError(f"{where}: new_tag must be an explicit tag (never latest), got {tag!r}")
        if isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest):
            digest = "sha256:" + digest
        if not isinstance(digest, str) or not DIGEST.fullmatch(digest):
            raise PinError(f"{where}: new_digest must be sha256:<64 hex>, got {digest!r}")
        ref = f"{image}:{tag}@{digest}"
        if pins.get(tool, ref) != ref:
            raise PinError(f"{where}: two different updates for {tool}")
        pins[tool] = ref
    return pins


def pin_args(pins: dict) -> list:
    """{tool: ref} -> ['--pin', 'tool=ref', ...] in a stable order."""
    out: list = []
    for tool in sorted(pins):
        out += ["--pin", f"{tool}={pins[tool]}"]
    return out


# ------------------------------------------------------------------ the fixture repo

def fake_token(label: str) -> str:
    """A GitHub-token-shaped string (gh + p_ + 36 base62 chars) derived from a hash: deterministic,
    well-formed enough for secret scanners, and never issued by GitHub."""
    alphabet = string.digits + string.ascii_uppercase + string.ascii_lowercase
    n = int.from_bytes(hashlib.sha256(f"security-audit smoke fixture {label}".encode()).digest(), "big")
    chars = []
    for _ in range(36):
        n, r = divmod(n, 62)
        chars.append(alphabet[r])
    return "gh" + "p_" + "".join(chars)


def fixture_dest(rel: PurePosixPath) -> PurePosixPath:
    """tree-relative source path -> path inside the built fixture."""
    if not rel.name.endswith(FIXTURE_SUFFIX):
        raise ValueError(f"fixture file without the {FIXTURE_SUFFIX} suffix: {rel}")
    parts = [DIR_RENAMES.get(p, p) for p in rel.parts[:-1]] + [rel.name[:-len(FIXTURE_SUFFIX)]]
    return PurePosixPath(*parts)


def build_tree(dest: Path, tree: Path = TREE) -> list:
    """Copy the fixture tree into dest (LF kept, placeholders filled). Returns the written paths."""
    written = []
    for src in sorted(tree.rglob("*")):
        if not src.is_file():
            continue
        rel = fixture_dest(PurePosixPath(src.relative_to(tree).as_posix()))
        text = src.read_text(encoding="utf-8")
        text = TOKEN_PLACEHOLDER.sub(lambda m: fake_token(m.group(1).lower()), text)
        target = dest.joinpath(*rel.parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(text.encode("utf-8"))
        written.append(rel.as_posix())
    return written


def git_env(scratch: Path) -> dict:
    """Host git config shut out (no autocrlf, hooks, signing or templates from the machine)."""
    empty = scratch / "gitconfig-empty"
    empty.write_text("", encoding="utf-8")
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=str(empty), GIT_TERMINAL_PROMPT="0",
               GIT_AUTHOR_DATE=GIT_DATE, GIT_COMMITTER_DATE=GIT_DATE)
    return env


def make_repo(repo: Path, history_only, scratch: Path) -> None:
    """git init + commit everything, then delete the history-only files in a second commit."""
    env = git_env(scratch)

    def git(*args):
        r = subprocess.run(["git", *args], cwd=repo, env=env, capture_output=True, text=True,
                           encoding="utf-8", errors="replace")
        if r.returncode != 0:
            raise RuntimeError(f"git {' '.join(args)} failed: {(r.stderr or r.stdout).strip()[:300]}")

    git("-c", "init.defaultBranch=main", "init", "-q")
    for k, v in (("user.name", "smoke fixture"), ("user.email", "smoke-fixture@example.invalid"),
                 ("commit.gpgsign", "false"), ("core.autocrlf", "false")):
        git("config", "--local", k, v)
    git("add", "-A")
    git("commit", "-q", "-m", "fixture: planted defects for the scanner smoke test")
    gone = [p for p in history_only if (repo / p).is_file()]
    if gone:
        git("rm", "-q", "--", *gone)
        git("commit", "-q", "-m", "fixture: remove the history-only files")


def build_fixture(repo: Path, scratch: Path, history_only, tree: Path = TREE, git: bool = True) -> list:
    repo.mkdir(parents=True, exist_ok=True)
    written = build_tree(repo, tree)
    missing = [p for p in history_only if p not in written]
    if missing:
        raise RuntimeError(f"expect.json history_only names files the fixture tree lacks: {missing}")
    if git:
        make_repo(repo, history_only, scratch)
    return written


# ------------------------------------------------------------------ reading scanner output

def _d(x) -> dict:
    return x if isinstance(x, dict) else {}


def _l(x) -> list:
    return x if isinstance(x, list) else []


def _s(x) -> str:
    return x if isinstance(x, str) else ""


def read_sarif(path: Path):
    """-> (doc, error). Scanner output is untrusted data: parsed as JSON, never executed."""
    if not path.is_file():
        return None, f"{path.name} missing"
    try:
        doc = json.loads(path.read_text(encoding="utf-8", errors="replace") or "null")
    except ValueError as e:
        return None, f"{path.name} is not valid JSON ({str(e)[:80]})"
    if not isinstance(doc, dict) or not isinstance(doc.get("runs"), list):
        return None, f"{path.name} is not SARIF (no runs list)"
    return doc, ""


def sarif_results(doc: dict) -> list:
    """Each result as {"rule", "text" (rule id + rule metadata + message, lower case), "paths"}."""
    out = []
    for run in _l(doc.get("runs")):
        driver = _d(_d(_d(run).get("tool")).get("driver"))
        rules = [_d(r) for r in _l(driver.get("rules"))]
        by_id = {_s(r.get("id")): r for r in rules if _s(r.get("id"))}
        for res in _l(_d(run).get("results")):
            res = _d(res)
            ref = _d(res.get("rule"))
            rid = _s(res.get("ruleId")) or _s(ref.get("id"))
            idx = res.get("ruleIndex", ref.get("index"))
            rule = by_id.get(rid) or (rules[idx] if isinstance(idx, int) and 0 <= idx < len(rules) else {})
            rid = rid or _s(rule.get("id"))
            parts = [rid, _s(rule.get("id")), _s(rule.get("name")),
                     _s(_d(rule.get("shortDescription")).get("text")),
                     _s(_d(rule.get("fullDescription")).get("text")),
                     _s(_d(rule.get("help")).get("text")),
                     _s(_d(res.get("message")).get("text"))]
            parts += [_s(a) for a in _l(rule.get("deprecatedIds"))]
            paths = []
            for loc in _l(res.get("locations")):
                uri = _s(_d(_d(_d(loc).get("physicalLocation")).get("artifactLocation")).get("uri"))
                if uri:
                    paths.append(unquote(uri).replace("\\", "/"))
            out.append({"rule": rid or "unknown", "text": "\n".join(parts).lower(), "paths": paths})
    return out


def run_check(check: dict, raw: Path, default_outputs) -> tuple:
    """One expect.json check -> (passed, detail, matched rule ids)."""
    outputs = [check["output"]] if check.get("output") else list(default_outputs)
    tokens = [t.lower() for t in check.get("any_of", []) if isinstance(t, str) and t]
    want_path = _s(check.get("path_contains")).lower()
    if not tokens:
        return False, "expect.json check has no any_of", []
    matched, errors, total = [], [], 0
    for name in outputs:
        doc, err = read_sarif(raw / name)
        if err:
            errors.append(err)
            continue
        results = sarif_results(doc)
        total += len(results)
        for r in results:
            if any(t in r["text"] for t in tokens) and \
                    (not want_path or any(want_path in p.lower() for p in r["paths"])):
                if r["rule"] not in matched:
                    matched.append(r["rule"])
    if matched:
        return True, "", matched
    if errors and len(errors) == len(outputs):
        return False, "; ".join(errors), []
    where = f" at a path containing '{check['path_contains']}'" if want_path else ""
    shown = ", ".join(check.get("any_of", [])[:4]) + (", ..." if len(check.get("any_of", [])) > 4 else "")
    msg = f"none of [{shown}] reported{where} in {'/'.join(outputs)} ({total} results)"
    return False, "; ".join([msg] + errors), []


def evaluate_tool(tool: str, rec, raw: Path, spec, default_image: str, outputs) -> dict:
    """One scanner's row: ran?, expected found?, ok?, detail."""
    rec = _d(rec)
    row = {"tool": tool, "image": rec.get("image") or default_image, "digest": rec.get("digest", ""),
           "status": rec.get("status", "not reported"), "ran": False, "expected_found": False, "ok": False,
           "matched": [], "exit_codes": {k: rec[k] for k in ("exit_code", "exit_code_dir") if k in rec},
           "detail": ""}
    if not spec:
        row["detail"] = "no expectations for this tool in expect.json"
        return row
    if not rec:
        row["detail"] = "run_scanners.py did not report this tool"
        return row
    if rec.get("status") != "ok":
        row["detail"] = f"{rec.get('status')}: {rec.get('reason', 'no reason given')}"[:300]
        return row
    row["ran"] = True
    problems = []
    ok_codes = spec.get("ok_exit_codes")
    for key, code in row["exit_codes"].items():
        if isinstance(ok_codes, list) and code not in ok_codes:
            tail = _s(rec.get("stderr_tail")).strip().splitlines()
            problems.append(f"{key} {code} (ok: {ok_codes})" + (f": {tail[-1][:160]}" if tail else ""))
    sarif_outputs = [o for o in outputs if o.endswith(".sarif")]
    checks = _l(spec.get("checks"))
    if not checks:
        problems.append("expect.json lists no checks for this tool")
    found = bool(checks)
    for check in checks:
        passed, detail, matched = run_check(_d(check), raw, sarif_outputs)
        row["matched"] += [m for m in matched if m not in row["matched"]]
        if not passed:
            found = False
            problems.append(detail)
    row["expected_found"] = found
    row["ok"] = found and not problems
    row["detail"] = "; ".join(problems) if problems else "found " + ", ".join(row["matched"][:4]) + \
        (" ..." if len(row["matched"]) > 4 else "")
    return row


def evaluate(manifest, raw: Path, expect: dict, tools, images: dict, outputs: dict) -> list:
    """Rows for the requested tools, from scanners.json and the raw SARIF."""
    manifest = _d(manifest)
    recs = {_d(r).get("tool"): _d(r) for r in _l(manifest.get("tools"))}
    specs = _d(expect.get("tools"))
    rows = []
    for tool in tools:
        row = evaluate_tool(tool, recs.get(tool), raw, _d(specs.get(tool)), images.get(tool, ""),
                            outputs.get(tool, []))
        if manifest.get("fatal") and not row["ran"]:
            row["detail"] = str(manifest["fatal"])[:300]
        rows.append(row)
    return rows


def normalized_counts(candidates: Path, expect: dict, tools) -> dict:
    """Per tool: candidates in candidates.jsonl whose witness rule is one of the planted ids."""
    counts = {t: 0 for t in tools}
    if not candidates.is_file():
        return counts
    specs = _d(expect.get("tools"))
    tokens = {t: [x.lower() for c in _l(_d(specs.get(t)).get("checks")) for x in _l(_d(c).get("any_of"))
                  if isinstance(x, str)] for t in tools}
    for line in candidates.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            witnesses = [w.split(":", 1)[-1].lower() for w in _l(_d(json.loads(line)).get("witnesses"))
                         if isinstance(w, str)]
        except ValueError:
            continue
        for t in tools:
            if any(tok in w for w in witnesses for tok in tokens[t]):
                counts[t] += 1
    return counts


def overall_exit(rows, extra_failures) -> int:
    return EXIT_PASS if rows and all(r["ok"] for r in rows) and not extra_failures else EXIT_FAIL


# ------------------------------------------------------------------ side effects (replaced in tests)

def detect_engine() -> dict:
    sys.path.insert(0, str(SKILL_SCRIPTS))
    import env_check  # noqa: E402  (the skill's own probe: same engine choice as run_scanners.py)
    return env_check.detect_engine("auto", timeout=20)


def invoke(cmd: list, timeout: int):
    """-> (returncode, stdout, stderr)."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace",
                           timeout=timeout)
        return r.returncode, r.stdout or "", r.stderr or ""
    except subprocess.TimeoutExpired:
        return -1, "", f"timed out after {timeout}s"


# ------------------------------------------------------------------ report

def short_ref(ref: str) -> str:
    """image:tag@sha256:<64 hex> -> image:tag@sha256:<12 hex> for the table (JSON keeps it whole)."""
    return re.sub(r"(@sha256:[0-9a-f]{12})[0-9a-f]{52}", r"\1", ref or "")


def table(rows) -> str:
    head = ("tool", "ran", "expected", "image", "detail")
    body = [(r["tool"], "yes" if r["ran"] else "no", "found" if r["expected_found"] else "MISSED",
             short_ref(r["image"]) + (" (candidate)" if r.get("candidate") else ""), r["detail"])
            for r in rows]
    widths = [max(len(head[i]), *(len(b[i]) for b in body)) if body else len(head[i]) for i in range(4)]
    lines = ["  ".join(head[i].ljust(widths[i]) for i in range(4)) + "  " + head[4]]
    lines += ["  ".join(b[i].ljust(widths[i]) for i in range(4)) + "  " + b[4] for b in body]
    return "\n".join(lines)


def rmtree(path: Path) -> None:
    """shutil.rmtree that also clears read-only files (git objects on Windows)."""
    def retry(func, p, _exc):
        try:
            os.chmod(p, 0o700)
            func(p)
        except OSError:
            pass
    if sys.version_info >= (3, 12):
        shutil.rmtree(path, onexc=retry)
    else:
        shutil.rmtree(path, onerror=retry)


def write_json(path, report: dict) -> None:
    if path:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(report, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")


# ------------------------------------------------------------------ main

def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--pins-json", help="update_pins.py --json output; its updates become --pin overrides")
    ap.add_argument("--tool", action="append", default=[], metavar="NAME",
                    help="only this scanner (repeatable, or comma-separated); default: all")
    ap.add_argument("--json", dest="json_out", metavar="OUT", help="also write the result as JSON")
    ap.add_argument("--keep", action="store_true", help="keep the temporary fixture and scanner output")
    ap.add_argument("--timeout", type=int, default=900, help="per-scanner timeout passed to run_scanners.py")
    ap.add_argument("--expect", default=str(EXPECT), help=argparse.SUPPRESS)
    a = ap.parse_args(argv)

    images = runner_literal("IMAGES")
    outputs = runner_literal("EXPECTED")
    expect = json.loads(Path(a.expect).read_text(encoding="utf-8"))
    tools = [t.strip() for arg in a.tool for t in arg.split(",") if t.strip()] or list(images)
    tools = list(dict.fromkeys(tools))
    unknown = [t for t in tools if t not in images]
    if unknown:
        ap.error(f"unknown tool(s) {unknown}; known: {', '.join(images)}")

    report = {"date": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"), "result": "error",
              "exit_code": EXIT_FAIL, "pins_json": a.pins_json, "tools_requested": tools, "pins": {},
              "pins_ignored": [], "engine": None, "run_scanners_exit": None, "normalize": None, "tools": []}

    pins = {}
    if a.pins_json:
        try:
            pins = pins_from_updates(json.loads(Path(a.pins_json).read_text(encoding="utf-8")), set(images))
        except (OSError, ValueError) as e:  # PinError and JSONDecodeError are ValueErrors
            print(f"error: {e}", file=sys.stderr)
            report["detail"] = str(e)
            write_json(a.json_out, report)
            return EXIT_FAIL
    report["pins_ignored"] = sorted(t for t in pins if t not in tools)
    pins = {t: ref for t, ref in pins.items() if t in tools}
    report["pins"] = pins
    if report["pins_ignored"]:
        print(f"note: pins for {', '.join(report['pins_ignored'])} ignored (not in --tool)")

    eng = detect_engine()
    report["engine"] = eng.get("engine")
    if not eng.get("daemon_ok"):
        installed = ", ".join(eng.get("installed") or []) or "none"
        msg = (f"no container engine answers (installed: {installed}). The smoke test runs the scanner "
               "images and cannot pass without docker or podman: start the daemon, or run it in CI.")
        print(f"error: {msg}", file=sys.stderr)
        report.update(result="no-engine", exit_code=EXIT_NO_ENGINE, detail=msg)
        write_json(a.json_out, report)
        return EXIT_NO_ENGINE
    if not shutil.which("git"):
        print("error: git is not on PATH (the fixture must be a git repository)", file=sys.stderr)
        report["detail"] = "git not on PATH"
        write_json(a.json_out, report)
        return EXIT_FAIL

    scratch = Path(tempfile.mkdtemp(prefix="smoke-scanners-"))
    repo, out = scratch / "repo", scratch / "out"
    extra_failures: list = []
    rows: list = []
    try:
        history_only = [h for h in _l(expect.get("history_only")) if isinstance(h, str)]
        try:
            build_fixture(repo, scratch, history_only)
        except (OSError, RuntimeError, ValueError) as e:
            print(f"error: building the fixture failed: {e}", file=sys.stderr)
            report["detail"] = f"fixture: {e}"
            write_json(a.json_out, report)
            return EXIT_FAIL
        out.mkdir()
        if os.name != "nt":  # readable by whatever uid the scan containers end up with
            os.chmod(repo, 0o755)
            os.chmod(out, 0o755)

        cmd = [sys.executable, "-B", str(RUN_SCANNERS), str(repo), "--out", str(out), "--tools", ",".join(tools),
               "--mode", "container", "--timeout", str(a.timeout), *pin_args(pins)]
        print(f"running {len(tools)} scanner(s) on the planted-defect fixture "
              f"({len(pins)} candidate pin(s)); this pulls images on first use ...", flush=True)
        rc, so, se = invoke(cmd, timeout=a.timeout * len(tools) + 600)
        report["run_scanners_exit"] = rc
        if so.strip():
            print(so.rstrip())
        if se.strip():
            print(se.rstrip(), file=sys.stderr)
        if rc == 3:  # run_scanners: engine went away between our probe and its own
            report.update(result="no-engine", exit_code=EXIT_NO_ENGINE, detail="run_scanners.py: no container engine")
            write_json(a.json_out, report)
            return EXIT_NO_ENGINE
        if rc not in (0, 4, 5):
            extra_failures.append(f"run_scanners.py exited {rc}: {se.strip()[-300:]}")

        manifest = None
        sj = out / "scanners.json"
        if sj.is_file():
            try:
                manifest = json.loads(sj.read_text(encoding="utf-8"))
            except ValueError as e:
                extra_failures.append(f"scanners.json unreadable: {e}")
        else:
            extra_failures.append("run_scanners.py wrote no scanners.json")
        rows = evaluate(manifest, out / "raw", expect, tools, {**images, **pins}, outputs)
        for r in rows:
            r["candidate"] = r["tool"] in pins
            if r["candidate"] and r["ran"] and r["image"] != pins[r["tool"]]:
                r["ok"] = False
                r["detail"] = f"ran {r['image']!r}, not the candidate {pins[r['tool']]!r}; " + r["detail"]

        if (out / "raw").is_dir():
            nrc, nso, nse = invoke([sys.executable, "-B", str(NORMALIZE), str(out), "--repo", str(repo),
                                    "--summary-out", str(out / "summary.md")], timeout=600)
            counts = normalized_counts(out / "candidates.jsonl", expect, tools)
            report["normalize"] = {"exit_code": nrc, "planted_candidates": counts}
            for r in rows:
                r["normalized"] = counts.get(r["tool"], 0)
            if nrc != 0:
                extra_failures.append(f"normalize_findings.py exited {nrc}: {(nse or nso).strip()[-300:]}")
    finally:
        if a.keep:
            print(f"kept: fixture {repo}, scanner output {out}")
            report["kept"] = str(scratch)
        else:
            rmtree(scratch)
            if scratch.exists():
                print(f"warning: could not fully remove {scratch}", file=sys.stderr)

    code = overall_exit(rows, extra_failures)
    report.update(tools=rows, exit_code=code, result="pass" if code == EXIT_PASS else "fail")
    if extra_failures:
        report["failures"] = extra_failures
    print()
    print(table(rows))
    for f in extra_failures:
        print(f"FAIL: {f}")
    passed = sum(1 for r in rows if r["ok"])
    print(f"\n{'PASS' if code == EXIT_PASS else 'FAIL'}: {passed}/{len(rows)} scanners ran and found "
          "their planted defect")
    write_json(a.json_out, report)
    return code


if __name__ == "__main__":
    sys.exit(main())
