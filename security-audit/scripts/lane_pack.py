#!/usr/bin/env python3
"""
Lane pack (Phase 4) - per review lane, the code a lane would otherwise fetch with its first 20-40
Read / Grep turns, pre-extracted into one redacted markdown file. Every subagent turn re-sends its
whole context, so fewer turns is most of the saving; the pack is a starting point, not coverage.

Picks by lane (mapping in LANES below) from the digest index (repo_digest.py --json), the route map
(route_map.py routes.json) and file names; extracts +-N line windows (start pulled back to the
enclosing def / function where cheap), merges overlapping ranges, orders by signal, stops at the
byte budget and lists what was left out. Every line passes through peek.redact; secret-bearing files
(.env*, keys, *.tfvars, prompt logs, the digest's secret-file list) are listed by name only.

Usage:
  python lane_pack.py <repo> --digest-json <work>/<repo>/digest.json [--routes <work>/<repo>/routes.json]
                      --lane authz-logic[+injection-dataflow] --out <work>/<repo>/packs/<lane>.md
                      [--budget-kb 60] [--context 6]
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
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from peek import redact_lines  # noqa: E402
import safegit  # noqa: E402
from repo_digest import SECRET_FILE, TESTISH, host_path  # noqa: E402

LANES = ("authz-logic", "injection-dataflow", "sensitive-data", "ai-agentic", "supply-chain-infra", "mobile", "perf-quality")
# never excerpted, whatever the lane: listed by name, viewed with peek.py
NEVER = re.compile(r"(^|/)(\.env[^/]*|[^/]*\.(pem|key|p12|pfx|jks|keystore|der|gpg|asc|tfvars|tfstate)|id_(rsa|dsa|ecdsa|ed25519)"
                   r"[^/]*|[^/]*(prompt[_-]?(history|log)|transcripts?)[^/]*|\.specstory/.*|[^/]*\.(sqlite3?|db|dump))$", re.I)
LOCKFILE = re.compile(r"(^|/)(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|poetry\.lock|Pipfile\.lock|Gemfile\.lock|"
                      r"composer\.lock|go\.sum|Cargo\.lock)$")
DEF_RX = re.compile(r"^\s*(async\s+def|def|class|function|async\s+function|public|private|protected|func|fun|"
                    r"export\s+(async\s+)?function|(const|let)\s+\w+\s*=\s*(async\s*)?\(|@\w+)")
AUTH_PATH = re.compile(r"(?i)^(?!\.claude/|\.cursor/|\.github/)(?:.*/)?(?:[^/]*(auth|middleware|guard|polic|permission|"
                       r"dependenc|security|session|jwt|acl|login)[^/]*|(middlewares?|guards?|policies|dependencies|auth)/[^/]+)"
                       r"\.(py|js|mjs|cjs|ts|java|kt|rb|php|go|cs)$")
STRONG_AUTH = re.compile(r"(?i)auth|permission|role|admin|current_?user|login|owner|tenant|access|token|session|guard|jwt")
MODEL_PATH = re.compile(r"(?i)(^|/)(models?|entities|entity|schemas?|migrations?|alembic|prisma|db/migrate)/[^/]+$|"
                        r"(^|/)(models?|schema|entities)\.(py|ts|js|rb|prisma|graphql|sql)$|\.sql$")
LOG_PATH = re.compile(r"(?i)(^|/)[^/]*(logging|logger|log_?config|logback|log4j)[^/]*\.(py|js|ts|json|ya?ml|xml|conf|properties)$")
MANIFEST = re.compile(r"(^|/)(package\.json|requirements[^/]*\.txt|pyproject\.toml|Pipfile|setup\.py|go\.mod|pom\.xml|"
                      r"build\.gradle(\.kts)?|Gemfile|composer\.json|Cargo\.toml|\.npmrc|\.yarnrc\.yml)$")
INFRA = re.compile(r"(?i)(^|/)(Dockerfile[^/]*|[^/]*compose[^/]*\.ya?ml|\.github/workflows/[^/]+|\.gitlab-ci\.yml|"
                   r"buildspec[^/]*\.ya?ml|Jenkinsfile|azure-pipelines\.yml|bitbucket-pipelines\.yml|\.circleci/config\.yml|"
                   r"[^/]*\.tf|[^/]*\.bicep|serverless\.ya?ml|template\.ya?ml|Chart\.yaml|values[^/]*\.ya?ml|"
                   r"(k8s|kubernetes|helm|charts|deploy|manifests)/[^/]+\.ya?ml|\.dockerignore|nginx[^/]*\.conf)$")
AGENT_FILE = re.compile(r"(?i)(^|/)(CLAUDE|AGENTS|GEMINI|SKILL)\.md$|^\.claude/|^\.cursor/|^\.windsurf/|\.mdc$|"
                        r"^\.github/(copilot-instructions\.md|prompts/|instructions/|chatmodes/)")
MOBILE_FILE = re.compile(r"(?i)(AndroidManifest\.xml|Info\.plist|network_security_config\.xml|\.entitlements|"
                         r"AppDelegate\.\w+|MainActivity\.\w+)$")
MOBILE_RX = re.compile(r"WebView|addJavascriptInterface|setJavaScriptEnabled|SharedPreferences|UserDefaults|Keychain|"
                       r"NSAllowsArbitraryLoads|cleartextTrafficPermitted|exported\s*=\s*\"true\"|AsyncStorage|"
                       r"SecureStore|deep_?link|intent-filter|canOpenURL|openURL")
QUERY_RX = re.compile(r"\.(query|filter|filter_by|all|first|find|findAll|findOne|findMany|findUnique|where|execute|"
                      r"select|aggregate|count)\(|\.objects\.|session\.execute|cursor\.|\bSELECT\b|\.raw\(")
LOOP_RX = re.compile(r"^\s*(for|while)\b|\.(map|forEach|each)\s*[({]|\bfor\s*\(")
CACHE_RX = re.compile(r"(?i)lru_cache|@cache\b|cache\.(get|set)|redis|memoi[sz]e|Cacheable|timeout\s*=|setTimeout|limit\(|paginat")

# lane -> (digest classes with priority, path rules [(regex, priority, whole-file max lines)], line scans, use routes)
LANES_SPEC = {
    "authz-logic": {"classes": {"auth-helper": 2, "route-handler": 3}, "paths": [(AUTH_PATH, 1, 160)], "routes": True},
    "injection-dataflow": {"classes": {"shell-exec": 1, "code-eval-deserialise": 1, "sql-build": 1, "html-output": 2,
                                       "file-path": 2, "outbound-http": 3}, "paths": []},
    "sensitive-data": {"classes": {"crypto-random": 2, "file-path": 3}, "paths": [(MODEL_PATH, 1, 220), (LOG_PATH, 1, 120)]},
    "ai-agentic": {"classes": {"llm-agent": 1, "agent-permissions": 1}, "paths": [(AGENT_FILE, 2, 80)]},
    "supply-chain-infra": {"classes": {"ci-release": 1}, "paths": [(INFRA, 1, 160), (MANIFEST, 2, 120)]},
    "mobile": {"classes": {}, "paths": [(MOBILE_FILE, 1, 160)], "scan": [(MOBILE_RX, 2, None)]},
    "perf-quality": {"classes": {"outbound-http": 2}, "paths": [], "scan": [(QUERY_RX, 3, LOOP_RX), (CACHE_RX, 3, None)]},
}


def secret_bearing(rel: str, listed: set) -> bool:
    return rel in listed or bool(NEVER.search(rel)) or bool(SECRET_FILE.search(rel))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("repo")
    ap.add_argument("--digest-json", required=True)
    ap.add_argument("--routes", help="routes.json from route_map.py (authz-logic)")
    ap.add_argument("--lane", required=True, help="one lane or a group joined with +")
    ap.add_argument("--out", required=True)
    ap.add_argument("--budget-kb", type=float, default=60)
    ap.add_argument("--context", type=int, default=6, help="lines before / after each hit")
    a = ap.parse_args()
    root = Path(host_path(a.repo)).resolve()
    lanes = a.lane.split("+")
    bad = [x for x in lanes if x not in LANES_SPEC]
    if not root.is_dir() or bad:
        print(f"error: {'unknown lane ' + ', '.join(bad) if bad else 'not a directory: ' + a.repo} "
              f"(lanes: {', '.join(LANES)})", file=sys.stderr)
        return 2
    try:
        dg = json.loads(Path(host_path(a.digest_json)).read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        print(f"error: digest json: {e} - run repo_digest.py --json first", file=sys.stderr)
        return 2
    routes = {}
    if a.routes and Path(host_path(a.routes)).is_file():
        routes = json.loads(Path(host_path(a.routes)).read_text(encoding="utf-8"))
    listed = set(dg.get("secret_files", []))
    files = sorted({r for v in dg.get("inventory", {}).values() for r, _ in v} | listed)
    N = a.context

    hits = defaultdict(list)  # path -> [(prio, start, end, reason)]
    named_only = set()

    def add(prio, rel, line, reason, whole=None):
        if secret_bearing(rel, listed):
            named_only.add(rel)
            return
        if whole:
            hits[rel].append((prio, 1, whole, reason))
        else:
            hits[rel].append((prio, max(1, line - N), line + N, reason))

    for lane in lanes:
        spec = LANES_SPEC[lane]
        for cls, prio in spec["classes"].items():
            for h in dg.get("classes", {}).get(cls, []):
                p = prio
                if cls == "auth-helper":  # validate_email() is not authz: demote hits without an authz word
                    src = read(root, h["path"])
                    ln = src[h["line"] - 1] if 0 < h["line"] <= len(src) else ""
                    p = prio if STRONG_AUTH.search(ln) else 4
                add(p, h["path"], h["line"], f"{cls} {h['label']}")
        for rx, prio, maxl in spec["paths"]:
            for rel in files:
                if rx.search(rel):
                    add(prio, rel, 1, f"{lane} file", maxl)
        if spec.get("routes") and routes:
            for r in routes.get("routes", []):
                noauth = not any(not m.startswith("!") for m in r.get("auth", []))
                add(1 if noauth else 3, r["file"], r["line"],
                    f"{'NO auth marker: ' if noauth else 'route '}{r['method']} {r['path']}")
            for g in routes.get("global_auth", []):
                p, _, ln = g["at"].rpartition(":")
                add(1, p, int(ln) if ln.isdigit() else 1, f"global auth: {g['what']}")
        for rx, prio, near in spec.get("scan", []):
            for rel in files:
                if secret_bearing(rel, listed) or LOCKFILE.search(rel) or not re.search(
                        r"\.(py|js|ts|tsx|jsx|java|kt|swift|dart|m|rb|php|go|cs|xml|plist)$", rel):
                    continue
                lines = read(root, rel)
                plain = 0
                for i, ln in enumerate(lines, 1):
                    if rx.search(ln):
                        loop = near and any(near.search(x) for x in lines[max(0, i - 9):i - 1])
                        plain += not loop
                        if loop or plain <= 4:  # every query-in-loop; at most 4 plain sites per file
                            add(1 if loop else prio, rel, i, "query inside a loop?" if loop else f"{lane} {rx.search(ln).group(0)[:20]}")

    # build per-file ranges (merged, start pulled back to the enclosing def)
    sections = []
    for rel, hs in hits.items():
        lines = read(root, rel)
        if not lines:
            continue
        rngs = []
        for prio, s, e, why in sorted(hs, key=lambda h: (h[1], h[0])):
            e = min(e, len(lines))
            for k in range(s - 1, max(0, s - 13), -1):
                if DEF_RX.match(lines[k - 1]) and (k == 1 or not lines[k - 2].strip().startswith("@")):
                    s = k if s - k <= 12 else s
                    break
            if rngs and s <= rngs[-1][1] + 2:
                rngs[-1] = [rngs[-1][0], max(rngs[-1][1], e), min(rngs[-1][2], prio), rngs[-1][3] | {why}]
            else:
                rngs.append([s, e, prio, {why}])
        sections.append((min(r[2] for r in rngs), -len(rngs), rel, rngs, lines))
    sections.sort(key=lambda x: (x[0], x[1], x[2]))

    budget = int(a.budget_kb * 1024)
    head = [f"# Lane pack - {a.lane} - {root.name}", "",
            "Excerpts picked by script (digest index, route map, file names), every line redacted (peek.redact). "
            "A starting point, NOT coverage: Read / Grep the repo for context the pack lacks (callers, services, "
            "models, config) and for everything under \"Left out\". Line numbers are real `path:line`; cite them as such.", ""]
    if routes and "authz-logic" in lanes:
        na = routes.get("no_auth_marker", [])
        head += [f"Routes: {len(routes.get('routes', []))} parsed ({', '.join(f'{k} {v}' for k, v in routes.get('frameworks', {}).items())}); "
                 f"{len(na)} with no auth marker (excerpted first); global auth: "
                 + ("; ".join(f"`{g['at']}` {g['what']}" for g in routes.get("global_auth", [])[:6]) or "none detected")
                 + ". Gaps: " + ("; ".join(routes.get("gaps", [])[:5]) or "none"), ""]
    body, left, used = [], [], len("\n".join(head).encode("utf-8")) + 1200 + 120 * len(named_only | listed)
    nexc = nfiles = 0
    for prio, _, rel, rngs, lines in sections:
        red = list(redact_lines(lines))
        part, rest = [], []
        for s, e, p, whys in rngs:
            chunk = [f"`{rel}:{s}-{e}` - {'; '.join(sorted(whys))[:200]}", "```"]
            chunk += [f"{n:5d}| {red[n - 1][:300]}" for n in range(s, e + 1)] + ["```"]
            size = len("\n".join(chunk).encode("utf-8")) + 1 + (0 if part else len(rel.encode("utf-8")) + 24)
            if used + size > budget:
                rest.append(f"{s}-{e}")
                continue
            used += size
            part += chunk
            nexc += 1
        if part:
            nfiles += 1
            body += ["", f"## `{rel}` (priority {prio})"] + part
        if rest:
            left.append(f"`{rel}` lines {', '.join(rest[:12])}" + (f" +{len(rest) - 12}" if len(rest) > 12 else ""))
    tail = ["", "## Left out (budget) - Read these if your lane needs them"] + ([f"- {x}" for x in left] or ["- nothing"])
    tail += ["", "## Secret-bearing files (names only - view with peek.py, never Read)"]
    tail += [", ".join(f"`{f}`" for f in sorted(named_only | listed)[:60]) or "none"]
    head.insert(4, f"Contents: {nexc} excerpts from {nfiles} files, ~{used // 1024} KB of a {a.budget_kb:g} KB budget; "
                   f"{len(left)} files (partly) left out.")
    out = Path(host_path(a.out))
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(head + body + tail) + "\n", encoding="utf-8")
    print(f"wrote {a.out} - {nexc} excerpts / {nfiles} files, {out.stat().st_size} bytes, {len(left)} left out")
    return 0


_CACHE: dict = {}


def read(root: Path, rel: str) -> list[str]:
    if rel not in _CACHE:
        p = root / rel
        lines = []
        try:
            if not TESTISH.search(rel) and not safegit.escapes(root, p) and p.is_file() and p.stat().st_size <= 1_000_000:
                lines = safegit.read_text(p).splitlines()
        except OSError:
            pass
        _CACHE[rel] = lines
    return _CACHE[rel]


if __name__ == "__main__":
    sys.exit(main())
