#!/usr/bin/env python3
"""
レーンパック（Phase 4）- レビューレーンごとに、レーンが最初の 20-40 回の Read / Grep ターンで取得するはずの
コードを、マスク済みの 1 つの Markdown ファイルに事前抽出する。サブエージェントは毎ターン文脈全体を送り直すため、
ターン数を減らすことが節約の大部分になる。パックは出発点であって、網羅ではない。

レーンごとに（対応関係は下の LANES）、ダイジェストの索引（repo_digest.py --json）、ルートマップ
（route_map.py の routes.json）、ファイル名から選ぶ。前後 N 行の範囲を抽出し（低コストで済む場合は開始位置を
囲んでいる def / function まで戻す）、重なる範囲を統合し、シグナルの強さ順に並べ、バイト数の上限で止め、
省いたものを一覧にする。すべての行は peek.redact を通す。シークレットを含むファイル（.env*、鍵、*.tfvars、
プロンプトログ、ダイジェストのシークレットファイル一覧）は名前だけを示す。

使い方:
  python lane_pack.py <repo> --digest-json <work>/<repo>/digest.json [--routes <work>/<repo>/routes.json]
                      --lane authz-logic[+injection-dataflow] --out <work>/<repo>/packs/<lane>.md
                      [--budget-kb 60] [--context 6]
"""
from __future__ import annotations

import sys
sys.dont_write_bytecode = True  # インストール済みスキルに __pycache__ を作らない
for _s in (sys.stdout, sys.stderr):  # cp932 / cp1252 のコンソールやパイプでも UTF-8 で出力する
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
# レーンにかかわらず決して抜粋しない：名前だけを示し、peek.py で見る
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

# レーン -> (優先度付きのダイジェスト分類、パスの規則 [(regex, priority, whole-file max lines)]、行の走査、ルートの使用)
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
    ap.add_argument("--routes", help="route_map.py が出力した routes.json（authz-logic）")
    ap.add_argument("--lane", required=True, help="1 つのレーン、または + でつないだグループ")
    ap.add_argument("--out", required=True)
    ap.add_argument("--budget-kb", type=float, default=60)
    ap.add_argument("--context", type=int, default=6, help="各ヒットの前後に含める行数")
    a = ap.parse_args()
    root = Path(host_path(a.repo)).resolve()
    lanes = a.lane.split("+")
    bad = [x for x in lanes if x not in LANES_SPEC]
    if not root.is_dir() or bad:
        print(f"error: {'不明なレーン ' + ', '.join(bad) if bad else 'ディレクトリではない: ' + a.repo}"
              f"（レーン: {', '.join(LANES)}）", file=sys.stderr)
        return 2
    try:
        dg = json.loads(Path(host_path(a.digest_json)).read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        print(f"error: digest json: {e} - 先に repo_digest.py --json を実行する", file=sys.stderr)
        return 2
    routes = {}
    if a.routes and Path(host_path(a.routes)).is_file():
        routes = json.loads(Path(host_path(a.routes)).read_text(encoding="utf-8"))
    listed = set(dg.get("secret_files", []))
    files = sorted({r for v in dg.get("inventory", {}).values() for r, _ in v} | listed)
    N = a.context

    hits = defaultdict(list)  # パス -> [(prio, start, end, reason)]
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
                if cls == "auth-helper":  # validate_email() は認可ではない：認可を示す語のないヒットは優先度を下げる
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
                        if loop or plain <= 4:  # ループ内のクエリはすべて。通常の箇所はファイルごとに最大 4 件
                            add(1 if loop else prio, rel, i, "query inside a loop?" if loop else f"{lane} {rx.search(ln).group(0)[:20]}")

    # ファイルごとの範囲を作る（統合し、開始位置は囲んでいる def まで戻す）
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
    print(f"{a.out} を書き出した - 抜粋 {nexc} 件 / ファイル {nfiles} 件、{out.stat().st_size} バイト、省略 {len(left)} 件")
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
