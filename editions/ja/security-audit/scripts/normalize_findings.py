#!/usr/bin/env python3
"""
スキャナの生出力（SARIF）を、重複排除済みの 1 つのコンパクトな候補リストに正規化する（Phase 3->5）。

スキャナの出力は信頼できないデータ：JSON として解析するだけで決して実行しない。メッセージは切り詰め、
シークレットらしき文字列はマスクする。ソース中のインライン抑制はここでは何にも影響しない。

<audit_dir>/candidates.jsonl（位置クラスタごとに 1 つの JSON オブジェクト）を書き出し、コンパクトな
トリアージ要約を表示する：ツール / 重大度ごとの件数、続いて重大度順のルールグループ。test/vendor/
example のパスは、本番コードを埋もれさせないよう分けて示す。
ルール上ほぼ確実に実在しない候補には `auto_refuted: <reason>` を付ける（リポジトリからプロセス内で読み取り、
決して表示しないプレースホルダーのシークレット値、vendor に同梱されたドキュメント、テストや vendor のファイル中の
本番専用 SAST ルール）。レーンと検証エージェントはこれらを飛ばす。自動反証の対象外：履歴のみのシークレット、
秘密鍵、実在するキー形式（AKIA、ghp_、xox、sk_live_ ...）、その他すべて。

使い方:
  python normalize_findings.py <audit_dir> [--repo <repo>] [--top 40] [--min-sev low|medium|high]
"""
from __future__ import annotations

import sys
sys.dont_write_bytecode = True  # インストール済みスキルに __pycache__ を作らない
for _s in (sys.stdout, sys.stderr):  # cp932 / cp1252 のコンソールやパイプでも UTF-8 で出力する
    if hasattr(_s, "reconfigure"):
        _s.reconfigure(encoding="utf-8", errors="replace")

import argparse
import json
import os
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from urllib.parse import unquote

sys.path.insert(0, str(Path(__file__).resolve().parent))
from peek import find_secrets, redact as _redact  # noqa: E402

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
NOISE_PATH = re.compile(r"(^|/)(tests?|__tests__|spec|specs|fixtures?|mocks?|e2e|testdata|examples?|"
                        r"samples?|demo|docs?|node_modules|vendor|third[_-]?party|logs?|tmp|coverage)(/|$)|\.(test|spec)\.|"
                        r"\.log$|"
                        r"\.min\.(js|css)$", re.I)
SECRETISH = re.compile(r"([A-Za-z0-9+/_\-]{24,})")
CWE_RX = re.compile(r"CWE-(\d+)", re.I)

# ---- 決定的な誤検知の事前トリアージ（auto_refuted）。保守的：迷ったら残す ----
# 値はリポジトリからプロセス内で読み取り、表示も保存もしない。残すのは理由だけ。
REAL_FORMAT = re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA)[A-Z0-9]{16}\b|\bgh[pousr]_[A-Za-z0-9]{20,}|\bglpat-|"
                         r"\bxox[abprs]-|\b(?:sk|rk)_(?:live|test|prod)_|\bAIza[0-9A-Za-z_\-]{30,}|\bsk-(?:proj-|ant-)|"
                         r"-----BEGIN [A-Z ]*PRIVATE KEY")
NEVER_RULE = re.compile(r"(?i)private[-_]?key|pkcs|card|\bpan\b|cvv|aws|github|gitlab|slack|gcp|azure|jwt")
VALUE_AFTER = re.compile(r"(?i)(?:bearer|basic|token|secret|passw(?:or)?d|pwd|api[-_]?key|key|auth\w*)[\"']?\s*"
                         r"(?:[:=]|=>|\s)\s*[\"']?(?!(?:bearer|basic|token)\b)(<[^>]*>|\$\{[^}]*\}|\{\{.*?\}\}|[^\s\"'`,;)]+)")
PH_WORD = re.compile(r"^(?:dummy|example|sample|test|testing|fake|changeme|placeholder|mock|redacted|xxx+)"
                     r"(?:[a-z]{0,8}|\d{0,4})$", re.I)
PH_WHOLE = re.compile(r"(?i)^(?:<[^>]*>|\$\{[^}]*\}|\{\{.*\}\}|\$[A-Z_][A-Z0-9_]*|%[A-Z_][A-Z0-9_]*%)$|"
                      r"your[_-].*[_-]here|x{3,}|\*{3,}|\.{3}")
PH_DOC_WORD = re.compile(r"^(?:token|secret|password|passwd|key|value|abc|abc123|abcdef|1234\d{0,4}|foo|bar|baz|"
                         r"demo|local|my(?:token|secret|key|password|pass)?|id|none|null|string)$", re.I)
DOC_FILE = re.compile(r"(?i)(^|/)(docs?|examples?|samples?)/|(^|/)readme[^/]*$|\.(md|mdx|rst|adoc|txt)$|"
                      r"\.(example|sample|dist|template)(\.\w+)?$")
VENDORED = re.compile(r"(?i)(^|/)(node_modules|vendor|third[_-]?party|bower_components|\.agents/skills)/")
TEST_FILE = re.compile(r"(?i)(^|/)(tests?|__tests__|spec|specs|e2e|testdata|fixtures?)/|(^|/)test_[^/]+$|"
                       r"_test\.\w+$|\.(test|spec)\.\w+$|(^|/)conftest\.py$")
# デプロイされた本番コードでのみ意味を持つ SAST ルール群（テストや vendor のサンプルでは無関係）
PROD_ONLY_RULE = re.compile(r"(?i)cors|csrf|debug|cookie|bind[-_.]?(all|0)|0-0-0-0|healthcheck|missing-user|"
                            r"security-header|helmet|hsts|insecure-transport|http-not-https|ssl-?verif|verify[-_]?false|"
                            r"tls-?verif|insecure-random|weak-random|hardcoded-tmp|tempfile|assert-used")


def entropy(s: str) -> float:
    import math
    n = len(s)
    return -sum(s.count(ch) / n * math.log2(s.count(ch) / n) for ch in set(s)) if n else 0.0


def is_placeholder(v: str, doc: bool = False) -> bool:
    if not v or PH_WHOLE.search(v) or len(set(re.sub(r"[^A-Za-z0-9]", "", v))) <= 1:
        return True
    words = [w for w in re.split(r"[^A-Za-z0-9]+", v) if w]
    return any(PH_WORD.match(w) or (doc and PH_DOC_WORD.match(w)) for w in words)


def looks_real(v: str) -> bool:
    """長くランダムに見える値（実在するキー形式は先に行全体で検出済み）。"""
    return len(v) >= 24 and entropy(v) >= 4.0


def line_values(repo: str, file: str, line: int, commit: str, cols: tuple, cache: dict) -> list[str] | None:
    """スキャナの一致範囲にあるシークレットらしき値（None = 行を読み取れない）。"""
    key = (commit, file)
    if key not in cache:
        text = None
        if commit:
            import safegit
            text = safegit.out(repo, "show", f"{commit}:{file}") or None
        if text is None:
            p = Path(repo) / file
            try:
                text = p.read_text(encoding="utf-8", errors="replace") if p.is_file() else None
            except OSError:
                text = None
        cache[key] = text.splitlines() if text is not None else None
    lines = cache[key]
    if not lines or not 0 < line <= len(lines):
        return None
    sc, ec, el = cols
    src = lines[line - 1:max(el, line)][:20]  # 一致は複数行にまたがることがある（curl ... \ -H "Authorization: ..."）
    span = "\n".join(src)
    if sc and ec:
        span = "\n".join(src[:-1] + [src[-1][:ec + 1]])[max(sc - 2, 0):] if len(src) > 1 else src[0][max(sc - 2, 0):ec + 1]
    if REAL_FORMAT.search("\n".join(src)):
        return ["real-format"]  # 一致した行のどこかに実在するキーの形：決して自動反証しない
    vals = [m.group(1) for m in VALUE_AFTER.finditer(span)]
    if not vals:  # 一致範囲にキーワードがない：一致そのものが値（stripe-access-token、秘密鍵 ...）
        vals = sorted(re.findall(r"[^\s\"'`,;()=:]{8,}", span), key=len)[-1:]
    return vals[-1:] if vals else None


def auto_refute(c: dict, repo: str | None, cache: dict) -> str:
    """ルール上ほぼ確実に実在しない候補ならその理由、残す場合は ''。"""
    f, rules = c["file"], " ".join(c["witnesses"])
    if c["category"] == "code":
        if PROD_ONLY_RULE.search(rules):
            if TEST_FILE.search(f):
                return "production-only SAST rule in a test file"
            if VENDORED.search(f):
                return "production-only SAST rule in vendored third-party code"
        return ""
    if c["category"] != "secret" or not repo or not c.get("in_head", False) or NEVER_RULE.search(rules):
        return ""  # 履歴のみの漏洩、秘密鍵、実在するクラウドキー形式は常にレーンに回す
    doc, vend = bool(DOC_FILE.search(f)), bool(VENDORED.search(f))
    verdicts = set()
    for commit, cols in c["_spans"]:
        vals = line_values(repo, f, c["line"], commit, cols, cache)
        v = vals[0] if vals else ""
        if not v or v == "real-format" or looks_real(v):
            return ""
        if is_placeholder(v):
            verdicts.add("placeholder value")
        elif doc and is_placeholder(v, doc=True):
            verdicts.add("placeholder value in documentation/example")
        elif vend and doc:
            verdicts.add("vendored third-party docs, value not real-looking")
        else:
            return ""
    return "; ".join(sorted(verdicts))


def host_path(p: str) -> str:
    """Windows で Git-Bash 形式の /c/Users/... を受け付ける（そうしないと黙って C:/c/Users に解決される）。"""
    if os.name == "nt":
        m = re.match(r"^/([a-zA-Z])(/.*)?$", p or "")
        if m:
            return f"{m.group(1).upper()}:{m.group(2) or '/'}"
    return p


def norm_path(uri: str, repo: str | None) -> str:
    p = unquote(uri or "")
    p = re.sub(r"^file://", "", p)
    p = p.replace("\\", "/")
    if p.startswith("/src/"):
        p = p[len("/src/"):]
    if repo:
        r = repo.replace("\\", "/").rstrip("/") + "/"
        if p.lower().startswith(r.lower()):
            p = p[len(r):]
        elif p.lower().startswith("/" + r.lower()):
            p = p[len(r) + 1:]
    p = p.lstrip("/")
    if repo and p.startswith("src/") and not (Path(repo) / p).exists() and (Path(repo) / p[4:]).exists():
        p = p[4:]
    return p


def sev_from(result: dict, rule: dict, tool_hint: str = "") -> str:
    props = {**(rule.get("properties") or {}), **(result.get("properties") or {})}
    ss = props.get("security-severity")
    try:
        v = float(ss)
        return "critical" if v >= 9 else "high" if v >= 7 else "medium" if v >= 4 else "low"
    except (TypeError, ValueError):
        pass
    if tool_hint.startswith("checkov"):
        return "medium"  # Checkov CE は実質的な重大度を出さず、すべての結果が level=error で届く
    lvl = result.get("level") or (rule.get("defaultConfiguration") or {}).get("level") or "warning"
    return {"error": "high", "warning": "medium", "note": "low", "none": "info"}.get(lvl, "medium")


def short(text: str, n: int = 160) -> str:
    text = " ".join((text or "").split())
    if find_secrets(text):  # 本物のシークレットの形があるときだけマスクする（ルールのメッセージを読める状態に保つ）
        text = _redact(text, False)[0]
    text = SECRETISH.sub(lambda m: m.group(1)[:4] + "[REDACTED]", text)
    return text[:n] + ("..." if len(text) > n else "")


PKG_TRIVY = re.compile(r"Package:\s*(\S+)\s+Installed Version:\s*(\S+)")
PKG_OSV = re.compile(r"Package '([^']+)@([^']+)'")
FIXED = re.compile(r"Fixed Version:\s*([^\s,]+)")


def category(tool: str, rule: str, msg: str = "") -> str:
    r = rule.lower()
    if "License" in msg and "Classification" in msg:
        return "license"
    if tool.startswith("trivy") and "Installed Version" in msg:
        return "dependency"
    if tool.startswith("gitleaks") or "secret" in r or tool.startswith("trufflehog"):
        return "secret"
    if tool.startswith("osv") or (tool.startswith("trivy") and re.match(r"(cve|ghsa|go|pysec|rustsec)-", r)):
        return "dependency"
    if tool.startswith(("checkov", "zizmor", "hadolint", "kics", "trivy")):
        return "config"
    return "code"


def parse_sarif(path: Path, repo: str | None) -> list[dict]:
    try:
        doc = json.loads(path.read_text(encoding="utf-8", errors="replace") or "{}")
    except ValueError:
        return [{"_error": f"unparseable SARIF: {path.name}"}]
    out = []
    for run in doc.get("runs", []) or []:
        driver = ((run.get("tool") or {}).get("driver") or {})
        tool = (driver.get("name") or path.stem).lower()
        rules = {r.get("id"): r for r in driver.get("rules", []) or []}
        for res in run.get("results", []) or []:
            rid = res.get("ruleId") or (res.get("rule") or {}).get("id") or "unknown"
            rule = rules.get(rid, {})
            locs = res.get("locations") or [{}]
            pl = (locs[0].get("physicalLocation") or {})
            uri = (pl.get("artifactLocation") or {}).get("uri", "")
            region = pl.get("region") or {}
            line = region.get("startLine") or 0
            tags = " ".join((rule.get("properties") or {}).get("tags", []) or [])
            cwes = sorted(set(CWE_RX.findall(tags + " " + json.dumps(rule.get("properties") or {})[:2000])))
            fp = res.get("partialFingerprints") or {}
            msg = (res.get("message") or {}).get("text") or ""
            cat = category(tool, rid, msg)
            pkg = None
            if cat == "dependency":
                m = PKG_TRIVY.search(msg) or PKG_OSV.search(msg)
                if m:
                    fx = FIXED.search(msg)
                    pkg = {"name": m.group(1), "version": m.group(2),
                           "fixed": fx.group(1).lstrip(">=~^ ") if fx else ""}
            out.append({
                "category": cat, "package": pkg,
                "tool": tool, "source_file": path.name, "rule": rid,
                "severity": sev_from(res, rule, tool),
                "file": norm_path(uri, repo), "line": line,
                "cwe": [f"CWE-{c}" for c in cwes][:3],
                "message": short((res.get("message") or {}).get("text") or
                                 (rule.get("shortDescription") or {}).get("text", "")),
                "commit": (fp.get("commitSha") or "")[:10],
                "_span": (fp.get("commitSha") or "", (region.get("startColumn") or 0, region.get("endColumn") or 0,
                                                     region.get("endLine") or line)),
            })
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("audit_dir")
    ap.add_argument("--repo", help="リポジトリのパス（ネイティブ実行時の絶対パスを取り除き、HEAD でのファイルの有無を確認する）")
    ap.add_argument("--top", type=int, default=40)
    ap.add_argument("--summary-out", help="要約をこのファイルにも書き出す（UTF-8）")
    ap.add_argument("--min-sev", choices=["low", "medium", "high", "critical"], default="low")
    a = ap.parse_args()
    d = Path(host_path(a.audit_dir))
    raw = d / "raw"
    if not raw.is_dir():
        print(f"error: {raw} が見つからない（先に run_scanners.py を実行する）", file=sys.stderr)
        return 2
    repo = str(Path(host_path(a.repo)).resolve()) if a.repo else None
    if repo and not Path(repo).is_dir():
        print(f"error: --repo がディレクトリではない: {a.repo}（解決後 {repo}）", file=sys.stderr)
        return 2
    items, errors = [], []
    for f in sorted(raw.rglob("*.sarif")):
        for it in parse_sarif(f, repo):
            (errors if "_error" in it else items).append(it)

    # ツールをまたいで位置（+ CWE 系統）でクラスタ化する：1 つの候補に複数の検出元
    clusters: dict[tuple, dict] = {}
    for it in items:
        key = (it["file"], it["line"], it["cwe"][0] if it["cwe"] else it["rule"])
        if it["category"] == "secret":
            key = (it["file"], it["line"], "secret")
        elif it["category"] == "dependency" and it["package"]:
            key = ("dep", it["package"]["name"], it["package"]["version"], it["rule"])
        c = clusters.get(key)
        if c is None:
            c = dict(it)
            c["witnesses"] = [f"{it['tool']}:{it['rule']}"]
            c["_spans"] = []
            c["noise_path"] = bool(NOISE_PATH.search(it["file"]))
            if repo and it["file"]:
                c["in_head"] = (Path(repo) / it["file"]).exists()
            clusters[key] = c
        else:
            w = f"{it['tool']}:{it['rule']}"
            if w not in c["witnesses"]:
                c["witnesses"].append(w)
            if SEV_ORDER[it["severity"]] < SEV_ORDER[c["severity"]]:
                c["severity"] = it["severity"]
            c["commit"] = c["commit"] or it["commit"]
        c["_spans"].append(it["_span"])
    cache: dict = {}
    for c in clusters.values():
        c.pop("_span", None)
        why = auto_refute(c, repo, cache)
        del c["_spans"]
        if why:
            c["auto_refuted"] = why
    cands = sorted(clusters.values(), key=lambda c: ("auto_refuted" in c, c["noise_path"], not c.get("in_head", True),
                                                     SEV_ORDER[c["severity"]], c["rule"], c["file"], c["line"]))
    for i, c in enumerate(cands, 1):
        c["cid"] = f"C{i:04d}"
    with (d / "candidates.jsonl").open("w", encoding="utf-8") as fh:
        for c in cands:
            fh.write(json.dumps(c, ensure_ascii=False) + "\n")

    # 要約
    by_tool = Counter((c["witnesses"][0].split(":")[0], c["severity"]) for c in cands)
    if a.summary_out:  # 要約全体をファイルに取り込み、標準出力には参照先だけを出す
        import io
        _buf, _stdout = io.StringIO(), sys.stdout

        class _Capture(io.TextIOBase):
            def write(self, x):
                return _buf.write(x)
        sys.stdout = _Capture()
    refuted = [c for c in cands if "auto_refuted" in c]
    print(f"# scanner candidates: {len(items)} raw hits -> {len(cands)} location clusters "
          f"({sum(1 for c in cands if c['noise_path'])} in test/vendor/example/doc paths)")
    ar = Counter(c["auto_refuted"] for c in refuted)
    print(f"- auto-refuted {len(refuted)}" + (f" ({', '.join(f'{r} {n}' for r, n in ar.most_common())}) - "
          "skipped by lanes and the verifier, listed under Refuted in the report" if refuted else ""))
    tools = sorted({t for t, _ in by_tool})
    for t in tools:
        print(f"- {t}: " + ", ".join(f"{s}={by_tool[(t, s)]}" for s in SEV_ORDER if by_tool[(t, s)]))
    for e in errors:
        print(f"- PARSE ERROR: {e['_error']}")
    floor = SEV_ORDER[a.min_sev]
    for cat, title in (("secret", "Secrets"), ("code", "Code (SAST)"), ("config", "Config / IaC / CI")):
        groups = defaultdict(list)
        for c in cands:
            if c["category"] == cat and SEV_ORDER[c["severity"]] <= floor and "auto_refuted" not in c:
                hist = cat == "secret" and not c.get("in_head", True)
                groups[(c["noise_path"], c["severity"], c["witnesses"][0].split(":")[0],
                        c["rule"] + (" [history-only: still compromised, rotate]" if hist else ""))].append(c)
        n = sum(len(v) for v in groups.values())
        print(f"\n## {title}: {n} candidates in {len(groups)} rule groups (production paths first)")
        noise_n = sum(len(v) for k, v in groups.items() if k[0])
        groups = {k: v for k, v in groups.items() if not k[0]}
        if noise_n:
            print(f"- ({noise_n} candidates in test/vendor/example/doc/log paths collapsed; grep candidates.jsonl "
                  f"for noise_path=true)")
        for i, ((noise, sev, tool, rule), cs) in enumerate(sorted(
                groups.items(), key=lambda kv: (kv[0][0], SEV_ORDER[kv[0][1]], -len(kv[1])))):
            if i >= a.top:
                print(f"... {len(groups) - i} more groups (grep candidates.jsonl)")
                break
            locs = ", ".join(f"{c['file']}:{c['line']}" + ("" if c.get("in_head", True) else " (history-only)")
                             + (f"@{c['commit']}" if c.get("commit") else "") for c in cs[:4])
            more = f" +{len(cs) - 4}" if len(cs) > 4 else ""
            multi = " [multi-tool]" if any(len(c["witnesses"]) > 1 for c in cs) else ""
            print(f"- [{sev}]{' [noise-path]' if noise else ''}{multi} {tool} {rule} {','.join(cs[0]['cwe'])} "
                  f"x{len(cs)}: {cs[0]['message'][:100]}\n    at {locs}{more}")
    # 依存関係：package@version ごとに 1 行（根本原因 = パッケージ）、最も高い重大度から順に
    pk = defaultdict(lambda: {"vulns": set(), "sev": "info", "fixed": set(), "files": set(), "tools": set()})
    for c in cands:
        if c["category"] != "dependency" or not c["package"]:
            continue
        k = (c["package"]["name"], "")
        e = pk[k]
        e.setdefault("versions", set()).add(c["package"]["version"])
        e["vulns"].add(c["rule"])
        e["files"].add(c["file"])
        e["tools"].update(w.split(":")[0] for w in c["witnesses"])
        if c["package"]["fixed"]:
            e["fixed"].add(c["package"]["fixed"])
        if SEV_ORDER[c["severity"]] < SEV_ORDER[e["sev"]]:
            e["sev"] = c["severity"]
    malicious = sorted(f"{n}@{','.join(sorted(e['versions']))}" for (n, _), e in pk.items()
                       if any(x.startswith("MAL-") for x in e["vulns"]))
    if malicious:
        print(f"\n!! KNOWN-MALICIOUS PACKAGES (OSV MAL-*): {', '.join(malicious)} -> P0 supply-chain candidate")
    lic = sum(1 for c in cands if c["category"] == "license")
    if lic:
        print(f"\n(license notices: {lic}, omitted; review only if the client has a license policy)")
    rows = sorted(pk.items(), key=lambda kv: (SEV_ORDER[kv[1]["sev"]], -len(kv[1]["vulns"])))
    rows = [r for r in rows if SEV_ORDER[r[1]["sev"]] <= floor]
    print(f"\n## Dependencies: {len(rows)} vulnerable package versions "
          f"({sum(len(v['vulns']) for _, v in rows)} advisories). Root cause = package; one finding per "
          f"upgrade action, not per CVE.")
    for i, ((name, ver), e) in enumerate(rows):
        if i >= a.top:
            print(f"... {len(rows) - i} more packages (grep candidates.jsonl for category=dependency)")
            break
        fx = ", ".join(sorted(e["fixed"]))[:40] or "see advisory"
        print(f"- [{e['sev']}] {name}@{','.join(sorted(e['versions']))}: {len(e['vulns'])} advisories ({', '.join(sorted(e['vulns'])[:3])}"
              f"{'...' if len(e['vulns']) > 3 else ''}) fixed>= {fx} [{'+'.join(sorted(e['tools']))}] "
              f"in {', '.join(sorted(e['files']))[:80]}")
    if refuted:
        grp = defaultdict(list)
        for c in refuted:
            grp[(c["auto_refuted"], c["witnesses"][0])].append(c)
        print(f"\n## Auto-refuted by rule: {len(refuted)} (not for lanes; cids in candidates.jsonl, auto_refuted=...)\n"
              "| reason | rule | n | cids | first files |\n|--------|------|---|------|-------------|")
        for (why, rule), cs in sorted(grp.items(), key=lambda kv: -len(kv[1])):
            files = ", ".join(sorted({c["file"] for c in cs})[:2])
            print(f"| {why} | {rule} | {len(cs)} | {cs[0]['cid']}..{cs[-1]['cid']} | {files[:90]} |")
    if a.summary_out:
        sys.stdout = _stdout
        Path(host_path(a.summary_out)).write_text(_buf.getvalue(), encoding="utf-8")
        print(f"{a.summary_out} を書き出した（候補 {len(cands)} 件）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
