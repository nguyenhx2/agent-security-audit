#!/usr/bin/env python3
"""
納品前に、登録済みの指摘事項と報告書を検証する（Phase 6-7 のゲート）。終了コード 0 = 合格。

チェック内容:
  - すべての指摘事項ファイルのフロントマターが揃っている（id, repo, severity, kind, standard,
    standard_version, requirement_id, confirmed_by, status, found）
  - severity / kind / status / confidence の値が許可された集合に含まれる
  - 要件 ID を単独で使わない：standard_version があり、プレースホルダーではないこと
  - アンカーが解決できる：Location の `path:line` がリポジトリに存在し、行がファイルの範囲内にある
  - 未解決の {{placeholders}} がどこにもない
  - カード番号らしき値（Luhn 検査を通る 13-19 桁）が指摘事項にも報告書にも一切ない
  - 報告書に必須セクション（範囲 + 欠落、保存データの機微情報、利用者の対応事項、
    手法と制限）があり、重大度別の件数が指摘事項ファイルと一致する
  - id の重複 / (file:line, requirement) の組の重複

使い方:
  python validate_findings.py <findings_dir> [--report security-audit-report_<...>.md] [--repo name=path ...]
         [--lang <code>]   報告書なしで監査言語を指定する（検証エージェントの自己チェック）。既定：--report から
                           検出、なければ en。ja / zh / ko では指摘事項中の英語の文章は ERROR。
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
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from peek import find_secrets  # noqa: E402
from i18n import LOCATION_RX, detect_lang, english_prose_lines  # noqa: E402

REQUIRED = ["id", "repo", "severity", "kind", "standard", "standard_version", "requirement_id",
            "confirmed_by", "status", "found"]
SEVERITIES = {"P0", "P1", "P2", "Info"}
KINDS = {"security", "performance", "quality", "sensitive-data-at-rest", "supply-chain", "privacy",
         "configuration", "secret"}
STATUSES = {"open", "in-progress", "closed", "accepted-risk", "false-positive"}
CONFIDENCE = {"confirmed", "likely", "needs-runtime-check"}
# 各必須セクションは、テンプレートの番号（"## 2."）または英語 / 日本語のキーワードで判定する。
# これにより利用者の言語で書かれた報告書も合格する。
REPORT_SECTIONS = {
    "scope and coverage gaps": r"^##\s*2[.)]|scope|coverage|範囲|カバレッジ",
    "sensitive data at rest": r"^##\s*4[.)]|sensitive data|機微|機密|保存データ",
    "what the user must do": r"^##\s*7[.)]|what the user must do|user action|対応|実施事項",
    "method and limitations": r"^##\s*8[.)]|method and limitations|手法|制限|限界",
}
CODE = re.compile(r"```.*?```|`[^`\n]*`", re.S)


def has_placeholder(text: str) -> bool:
    """埋められていないテンプレートのプレースホルダー。監査対象コードから引用したテンプレート構文（Swig、Jinja、
    Handlebars、GitHub Actions）は `code` スパンやコードフェンス内なら問題ないため、それらは無視する。"""
    return bool(PLACEHOLDER.search(CODE.sub("", text)))


PLACEHOLDER = re.compile(r"(?<![$])\{\{(?!\s*(github|matrix|secrets|env|inputs|steps|needs|vars|runner)\.)")
PAN_LIT = re.compile(r"(?<![\d#])(\d[ -]?){12,18}\d(?![\d#])")
ANCHOR = re.compile(r"`((?:[\w.@+-][\w.@+ -]*/)*(?:[\w@+-][\w@+ -]*\.[A-Za-z0-9]+|[\w@+-]*\.[A-Za-z0-9]+|Dockerfile[\w.-]*|Makefile|Jenkinsfile|"
                    r"Gemfile|Procfile|Vagrantfile|Brewfile|Podfile|[\w.-]+/[\w-]+)):(\d+)(?:-\d+)?`")


def host_path(p: str) -> str:
    """Windows で Git-Bash 形式の /c/Users/... を受け付ける（そうしないと黙って C:/c/Users に解決される）。"""
    if os.name == "nt":
        m = re.match(r"^/([a-zA-Z])(/.*)?$", p or "")
        if m:
            return f"{m.group(1).upper()}:{m.group(2) or '/'}"
    return p


# `standard:` 項目に使う基準の正規名（最長一致を優先）。別名はこれらに対応付ける。
CANON = [
    "OWASP Top 10 for Agentic Applications", "OWASP Top 10 for LLM Applications", "OWASP MCP Top 10",
    "OWASP API Security Top 10", "OWASP Mobile Top 10", "OWASP Kubernetes Top 10",
    "OWASP Non-Human Identities Top 10",
    "OWASP Top 10 CI/CD Security Risks", "OWASP Top 10", "OWASP ASVS", "OWASP MASVS", "OWASP MASTG",
    "OWASP AISVS", "PCI DSS", "CIS AWS Foundations", "CIS Azure Foundations", "CIS GCP Foundations",
    "CIS Kubernetes", "CIS Docker", "SLSA", "NIST SSDF SP 800-218", "NIST SP 800-63-4", "CWE",
    "GDPR", "UK GDPR", "Japan APPI", "Japan My Number Act", "IPA How to Secure Your Web Site",
    "MHLW Medical Information Security Guidelines", "MIC/METI Medical Service Provider Guidelines",
    "FISC Security Guidelines", "Vietnam PDPL", "Vietnam Cybersecurity Law", "CCPA", "HIPAA",
    "Japan Credit Card Security Guidelines", "FSA Cybersecurity Guidelines", "Japan Government Unified Standards",
    "ISMAP", "MEXT Education Information Security Guidelines", "JC-STAR", "Japan Telecommunications Business Act",
    "ETSI EN 303 645", "IEC 62443", "UN R155", "UN R156", "FERPA", "COPPA", "GLBA Safeguards Rule",
    "NYDFS 23 NYCRR 500", "Vietnam Decree 85/2016", "Vietnam Circular 09/2020/TT-NHNN",
    "Vietnam Circular 50/2024/TT-NHNN", "Vietnam E-commerce Law", "Japan Active Cyber Defense Act",
    "EU CRA", "EU AI Act", "NIS2", "DORA",
]
ALIASES = {
    "owasp top ten": "OWASP Top 10", "owasp ci/cd security top 10": "OWASP Top 10 CI/CD Security Risks",
    "owasp cicd top 10": "OWASP Top 10 CI/CD Security Risks", "cicd-sec": "OWASP Top 10 CI/CD Security Risks",
    "owasp api top 10": "OWASP API Security Top 10", "owasp llm top 10": "OWASP Top 10 for LLM Applications",
    "owasp agentic top 10": "OWASP Top 10 for Agentic Applications",
    "cis docker benchmark": "CIS Docker", "cis aws foundations benchmark": "CIS AWS Foundations",
    "cis aws": "CIS AWS Foundations", "apppi": "Japan APPI", "appi": "Japan APPI", "pdpl": "Vietnam PDPL",
    "masvs": "OWASP MASVS", "asvs": "OWASP ASVS",
    # 日本の基準。"ipa" / "fisc" 単独のキーは置かない：IPA はセキュリティ上の注意喚起も公開しており、
    # それは根拠であって引用する基準ではない。
    "ipa secure website": "IPA How to Secure Your Web Site", "ipa safe website": "IPA How to Secure Your Web Site",
    "安全なウェブサイトの作り方": "IPA How to Secure Your Web Site",
    "3 ministries 2 guidelines": "MHLW Medical Information Security Guidelines",
    "3省2ガイドライン": "MHLW Medical Information Security Guidelines",
    "医療情報システムの安全管理に関するガイドライン": "MHLW Medical Information Security Guidelines",
    "mhlw medical": "MHLW Medical Information Security Guidelines",
    "医療情報を取り扱う情報システム": "MIC/METI Medical Service Provider Guidelines",
    "mic/meti medical": "MIC/METI Medical Service Provider Guidelines",
    "fisc safety standards": "FISC Security Guidelines", "fisc security": "FISC Security Guidelines",
    "fisc安全対策基準": "FISC Security Guidelines", "金融機関等コンピュータシステムの安全対策基準": "FISC Security Guidelines",
    "my number act": "Japan My Number Act", "番号法": "Japan My Number Act", "マイナンバー法": "Japan My Number Act",
    "個人情報保護法": "Japan APPI", "個人情報の保護に関する法律": "Japan APPI",
    "クレジットカード・セキュリティガイドライン": "Japan Credit Card Security Guidelines",
    "credit card security guidelines": "Japan Credit Card Security Guidelines",
    "金融分野におけるサイバーセキュリティに関するガイドライン": "FSA Cybersecurity Guidelines",
    "fsa cyber": "FSA Cybersecurity Guidelines", "統一基準": "Japan Government Unified Standards",
    "政府機関等のサイバーセキュリティ対策のための統一基準": "Japan Government Unified Standards",
    "教育情報セキュリティポリシーに関するガイドライン": "MEXT Education Information Security Guidelines",
    "サイバー対処能力強化法": "Japan Active Cyber Defense Act", "jc star": "JC-STAR", "外部送信規律": "Japan Telecommunications Business Act",
    "電気通信事業法": "Japan Telecommunications Business Act", "etsi en 303645": "ETSI EN 303 645",
    "isa/iec 62443": "IEC 62443", "isa 62443": "IEC 62443", "23 nycrr 500": "NYDFS 23 NYCRR 500",
    "nydfs": "NYDFS 23 NYCRR 500", "glba": "GLBA Safeguards Rule", "ftc safeguards rule": "GLBA Safeguards Rule",
}


def canon_std(name: str) -> str:
    n = re.sub(r"\s+", " ", (name or "").strip())
    low = n.lower()
    for k in sorted(ALIASES, key=len, reverse=True):
        if low.startswith(k):
            return ALIASES[k]
    for c in CANON:
        if low.startswith(c.lower()):
            return c
    return n


def split_citations(text: str) -> list[tuple[str, str]]:
    """'OWASP ASVS 5.0.0 V8.2; OWASP Top 10:2025 A01; CWE-639' -> [(std, version), ...]"""
    out = []
    for part in re.split(r"[;,]\s*", text or ""):
        part = part.strip().replace("Top 10:", "Top 10 ")
        if not part or part.upper().startswith("CWE"):
            continue
        std = canon_std(part)
        rest = part[len(std):].strip() if part.lower().startswith(std.lower()) else part
        m = re.match(r"(v?\d[\w.]*)", rest)
        if std in CANON:
            out.append((std, m.group(1) if m else "?"))
    return out


def luhn_ok(num: str) -> bool:
    d = [int(c) for c in num if c.isdigit()]
    if not 13 <= len(d) <= 19 or len(set(d)) == 1:
        return False
    s = 0
    for i, x in enumerate(reversed(d)):
        if i % 2:
            x = x * 2 - 9 if x * 2 > 9 else x * 2
        s += x
    return s % 10 == 0


def frontmatter(text: str) -> dict:
    m = re.match(r"^---\s*\n(.*?)\n---\s*\n", text, re.S)
    if not m:
        return {}
    fm = {}
    for line in m.group(1).splitlines():
        line = re.sub(r"\s+#.*$", "", line)
        if ":" in line and not line.startswith(" "):
            k, v = line.split(":", 1)
            fm[k.strip()] = v.strip().strip("'\"")
    return fm


PROSE_CHECK = {"ja", "zh", "ko"}  # 非ラテン文字の言語：英単語が 7 語以上続くものは未翻訳の文章とみなす


def intel_unaddressed(fdir: Path, files: list, report: Path | None) -> list[str]:
    """work/intel.json（threat_intel.py）：指定バージョンに該当する KEV / 国内注意喚起の CVE と、サポート終了の
    デプロイ済み構成要素は、すべて指摘に含めるか報告書（例えば Refuted の欄）に記載しなければならない。"""
    root = fdir.parent.parent if fdir.parent.name == "findings" else fdir.parent
    ip = root / "work" / "intel.json"
    if not ip.is_file():
        return []
    try:
        intel = json.loads(ip.read_text(encoding="utf-8"))
    except ValueError:
        return ["intel.json unreadable - re-run threat_intel.py"]
    found = "\n".join(f.read_text(encoding="utf-8", errors="replace") for f in files)
    refuted = report_refuted(report) if report and report.is_file() else ""
    out = []
    for c in intel.get("components", []):
        srcs = [s.rsplit(":", 1)[0] for s in (c.get("sources") or [c.get("source", "")]) if s]
        where = f"{c.get('product')} {c.get('version')} ({srcs[0] if srcs else '?'})"
        for r in c.get("cves", []):
            if (r.get("kev") or r.get("in_alert")) and r.get("id") and r["id"] not in found and r["id"] not in refuted:
                out.append(f"intel: {r['id']} ({'KEV' if r.get('kev') else 'national alert'}) affects {where} - "
                           f"register a finding or list it under Refuted with the reason")
        if c.get("status") == "eol" and c.get("context") == "deploy":
            prod = str(c.get("product", "")).lower()
            if not any(s in found for s in srcs) or prod not in found.lower():
                if prod not in refuted.lower():
                    out.append(f"intel: end-of-life {where} is in no finding - register it (P1/P2) or list it under "
                               f"Refuted with the reason")
    return out


def report_refuted(report: Path) -> str:
    t = report.read_text(encoding="utf-8", errors="replace")
    m = re.search(r"^###[^\n]*(Refuted|否定された候補|反証)[^\n]*\n(.*?)(?=^##)", t, re.S | re.M)
    return m.group(2) if m else ""


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("findings_dir")
    ap.add_argument("--report")
    ap.add_argument("--repo", action="append", default=[], help="name=path。アンカーの解決に使う")
    ap.add_argument("--lang", help="監査言語（例：ja）。--report からの検出より優先する")
    a = ap.parse_args()
    repos = {k: host_path(v) for k, v in (r.split("=", 1) for r in a.repo)}
    errs, warns = [], []
    fdir = Path(host_path(a.findings_dir))
    if not fdir.is_dir():
        print(f"ERROR findings_dir が見つからない: {a.findings_dir}")
        return 1
    files = sorted(fdir.rglob("*.md"))
    rlang = "en"  # 監査言語 = 報告書の言語。英語以外の監査に英語の文章を混ぜてはならない
    if a.report and Path(host_path(a.report)).is_file():
        rlang = detect_lang(Path(host_path(a.report)).read_text(encoding="utf-8", errors="replace"))
    if a.lang:
        rlang = a.lang.strip().lower()
    files = [f for f in files if not re.match(r"(security-audit-report|audit-report)", f.name, re.I)]
    if not files:
        warns.append("指摘事項ファイルが見つからない（監査で本当に何も見つからなかった場合に限り問題ない - その旨を報告書に記載する）")
    ids, pairs, sev_count = Counter(), Counter(), Counter()
    for f in files:
        text = f.read_text(encoding="utf-8", errors="replace")
        fm = frontmatter(text)
        where = f.as_posix()
        if not fm:
            errs.append(f"{where}: YAML フロントマターがない")
            continue
        for k in REQUIRED:
            if not fm.get(k) or "{{" in fm.get(k, ""):
                errs.append(f"{where}: フロントマターの '{k}' がないか、プレースホルダーのまま")
        if fm.get("severity") and fm["severity"] not in SEVERITIES:
            errs.append(f"{where}: severity '{fm['severity']}' は {sorted(SEVERITIES)} のいずれでもない")
        if fm.get("kind") and fm["kind"] not in KINDS:
            warns.append(f"{where}: kind '{fm['kind']}' は {sorted(KINDS)} のいずれでもない")
        if fm.get("status") and fm["status"] not in STATUSES:
            errs.append(f"{where}: status '{fm['status']}' は {sorted(STATUSES)} のいずれでもない")
        if fm.get("confidence") and fm["confidence"] not in CONFIDENCE:
            errs.append(f"{where}: confidence '{fm['confidence']}' は {sorted(CONFIDENCE)} のいずれでもない")
        if canon_std(fm.get("standard", "")) == "CWE":
            warns.append(f"{where}: CWE は主たる基準ではない - OWASP Top 10 / ASVS / モジュールの基準を"
                         f"引用し、CWE は `cwe:` に記載する")
        for st, v in split_citations(fm.get("also_maps_to", "")):
            if v == "?":
                warns.append(f"{where}: also_maps_to の '{st}' にバージョンがない")
        if fm.get("standard") and canon_std(fm["standard"]) not in CANON:
            warns.append(f"{where}: standard '{fm['standard']}' は正規名ではない（"
                         f"reference/standards/index.md の 'Citation rule' を参照）")
        elif fm.get("standard") and canon_std(fm["standard"]) != fm["standard"]:
            warns.append(f"{where}: 基準の正規名 '{canon_std(fm['standard'])}' を使う")
        if fm.get("standard_version", "").lower() in ("", "latest", "current", "n/a"):
            errs.append(f"{where}: standard_version は明示的なバージョンにする（ID はバージョンごとに定義される）")
        ids[fm.get("id")] += 1
        sev_count[fm.get("severity")] += 1
        if has_placeholder(text):
            errs.append(f"{where}: 本文に未解決の {{{{placeholder}}}} がある")
        if rlang in PROSE_CHECK:
            eng = english_prose_lines(text, keep=tuple(CANON))
            if eng:
                errs.append(f"{where}: {rlang} の監査に英語の文章がある（{len(eng)} 行以上）。例：{eng[0]!r} - "
                            f"翻訳する（コード、パス、ID、基準名はそのままでよい）")
        sec = find_secrets(CODE.sub(lambda m: m.group(0) if "REDACTED" in m.group(0) else m.group(0), text))
        if sec:
            errs.append(f"{where}: シークレットらしき値がある（{', '.join(sec)}）- 名前と該当箇所のみを示す")
        if fm.get("id") and f.stem != fm["id"].lower():
            warns.append(f"{where}: ファイル名は id の小文字にする（{fm['id'].lower()}.md）")
        for m in PAN_LIT.finditer(text):
            if luhn_ok(m.group(0)):
                errs.append(f"{where}: カード番号らしき値がある - 削除する（カラム名 + file:line のみを報告する）")
                break
        loc = re.search(r"^##\s*" + LOCATION_RX + r".*?$(.*?)(?=^##\s|\Z)", text, re.S | re.M | re.I)
        anchors = ANCHOR.findall(loc.group(loc.lastindex) if loc else text)
        if not anchors and fm.get("kind") not in ("supply-chain",):
            warns.append(f"{where}: 本文に `path:line` のアンカーが見つからない")
        repo_path = repos.get(fm.get("repo", ""))
        shared = fm.get("shares_anchor_with", "")
        for path, line in set(anchors):
            if re.search(r"(lock|\.sum|requirements[\w.-]*\.txt|package\.json|go\.mod|pom\.xml|\.gradle|Gemfile|"
                         r"Cargo\.toml|composer\.json|pyproject\.toml)$", path, re.I):
                continue  # 複数のパッケージがマニフェスト / ロックファイルの同じ行を共有するのは正当
            if not shared:  # 共有と宣言されたアンカー（根本原因が異なる）は重複排除の候補にしない
                pairs[(path, line, fm.get("requirement_id"))] += 1
            if repo_path and not re.search(r"history:\w+\s+`" + re.escape(path) + ":" + line, text):
                p = Path(repo_path) / path
                if not p.exists():
                    errs.append(f"{where}: アンカー {path}:{line} - リポジトリ '{fm.get('repo')}' にファイルが見つからない")
                elif p.is_dir():
                    warns.append(f"{where}: アンカー {path}:{line} はディレクトリ - その中のファイルをアンカーにする")
                else:
                    try:
                        n = sum(1 for _ in p.open(encoding="utf-8", errors="ignore"))
                    except OSError as e:
                        warns.append(f"{where}: アンカー {path}:{line} を読めない（{e.__class__.__name__}）")
                        continue
                    if int(line) > n:
                        errs.append(f"{where}: アンカー {path}:{line} がファイル末尾を超えている（{n} 行）")
    for i, n in ids.items():
        if n > 1:
            errs.append(f"指摘事項の id {i} が重複している（{n} ファイル）")
    for (p, l, r), n in pairs.items():
        if n > 1:
            warns.append(f"{p}:{l} が {r} について {n} 件の指摘事項から引用されている - 根本原因で重複排除すべきでは？")

    if a.report:
        rp = Path(host_path(a.report))
        if not rp.exists():
            errs.append(f"報告書が見つからない: {rp}")
        else:
            rt = rp.read_text(encoding="utf-8", errors="replace")
            low = rt.lower()
            heads = "\n".join(l for l in low.splitlines() if l.startswith("#"))
            for name, rx in REPORT_SECTIONS.items():
                if not re.search(rx, heads, re.M):
                    errs.append(f"report: 必須セクション '{name}' がない（テンプレートの番号付き '## N.' "
                                f"見出しを残す）")
            if has_placeholder(rt):
                errs.append("report: 未解決の {{placeholder}} がある")
            if rlang in PROSE_CHECK:
                eng = english_prose_lines(rt, max_hits=8, keep=tuple(CANON))
                if eng:
                    errs.append(f"report: {rlang} の報告書に英語の文章がある（{len(eng)} 行以上）。例：{eng[0]!r}")
            sec = find_secrets(rt)
            if sec:
                errs.append(f"report: シークレットらしき値がある（{', '.join(sec)}）")
            if not re.match(r"security-audit-report_[a-z0-9-]+_\d{4}-\d{2}-\d{2}(_\d{4})?(_\d)?(_[a-z]{2,5})?\.md$", rp.name):
                warns.append(f"report: ファイル名は security-audit-report_<project>_<YYYY-MM-DD_HHMM>[_<lang>].md にする")
            for m in PAN_LIT.finditer(rt):
                if luhn_ok(m.group(0)):
                    errs.append("report: カード番号らしき値がある")
                    break
            # 古い雛形のチェック：表の各行が対応する指摘事項ファイルと一致しなければならない
            fmap = {}
            for f in files:
                t_ = f.read_text(encoding="utf-8", errors="replace")
                fm_ = frontmatter(t_)
                lc = re.search(r"^##\s*" + LOCATION_RX + r".*?$(.*?)(?=^##\s|\Z)", t_, re.S | re.M | re.I)
                an = re.search(r"`([^`\n]+?:\d+(?:-\d+)?)`", lc.group(lc.lastindex) if lc else t_)
                if fm_.get("id"):
                    fmap[fm_["id"]] = (fm_.get("severity"), an.group(1) if an else "")
            cur = None
            seen = set()
            for line in rt.splitlines():
                h = re.match(r"^###\s+(P0|P1|P2|Info|情報)\b", line)
                if h:
                    cur = {"情報": "Info"}.get(h.group(1), h.group(1))
                    continue
                if line.startswith("## "):
                    cur = None
                m = re.match(r"^\|\s*(FIND-[\w-]+)\s*\|", line)
                if m and cur:
                    fid = m.group(1)
                    seen.add(fid)
                    if fid not in fmap:
                        errs.append(f"report: {fid} が記載されているが、指摘事項ファイルがない")
                        continue
                    sev_f, an_f = fmap[fid]
                    if sev_f != cur:
                        errs.append(f"report: {fid} は {cur} の下に記載されているが、指摘事項では {sev_f} - 表を再生成する")
                    an_r = re.findall(r"`([^`\n]+?:\d+(?:-\d+)?)`", line)
                    if an_f and an_r and an_r[-1] != an_f:
                        errs.append(f"report: {fid} の該当箇所 {an_r[-1]} != 指摘事項 {an_f} - 表が古い")
            for fid in fmap:
                if fid not in seen and sev_count.get(fmap[fid][0]):
                    warns.append(f"report: {fid} は指摘事項ファイルがあるが、報告書の表に載っていない")
            for sev, pat in (("P0", "P0"), ("P1", "P1"), ("P2", "P2"), ("Info", "(?:Info|情報)")):
                m = re.search(rf"^\|\s*{pat}[^|]*\|\s*(\d+)\s*\|\s*$", rt, re.M)
                if m and int(m.group(1)) != sev_count.get(sev, 0):
                    errs.append(f"report: {sev} の件数 {m.group(1)} != 指摘事項ファイル {sev_count.get(sev, 0)}")
            if not re.search(r"verified:?\s*\**\s*20\d\d-\d\d-\d\d|\|\s*20\d\d-\d\d-\d\d\s*\|", rt):
                warns.append("report: 基準の 'verified' 日付が見つからない")

    warns += intel_unaddressed(fdir, files, Path(host_path(a.report)) if a.report else None)
    for w in warns:
        print(f"WARN  {w}")
    for e in errs:
        print(f"ERROR {e}")
    print(f"\n指摘事項ファイル {len(files)} 件、重大度 {dict(sev_count)}、エラー {len(errs)} 件、警告 {len(warns)} 件")
    return 1 if errs else 0


if __name__ == "__main__":
    sys.exit(main())
