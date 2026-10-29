#!/usr/bin/env python3
"""
Validate registered findings + report before delivery (Phase 6-7 gate). Exit 0 = pass.

Checks:
  - every finding file has complete frontmatter (id, repo, severity, kind, standard,
    standard_version, requirement_id, confirmed_by, status, found)
  - severity / kind / status / confidence values are from the allowed sets
  - no bare requirement IDs: standard_version must be present and non-placeholder
  - anchors resolve: `path:line` in Location exists in the repo and the line is within the file
  - no unresolved {{placeholders}} anywhere
  - NO card-number-like (Luhn-valid 13-19 digit) values anywhere in findings or report
  - report carries the mandatory sections (scope+gaps, sensitive data at rest, user actions,
    method and limitations) and its severity counts match the finding files
  - duplicate ids / duplicate (file:line, requirement) pairs

Usage:
  python validate_findings.py <findings_dir> [--report security-audit-report_<...>.md] [--repo name=path ...]
         [--lang <code>]   audit language without a report (verifier self-check); default: detected
                           from --report, else en. ja / zh / ko: English prose in a finding is an ERROR.
"""
from __future__ import annotations

import sys
sys.dont_write_bytecode = True  # keep the installed skill free of __pycache__
for _s in (sys.stdout, sys.stderr):  # UTF-8 output even on cp932 / cp1252 consoles and pipes
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
# Each mandatory section is accepted by its template number ("## 2.") or by a keyword in EN / JA,
# so reports written in the user's language pass.
REPORT_SECTIONS = {
    "scope and coverage gaps": r"^##\s*2[.)]|scope|coverage|範囲|カバレッジ",
    "sensitive data at rest": r"^##\s*4[.)]|sensitive data|機微|機密|保存データ",
    "what the user must do": r"^##\s*7[.)]|what the user must do|user action|対応|実施事項",
    "method and limitations": r"^##\s*8[.)]|method and limitations|手法|制限|限界",
}
CODE = re.compile(r"```.*?```|`[^`\n]*`", re.S)


def has_placeholder(text: str) -> bool:
    """Template placeholders left unfilled. Template syntax quoted from audited code (Swig, Jinja,
    Handlebars, GitHub Actions) is fine inside `code` spans or fences, so those are ignored."""
    return bool(PLACEHOLDER.search(CODE.sub("", text)))


PLACEHOLDER = re.compile(r"(?<![$])\{\{(?!\s*(github|matrix|secrets|env|inputs|steps|needs|vars|runner)\.)")
PAN_LIT = re.compile(r"(?<![\d#])(\d[ -]?){12,18}\d(?![\d#])")
ANCHOR = re.compile(r"`((?:[\w.@+-][\w.@+ -]*/)*(?:[\w@+-][\w@+ -]*\.[A-Za-z0-9]+|[\w@+-]*\.[A-Za-z0-9]+|Dockerfile[\w.-]*|Makefile|Jenkinsfile|"
                    r"Gemfile|Procfile|Vagrantfile|Brewfile|Podfile|[\w.-]+/[\w-]+)):(\d+)(?:-\d+)?`")


def host_path(p: str) -> str:
    """Accept Git-Bash style /c/Users/... on Windows (otherwise it silently resolves to C:/c/Users)."""
    if os.name == "nt":
        m = re.match(r"^/([a-zA-Z])(/.*)?$", p or "")
        if m:
            return f"{m.group(1).upper()}:{m.group(2) or '/'}"
    return p


# Canonical standard names for the `standard:` field (longest match first). Aliases map to them.
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
    # Japanese standards. No bare "ipa" / "fisc" key: IPA also publishes security alerts, which are
    # evidence, not a standard to cite.
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


PROSE_CHECK = {"ja", "zh", "ko"}  # non-Latin scripts: a run of 7+ English words is untranslated prose


def intel_unaddressed(fdir: Path, files: list, report: Path | None) -> list[str]:
    """work/intel.json (threat_intel.py): every KEV / national-alert CVE on a pinned version and every
    end-of-life deployed component must be in a finding or named in the report (e.g. under Refuted)."""
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
    ap.add_argument("--repo", action="append", default=[], help="name=path, to resolve anchors")
    ap.add_argument("--lang", help="audit language (e.g. ja); overrides detection from --report")
    a = ap.parse_args()
    repos = {k: host_path(v) for k, v in (r.split("=", 1) for r in a.repo)}
    errs, warns = [], []
    fdir = Path(host_path(a.findings_dir))
    if not fdir.is_dir():
        print(f"ERROR findings_dir not found: {a.findings_dir}")
        return 1
    files = sorted(fdir.rglob("*.md"))
    rlang = "en"  # audit language = report language; non-English audits must not mix English prose
    if a.report and Path(host_path(a.report)).is_file():
        rlang = detect_lang(Path(host_path(a.report)).read_text(encoding="utf-8", errors="replace"))
    if a.lang:
        rlang = a.lang.strip().lower()
    files = [f for f in files if not re.match(r"(security-audit-report|audit-report)", f.name, re.I)]
    if not files:
        warns.append("no finding files found (fine only if the audit truly found nothing - say so in report)")
    ids, pairs, sev_count = Counter(), Counter(), Counter()
    for f in files:
        text = f.read_text(encoding="utf-8", errors="replace")
        fm = frontmatter(text)
        where = f.as_posix()
        if not fm:
            errs.append(f"{where}: missing YAML frontmatter")
            continue
        for k in REQUIRED:
            if not fm.get(k) or "{{" in fm.get(k, ""):
                errs.append(f"{where}: frontmatter '{k}' missing or placeholder")
        if fm.get("severity") and fm["severity"] not in SEVERITIES:
            errs.append(f"{where}: severity '{fm['severity']}' not in {sorted(SEVERITIES)}")
        if fm.get("kind") and fm["kind"] not in KINDS:
            warns.append(f"{where}: kind '{fm['kind']}' not in {sorted(KINDS)}")
        if fm.get("status") and fm["status"] not in STATUSES:
            errs.append(f"{where}: status '{fm['status']}' not in {sorted(STATUSES)}")
        if fm.get("confidence") and fm["confidence"] not in CONFIDENCE:
            errs.append(f"{where}: confidence '{fm['confidence']}' not in {sorted(CONFIDENCE)}")
        if canon_std(fm.get("standard", "")) == "CWE":
            warns.append(f"{where}: CWE is not a primary standard - cite OWASP Top 10 / ASVS / module "
                         f"standard and put the CWE in `cwe:`")
        for st, v in split_citations(fm.get("also_maps_to", "")):
            if v == "?":
                warns.append(f"{where}: also_maps_to '{st}' has no version")
        if fm.get("standard") and canon_std(fm["standard"]) not in CANON:
            warns.append(f"{where}: standard '{fm['standard']}' is not a canonical name (see "
                         f"reference/standards/index.md 'Citation rule')")
        elif fm.get("standard") and canon_std(fm["standard"]) != fm["standard"]:
            warns.append(f"{where}: use canonical standard name '{canon_std(fm['standard'])}'")
        if fm.get("standard_version", "").lower() in ("", "latest", "current", "n/a"):
            errs.append(f"{where}: standard_version must be an explicit version (IDs are version-scoped)")
        ids[fm.get("id")] += 1
        sev_count[fm.get("severity")] += 1
        if has_placeholder(text):
            errs.append(f"{where}: unresolved {{{{placeholder}}}} in body")
        if rlang in PROSE_CHECK:
            eng = english_prose_lines(text, keep=tuple(CANON))
            if eng:
                errs.append(f"{where}: English prose in a {rlang} audit ({len(eng)}+ lines), e.g. {eng[0]!r} - "
                            f"translate (code, paths, IDs, standard names may stay)")
        sec = find_secrets(CODE.sub(lambda m: m.group(0) if "REDACTED" in m.group(0) else m.group(0), text))
        if sec:
            errs.append(f"{where}: secret-like value present ({', '.join(sec)}) - show name + location only")
        if fm.get("id") and f.stem != fm["id"].lower():
            warns.append(f"{where}: file name should be the id in lowercase ({fm['id'].lower()}.md)")
        for m in PAN_LIT.finditer(text):
            if luhn_ok(m.group(0)):
                errs.append(f"{where}: card-number-like value present - remove it (report column + file:line only)")
                break
        loc = re.search(r"^##\s*" + LOCATION_RX + r".*?$(.*?)(?=^##\s|\Z)", text, re.S | re.M | re.I)
        anchors = ANCHOR.findall(loc.group(loc.lastindex) if loc else text)
        if not anchors and fm.get("kind") not in ("supply-chain",):
            warns.append(f"{where}: no `path:line` anchor found in body")
        repo_path = repos.get(fm.get("repo", ""))
        shared = fm.get("shares_anchor_with", "")
        for path, line in set(anchors):
            if re.search(r"(lock|\.sum|requirements[\w.-]*\.txt|package\.json|go\.mod|pom\.xml|\.gradle|Gemfile|"
                         r"Cargo\.toml|composer\.json|pyproject\.toml)$", path, re.I):
                continue  # several packages legitimately share a manifest/lockfile line
            if not shared:  # declared shared anchors (different root causes) are not dedupe candidates
                pairs[(path, line, fm.get("requirement_id"))] += 1
            if repo_path and not re.search(r"history:\w+\s+`" + re.escape(path) + ":" + line, text):
                p = Path(repo_path) / path
                if not p.exists():
                    errs.append(f"{where}: anchor {path}:{line} - file not found in repo '{fm.get('repo')}'")
                elif p.is_dir():
                    warns.append(f"{where}: anchor {path}:{line} is a directory - anchor a file inside it")
                else:
                    try:
                        n = sum(1 for _ in p.open(encoding="utf-8", errors="ignore"))
                    except OSError as e:
                        warns.append(f"{where}: anchor {path}:{line} not readable ({e.__class__.__name__})")
                        continue
                    if int(line) > n:
                        errs.append(f"{where}: anchor {path}:{line} beyond EOF ({n} lines)")
    for i, n in ids.items():
        if n > 1:
            errs.append(f"duplicate finding id {i} ({n} files)")
    for (p, l, r), n in pairs.items():
        if n > 1:
            warns.append(f"{p}:{l} cited by {n} findings for {r} - dedupe by root cause?")

    if a.report:
        rp = Path(host_path(a.report))
        if not rp.exists():
            errs.append(f"report not found: {rp}")
        else:
            rt = rp.read_text(encoding="utf-8", errors="replace")
            low = rt.lower()
            heads = "\n".join(l for l in low.splitlines() if l.startswith("#"))
            for name, rx in REPORT_SECTIONS.items():
                if not re.search(rx, heads, re.M):
                    errs.append(f"report: mandatory section '{name}' missing (keep the numbered '## N.' "
                                f"headings from the template)")
            if has_placeholder(rt):
                errs.append("report: unresolved {{placeholder}}")
            if rlang in PROSE_CHECK:
                eng = english_prose_lines(rt, max_hits=8, keep=tuple(CANON))
                if eng:
                    errs.append(f"report: English prose in a {rlang} report ({len(eng)}+ lines), e.g. {eng[0]!r}")
            sec = find_secrets(rt)
            if sec:
                errs.append(f"report: secret-like value present ({', '.join(sec)})")
            if not re.match(r"security-audit-report_[a-z0-9-]+_\d{4}-\d{2}-\d{2}(_\d{4})?(_\d)?(_[a-z]{2,5})?\.md$", rp.name):
                warns.append(f"report: name should be security-audit-report_<project>_<YYYY-MM-DD_HHMM>[_<lang>].md")
            for m in PAN_LIT.finditer(rt):
                if luhn_ok(m.group(0)):
                    errs.append("report: card-number-like value present")
                    break
            # stale-scaffold check: every table row must agree with its finding file
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
                        errs.append(f"report: {fid} listed but no finding file")
                        continue
                    sev_f, an_f = fmap[fid]
                    if sev_f != cur:
                        errs.append(f"report: {fid} listed under {cur} but finding says {sev_f} - rebuild tables")
                    an_r = re.findall(r"`([^`\n]+?:\d+(?:-\d+)?)`", line)
                    if an_f and an_r and an_r[-1] != an_f:
                        errs.append(f"report: {fid} location {an_r[-1]} != finding {an_f} - stale table")
            for fid in fmap:
                if fid not in seen and sev_count.get(fmap[fid][0]):
                    warns.append(f"report: {fid} has a finding file but is not in the report tables")
            for sev, pat in (("P0", "P0"), ("P1", "P1"), ("P2", "P2"), ("Info", "(?:Info|情報)")):
                m = re.search(rf"^\|\s*{pat}[^|]*\|\s*(\d+)\s*\|\s*$", rt, re.M)
                if m and int(m.group(1)) != sev_count.get(sev, 0):
                    errs.append(f"report: {sev} count {m.group(1)} != finding files {sev_count.get(sev, 0)}")
            if not re.search(r"verified:?\s*\**\s*20\d\d-\d\d-\d\d|\|\s*20\d\d-\d\d-\d\d\s*\|", rt):
                warns.append("report: no standards 'verified' date found")

    warns += intel_unaddressed(fdir, files, Path(host_path(a.report)) if a.report else None)
    for w in warns:
        print(f"WARN  {w}")
    for e in errs:
        print(f"ERROR {e}")
    print(f"\n{len(files)} finding files; severities {dict(sev_count)}; {len(errs)} errors, {len(warns)} warnings")
    return 1 if errs else 0


if __name__ == "__main__":
    sys.exit(main())
