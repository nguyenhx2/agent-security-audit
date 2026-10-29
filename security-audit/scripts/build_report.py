#!/usr/bin/env python3
"""
Scaffold the audit report (security-audit-report_<project>_<ts>.md) from the audit_dir (Phase 7). Fills everything mechanical; leaves
`{{...}}` only for narrative the model must write (executive summary, actions, cross-repo notes).

Sources: findings/<repo>/*.md frontmatter + titles, <repo>/scanners.json, <repo>/sweep.json,
profile.md. Counts and tables always agree with the finding files (validate_findings checks this).

Output: <audit_dir>/reports/md/security-audit-report_<project>_<YYYY-MM-DD_HHMM>.md (layout.py) (lowercase, timestamped, so
re-runs never collide). Render HTML afterwards with render_html.py when the user chose HTML.

Usage:
  python build_report.py <audit_dir> [--depth quick|standard|deep] [--project NAME] [--out FILE]
         [--skill-version 1.15.0] [--standards-verified 2026-10-26] [--refresh-meta]

Header facts (skill version, standards-verified date, <ts>, audited commit per repo) are fixed at the
first build and stored in work/report-settings.json, so rebuilds and translations never drift. The
commit comes from scan time (scanners.json, else profile.md); --refresh-meta re-derives all but <ts>.
"""
from __future__ import annotations

import sys
sys.dont_write_bytecode = True  # keep the installed skill free of __pycache__
for _s in (sys.stdout, sys.stderr):  # UTF-8 output even on cp932 / cp1252 consoles and pipes
    if hasattr(_s, "reconfigure"):
        _s.reconfigure(encoding="utf-8", errors="replace")

import argparse
import datetime as dt
import json
import os
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from i18n import (LANGS, LOCATION_RX, T as I18N, ai_risk, ai_surface, gap_text, intel_status, label,  # noqa: E402
                  std_name, ui)
from layout import findings_dir as _fdir, report_out, work_dir  # noqa: E402
import safegit  # noqa: E402

SEV = ["P0", "P1", "P2", "Info"]


def host_path(p: str) -> str:
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


def frontmatter(text: str) -> dict:
    m = re.match(r"^---\s*\n(.*?)\n---\s*\n", text, re.S)
    fm = {}
    if m:
        for line in m.group(1).splitlines():
            line = re.sub(r"\s+#.*$", "", line)
            if ":" in line and not line.startswith(" "):
                k, v = line.split(":", 1)
                fm[k.strip()] = v.strip().strip("'\"")
    return fm


def first_anchor(text: str) -> str:
    """First `path:line` of the Location section (the scope validate_findings and render_xlsx use), so a
    path quoted in the title or another section never becomes the table location. An entry is
    "- `path:line` - note"; the path may contain spaces, the note is split off at " - "."""
    sec = re.search(r"^##\s*" + LOCATION_RX + r".*?$(.*?)(?=^##\s|\Z)", text, re.S | re.M | re.I)
    body = sec.group(sec.lastindex) if sec else text
    for entry in re.findall(r"^\s*[-*]\s+(.+)$", body, re.M):
        m = re.search(r"`([^`]+?:\d+(?:-\d+)?)`", re.split(r"\s+-\s+", entry, maxsplit=1)[0])
        if m:
            return f"`{m.group(1)}`"
    m = re.search(r"`([^`]+?:\d+(?:-\d+)?)`", body)
    return f"`{m.group(1)}`" if m else "-"


def cell(text) -> str:
    """Markdown table cell: a literal `|` would start a new column."""
    return str(text).replace("|", "\\|")


def legacy_meta(rdir: Path) -> dict:
    """Header facts of a report built before they were stored in report-settings.json (oldest report)."""
    reps = sorted(rdir.glob("security-audit-report_*.md"))
    if not reps:
        return {}
    text, meta = reps[0].read_text(encoding="utf-8", errors="replace"), {}
    m = re.search(r"_(\d{4}-\d{2}-\d{2}(?:_\d{4})?(?:_\d+)?)(?:_[a-z]{2,5})?\.md$", reps[0].name)
    if m:
        meta["ts"] = m.group(1)
    for key, rx in (("skill_version", r"security-audit\D{0,12}v(\d+\.\d+\.\d+)"),
                    ("standards_verified", r"^- \*\*.*?(\d{4}-\d{2}-\d{2})\S*\s*:\*\*\s*$")):
        m = re.search(rx, text, re.M)
        if m:
            meta[key] = m.group(1)
    return meta


def profile_commit(W: Path, repo: str) -> tuple[str, bool | None] | None:
    """(head, dirty) that detect_stack recorded for `repo` in work/profile.md (md or json output)."""
    pf = W / "profile.md"
    if not pf.exists():
        return None
    text = pf.read_text(encoding="utf-8", errors="replace")
    try:
        for prof in json.loads(text):
            if prof.get("name") == repo and (prof.get("git") or {}).get("head"):
                return prof["git"]["head"], prof["git"].get("dirty")
        return None
    except (ValueError, AttributeError, TypeError):
        pass
    sec = re.search(rf"^##\s+{re.escape(repo)}\s.*?(?=^##\s|\Z)", text, re.S | re.M)
    m = re.search(r"""['"]head['"]:\s*['"]([0-9a-f]{7,40})['"]""", sec.group(0)) if sec else None
    if not m:
        return None
    dm = re.search(r"""['"]dirty['"]:\s*(True|False|true|false)""", sec.group(0))
    return m.group(1), (dm.group(1).lower() == "true") if dm else None


def title_of(text: str, fid: str) -> str:
    m = re.search(r"^#\s+(.+)$", text, re.M)
    t = m.group(1).strip() if m else fid
    return re.sub(rf"^{re.escape(fid)}\s*[-:]\s*", "", t)


def cite(fm: dict) -> str:
    std, ver = canon_std(fm.get("standard", "")), str(fm.get("standard_version", ""))
    if std == "OWASP Top 10" and ver.isdigit():
        return f"OWASP Top 10:{ver} {fm.get('requirement_id', '')}".strip()  # canonical form (index.md)
    return f"{std} {ver} {fm.get('requirement_id', '')}".strip()


def intel_section(W: Path, X: dict, lang: str) -> list[str]:
    """Section 2 subsection from work/intel.json (threat_intel.py): components with a support or advisory
    issue, then the feeds checked. Ids, versions and product keys only - no feed prose."""
    out = [f"### {X['intel']}"]
    ip = W / "intel.json"
    try:
        intel = json.loads(ip.read_text(encoding="utf-8")) if ip.exists() else None
    except ValueError:
        intel = None
    if intel is None:
        return out + [X["intel_not_run"] + "\n"]
    comps = intel.get("components", [])
    if not comps:
        out.append(X["intel_none"])
    order = {"act-now": 0, "review": 1, "update": 2, "ok": 3}
    shown = [c for c in comps if c.get("priority") != "ok"]
    if shown:
        out.append("| " + " | ".join(X["intel_cols"]) + " |")
        out.append("|" + "---|" * len(X["intel_cols"]))
    for c in sorted(shown, key=lambda c: (order.get(c.get("priority"), 9), c.get("repo", ""), c.get("product", ""))):
        e = c.get("eol") or {}
        sup = intel_status(c.get("status", "unknown"), lang)
        if e.get("cycle"):
            sup += f" (`{cell(e['cycle'])}`" + (f", EOL `{cell(e['eol_from'])}`" if e.get("eol_from") else "") + \
                (f", latest `{cell(e['latest'])}`" if e.get("latest") else "") + ")"
        adv = [f"`{r['id']}`" + (" KEV" if r.get("kev") else "") for r in c.get("cves", [])[:4]]
        adv += [f"`{x}`" for x in (c.get("alert_cves_unconfirmed") or [])[:2] if f"`{x}`" not in " ".join(adv)]
        feeds = sorted({FEED_LABEL.get(a.get("feed"), a.get("feed")) for a in c.get("alerts", [])})
        if feeds:
            adv.append("/".join(feeds))
        if c.get("kev_recent"):
            adv.append("KEV " + ", ".join(f"`{k['id']}`" for k in c["kev_recent"][:2]))
        srcs = c.get("sources") or [c.get("source", "")]
        out.append(f"| {cell(c.get('repo'))} | `{cell(c.get('product'))}` | `{cell(c.get('version'))}` | "
                   f"{', '.join(f'`{cell(s)}`' for s in srcs[:3])} | {sup} | {', '.join(adv) or '-'} |")
    rest = len(comps) - len(shown)
    if rest and comps:
        out.append("\n" + X["intel_rest"].format(n=rest))
    feeds = intel.get("feeds", [])
    sep = "、" if lang == "ja" else ", "  # labels in code spans: product names, not prose
    ok = sep.join(f"`{f['label']}`" for f in feeds if f.get("status") not in ("failed", "skipped"))
    bad = sep.join(f"`{f['label']}`" for f in feeds if f.get("status") == "failed")
    out.append("\n" + X["intel_feeds"].format(date=intel.get("date", "?"), days=intel.get("window_days", "?"),
                                             ok=ok or "-"))
    if bad:
        out.append(X["intel_failed"].format(failed=bad))
    out.append("\n" + X["intel_note"] + "\n")
    return out


FEED_LABEL = {"ipa": "IPA", "jpcert": "JPCERT/CC", "jvn": "JVN", "jvndb": "JVN iPedia", "kev": "KEV"}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("audit_dir")
    ap.add_argument("--depth", default=None)
    ap.add_argument("--project", default=None)
    ap.add_argument("--skill-version", default=None, help="default: stored at the first build, else SKILL.md")
    ap.add_argument("--standards-verified", default=None, help="default: stored at the first build, else SKILL.md")
    ap.add_argument("--refresh-meta", action="store_true",
                    help="re-derive skill version, standards date and audited commits (ignore the stored ones)")
    ap.add_argument("--out", help="explicit report path (default: timestamped name in audit_dir)")
    ap.add_argument("--ts", help="YYYY-MM-DD_HHMM fixed at Phase 0 (default: audit_dir name, else now)")
    ap.add_argument("--force", action="store_true", help="overwrite an existing report (discards narrative)")
    ap.add_argument("--fill", help="JSON {key: text} - replaces {{key: ...}} placeholders (narrative)")
    ap.add_argument("--list-placeholders", action="store_true", help="print placeholder keys of an existing report")
    ap.add_argument("--lang", default=None,
                    help="report language code (en / ja fully localised; other codes use English labels)")
    ap.add_argument("--findings-dir", default=None,
                    help="findings folder relative to audit_dir (default: findings/<lang>; legacy findings[-<lang>])")
    ap.add_argument("--lang-suffix", action="store_true",
                    help="append _<lang> to the report name (use when producing several languages)")
    a = ap.parse_args()
    d = Path(host_path(a.audit_dir))
    W = work_dir(d)
    # remembered settings (per findings dir) so a --force/--fill rebuild needs no repeated flags
    sfile = W / "report-settings.json"
    saved = json.loads(sfile.read_text(encoding="utf-8")) if sfile.exists() else {}
    if a.findings_dir is None:
        a.findings_dir = _fdir(d, a.lang or "en").relative_to(d).as_posix()
    mine = saved.get(a.findings_dir, {})
    a.depth = a.depth or mine.get("depth") or "{{depth}}"
    a.project = a.project if a.project is not None else mine.get("project", "")
    a.lang = a.lang or mine.get("lang") or "en"
    a.lang_suffix = a.lang_suffix or mine.get("lang_suffix", False)
    # audit-wide header facts: fixed at the first build so a rebuild never re-derives them live
    meta = dict(saved.get("_audit", {}))
    if a.refresh_meta:  # <ts> stays: it names the report (use --ts to change it)
        meta = {k: v for k, v in meta.items() if k == "ts"}
    if not meta and not a.refresh_meta:
        meta = legacy_meta(report_out(d, "x.md").parent)
    if "skill_version" not in meta or "standards_verified" not in meta:
        _skill = (Path(__file__).resolve().parent.parent / "SKILL.md").read_text(encoding="utf-8")
        _v = re.search(r'version:\s*"?([\d.]+)', _skill)
        _sv = re.search(r'standards-verified:\s*"?([\d-]+)', _skill)
        meta.setdefault("skill_version", _v.group(1) if _v else "?")
        meta.setdefault("standards_verified", _sv.group(1) if _sv else "?")
    meta["skill_version"] = a.skill_version = a.skill_version or meta["skill_version"]
    meta["standards_verified"] = a.standards_verified = a.standards_verified or meta["standards_verified"]
    if a.ts or "ts" not in meta:  # --ts, else the audit_dir name (fixed at Phase 0), else now
        meta["ts"] = a.ts or (d.name if re.fullmatch(r"\d{4}-\d{2}-\d{2}(_\d{4})?(_\d+)?", d.name)
                              else dt.datetime.now().strftime("%Y-%m-%d_%H%M"))
    commits_meta = meta.setdefault("commits", {})
    if not a.list_placeholders:
        saved[a.findings_dir] = {"depth": a.depth, "project": a.project, "lang": a.lang, "lang_suffix": a.lang_suffix}
        saved["_audit"] = meta  # rewritten below once the audited commits are known
        sfile.write_text(json.dumps(saved, indent=1, ensure_ascii=False), encoding="utf-8")

    findings = []
    fdir = d / a.findings_dir
    if not fdir.is_dir():
        print(f"error: findings dir not found: {fdir}", file=sys.stderr)
        return 2
    for f in sorted(fdir.rglob("*.md")):
        t = f.read_text(encoding="utf-8", errors="replace")
        fm = frontmatter(t)
        if fm:
            findings.append((fm, title_of(t, fm.get("id", f.stem)), first_anchor(t)))
    counts = Counter(fm.get("severity") for fm, _, _ in findings)
    repos = sorted({p.name for p in W.iterdir() if p.is_dir() and p.name not in ("findings", "reports", "work")
                    and not p.name.startswith("findings")
                    and ((p / "scanners.json").exists() or (p / "sweep.json").exists())})

    proj = re.sub(r"[^a-z0-9]+", "-", (a.project or "-".join(repos) or "audit").lower()).strip("-")[:40]
    ts = meta["ts"]  # stored at the first build: a renamed audit folder still rebuilds the same report
    suffix = f"_{a.lang}" if a.lang_suffix else ""
    out = Path(host_path(a.out)) if a.out else report_out(d, f"security-audit-report_{proj}_{ts}{suffix}.md")
    if a.list_placeholders:
        src = out if out.exists() else None
        if not src:
            print("error: --list-placeholders needs an existing report (--out <report.md>)", file=sys.stderr)
            return 2
        for k, hint in re.findall(r"\{\{(\w+): ([^{}]*)\}\}", src.read_text(encoding="utf-8")):
            print(f"{k}: {hint}")
        return 0
    if out.exists() and not a.force:
        print(f"error: {out} exists. Rebuild with --force (discards narrative already written) - "
              f"finish all findings before filling narrative.", file=sys.stderr)
        return 2

    lang = a.lang
    X = ui(lang)

    def ph(key: str, text: str) -> str:
        return text.replace("{{", "{{" + key + ": ", 1)
    sev_long = lambda s_: label("severity_long", s_, lang)  # noqa: E731
    L = []
    L.append(f"# {X['report_title']} - {a.project or ', '.join(repos) or '{{project}}'}\n")
    L.append("| | |\n|---|---|")
    L.append(f"| {X['date']} | {ts[:10]} |")  # audit date from <ts>, stable across rebuilds
    L.append(f"| {X['repos']} | {', '.join(repos) or '{{repos}}'} |")
    L.append(f"| {X['depth']} | {label('depth', a.depth, lang)} |")
    modes = set()
    scan = {}
    for r in repos:
        sp = W / r / "scanners.json"
        if sp.exists():
            scan[r] = json.loads(sp.read_text(encoding="utf-8"))
            modes.add(scan[r].get("mode", "?"))
    L.append(f"| {X['auditor']} | {X['auditor_val'].format(v=a.skill_version)} |")
    L.append(f"| {X['mode']} | {', '.join(sorted(modes)) or X['none_mode']} |")
    commits = []
    for r in repos:
        # audited commit: stored at the first build, else scan time (scanners.json), profile.md, live repo
        if r not in commits_meta:
            hd = (scan[r]["commit"], scan[r].get("dirty")) if scan.get(r, {}).get("commit") else profile_commit(W, r)
            if not hd:
                sp = W / r / "sweep.json"
                rp = json.loads(sp.read_text(encoding="utf-8")).get("repo") if sp.exists() else None
                hd = safegit.head_dirty(rp) if rp and Path(rp).is_dir() else None
            if hd and hd[0]:
                commits_meta[r] = list(hd)
        if r in commits_meta:
            h, dirty = commits_meta[r]
            commits.append(f"{r} @ `{h}`" + (f" ({X['dirty']})" if dirty else ""))
    if not a.list_placeholders:
        sfile.write_text(json.dumps(saved, indent=1, ensure_ascii=False), encoding="utf-8")
    L.append(f"| {X['commit']} | {', '.join(commits) or '-'} |\n")

    L.append(f"## {X['s1']}")
    L.append(ph("exec_summary", X["s1_ph"]) + "\n")
    L.append(f"| {X['severity']} | {X['count']} |\n|----------|-------|")
    for s_ in SEV:
        L.append(f"| {sev_long(s_)} | {counts.get(s_, 0)} |")
    L.append("")

    L.append(f"## {X['s2']}")
    L.append(X["mount_note"] + "\n")
    L.append("| " + " | ".join(X["cov_cols"]) + " |")
    L.append("|" + "---|" * len(X["cov_cols"]))
    for r in repos:
        m = scan.get(r, {})
        tools = ", ".join(
            f"{t['tool']}@{(t.get('digest') or t.get('version') or '?').split('@')[-1].replace('sha256:', '')[:12]}"
            for t in m.get("tools", []) if t.get("status") == "ok") or "-"
        gaps = "; ".join(f"`{cell(gap_text(g, lang))}`" for g in m.get("coverage_gaps", [])) or ph(f"gaps_{re.sub(r'[^A-Za-z0-9]', '_', r)}", X["gaps_ph"])
        L.append(f"| {r} | {tools} | {m.get('mount_file_count', '-')} | "
                 f"{X['full'] if m.get('git_history') else X['gap']} | {gaps} |")
    L.append("\n" + ph("lanes", X["lanes_ph"]))
    L.append(ph("classes_not_examined", X["classes_ph"]) + "\n")
    L.append(f"### {X['ai_inv']}")
    ai_rows = []
    for r in repos:
        ap_ = W / r / "agent-config.json"
        if not ap_.exists():
            ai_rows.append(f"- **{r}:** {X['ai_not_run']}")
            continue
        inv = json.loads(ap_.read_text(encoding="utf-8"))
        if not inv.get("rows"):
            ai_rows.append(f"- **{r}:** {X['ai_none']}")
            continue
        by = defaultdict(list)
        for row in inv["rows"]:
            by[row["surface"]].append(row)
        ai_rows.append("| " + " | ".join(X["ai_cols"]) + " |")
        ai_rows.append("|" + "---|" * len(X["ai_cols"]))
        for surf, items in sorted(by.items(), key=lambda kv: -sum(1 for x in kv[1] if x["risk"])):
            risky = [x for x in items if x["risk"]]
            labs = sorted({lab.replace("`", "") for x in risky for lab in x["risk"]})
            loc = [ai_risk(lab, lang) for lab in labs]
            if all(v is not None for v in loc):
                ex = ("、" if lang == "ja" else ", ").join(list(dict.fromkeys(loc))[:3]) or "-"
                surf_txt = ai_surface(surf, lang)
            else:
                ex = ", ".join(f"`{lab[:70]}`" for lab in labs[:3]) or "-"
                surf_txt = f"`{surf}`"
            ai_rows.append(f"| {r} | {surf_txt} | {len(items)} | {len(risky)} | {ex.replace('|', '/')} |")
    L += ai_rows
    L.append("\n" + X["ai_note"] + "\n")
    L += intel_section(W, X, lang)

    L.append(f"## {X['s3']}")
    L.append(X["s3_note"] + "\n")
    for s_ in SEV:
        rows = [(fm, t, an) for fm, t, an in findings if fm.get("severity") == s_]
        L.append(f"### {sev_long(s_)}")
        if not rows:
            L.append(X["none_reg"] + (ph("info", X["info_ph"]) if s_ == "Info" else "") + "\n")
            continue
        L.append("| " + " | ".join(X["f_cols"]) + " |")
        L.append("|" + "---|" * len(X["f_cols"]))
        for fm, t, an in rows:
            L.append(f"| {fm.get('id')} | {cell(fm.get('repo'))} | {cell(t)} | "
                     f"{label('confidence', fm.get('confidence', '-'), lang)} | {cell(cite(fm))} | {cell(an)} |")
        L.append("")

    L.append(f"### {X['refuted']}")
    L.append(ph("refuted", X["refuted_ph"]) + "\n")
    L.append(f"## {X['s4']}")
    for r in repos:
        sp = W / r / "sweep.json"
        if not sp.exists():
            L.append(f"- **{r}:** {X['sweep_not_run']}")
            continue
        sw = json.loads(sp.read_text(encoding="utf-8"))
        cls = sw.get("counts_by_class", {})
        L.append(f"- **{r}:** " + X["sweep_line"].format(
            files=sw.get("files_scanned"), mig=sw.get("migration_files"), sch=sw.get("schema_files"),
            date=sw.get("date"), classes=", ".join(f"`{c}`" for c in sorted(sw.get("patterns", {}))),
            counts=", ".join(f"`{k}`={v}" for k, v in sorted(cls.items())) or "0"))
    L.append(f"- **{X['sad']}:** {ph('sad', X['found_ph'])}")
    L.append(f"- **{X['pan']}:** {ph('pan', X['found_ph'])}")
    L.append(f"- **{X['other_sens']}:** {ph('other_sensitive', X['found_ph'])}")
    L.append(f"- **{X['spill']}:** {X['spill_txt']} - {ph('spill', X['result_ph'])}")
    L.append(f"- {X['no_data']}\n")

    L.append(f"## {X['s5']}\n{ph('cross_repo', X['s5_ph'])}\n")
    perf = [(fm, t, an) for fm, t, an in findings if fm.get("kind") in ("performance", "quality")]
    L.append(f"## {X['s6']}")
    if perf:
        for fm, t, an in perf:
            L.append(f"- {fm.get('id')} ({label('severity', fm.get('severity'), lang)}) {t} - {an}")
    else:
        L.append(X["s6_none"])
    L.append("")
    L.append(f"## {X['s7']}")
    L.append(ph("actions", X["s7_ph"]) + "\n")
    L.append(X["s7_note"] + "\n")

    L.append(f"## {X['s8']}")
    L.append(f"- **{X['type']}:** {X['type_txt']}")
    L.append(f"- **{X['scope_dec']}:** {ph('scope', X['scope_ph'])}")
    L.append(f"- **{X['baseline'].format(d=a.standards_verified)}:**\n")
    L.append("  | " + " | ".join(X["std_cols"]) + " |\n  |---|---|---|---|")
    by_std = defaultdict(lambda: [0, 0])
    for fm, _, _ in findings:
        std = canon_std(fm.get("standard", ""))
        ver = fm.get("standard_version", "").replace(":", "")
        by_std[(std, ver)][0] += 1
        for st, v in split_citations(fm.get("also_maps_to", "")):
            if (st, v) != (std, ver) and v != "?":
                by_std[(st, v)][1] += 1
    for (std, v), (n1, n2) in sorted(by_std.items()):
        if std != "CWE":
            L.append(f"  | {std_name(std, lang)} | {v} | {n1} | {n2} |")
    L.append("")
    imgs = sorted({f"`{t.get('image', t['tool']).split('@')[0]}` "
                   f"(`{(t.get('digest') or t.get('version') or '?').split('@')[-1][:19]}`)"
                   for m in scan.values() for t in m.get("tools", []) if t.get("status") == "ok"})
    L.append(f"- **{X['scanners']}:** {'; '.join(imgs) or '-'}. {X['drift']}")
    L.append(f"- **{X['not_conclude']}:**")
    for line in X["nc"]:
        L.append(f"  - {line}")
    text = "\n".join(L) + "\n"
    if a.fill:
        fill = json.loads(Path(host_path(a.fill)).read_text(encoding="utf-8"))
        text = re.sub(r"\{\{(\w+): [^{}]*\}\}", lambda m: str(fill[m.group(1)]) if m.group(1) in fill else m.group(0),
                      text)
    out.write_text(text, encoding="utf-8")
    L = text.splitlines()
    left = sum(1 for line in L if "{{" in line)
    print(f"wrote {out} - {len(findings)} findings {dict(counts)}; {left} narrative placeholders to fill")
    return 0


if __name__ == "__main__":
    sys.exit(main())
