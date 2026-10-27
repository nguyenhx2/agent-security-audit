#!/usr/bin/env python3
"""
Render the audit report + finding files into ONE self-contained, searchable, sortable HTML file.

Features: severity cards (click to filter), findings explorer (full-text search incl. finding bodies,
filters for severity/repo/kind/confidence/status, click-to-sort columns with severity-aware order,
expandable detail rows, deep links `#FIND-ID`, CSV export of the filtered view), the full report
with a table of contents, and sortable tables everywhere. Light/dark, print-friendly.

Safety: everything from the audit (which quotes audited code) is HTML-escaped; no raw HTML from
markdown is passed through; no external resources; strict CSP. Data is embedded as JSON with `</`
escaped.

Usage:
  python render_html.py <report.md> [--findings <audit_dir>/findings] [--out <file.html>]
Default output: the report path with .html.
"""
from __future__ import annotations

import sys
sys.dont_write_bytecode = True  # keep the installed skill free of __pycache__
for _s in (sys.stdout, sys.stderr):  # UTF-8 output even on cp932 / cp1252 consoles and pipes
    if hasattr(_s, "reconfigure"):
        _s.reconfigure(encoding="utf-8", errors="replace")

import argparse
import base64
import hashlib
import html
import json
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from layout import findings_dir as _fdir, format_out, root_of_report  # noqa: E402
from i18n import LANGS, T as I18N, detect_lang, label, ui as ui_labels  # noqa: E402

SEV_RANK = {"P0": 0, "P1": 1, "P2": 2, "Info": 3}


def host_path(p: str) -> str:
    if os.name == "nt":
        m = re.match(r"^/([a-zA-Z])(/.*)?$", p or "")
        if m:
            return f"{m.group(1).upper()}:{m.group(2) or '/'}"
    return p


# ---------------- minimal, escaping markdown -> HTML ----------------
def inline(t: str) -> str:
    out, i = [], 0
    for m in re.finditer(r"`([^`]+)`", t):  # protect code spans first
        out.append(_inline_text(t[i:m.start()]))
        out.append(f"<code>{html.escape(m.group(1))}</code>")
        i = m.end()
    out.append(_inline_text(t[i:]))
    return "".join(out)


def _inline_text(t: str) -> str:
    t = html.escape(t, quote=False)

    def link(m):
        url = html.unescape(m.group(2)).strip()
        if not re.match(r"^(https?://|#|\.{1,2}/|[\w.-]+\.(md|html)$)", url):
            return m.group(0)
        return f'<a href="{html.escape(url)}" rel="noopener noreferrer">{m.group(1)}</a>'
    t = re.sub(r"\[([^\]]+)\]\(([^)\s]+)\)", link, t)
    t = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", t)
    t = re.sub(r"(?<![\w*])\*([^*\n]+)\*(?![\w*])", r"<em>\1</em>", t)
    return t


def slug(t: str) -> str:
    s = re.sub(r"[^\w\s-]", "", t, flags=re.U).strip().lower()
    return re.sub(r"[\s_]+", "-", s)[:60] or "section"


def md_to_html(md: str, toc: list | None = None) -> str:
    lines = md.splitlines()
    out, i = [], 0
    while i < len(lines):
        ln = lines[i]
        if ln.strip().startswith("```"):
            buf = []
            i += 1
            while i < len(lines) and not lines[i].strip().startswith("```"):
                buf.append(lines[i])
                i += 1
            out.append(f"<pre><code>{html.escape(chr(10).join(buf))}</code></pre>")
            i += 1
            continue
        m = re.match(r"^(#{1,6})\s+(.*)$", ln)
        if m:
            lvl, txt = len(m.group(1)), m.group(2).strip()
            sid = slug(txt)
            if toc is not None and lvl in (2, 3):
                toc.append((lvl, sid, txt))
            out.append(f'<h{lvl} id="{sid}">{inline(txt)}</h{lvl}>')
            i += 1
            continue
        if ln.lstrip().startswith("|") and i + 1 < len(lines) and re.match(r"^\s*\|?\s*:?-{2,}", lines[i + 1]):
            def cells(r):
                r = r.strip()
                r = r[1:] if r.startswith("|") else r
                r = r[:-1] if r.endswith("|") and not r.endswith("\\|") else r
                # split on unescaped pipes only; `\|` inside a cell (title, code) is shown as `|`
                return [c.strip().replace("\\|", "|") for c in re.split(r"(?<!\\)\|", r)]
            head = cells(ln)
            i += 2
            rows = []
            while i < len(lines) and lines[i].lstrip().startswith("|"):
                rows.append(cells(lines[i]))
                i += 1
            th = "".join(f"<th>{inline(h)}</th>" for h in head)
            tb = "".join("<tr>" + "".join(f"<td>{inline(c)}</td>" for c in r) + "</tr>" for r in rows)
            out.append(f'<div class="tw"><table class="sortable"><thead><tr>{th}</tr></thead>'
                       f"<tbody>{tb}</tbody></table></div>")
            continue
        if re.match(r"^\s*([-*]|\d+[.)])\s+", ln):
            ordered = bool(re.match(r"^\s*\d+[.)]", ln))
            items = []
            while i < len(lines) and (re.match(r"^\s*([-*]|\d+[.)])\s+", lines[i]) or
                                      (lines[i].startswith("   ") and lines[i].strip() and items)):
                if re.match(r"^\s*([-*]|\d+[.)])\s+", lines[i]):
                    items.append(re.sub(r"^\s*([-*]|\d+[.)])\s+", "", lines[i]))
                else:
                    items[-1] += " " + lines[i].strip()
                i += 1
            tag = "ol" if ordered else "ul"
            out.append(f"<{tag}>" + "".join(f"<li>{inline(x)}</li>" for x in items) + f"</{tag}>")
            continue
        if not ln.strip():
            i += 1
            continue
        buf = [ln.strip()]
        i += 1
        while i < len(lines) and lines[i].strip() and not re.match(r"^(#|\||```|\s*([-*]|\d+[.)])\s)", lines[i]):
            buf.append(lines[i].strip())
            i += 1
        out.append(f"<p>{inline(' '.join(buf))}</p>")
    return "\n".join(out)


# ---------------- findings ----------------
def parse_finding(text: str) -> tuple[dict, str]:
    m = re.match(r"^---\s*\n(.*?)\n---\s*\n(.*)$", text, re.S)
    if not m:
        return {}, text
    fm = {}
    for line in m.group(1).splitlines():
        line = re.sub(r"\s+#.*$", "", line)
        if ":" in line and not line.startswith(" "):
            k, v = line.split(":", 1)
            fm[k.strip()] = v.strip().strip("'\"")
    return fm, m.group(2)


def load_findings(fdir: Path, lang: str = "en") -> list[dict]:
    rows = []
    for f in sorted(fdir.rglob("*.md")):
        fm, body = parse_finding(f.read_text(encoding="utf-8", errors="replace"))
        if not fm.get("id"):
            continue
        t = re.search(r"^#\s+(.+)$", body, re.M)
        title = re.sub(rf"^{re.escape(fm['id'])}\s*[-:]\s*", "", t.group(1).strip()) if t else fm["id"]
        body = re.sub(r"^#\s+.+$", "", body, count=1, flags=re.M)
        anchor = re.search(r"`([^`\n]+?:\d+(?:-\d+)?)`", body)
        rows.append({
            "id": fm["id"], "severity": fm.get("severity", ""), "repo": fm.get("repo", ""),
            "sev_label": label("severity", fm.get("severity", ""), lang),
            "kind": label("kind", fm.get("kind", ""), lang),
            "confidence": label("confidence", fm.get("confidence", ""), lang),
            "status": label("status", fm.get("status", ""), lang), "title": title,
            "standard": " ".join(x for x in (fm.get("standard"), fm.get("standard_version"),
                                             fm.get("requirement_id")) if x),
            "cwe": fm.get("cwe", ""), "location": anchor.group(1) if anchor else "",
            "file": f.relative_to(fdir).as_posix(),
            "body_html": md_to_html(body), "text": (title + " " + body).lower()[:20000],
        })
    rows.sort(key=lambda r: (SEV_RANK.get(r["severity"], 9), r["repo"], r["id"]))
    return rows


CSS = """
:root{--bg:#fff;--fg:#1d2330;--mut:#5b6475;--bd:#d9dee7;--card:#f6f8fb;--acc:#2457c5;
--p0:#b42318;--p1:#c4510a;--p2:#a67c00;--info:#4a5568;--hl:#fff4c2}
@media (prefers-color-scheme:dark){:root{--bg:#12151b;--fg:#e4e8ef;--mut:#9aa4b5;--bd:#2c3340;
--card:#1a1f28;--acc:#7aa2ff;--p0:#ff6b5e;--p1:#ff9a4d;--p2:#e8c547;--info:#a0aec0;--hl:#3a3420}}
*{box-sizing:border-box}body{margin:0;font:14px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,
"Noto Sans","Noto Sans JP","Hiragino Sans",Meiryo,sans-serif;background:var(--bg);color:var(--fg)}
header{padding:20px 28px;border-bottom:1px solid var(--bd)}header h1{margin:0 0 4px;font-size:22px}
.meta{color:var(--mut);font-size:13px}.wrap{display:grid;grid-template-columns:230px 1fr;gap:0}
nav{position:sticky;top:0;align-self:start;max-height:100vh;overflow:auto;padding:16px;
border-right:1px solid var(--bd);font-size:13px}nav a{display:block;color:var(--fg);text-decoration:none;
padding:3px 0}nav a.l3{padding-left:12px;color:var(--mut)}main{padding:20px 28px;min-width:0}
.cards{display:flex;gap:12px;flex-wrap:wrap;margin:8px 0 18px}.card{flex:1 1 120px;background:var(--card);
border:1px solid var(--bd);border-radius:10px;padding:12px 14px;cursor:pointer;user-select:none}
.card b{display:block;font-size:26px}.card.on{outline:2px solid var(--acc)}
.sev{display:inline-block;min-width:38px;text-align:center;border-radius:6px;padding:1px 6px;
font-weight:600;color:#fff;font-size:12px}.sev-P0{background:var(--p0)}.sev-P1{background:var(--p1)}
.sev-P2{background:var(--p2)}.sev-Info{background:var(--info)}
.tools{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin:8px 0}
input,select,button{font:inherit;color:var(--fg);background:var(--bg);border:1px solid var(--bd);
border-radius:8px;padding:6px 10px}input[type=search]{flex:1 1 280px}button{cursor:pointer}
.tw{overflow:auto;margin:10px 0}table{border-collapse:collapse;width:100%;font-size:13px}
th,td{border-bottom:1px solid var(--bd);padding:6px 8px;text-align:left;vertical-align:top}
th{position:sticky;top:0;background:var(--card);cursor:pointer;white-space:nowrap}
th.asc::after{content:" \\25B2"}th.desc::after{content:" \\25BC"}
#ft td:first-child,#ft td:nth-child(2),#ft td:nth-child(5),#ft td:nth-child(6),#ft td:nth-child(9){white-space:nowrap}#ft td:nth-child(4){min-width:240px}
tr.f{cursor:pointer}tr.f:hover{background:var(--card)}tr.d td{background:var(--card)}
tr.d .body{max-width:1100px}code{font-family:ui-monospace,Consolas,monospace;font-size:12.5px;
background:var(--card);border:1px solid var(--bd);border-radius:4px;padding:0 4px}
pre{background:var(--card);border:1px solid var(--bd);border-radius:8px;padding:10px;overflow:auto}
pre code{border:0;padding:0}mark{background:var(--hl);color:inherit}.count{color:var(--mut)}
h2{margin-top:34px;border-bottom:1px solid var(--bd);padding-bottom:4px}a{color:var(--acc)}
@media (max-width:900px){.wrap{grid-template-columns:1fr}nav{display:none}}
@media print{nav,.tools,.cards{display:none}.wrap{display:block}tr.d{display:table-row!important}}
"""

JS = r"""
const DATA=JSON.parse(document.getElementById('data').textContent);
const UI=JSON.parse(document.getElementById('ui').textContent);
const RANK={P0:0,P1:1,P2:2,Info:3};
const $=s=>document.querySelector(s);
const st={q:'',sev:'',repo:'',kind:'',conf:'',status:'',sortKey:'severity',dir:1,open:new Set()};
function opts(sel,key){const v=[...new Set(DATA.map(r=>r[key]).filter(Boolean))].sort();
 v.forEach(x=>{const o=document.createElement('option');o.value=x;o.textContent=x;$(sel).appendChild(o)})}
function esc(s){return String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
function hl(s){const t=esc(s);if(!st.q)return t;const q=st.q.replace(/[.*+?^${}()|[\]\\]/g,'\\$&');
 return t.replace(new RegExp(q,'gi'),m=>'<mark>'+m+'</mark>')}
function rows(){const q=st.q.toLowerCase();return DATA.filter(r=>(!st.sev||r.severity===st.sev)&&
 (!st.repo||r.repo===st.repo)&&(!st.kind||r.kind===st.kind)&&(!st.conf||r.confidence===st.conf)&&
 (!st.status||r.status===st.status)&&(!q||r.text.includes(q)||r.id.toLowerCase().includes(q)||
 r.standard.toLowerCase().includes(q)||r.location.toLowerCase().includes(q))).sort((a,b)=>{
 const k=st.sortKey;let x=a[k],y=b[k];if(k==='severity'){x=RANK[x]??9;y=RANK[y]??9}
 return (x<y?-1:x>y?1:0)*st.dir||((RANK[a.severity]??9)-(RANK[b.severity]??9))})}
const COLS=['id','severity','repo','title','kind','confidence','standard','location','status'].map((k,i)=>[k,UI.h_cols[i]]);
function render(){const rs=rows();$('#count').textContent=rs.length+' / '+DATA.length;
 $('#fh').innerHTML=COLS.map(([k,l])=>`<th data-k="${k}" class="${st.sortKey===k?(st.dir>0?'asc':'desc'):''}">${l}</th>`).join('');
 $('#fb').innerHTML=rs.map(r=>`<tr class="f" id="${esc(r.id)}" data-id="${esc(r.id)}">`+
 COLS.map(([k])=>k==='severity'?`<td><span class="sev sev-${esc(r.severity)}">${esc(r.sev_label)}</span></td>`:
 k==='location'?`<td><code>${hl(r.location)}</code></td>`:`<td>${hl(r[k]??'')}</td>`).join('')+'</tr>'+
 (st.open.has(r.id)?`<tr class="d"><td colspan="${COLS.length}"><div class="body">${r.body_html}</div>
 <div class="count">${esc(UI.file)}: findings/${esc(r.file)}</div></td></tr>`:'')).join('');
 document.querySelectorAll('.card').forEach(c=>c.classList.toggle('on',c.dataset.sev===st.sev))}
function bind(){opts('#repo','repo');opts('#kind','kind');opts('#conf','confidence');opts('#status','status');
 $('#q').addEventListener('input',e=>{st.q=e.target.value.trim();render()});
 [['#sev','sev'],['#repo','repo'],['#kind','kind'],['#conf','conf'],['#status','status']].forEach(([s,k])=>
  $(s).addEventListener('change',e=>{st[k]=e.target.value;render()}));
 $('#fh').addEventListener('click',e=>{const k=e.target.dataset.k;if(!k)return;
  st.dir=st.sortKey===k?-st.dir:1;st.sortKey=k;render()});
 $('#fb').addEventListener('click',e=>{const tr=e.target.closest('tr.f');if(!tr||e.target.closest('a'))return;
  const id=tr.dataset.id;st.open.has(id)?st.open.delete(id):st.open.add(id);render()});
 document.querySelectorAll('.card').forEach(c=>c.addEventListener('click',()=>{
  st.sev=st.sev===c.dataset.sev?'':c.dataset.sev;$('#sev').value=st.sev;render()}));
 $('#reset').addEventListener('click',()=>{Object.assign(st,{q:'',sev:'',repo:'',kind:'',conf:'',status:''});
  ['#q','#sev','#repo','#kind','#conf','#status'].forEach(s=>$(s).value='');render()});
 $('#expand').addEventListener('click',()=>{const rs=rows();const all=rs.every(r=>st.open.has(r.id));
  rs.forEach(r=>all?st.open.delete(r.id):st.open.add(r.id));render()});
 $('#csv').addEventListener('click',()=>{const rs=rows();const ks=COLS.map(c=>c[0]);
  const csv=[ks.join(',')].concat(rs.map(r=>ks.map(k=>{let v=String(r[k]??'');if(/^[=+\-@\t\r]/.test(v))v="'"+v;return '"'+v.replace(/"/g,'""')+'"'}).join(','))).join('\n');
  const a=document.createElement('a');a.href=URL.createObjectURL(new Blob(['﻿'+csv],{type:'text/csv'}));
  a.download=document.title.replace(/[^\w.-]+/g,'_')+'_findings.csv';a.click()});
 const h=decodeURIComponent(location.hash.slice(1));if(h&&DATA.some(r=>r.id===h)){st.open.add(h);render();
  document.getElementById(h)?.scrollIntoView()}
 // generic sortable tables in the report body
 document.querySelectorAll('#report table.sortable').forEach(t=>{t.querySelectorAll('th').forEach((th,i)=>
  th.addEventListener('click',()=>{const tb=t.tBodies[0];const asc=!th.classList.contains('asc');
  t.querySelectorAll('th').forEach(x=>x.classList.remove('asc','desc'));th.classList.add(asc?'asc':'desc');
  const key=r=>{const s=r.cells[i]?.innerText.trim()??'';const m=s.match(/^(P[0-2]|Info)\b/);
   if(m)return RANK[m[1]];const n=parseFloat(s.replace(/,/g,''));return isNaN(n)?s.toLowerCase():n};
  [...tb.rows].sort((a,b)=>{const x=key(a),y=key(b);return (x<y?-1:x>y?1:0)*(asc?1:-1)})
   .forEach(r=>tb.appendChild(r))}))})}
bind();render();
"""


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("report")
    ap.add_argument("--findings")
    ap.add_argument("--out")
    ap.add_argument("--lang", default="auto", help="UI language code (default: detected from the report)")
    a = ap.parse_args()
    rp = Path(host_path(a.report))
    if not rp.is_file():
        print(f"error: report not found: {rp}", file=sys.stderr)
        return 2
    md = rp.read_text(encoding="utf-8", errors="replace")
    title_m = re.search(r"^#\s+(.+)$", md, re.M)
    title = title_m.group(1).strip() if title_m else rp.stem
    md_body = re.sub(r"^#\s+.+$", "", md, count=1, flags=re.M)
    toc: list = []
    report_html = md_to_html(md_body, toc)
    lang = a.lang if a.lang != "auto" else (re.search(r"_([a-z]{2})\.md$", rp.name) or [None, detect_lang(md)])[1]
    X = ui_labels(lang)
    fdir = Path(host_path(a.findings)) if a.findings else _fdir(root_of_report(rp), lang)
    data = load_findings(fdir, lang) if fdir.is_dir() else []
    counts = {s: sum(1 for r in data if r["severity"] == s) for s in SEV_RANK}
    cards = "".join(f'<div class="card" data-sev="{s}"><span class="sev sev-{s}">{html.escape(label("severity", s, lang))}'
                    f'</span><b>{n}</b></div>' for s, n in counts.items())
    nav = f'<a href="#findings-explorer"><b>{html.escape(X["explorer"])}</b></a>' + "".join(
        f'<a class="l{lvl}" href="#{sid}">{html.escape(t)}</a>' for lvl, sid, t in toc)
    payload = json.dumps(data, ensure_ascii=False).replace("<", "\\u003c").replace(">", "\\u003e")
    js_hash = base64.b64encode(hashlib.sha256(JS.encode("utf-8")).digest()).decode()
    sev_opts = "".join(f'<option value="{s}">{html.escape(label("severity", s, lang))}</option>' for s in SEV_RANK)
    ui = json.dumps({"h_cols": X["h_cols"], "file": X["file"]}, ensure_ascii=False).replace("<", "\\u003c")
    doc = f"""<!doctype html><html lang="{lang}"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'sha256-{js_hash}'; img-src data:; base-uri 'none'; form-action 'none'">
<meta name="referrer" content="no-referrer"><title>{html.escape(title)}</title><style>{CSS}</style></head><body>
<header><h1>{html.escape(title)}</h1><div class="meta">{html.escape(rp.name)} · {len(data)} {html.escape(X["findings_n"])} ·
{html.escape(X["generated"])}</div></header>
<div class="wrap"><nav>{nav}</nav><main>
<section id="findings-explorer"><h2 id="findings-explorer-h">{html.escape(X["explorer"])}</h2>
<div class="cards">{cards}</div>
<div class="tools"><input type="search" id="q" placeholder="{html.escape(X["search"])}">
<select id="sev"><option value="">{html.escape(X["all_sev"])}</option>{sev_opts}</select>
<select id="repo"><option value="">{html.escape(X["all_repo"])}</option></select>
<select id="kind"><option value="">{html.escape(X["all_kind"])}</option></select>
<select id="conf"><option value="">{html.escape(X["all_conf"])}</option></select>
<select id="status"><option value="">{html.escape(X["all_status"])}</option></select>
<button id="expand" type="button">{html.escape(X["expand"])}</button><button id="csv" type="button">CSV</button>
<button id="reset" type="button">{html.escape(X["reset"])}</button><span class="count" id="count"></span></div>
<div class="tw"><table id="ft"><thead><tr id="fh"></tr></thead><tbody id="fb"></tbody></table></div>
</section><section id="report">{report_html}</section></main></div>
<script type="application/json" id="data">{payload}</script><script type="application/json" id="ui">{ui}</script><script>{JS}</script></body></html>"""
    out = Path(host_path(a.out)) if a.out else format_out(rp, "html")
    out.write_text(doc, encoding="utf-8")
    print(f"wrote {out} ({len(data)} findings, {len(doc) // 1024} KB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
