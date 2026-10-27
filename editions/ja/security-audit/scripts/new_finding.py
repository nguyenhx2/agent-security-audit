#!/usr/bin/env python3
"""JSON のリストから指摘事項ファイルを書き出す（Phase 6）- 正しいフロントマター、言語別の見出し、id によるファイル名。

多数の Markdown ファイルを手書きするより速く、誤りも少ない。入力：オブジェクトのリストを持つ JSON ファイル。
必須キー：id, repo, severity, confidence, kind, standard, standard_version, requirement_id,
confirmed_by, title, location, what, why, remedy。任意：also_maps_to, cwe, status（既定値 open）、
shares_anchor_with, evidence, verification, found（既定値は今日）。
`location` は "src/app.js:42 - sink: eval of request body" のような文字列のリスト（リポジトリ相対の
path:line を先頭に置く。バッククォートでの囲みは自動で行う）。git 履歴にのみ存在するシークレット：
"history:<commit> path/to/file:LINE - ..."（この場合、検証スクリプトはファイル存在チェックを省略する）。

使用できる値:
  severity      P0 | P1 | P2 | Info
  confidence    confirmed | likely | needs-runtime-check
  kind          security | sensitive-data-at-rest | secret | supply-chain | configuration | privacy |
                performance | quality
  status        open | in-progress | closed | accepted-risk | false-positive   （既定値 open）
  confirmed_by  監査言語による自由記述。例："manual review" や "semgrep <rule-id> + manual review"
  standard      正規名（reference/standards/index.md）。例：OWASP Top 10, OWASP ASVS,
                OWASP API Security Top 10, PCI DSS, CIS AWS Foundations, OWASP Top 10 CI/CD Security Risks
本文中のルール名、識別子、コードはバッククォートで囲む（ja の言語チェックを通すため）。

使い方:
  python new_finding.py <findings.json> --findings <audit_dir>/findings/<lang> --lang <lang> [--force]
  python new_finding.py <findings_ja.json> --findings <audit_dir>/findings/ja --lang ja --source <findings.json>
ファイルの出力先は <findings>/<repo>/<id>.md、つまり <audit_dir>/findings/<lang>/<repo>/find-<repo>-NNN.md。
書き出したファイルを表示する。入力が不正な場合は終了コード 1（問題をすべて列挙する）。
"""
from __future__ import annotations

import sys
sys.dont_write_bytecode = True  # インストール済みスキルに __pycache__ を作らない
for _s in (sys.stdout, sys.stderr):  # cp932 / cp1252 のコンソールやパイプでも UTF-8 で出力する
    if hasattr(_s, "reconfigure"):
        _s.reconfigure(encoding="utf-8", errors="replace")

import argparse
import datetime as dt
import json
import os
import re
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from i18n import FINDING_HEADINGS, LANGS  # noqa: E402
from validate_findings import CANON, canon_std  # noqa: E402

SEVERITIES = {"P0", "P1", "P2", "Info"}
CONFIDENCE = {"confirmed", "likely", "needs-runtime-check"}
STATUSES = {"open", "in-progress", "closed", "accepted-risk", "false-positive"}
KINDS = {"security", "sensitive-data-at-rest", "secret", "supply-chain", "configuration", "privacy",
         "performance", "quality"}
REQUIRED = ["id", "repo", "severity", "confidence", "kind", "standard", "standard_version", "requirement_id",
            "confirmed_by", "title", "location", "what", "why", "remedy"]


def host_path(p: str) -> str:
    if os.name == "nt":
        m = re.match(r"^/([a-zA-Z])(/.*)?$", p or "")
        if m:
            return f"{m.group(1).upper()}:{m.group(2) or '/'}"
    return p


# entry = [history:<commit> ]path:line[-line][ - note]。パスに空白を含んでよい（`src/My Component/a.tsx:10`）
ENTRY = re.compile(r"^(history:\w+\s+)?([^\s`][^`]*?:\d+(?:-\d+)?)(?=\s|$)\s*(.*)$")


def entry_ok(entry: str) -> bool:
    m = ENTRY.match(entry.strip().replace("`", "", 2) if entry.strip().startswith("`") else entry.strip())
    # パス中の空白はディレクトリ名の中になければならない（"sink at app.js:3" はパスではなく文章）
    return bool(m) and " - " not in m.group(2) and (" " not in m.group(2) or "/" in m.group(2).split(" ", 1)[1])


def anchor_line(entry: str) -> str:
    entry = entry.strip()
    if entry.startswith("`"):
        return f"- {entry}"
    m = ENTRY.match(entry)
    if not m:
        head, _, rest = entry.partition(" ")
        return f"- `{head}`" + (f" {rest}" if rest else "")
    commit = m.group(1).strip() + " " if m.group(1) else ""
    return f"- {commit}`{m.group(2)}`" + (f" {m.group(3)}" if m.group(3) else "")


def render(f: dict, lang: str) -> str:
    H = {k: v.get(lang, v["en"]) for k, v in FINDING_HEADINGS.items()}
    fm = [("id", f["id"]), ("repo", f["repo"]), ("severity", f["severity"]), ("confidence", f["confidence"]),
          ("kind", f["kind"]), ("standard", f["standard"]), ("standard_version", f["standard_version"]),
          ("requirement_id", f["requirement_id"])]
    for opt in ("also_maps_to", "cwe", "shares_anchor_with"):
        if f.get(opt):
            fm.append((opt, f[opt]))
    fm += [("confirmed_by", f["confirmed_by"]), ("status", f.get("status", "open")),
           ("found", f.get("found", dt.date.today().isoformat())), ("verified", f.get("verified", "n/a"))]
    out = ["---"] + [f"{k}: {v}" for k, v in fm] + ["---", "", f"# {f['id']} - {f['title']}", "",
                                                     f"## {H['location']}"]
    out += [anchor_line(x) for x in f["location"]] + ["", f"## {H['what']}", f["what"].strip(), "",
                                                      f"## {H['why']}", f["why"].strip(), ""]
    if f.get("evidence"):
        out += [f"## {H['evidence']}", f["evidence"].strip(), ""]
    out += [f"## {H['remedy']}", f["remedy"].strip(), ""]
    if f.get("verification"):
        out += [f"## {H['verification']}", f["verification"].strip(), ""]
    return "\n".join(out)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("json_file")
    ap.add_argument("--findings", required=True, help="<audit_dir>/findings/<lang>")
    ap.add_argument("--lang", default="en", help="見出しの言語コード（en / ja。その他は英語の見出し）")
    ap.add_argument("--force", action="store_true", help="既存の指摘事項ファイルを上書きする")
    ap.add_argument("--source", help="正本の findings.json：翻訳ファイルについて、すべてのコード項目"
                                     "（id, severity, standard ...）と各 location の path:line をここからコピーする")
    a = ap.parse_args()
    items = json.loads(Path(host_path(a.json_file)).read_text(encoding="utf-8"))
    if isinstance(items, dict):
        items = [items]
    if a.source:
        src = {f["id"]: f for f in json.loads(Path(host_path(a.source)).read_text(encoding="utf-8"))}
        missing = [f.get("id") for f in items if f.get("id") not in src]
        if missing or len(items) != len(src):
            print(f"error: 翻訳ファイルと --source の内容が一致しない（source にない id：{missing}、"
                  f"指摘事項 {len(items)} 件 対 {len(src)} 件）", file=sys.stderr)
            return 1
        for f in items:
            o = src[f["id"]]
            for k in ("repo", "severity", "confidence", "kind", "status", "standard", "standard_version",
                      "requirement_id", "also_maps_to", "cwe", "found", "shares_anchor_with"):
                if k in o:
                    f[k] = o[k]
            if len(f.get("location", [])) == len(o.get("location", [])):
                f["location"] = [so.split(" - ", 1)[0] + (" - " + t.split(" - ", 1)[1] if " - " in t else "")
                                 for t, so in zip(f["location"], o["location"])]
            else:
                f["location"] = o["location"]
    errs, ids = [], set()
    for i, f in enumerate(items):
        tag = f.get("id", f"item {i}")
        for k in REQUIRED:
            if not f.get(k):
                errs.append(f"{tag}: '{k}' がない")
        for k, allowed in (("severity", SEVERITIES), ("confidence", CONFIDENCE), ("kind", KINDS),
                           ("status", STATUSES)):
            if f.get(k) and f[k] not in allowed:
                errs.append(f"{tag}: {k} '{f[k]}' は {sorted(allowed)} のいずれでもない")
        if not re.fullmatch(r"FIND-[A-Z0-9-]+-\d{3,}", f.get("id", "")):
            errs.append(f"{tag}: id は FIND-<REPO>-001 の形式にする")
        if f.get("id") in ids:
            errs.append(f"{tag}: id が重複している")
        ids.add(f.get("id"))
        if f.get("standard") and canon_std(f["standard"]) not in CANON:
            errs.append(f"{tag}: standard '{f['standard']}' は正規名ではない（reference/standards/index.md を参照）")
        elif f.get("standard"):
            f["standard"] = canon_std(f["standard"])
        if f.get("location") and not all(entry_ok(x) for x in f["location"]):
            errs.append(f"{tag}: location の各項目はリポジトリ相対の path:line で始める")
    if errs:
        print("\n".join(f"ERROR {e}" for e in errs))
        return 1
    base = Path(host_path(a.findings))
    for f in items:
        p = base / f["repo"] / f"{f['id'].lower()}.md"
        if p.exists() and not a.force:
            print(f"ERROR {p} は既に存在する（上書きするには --force を使う）")
            return 1
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(render(f, a.lang), encoding="utf-8")
        print(f"{p} を書き出した")
    return 0


if __name__ == "__main__":
    sys.exit(main())
