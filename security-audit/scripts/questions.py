#!/usr/bin/env python3
"""Build the Phase 0 AskUserQuestion payload in the user's conversation language.

Detects the conversation language from the user's message (ja: kana/kanji, else en), fingerprints the repo(s), and prints JSON:
  {"conversation_lang": "ja", "call1": {"questions": [...]}, "call2": {...} | null, "defaults": {...}}
Pass "call1" (and "call2" when not null) to AskUserQuestion unchanged; "focus_lanes" maps each Focus
answer to review lanes (a detected AI or mobile domain gets its own Focus option). Languages without a table use
English text (translate it yourself if needed).

Usage:
  python questions.py <repo_path> [<repo_path> ...] --text "<the user's request>" [--lang xx]
                      [--out-folder "<audit_dir parent shown to the user>"]
--lang overrides detection (use it when the user's own instructions fix the conversation language).
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
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from detect_stack import profile, recommend, host_path  # noqa: E402
from i18n import detect_lang  # noqa: E402

Q = {
    "en": {
        "depth_q": "How deep should the audit of {target} go? (repo size: {size}; {archetype})",
        "deep": ("Deep (Recommended)", "Every review lane, run as parallel subagents grouped by repo size; Opus on design-level lanes, full coverage-checklist walk, verifier on P0-P2. Most thorough."),
        "standard": ("Standard", "Parallel review subagents (Sonnet) + verifier on P0/P1 findings. Faster, slightly less depth."),
        "quick": ("Quick", "Scripts + up to three lanes inline, no subagents. About 5-10 minutes - a fast first look."),
        "lang_q": "Which language(s) should the report be in? Each selected language gets its own complete report set (all generated from one source, so findings are identical). Pick Other to type any language.",
        "langs": {"en": ("English", "Fully localised English report set."),
                  "ja": ("日本語 (Japanese)", "Fully localised Japanese report set.")},
        "focus_q": "Which areas should the audit focus on?",
        "sector_note": " Industry rules detected in the code: {found} - they apply on top of the chosen areas. Use Other to add an industry the code does not show (finance, e-commerce, public sector, education, medical, IoT / OT).",
        "sectors": {"medical": "medical (MHLW 7.0 / MIC-METI 2.0, HIPAA)", "finance": "finance (FISC, FSA guideline, GLBA, NYDFS)",
                    "crypto": "crypto assets (custody, signing)", "ecommerce": "e-commerce (Japan credit card guideline 6.1, PCI DSS)",
                    "government": "public sector (Unified Standards, ISMAP)", "education": "education (MEXT, FERPA, COPPA)",
                    "iot": "IoT (JC-STAR, ETSI EN 303 645, EU CRA)", "ot": "industrial control (IEC 62443)",
                    "automotive": "vehicles (UN R155 / R156)"},
        "focus_ai": ("AI, LLM & agents", "{found}. Checks: {checks} (OWASP LLM / Agentic Top 10 2026, MCP Top 10, AISVS 1.01)."),
        "focus_mobile": ("Mobile app", "{found}. Checks: client storage and secrets, network config, exported components, WebViews (MASVS 2.1.0, Mobile Top 10 2024)."),
        "focus_merged": ("Secrets, data & supply chain", "Full-history secrets, dependency CVEs, CI/CD, containers/IaC, and how credentials, personal or health data are stored, logged or leaked."),
        "ai_found": {"llm-app": "LLM calls in the code", "agentic-app": "agent framework", "mcp": "MCP server/client code",
                     "agent-tooling": "AI coding-agent config ({detail})"},
        "ai_checks": {"llm-app": "prompt injection paths, output handling, data leakage, quotas",
                      "agentic-app": "tool scopes, autonomy limits, memory, human approval",
                      "mcp": "tool poisoning, auth, token handling",
                      "agent-tooling": "agent permissions and hooks, vendored skills / MCP servers, prompt logs, agents approving their own work"},
        "tool_names": {"settings": "settings", "settings_local": "local settings", "hooks": "hooks", "subagents": "subagents",
                       "commands": "commands", "skills_project": "skills", "skills_other": "other/vendored skills",
                       "mcp_configs": "MCP configs", "instructions": "instruction files", "prompt_logs": "prompt logs"},
        "mobile_found": "Mobile app detected ({platforms})",
        "focus": [("Application security", "Authorization, injection, authentication, unsafe file/subprocess handling."),
                  ("Secrets & supply chain", "Full-history secret scan, dependency CVEs, CI/CD pipeline, containers/IaC."),
                  ("Sensitive data", "How credentials, card, personal or health data are stored, logged or leaked."),
                  ("Performance & quality", "Measured or structural performance problems and code-quality defects.")],
        "fmt_q": "Which report formats do you want? Markdown is always produced (it is the validated source). Output folder: {folder} (reports in reports/<format>/) - pick Other to change it.",
        "fmt": [("HTML (Recommended)", "One offline interactive page: search, filters, sortable tables, expandable findings, CSV export."),
                ("Excel (Recommended)", "Tracking workbook: findings register with dropdowns, Owner/Due date, statistics + 4 charts, Coverage, Master lists.")],
        "jur_q": "Which privacy / data-protection laws apply? (personal, payment, health or financial data was detected)",
        "jur": [("GDPR (EU/UK)", "EU / UK data protection."), ("Japan APPI", "Act on the Protection of Personal Information."),
                ("Vietnam PDPL", "Personal Data Protection Law 91/2025/QH15 + Decree 356/2025."), ("US (CCPA, HIPAA)", "California privacy and US health data.")],
        "headers": ("Depth", "Language", "Focus", "Formats", "Law"),
    },
    "ja": {
        "depth_q": "{target} の監査の深さを選んでください（規模: {size}／{archetype}）",
        "deep": ("詳細（推奨）", "全レビューレーンを、リポジトリ規模に応じてまとめた並列サブエージェントで実施。設計系レーンは Opus、網羅チェックリスト全件、P0〜P2 を検証。最も網羅的。"),
        "standard": ("標準", "並列レビューサブエージェント（Sonnet）＋P0/P1 の検証。より速く、深さはやや浅い。"),
        "quick": ("クイック", "スクリプト＋最大3レーンをインラインで実施（サブエージェントなし）。約5〜10分の簡易確認。"),
        "lang_q": "報告書の言語を選んでください（複数可）。選んだ言語ごとに報告書一式を作成します（同じ正本から生成するため、指摘内容は全言語で同一です）。その他の言語は「Other」で入力できます。",
        "langs": {"en": ("English（英語）", "英語で完全にローカライズした報告書一式。"),
                  "ja": ("日本語", "日本語で完全にローカライズした報告書一式。")},
        "focus_q": "重点的に確認する領域を選んでください。",
        "sector_note": " コードから業種別の基準を検出しました：{found}。選んだ領域に加えて適用します。コードに現れない業種（金融、EC、公共、教育、医療、IoT／OT）は「Other」で追加できます。",
        "sectors": {"medical": "医療（厚労省 第7.0版／総務省・経産省 第2.0版）", "finance": "金融（FISC 安全対策基準、金融庁ガイドライン）",
                    "crypto": "暗号資産（管理・署名）", "ecommerce": "EC（クレジットカード・セキュリティガイドライン 6.1版、PCI DSS）",
                    "government": "公共（統一基準群、ISMAP）", "education": "教育（文部科学省ガイドライン）",
                    "iot": "IoT（JC-STAR、ETSI EN 303 645）", "ot": "制御システム（IEC 62443）",
                    "automotive": "車両（UN R155／R156）"},
        "focus_ai": ("AI・LLM・エージェント", "{found}。確認内容: {checks}（OWASP LLM／Agentic Top 10 2026、MCP Top 10、AISVS 1.01）。"),
        "focus_mobile": ("モバイルアプリ", "{found}。確認内容: 端末内の保存とシークレット、通信設定、公開コンポーネント、WebView（MASVS 2.1.0、Mobile Top 10 2024）。"),
        "focus_merged": ("シークレット・データ・サプライチェーン", "Git全履歴のシークレット、依存関係の脆弱性、CI/CD、コンテナ／IaC、認証情報・個人・健康情報の保存とログ出力、漏えい。"),
        "ai_found": {"llm-app": "コード内の LLM 呼び出し", "agentic-app": "エージェントフレームワーク", "mcp": "MCP サーバー／クライアント",
                     "agent-tooling": "AI コーディングエージェントの設定（{detail}）"},
        "ai_checks": {"llm-app": "プロンプトインジェクション経路、出力の扱い、情報漏えい、利用量制限",
                      "agentic-app": "ツール権限、自律動作の上限、メモリ、人の承認",
                      "mcp": "ツールポイズニング、認証、トークンの扱い",
                      "agent-tooling": "エージェントの権限とフック、同梱スキル／MCP サーバー、プロンプト履歴、エージェントによる自己承認"},
        "tool_names": {"settings": "設定", "settings_local": "ローカル設定", "hooks": "フック", "subagents": "サブエージェント",
                       "commands": "コマンド", "skills_project": "スキル", "skills_other": "その他／同梱スキル",
                       "mcp_configs": "MCP 設定", "instructions": "指示ファイル", "prompt_logs": "プロンプト履歴"},
        "mobile_found": "モバイルアプリを検出（{platforms}）",
        "focus": [("アプリケーションセキュリティ", "認可、インジェクション、認証、ファイル／サブプロセスの危険な扱い。"),
                  ("シークレットとサプライチェーン", "Git全履歴のシークレット、依存関係の脆弱性、CI/CD、コンテナ／IaC。"),
                  ("機微データ", "認証情報・カード・個人・健康情報の保存、ログ出力、漏えい。"),
                  ("性能と品質", "計測または構造的根拠のある性能問題とコード品質の欠陥。")],
        "fmt_q": "出力形式を選んでください。Markdown は常に作成します（検証の基準）。出力先: {folder}（報告書は reports/<形式>/ に保存。変更は「Other」）",
        "fmt": [("HTML（推奨）", "オフラインで使える対話型ページ: 検索、絞り込み、並べ替え、指摘の展開、CSV 出力。"),
                ("Excel（推奨）", "管理用ブック: プルダウン付き指摘一覧、担当／期限、統計＋グラフ4種、実施範囲、マスタ。")],
        "jur_q": "適用されるプライバシー／個人情報保護法令を選んでください（個人・決済・健康・金融データを検出）",
        "jur": [("GDPR（EU/英国）", "EU／英国のデータ保護法。"), ("個人情報保護法（APPI）", "日本の個人情報保護法。"),
                ("ベトナム PDPL", "個人データ保護法 91/2025/QH15 と政令 356/2025。"), ("米国（CCPA・HIPAA）", "カリフォルニア州プライバシー法と米国の医療情報。")],
        "headers": ("深さ", "言語", "重点", "形式", "法令"),
    },
}


def opt(pair):
    return {"label": pair[0], "description": pair[1]}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("repos", nargs="+")
    ap.add_argument("--text", default="", help="the user's request, for language detection")
    ap.add_argument("--lang", help="force the conversation language (e.g. from the user's CLAUDE.md)")
    ap.add_argument("--out-folder", default="<parent-of-repo>/<repo>-security-audit/<timestamp>/")
    a = ap.parse_args()
    lang = a.lang or detect_lang(a.text)
    X = Q.get(lang, Q["en"])
    profs = []
    for r in a.repos:
        root = Path(host_path(r)).resolve()
        if not root.is_dir():
            print(f"error: not a directory: {r}", file=sys.stderr)
            return 2
        p = profile(root, 60_000)
        p["recommendations"] = recommend(p)
        profs.append(p)
    size = max((p["recommendations"]["size"] for p in profs), key=["small", "medium", "large"].index)
    target = ", ".join(p["name"] for p in profs)
    archetype = ", ".join(sorted({p["recommendations"]["archetype"] for p in profs}))
    flags = {k for p in profs for k, v in p["recommendations"]["flags"].items() if v}
    ai_scope = [x for x in ("llm-app", "agentic-app", "mcp", "agent-tooling")
                if any(x in p["recommendations"].get("ai_scope", []) for p in profs)]
    platforms = sorted({m for p in profs for m in p["mobile"]})
    sectors = [x for x in X["sectors"] if any(x in p["recommendations"].get("sectors", {}) for p in profs)]
    # report languages: detected conversation language first (recommended), then the others
    order = [lang] + [x for x in ("en", "ja") if x != lang] if lang in ("en", "ja") else ["en", "ja"]
    lang_opts = []
    for i, code in enumerate(order[:2]):
        lab, desc = X["langs"][code]
        if i == 0 and lang in ("en", "ja"):
            lab += {"en": " (Recommended)", "ja": "（推奨）"}.get(lang, " (Recommended)")
        lang_opts.append({"label": lab, "description": desc})
    H = X["headers"]
    size = {"ja": {"small": "小", "medium": "中", "large": "大"},
}.get(lang, {}).get(size, size)
    # Focus: 4 options max. A detected specialist domain (AI / mobile) gets its own option, and
    # "secrets & supply chain" + "sensitive data" merge into one so the limit holds.
    F = X["focus"]
    lanes_of = {F[0][0]: ["authz-logic", "injection-dataflow"], F[1][0]: ["supply-chain-infra"],
                F[2][0]: ["sensitive-data"], F[3][0]: ["perf-quality"]}
    special = []
    if ai_scope:
        tool = {}
        for p in profs:
            for k, v in p.get("agent_tooling", {}).items():
                tool[k] = tool.get(k, 0) + v
        sep = "、" if lang == "ja" else ", "
        order = ["settings", "settings_local", "hooks", "subagents", "skills_project", "skills_other",
                 "mcp_configs", "commands", "instructions", "prompt_logs"]
        detail = sep.join(f"{X['tool_names'][k]} {tool[k]}" for k in order if tool.get(k))
        found = sep.join(X["ai_found"][x].format(detail=detail) for x in ai_scope)
        checks = ("；" if lang == "ja" else "; ").join(X["ai_checks"][x] for x in ai_scope)
        special.append((X["focus_ai"][0], X["focus_ai"][1].format(found=found, checks=checks), ["ai-agentic"]))
    if platforms:
        special.append((X["focus_mobile"][0], X["focus_mobile"][1].format(
            found=X["mobile_found"].format(platforms=", ".join(platforms))), ["mobile"]))
    if special:
        if len(special) == 2:   # both: one combined specialist option
            special = [(special[0][0] + " / " + special[1][0], special[0][1] + " " + special[1][1],
                        special[0][2] + special[1][2])]
        lab, desc, ln = special[0]
        merged = X["focus_merged"]
        focus_opts = [opt(F[0]), {"label": lab, "description": desc}, opt(merged), opt(F[3])]
        lanes_of = {F[0][0]: lanes_of[F[0][0]], lab: ln,
                    merged[0]: ["supply-chain-infra", "sensitive-data"], F[3][0]: ["perf-quality"]}
    else:
        focus_opts = [opt(f) for f in F]
    call1 = {"questions": [
        {"question": X["depth_q"].format(target=target, size=size, archetype=archetype), "header": H[0],
         "multiSelect": False, "options": [opt(X["deep"]), opt(X["standard"]), opt(X["quick"])]},
        {"question": X["lang_q"], "header": H[1], "multiSelect": True, "options": lang_opts},
        {"question": X["focus_q"] + (X["sector_note"].format(found=("、" if lang == "ja" else ", ").join(
            X["sectors"][x] for x in sectors)) if sectors else ""), "header": H[2], "multiSelect": True,
         "options": focus_opts},
        {"question": X["fmt_q"].format(folder=a.out_folder), "header": H[3], "multiSelect": True,
         "options": [opt(f) for f in X["fmt"]]},
    ]}
    call2 = None
    if flags & {"pii", "payments", "health", "financial"} or sectors:
        call2 = {"questions": [{"question": X["jur_q"], "header": H[4], "multiSelect": True,
                                "options": [opt(j) for j in X["jur"]]}]}
    print(json.dumps({"conversation_lang": lang, "call1": call1, "call2": call2, "focus_lanes": lanes_of,
                      "sectors": sectors,
                      "defaults": {"depth": "deep", "report_languages": [lang], "focus": "all detected lanes",
                                   "formats": ["md", "html", "xlsx"], "jurisdiction": None}},
                     ensure_ascii=False, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
