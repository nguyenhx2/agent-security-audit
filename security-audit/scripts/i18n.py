#!/usr/bin/env python3
"""
Shared localisation for every generated artefact (report scaffold, HTML, Excel, finding headings).

Machine codes stay English in finding frontmatter (severity P0-P2/Info, status, confidence, kind) so
scripts and filters are stable; everything a reader sees is rendered through these tables.
Languages: en, ja. Add a language by copying the "en" block.
"""
from __future__ import annotations

import sys
sys.dont_write_bytecode = True  # keep the installed skill free of __pycache__

import re

LANGS = ("en", "ja")

# ---- display labels for frontmatter codes ----
ENUM = {
    "severity": {
        "en": {"P0": "P0", "P1": "P1", "P2": "P2", "Info": "Info"},
        "ja": {"P0": "P0", "P1": "P1", "P2": "P2", "Info": "情報"},
    },
    "severity_long": {
        "en": {"P0": "P0 / Blocker", "P1": "P1 / Major", "P2": "P2 / Minor", "Info": "Info"},
        "ja": {"P0": "P0 / 致命的", "P1": "P1 / 重大", "P2": "P2 / 軽微", "Info": "情報"},
    },
    "severity_def": {
        "en": {"P0": "Blocker - direct high-impact compromise", "P1": "Major - exploitable under realistic conditions",
               "P2": "Minor - limited blast radius", "Info": "Hygiene / hardening"},
        "ja": {"P0": "致命的：直接的かつ重大な侵害", "P1": "重大：現実的な条件で悪用可能",
               "P2": "軽微：影響範囲が限定的", "Info": "情報：衛生・強化事項"},
    },
    "status": {
        "en": {"open": "open", "in-progress": "in-progress", "closed": "closed", "accepted-risk": "accepted-risk",
               "false-positive": "false-positive"},
        "ja": {"open": "未対応", "in-progress": "対応中", "closed": "対応済", "accepted-risk": "リスク受容",
               "false-positive": "誤検知"},
    },
    "confidence": {
        "en": {"confirmed": "confirmed", "likely": "likely", "needs-runtime-check": "needs-runtime-check"},
        "ja": {"confirmed": "確認済", "likely": "可能性高", "needs-runtime-check": "実行時確認要"},
    },
    "kind": {
        "en": {k: k for k in ("security", "sensitive-data-at-rest", "secret", "supply-chain", "configuration",
                              "privacy", "performance", "quality")},
        "ja": {"security": "セキュリティ", "sensitive-data-at-rest": "保存データの機微情報", "secret": "シークレット",
               "supply-chain": "サプライチェーン", "configuration": "設定", "privacy": "プライバシー",
               "performance": "性能", "quality": "品質"},
    },
}

ENUM["depth"] = {
    "en": {"quick": "quick", "standard": "standard", "deep": "deep"},
    "ja": {"quick": "クイック", "standard": "標準", "deep": "詳細"},
}
ENUM["tool_status"] = {
    "en": {"ok": "ok", "failed": "failed", "skipped": "skipped"},
    "ja": {"ok": "成功", "failed": "失敗", "skipped": "未実行"},
}
TOOL_COVERAGE = {
    "en": {"gitleaks": "secrets: full git history (all refs) + working tree",
           "semgrep": "SAST p/default ruleset; weak/no coverage for some languages - see detect_stack gaps",
           "trivy": "dependency CVEs (lockfiles), IaC/Dockerfile misconfig",
           "osv-scanner": "dependency CVEs via OSV.dev (lockfile-precise)",
           "checkov": "IaC misconfig: Terraform, CloudFormation, K8s, Helm, Dockerfile, GH Actions",
           "hadolint": "Dockerfile best practices + embedded ShellCheck",
           "zizmor": "GitHub Actions workflow security (offline audits only)",
           "mobsfscan": "mobile source SAST: Android, iOS, manifests, plists"},
    "ja": {"gitleaks": "シークレット：Git全履歴（全ref）と作業ツリー",
           "semgrep": "SAST（p/default ルールセット）。一部言語は非対応・弱い（detect_stack の欠落を参照）",
           "trivy": "依存関係の脆弱性（ロックファイル）、IaC／Dockerfile の設定不備",
           "osv-scanner": "OSV.dev による依存関係の脆弱性（ロックファイル単位で正確）",
           "checkov": "IaC の設定不備：Terraform、CloudFormation、K8s、Helm、Dockerfile、GitHub Actions",
           "hadolint": "Dockerfile のベストプラクティス（ShellCheck 内蔵）",
           "zizmor": "GitHub Actions ワークフローのセキュリティ（オフライン監査のみ）",
           "mobsfscan": "モバイルのソース SAST：Android、iOS、マニフェスト、plist"},
}
SWEEP_COLS = {
    "en": ["Repo", "Files", "Migrations", "Schema", "Lead counts by class"],
    "ja": ["リポジトリ", "ファイル数", "マイグレーション", "スキーマ", "分類別の検出候補数"],
}


def meta_keys() -> dict:
    """Localised report-header labels -> canonical keys (so parsers work for every language)."""
    out = {}
    for lg in LANGS:
        x = T[lg]
        out.update({x["date"]: "date", x["depth"]: "depth", x["mode"]: "scanner mode",
                    x["auditor"]: "auditor", x["repos"]: "repos"})
    return {k.lower(): v for k, v in out.items()}


# ---- finding file section headings (template + parsers) ----
FINDING_HEADINGS = {
    "location": {"en": "Location", "ja": "該当箇所"},
    "what": {"en": "What it is", "ja": "内容"},
    "why": {"en": "Why it matters", "ja": "影響"},
    "evidence": {"en": "Evidence", "ja": "根拠"},
    "remedy": {"en": "Remedy (the user applies it - the auditor does not patch)",
               "ja": "是正策（修正は利用者が実施。監査者は修正しない）",
},
    "verification": {"en": "Verification (how this closes)", "ja": "検証（クローズ条件）",
},
}
LOCATION_RX = r"(Location|該当箇所|場所)"
REMEDY_RX = r"(Remedy|是正|対策)"

# ---- strings used by scripts ----
T = {
    "en": {
        "report_title": "Security audit report", "date": "Date", "repos": "Repos in scope", "depth": "Depth",
        "auditor": "Auditor", "auditor_val": "Claude via security-audit skill v{v} - read-only on product source",
        "mode": "Scanner mode", "none_mode": "none (reading only)",
        "commit": "Audited commit", "dirty": "uncommitted changes present",
        "ai_inv": "AI and agent inventory", "ai_cols": ["Repo", "Surface", "Items", "With risk labels", "Examples"],
        "ai_none": "no AI components found (no LLM calls, agent frameworks, MCP, or AI coding-agent configuration) - negative result",
        "ai_not_run": "inventory not run (agent_config_audit.py) - state as a gap",
        "ai_note": "Risk labels are leads from `agent_config_audit.py`; confirmed ones are findings above.",
        "intel": "Platform versions and threat intelligence",
        "intel_cols": ["Repo", "Component", "Version", "Pinned at", "Support", "Advisories"],
        "intel_not_run": "not run (platform_inventory.py / threat_intel.py) - runtime, server and image patch level unchecked: state as a gap",
        "intel_none": "no runtime, server, datastore, image or framework pin found in the repos - the deployed platform is defined elsewhere: state as a gap",
        "intel_rest": "{n} more component(s) with no advisory or support issue.",
        "intel_feeds": "Advisory feeds checked on {date} (national alerts and new KEV entries from the last {days} days): {ok}.",
        "intel_failed": "Unavailable (gap, not clean): {failed}.",
        "intel_note": "Leads from `threat_intel.py`; a version pin is not proof of what runs. Confirmed items are findings in section 3; others are listed under Refuted with the reason. Advisories change daily - true as of the date above.",
        "s1": "1. Executive summary", "s1_ph": "{{3-5 sentences: P0 count first, worst findings in plain language, the single first action.}}",
        "severity": "Severity", "count": "Count",
        "s2": "2. Scope and coverage gaps",
        "mount_note": "Mount files = every file visible to scanners (incl. `.git`); the sweep in section 4 counts text source files only.",
        "cov_cols": ["Repo", "Scanners run (tool@digest)", "Mount files", "Secret history", "Gaps (stated, not clean)"],
        "full": "full", "gap": "gap", "gaps_ph": "{{manual gaps, e.g. languages without SAST, lanes not run}}",
        "lanes_ph": "- Review lanes run: {{lanes per repo; inline or subagents}}",
        "classes_ph": "- Coverage-checklist classes not examined: {{list or 'none'}}",
        "s3": "3. Findings", "s3_note": "Deduplicated by root cause. Detail in `findings/<repo>/<id in lowercase>.md`.",
        "none_reg": "None registered.", "info_ph": " {{optional: Info observations not registered as files, one line each - or delete this sentence}}",
        "f_cols": ["id", "repo", "title", "confidence", "standard + version + req", "location"],
        "refuted": "Refuted / false positives", "refuted_ph": "{{one line each: candidate (tool:rule or lane) - why refuted (file:line); or 'none'}}",
        "s4": "4. Sensitive data at rest (mandatory)", "sweep_not_run": "sweep NOT run - gap.",
        "sweep_line": "searched {files} files ({mig} migration, {sch} schema) on {date} with sensitive_sweep classes {classes}. Lead counts: {counts}.",
        "sad": "SAD never-store (CVV / track / PIN)", "pan": "PAN must-be-unreadable",
        "other_sens": "Credentials, secrets, national ID, health, biometric, contact PII",
        "spill": "Spill surfaces checked", "spill_txt": "logs, caches, exports/analytics, client stores, provider-response persistence",
        "found_ph": "{{findings or 'none found'}}", "result_ph": "{{result}}",
        "no_data": "No card number, secret value, or personal data is reproduced in this report.",
        "s5": "5. Cross-repo findings", "s5_ph": "{{or 'None - single repo'}}",
        "s6": "6. Performance and code quality", "s6_none": "No findings meeting the bar (measurement or structural argument).",
        "s7": "7. What the user must do (ordered, with sequencing)",
        "s7_ph": "{{1. action - finding ids - why first / dependency (rotate before purge, etc.)}}",
        "s7_note": "Findings close only when a re-scan with the same image digests + ruleset (or a re-read for manual findings) no longer reproduces them.",
        "s8": "8. Method and limitations (mandatory)",
        "type": "Type", "type_txt": "static audit of source, schema, configuration, IaC and git history with pinned scanners plus manual review. No runtime testing, exploitation, or production data access.",
        "scope_dec": "Scope decisions", "scope_ph": "{{depth / focus / jurisdiction / formats - user answers, or 'defaults from detection (--yes)'}}",
        "baseline": "Standards baseline (verified: {d})", "std_cols": ["Standard", "Version", "Primary citation", "Also maps to"],
        "scanners": "Scanners", "drift": "Rulesets and vulnerability DBs drift independently of image tags.",
        "not_conclude": "What a reader should NOT conclude",
        "nc": ["NOT \"the system is secure\" - absence of a finding is not proof of absence.",
               "NOT \"these are exploitable in production\" - severity is by consequence, not demonstrated exploit.",
               "NOT \"uncovered surfaces are clean\" - section 2 gaps are unknown, not safe.",
               "NOT \"a closed finding means the fix is correct in general\" - only that the same check no longer reproduces it."],
        # html
        "explorer": "Findings explorer", "search": "Search id, title, file, standard, CWE, text...",
        "all_sev": "All severities", "all_repo": "All repos", "all_kind": "All kinds", "all_conf": "All confidence",
        "all_status": "All status", "expand": "Expand / collapse", "reset": "Reset", "file": "file",
        "h_cols": ["ID", "Sev", "Repo", "Title", "Kind", "Confidence", "Standard", "Location", "Status"],
        "generated": "generated by security-audit", "findings_n": "findings",
        # xlsx
        "sheets": {"summary": "Summary", "findings": "Findings", "coverage": "Coverage", "master": "Master"},
    },
    "ja": {
        "report_title": "セキュリティ監査報告書", "date": "日付", "repos": "対象リポジトリ", "depth": "深度",
        "auditor": "監査者", "auditor_val": "Claude（security-audit スキル v{v}）※監査対象のソースは読み取り専用",
        "mode": "スキャナ方式", "none_mode": "なし（コード読解のみ）",
        "commit": "監査したコミット", "dirty": "未コミットの変更あり",
        "ai_inv": "AI・エージェントの構成一覧", "ai_cols": ["リポジトリ", "対象", "件数", "リスク表示あり", "例"],
        "ai_none": "AI 構成要素なし（LLM 呼び出し、エージェントフレームワーク、MCP、AI コーディングエージェント設定のいずれも検出せず）。否定結果として記録",
        "ai_not_run": "構成一覧は未実施（agent_config_audit.py）。未カバー領域として記載",
        "ai_note": "リスク表示は `agent_config_audit.py` による手掛かりであり、確認済みのものは上記の指摘として登録している。",
        "intel": "プラットフォームのバージョンと脅威情報",
        "intel_cols": ["リポジトリ", "構成要素", "バージョン", "指定箇所", "サポート状況", "関連する勧告"],
        "intel_not_run": "未実施（platform_inventory.py / threat_intel.py）。ランタイム・サーバー・イメージのパッチ適用状況は未確認のため、未カバー領域として記載",
        "intel_none": "ランタイム、サーバー、データストア、イメージ、フレームワークのバージョン指定がリポジトリ内に見つからない。実行環境は別の場所で定義されているため、未カバー領域として記載",
        "intel_rest": "ほかに、勧告やサポート上の問題がない構成要素が {n} 件ある。",
        "intel_feeds": "{date} に確認した勧告フィード（国内の注意喚起と KEV の新規登録は直近 {days} 日分）：{ok}。",
        "intel_failed": "取得できなかったフィード（未確認であり問題なしではない）：{failed}。",
        "intel_note": "`threat_intel.py` による手掛かりであり、バージョン指定は実際に稼働しているものの証明ではない。確認できたものは第3節の指摘とし、それ以外は理由を添えて「反証・誤検知」に記載した。勧告は日々更新されるため、上記の日付時点の内容である。",
        "s1": "1. エグゼクティブサマリー", "s1_ph": "{{3〜5文：P0件数を最初に、最も深刻な指摘を平易に、最初に取るべき対応を1つ}}",
        "severity": "重大度", "count": "件数",
        "s2": "2. 対象範囲と未カバー領域",
        "mount_note": "マウントファイル数＝スキャナから見える全ファイル（`.git` を含む）。第4節の機微データ調査はテキストのソースファイルのみを数える。",
        "cov_cols": ["リポジトリ", "実行スキャナ（ツール@ダイジェスト）", "マウントファイル数", "シークレット履歴", "未カバー領域（安全を意味しない）"],
        "full": "全履歴", "gap": "欠落", "gaps_ph": "{{手動で補った領域や未カバー領域（SAST非対応言語、未実施レーンなど）}}",
        "lanes_ph": "- 実施したレビューレーン：{{リポジトリごとのレーン（インライン／サブエージェント）}}",
        "classes_ph": "- 未確認の網羅チェック項目：{{一覧、または「なし」}}",
        "s3": "3. 指摘事項", "s3_note": "根本原因ごとに重複排除済み。詳細は `findings/<repo>/<小文字のID>.md` を参照。",
        "none_reg": "登録なし。", "info_ph": "{{任意：ファイル登録していない情報レベルの所見を1行ずつ。不要ならこの文を削除}}",
        "f_cols": ["ID", "リポジトリ", "件名", "確度", "基準・版・要件", "箇所"],
        "refuted": "否定された候補（誤検知）", "refuted_ph": "{{1行ずつ：候補（ツール:ルールまたはレーン）と否定理由（file:line）、または「なし」}}",
        "s4": "4. 保存データの機微情報（必須）", "sweep_not_run": "調査未実施（欠落）。",
        "sweep_line": "{date} に {files} ファイル（マイグレーション {mig}、スキーマ {sch}）を sensitive_sweep の分類 {classes} で調査。検出候補数：{counts}。",
        "sad": "保存禁止のSAD（CVV／トラック／PIN）", "pan": "判読不能化が必要なPAN",
        "other_sens": "認証情報・シークレット・国民ID・健康・生体・連絡先の個人情報",
        "spill": "漏えい経路の確認", "spill_txt": "ログ、キャッシュ、エクスポート／分析、クライアント保存領域、決済事業者応答の保存",
        "found_ph": "{{指摘、または「該当なし」}}", "result_ph": "{{結果}}",
        "no_data": "本報告書にはカード番号、シークレットの値、個人データを一切記載していない。",
        "s5": "5. リポジトリ横断の指摘", "s5_ph": "{{なければ「なし（単一リポジトリ）」}}",
        "s6": "6. 性能とコード品質", "s6_none": "基準（計測値または構造的根拠）を満たす指摘はない。",
        "s7": "7. 利用者が実施すべき対応（順序と前提関係）",
        "s7_ph": "{{1. 対応 - 指摘ID - 先に行う理由・前提（例：履歴削除の前にローテーション）}}",
        "s7_note": "指摘は、同じイメージダイジェストとルールセットでの再スキャン（手動指摘は再読）で再現しなくなった時点でのみクローズする。",
        "s8": "8. 手法と限界（必須）",
        "type": "種別", "type_txt": "ソース、スキーマ、設定、IaC、Git履歴を対象とした静的監査（固定版スキャナと手動レビュー）。実行時テスト、攻撃検証、本番データへのアクセスは行っていない。",
        "scope_dec": "範囲の決定", "scope_ph": "{{深度・重点・法域・出力形式（利用者の回答、または「検出結果に基づく既定値（--yes）」）}}",
        "baseline": "基準のベースライン（検証日：{d}）", "std_cols": ["基準", "版", "主引用", "併記"],
        "scanners": "スキャナ", "drift": "ルールセットと脆弱性DBはイメージのタグとは独立して更新される。",
        "not_conclude": "本報告書から結論づけてはならないこと",
        "nc": ["「システムは安全である」ではない。指摘がないことは問題がないことの証明ではない。",
               "「本番で悪用可能である」ではない。重大度は影響に基づき、実証された攻撃に基づくものではない。",
               "「未カバー領域は問題ない」ではない。第2節の欠落は不明であり、安全ではない。",
               "「クローズ済みの指摘は修正が一般に正しい」ではない。同じ検査で再現しなくなったことのみを意味する。"],
        "explorer": "指摘エクスプローラー", "search": "ID、件名、ファイル、基準、CWE、本文で検索…",
        "all_sev": "すべての重大度", "all_repo": "すべてのリポジトリ", "all_kind": "すべての種別", "all_conf": "すべての確度",
        "all_status": "すべての状況", "expand": "展開／折りたたみ", "reset": "リセット", "file": "ファイル",
        "h_cols": ["ID", "重大度", "リポジトリ", "件名", "種別", "確度", "基準", "箇所", "状況"],
        "generated": "security-audit により生成", "findings_n": "件の指摘",
        "sheets": {"summary": "サマリー", "findings": "指摘一覧", "coverage": "実施範囲", "master": "マスタ"},
    },
}


def detect_lang(text: str) -> str:
    """ja if kana present, else en."""
    if re.search(r"[\u3040-\u30ff]", text or ""):
        return "ja"
    return "en"


def label(kind: str, code: str, lang: str) -> str:
    table = ENUM.get(kind, {})
    return table.get(lang, table.get("en", {})).get(code, code)


INTEL_STATUS = {
    "en": {"eol": "end of life", "range-allows-eol": "range allows an EOL cycle", "behind": "behind latest patch",
           "current": "current", "floating": "floating tag", "managed": "managed runtime", "distro": "distro package",
           "unknown": "unknown"},
    "ja": {"eol": "サポート終了", "range-allows-eol": "範囲指定がサポート終了版を許容", "behind": "最新パッチ未適用",
           "current": "最新", "floating": "タグ追従（実体はビルド時に決定）", "managed": "マネージドランタイム",
           "distro": "ディストリビューションのパッケージ", "unknown": "不明"},
}


def intel_status(code: str, lang: str) -> str:
    return INTEL_STATUS.get(lang, INTEL_STATUS["en"]).get(code, code)


def ui(lang: str) -> dict:
    """Script labels for a language; languages without a table fall back to English labels (prose is
    still written in the chosen language)."""
    return T.get(lang, T["en"])


def lang_code(lang: str) -> str:
    """Normalise a user choice ('English', '日本語', 'ko', 'Korean') to a short code."""
    m = {"english": "en", "japanese": "ja", "日本語": "ja", "korean": "ko", "한국어": "ko",
         "chinese": "zh", "中文": "zh", "french": "fr", "german": "de", "spanish": "es", "thai": "th"}
    k = (lang or "").strip().lower()
    return m.get(k, k[:5] or "en")


# ---- language-consistency check (used by validate_findings) ----
_CODE = re.compile(r"```.*?```|`[^`\n]*`", re.S)
_KEEP = re.compile(
    r"(OWASP[\w /:.-]*?Top 10[\w /:.-]*|OWASP \w+|ASVS|MASVS|MASTG|AISVS|PCI DSS|CIS [A-Za-z /]+|SLSA|NIST[\w .-]*|"
    r"CWE-\d+|CVE-[\d-]+|GHSA-[\w-]+|FIND-[\w-]+|https?://\S+|[\w./-]+\.\w{1,5}(:\d+)?|"
    r"[A-Z][A-Za-z0-9]*(?:[-_.][A-Za-z0-9]+)+)")
_WORDS = re.compile(r"(?:\b[A-Za-z][A-Za-z'’]+\b[ ,;:()/-]*){7,}")


def english_prose_lines(text: str, max_hits: int = 5, keep: tuple = ()) -> list[str]:
    """Lines (outside code, IDs, paths, standard names) that contain >= 7 consecutive English words.
    `keep`: extra names that may stay in English (the canonical standard names)."""
    hits = []
    body = re.sub(r"^---\s*\n.*?\n---\s*\n", "", text or "", flags=re.S)
    names = sorted(keep, key=len, reverse=True)
    for line in _CODE.sub(" ", body).splitlines():
        if line.lstrip().startswith(("|---", "<!--")):
            continue
        stripped = line
        for n in names:
            stripped = stripped.replace(n, " ")
        stripped = _KEEP.sub(" ", stripped)
        m = _WORDS.search(stripped)
        if m:
            hits.append(line.strip()[:100])
            if len(hits) >= max_hits:
                break
    return hits


# ---- display names of canonical standards issued in Japan (standards table of a ja report)
STD_NAME = {"ja": {
    "IPA How to Secure Your Web Site": "IPA 安全なウェブサイトの作り方",
    "MHLW Medical Information Security Guidelines": "厚生労働省 医療情報システムの安全管理に関するガイドライン",
    "MIC/METI Medical Service Provider Guidelines":
        "総務省・経済産業省 医療情報を取り扱う情報システム・サービスの提供事業者における安全管理ガイドライン",
    "FISC Security Guidelines": "FISC 金融機関等コンピュータシステムの安全対策基準",
    "Japan APPI": "個人情報保護法", "Japan My Number Act": "番号法",
    "Japan Credit Card Security Guidelines": "クレジットカード・セキュリティガイドライン",
    "FSA Cybersecurity Guidelines": "金融庁 金融分野におけるサイバーセキュリティに関するガイドライン",
    "Japan Government Unified Standards": "政府機関等のサイバーセキュリティ対策のための統一基準",
    "MEXT Education Information Security Guidelines": "文部科学省 教育情報セキュリティポリシーに関するガイドライン",
    "Japan Telecommunications Business Act": "電気通信事業法",
    "Japan Active Cyber Defense Act": "サイバー対処能力強化法",
}}


def std_name(std: str, lang: str) -> str:
    return STD_NAME.get(lang, {}).get(std, std)


# ---- AI and agent inventory (agent_config_audit.py) surface names and risk labels
AI_SURFACE = {"ja": {
    "permissions": "権限ルール", "exec-settings": "コマンド実行設定", "env": "環境変数", "sandbox": "サンドボックス",
    "plugins": "プラグイン", "hooks": "フック", "mcp": "MCP サーバー", "subagents": "サブエージェント",
    "skills": "スキル", "commands": "コマンド", "instructions": "指示ファイル", "ci-agents": "CI のエージェント",
    "ide": "IDE 設定", "dangerous-flags": "危険なフラグ", "prompt-logs": "プロンプト履歴",
    "hidden-unicode": "不可視文字", "settings": "設定ファイル", "llm-code": "LLM 呼び出し"}}
AI_RISK = {"ja": [
    (r"^local-settings-committed$", "個人用設定がコミット済み"),
    (r"^bypass-or-auto-mode$", "確認を省略するモード"),
    (r"^broad-allow$", "広すぎる許可ルール"),
    (r"^file access outside the repo$", "リポジトリ外のファイルへのアクセス"),
    (r"^write/publish/exfil verb pre-approved$", "書き込み・公開・外部送信の操作を事前許可"),
    (r"^prefix-deny", "前方一致の拒否ルール（回避可能）"),
    (r"^reach-outside-repo$", "リポジトリ外への到達"),
    (r"^trifecta", "外部送信可能だが機密パスの読み取り拒否なし"),
    (r"^network call from hook$", "フックからのネットワーク通信"),
    (r"^needs PowerShell", "PowerShell 依存（macOS/Linux で動作しない可能性）"),
    (r"^needs bash", "bash 依存（Windows で動作しない可能性）"),
    (r"^auto commit/push$", "自動コミット／プッシュ"),
    (r"^runs a shell command$", "シェルコマンドを実行"),
    (r"^redirect/TLS/proxy env$", "通信先・TLS・プロキシを変更する環境変数"),
    (r"^inline secret value$", "値が直書きされたシークレット"),
    (r"^sandbox disabled$", "サンドボックス無効"),
    (r"^unsandboxed commands allowed$", "サンドボックス外のコマンドを許可"),
    (r"^all hooks disabled$", "全フック無効"),
    (r"^mcp auto-enabled$", "MCP サーバーを自動有効化"),
    (r"^third-party plugins", "第三者プラグインを全員に配布"),
    (r"^auto-approve$", "自動承認"),
    (r"^runs on folder open$", "フォルダーを開くと実行"),
    (r"^runs on the HOST$", "ホスト上で実行"),
    (r"^host mounts$", "ホストのマウント"),
    (r"^no approval / full access$", "承認なし／フルアクセス"),
    (r"^unpinned launch$", "バージョン未固定で起動"),
    (r"^inline secret in env", "環境変数にシークレットを直書き"),
    (r"^static header value", "固定のヘッダー値"),
    (r"^remote MCP over plain HTTP$", "暗号化されていない HTTP のリモート MCP"),
    (r"^filesystem server rooted", "ルートまたはホーム配下を公開するファイルシステムサーバー"),
    (r"^committed$", "コミット済み"),
    (r"^untracked \(not in git\)$", "未追跡（Git 管理外）"),
    (r"^no tools list", "ツール指定なし（全ツールを継承）"),
    (r"^reviewer/read-only role holds", "読み取り専用の役割が書き込み・実行権限を保持"),
    (r"^permissionMode=", "権限モードの変更"),
    (r"^persistent memory", "永続メモリ"),
    (r"^own hooks / MCP servers$", "独自のフック／MCP サーバー"),
    (r"^unscoped Bash pre-approved$", "範囲指定のない Bash を事前許可"),
    (r"^Agent/Skill pre-approved$", "Agent／Skill を事前許可"),
    (r"^exec / network / write command pre-approved$", "実行・通信・書き込みコマンドを事前許可"),
    (r"dynamic `!` command", "読み込み時に実行される動的コマンド"),
    (r"^frontmatter hooks$", "フロントマター内のフック"),
    (r"^outside \.claude/skills", "同梱または外部由来のスキル"),
    (r"^third-party \(own LICENSE\)", "第三者製（固定とレビューが必要）"),
    (r"^deploy/publish skill without", "自動起動を禁止していないデプロイ／公開スキル"),
    (r"^possible prompt injection", "エージェントを狙ったプロンプトインジェクションの可能性"),
    (r"^wording:", "安全策を回避させる記述"),
    (r"^untrusted trigger feeds agent$", "信頼できないトリガーがエージェントに入力"),
    (r"^agent job holds write/secrets$", "エージェントのジョブが書き込み権限／シークレットを保持"),
    (r"^agent safety disabled$", "エージェントの安全機構を無効化"),
    (r"^hidden instruction channel$", "隠れた指示の経路"),
    (r"^dangerous switch / exposure$", "危険な設定／公開"),
    (r"^scripts run by the agent", "エージェントが実行するスクリプト（コード同様にレビュー）"),
    (r"^history:", "履歴に残存（書き換えか受容）"),
    (r"^unparseable", "解析できない設定ファイル（手動で確認）"),
]}


# ---- run_scanners coverage gaps / reasons (stable English text in scanners.json, localised on render)
GAP_TEXT = {"ja": [
    (r"^([\w-]+): (.+)$", None),  # "<tool>: <reason>" - the reason is localised recursively
    (r"^osv-scanner needs network", "osv-scanner はネットワークが必要（ローカルの脆弱性DBなし）。依存関係は trivy のキャッシュDBのみで確認"),
    (r"^--offline and image not cached: (.+)$", "--offline 指定でイメージが未取得：{0}"),
    (r"^pull failed: (.*)$", "イメージの取得に失敗：{0}"),
    (r"^timeout after (\d+)s$", "{0} 秒でタイムアウト"),
    (r"^no output produced", "出力なし（stderr_tail を参照）"),
    (r"^(\S+) not on PATH and Docker unavailable$", "{0} が PATH になく Docker も利用不可"),
    (r"^(\S+) not on PATH$", "{0} が PATH にない"),
    (r"^(failed|skipped)$", None),
    (r"^git history unavailable", "Git 履歴なし（.git なし、または shallow clone）：シークレット検査は作業ツリーのみ"),
    (r"^repo scanner config may suppress results \(review it\): (.+)$",
     "リポジトリ内のスキャナ設定が結果を抑制する可能性（内容を確認）：{0}"),
]}


def gap_text(text: str, lang: str) -> str:
    """Localised coverage-gap / skip-reason text from scanners.json; unknown text is returned unchanged."""
    table = GAP_TEXT.get(lang)
    if not table or not text:
        return text
    for rx, tpl in table:
        m = re.match(rx, text)
        if not m:
            continue
        if rx.startswith("^([\\w-]+): "):
            inner = gap_text(m.group(2), lang)
            if inner == m.group(2):
                continue  # not a known reason: try the full-line patterns below
            return f"{m.group(1)}：{inner}"
        if tpl is None:
            return label("tool_status", m.group(1), lang)
        return tpl.format(*m.groups())
    return text


def ai_surface(name: str, lang: str) -> str:
    return AI_SURFACE.get(lang, {}).get(name, name)


def ai_risk(label: str, lang: str) -> str | None:
    """Localised risk label, or None when the language has no table (caller keeps the English code)."""
    table = AI_RISK.get(lang)
    if not table:
        return None
    for rx, text in table:
        if re.search(rx, label):
            return text
    return "その他のリスク表示" if lang == "ja" else None
