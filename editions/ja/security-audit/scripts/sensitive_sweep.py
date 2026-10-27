#!/usr/bin/env python3
"""
保存データの機微情報のスイープ（Phase 2）。場所のみを扱い、値は決して扱わない。

優先順に検索する：マイグレーション -> スキーマ / モデル / エンティティ定義 -> 決済プロバイダ応答の
永続化 -> 漏出面（ログ、キャッシュ、エクスポート、アナリティクス）-> クライアント側のストア。
file:line、一致した語、データクラス、検出面を報告する。スニペット内の 6 桁以上の数字の並びはすべてマスクする。
Luhn 検査に通る 13-19 桁のリテラルは "PAN-like literal" として、値なし（NO value）で報告する。

常に「該当なし」の記録（何を、どのパターンで検索したか）を書き出すため、クリーンな結果は沈黙ではなく
根拠になる。

使い方：
  python sensitive_sweep.py <repo> [--out sweep.json] [--extra-terms term1,term2] [--max-hits 400]
"""
from __future__ import annotations

import sys
sys.dont_write_bytecode = True  # インストール済みスキルに __pycache__ を残さない
for _s in (sys.stdout, sys.stderr):  # cp932 / cp1252 のコンソールやパイプでも UTF-8 で出力する
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
from peek import redact as _redact  # noqa: E402  秘匿化の実装は 1 つだけ

SKIP_DIRS = {".git", "node_modules", "vendor", "dist", "build", "out", "target", ".next", ".nuxt",
             ".venv", "venv", "__pycache__", "coverage", "Pods", ".gradle", ".terraform", ".dart_tool",
             "bower_components", ".svelte-kit", ".turbo", ".cache", "bin", "obj"}
TEXT_EXT = {".tfvars", ".hcl", ".ini", ".conf", ".cfg", ".toml", ".plist", ".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".go", ".java", ".kt", ".rb", ".php",
            ".cs", ".rs", ".swift", ".dart", ".sql", ".prisma", ".graphql", ".gql", ".yaml", ".yml",
            ".json", ".vue", ".svelte", ".scala", ".ex", ".exs", ".xml", ".properties", ".env",
            ".tf", ".proto", ".avsc", ".m", ".erb", ".twig", ".blade.php", ".cshtml", ".html"}
# 文章 / データ / ログのテキスト：リポジトリ内で保存データが漏れる場所（プロンプトログ、エクスポート、ノートブック、ダンプ）
DOC_EXT = {".txt", ".md", ".mdc", ".csv", ".tsv", ".log", ".jsonl", ".ndjson", ".ipynb", ".sh", ".bash",
           ".ps1", ".bat", ".cmd", ".rst", ".adoc"}
# バイナリ / データファイル：名前（NAME）のみ報告する（内容は決して読まない）
DATA_EXT = {".sqlite", ".sqlite3", ".db", ".mdb", ".accdb", ".xlsx", ".xls", ".parquet", ".avro", ".bak",
            ".dump", ".sql.gz", ".pgdump", ".rdb", ".pcap", ".har", ".mbox", ".pst", ".eml", ".msg"}

# データクラス -> （重大度のヒント、正規表現）。単語境界に近い判定で snake / camel / kebab 形式を許容する。
B = r"(?<![A-Za-z0-9])"
E = r"(?![A-Za-z0-9])"
CLASSES = {
    "SAD-never-store": ("P0 if persisted post-authorization (PCI DSS v4.0.1 Req 3.3.1)", re.compile(
        B + r"(cvv2?|cvc2?|cid|card_?verification|security_?code|track_?[12]|track_?data|"
            r"mag_?stripe|pin_?block|pinblock|card_?pin)" + E, re.I)),
    "PAN-must-be-unreadable": ("P0 if plaintext (PCI DSS v4.0.1 Req 3.5.1)", re.compile(
        B + r"(card_?number|cardnumber|card_?no|cc_?num(ber)?|credit_?card(_?number)?|creditcard|"
            r"pan|primary_?account_?number|full_?pan|card_?num|account_?number)" + E, re.I)),
    "card-adjacent": ("context: confirms card handling", re.compile(
        B + r"(exp(iry|iration)?_?(date|month|year)|exp_?month|exp_?year|card_?holder(_?name)?|"
            r"cardholder|bin_?number|last_?4|last_?four)" + E, re.I)),
    "financial-account": ("encrypt with managed keys / tokenize; never decryptable by ordinary users "
                          "(ASVS 5.0.0 V14; PDPL sensitive data)", re.compile(
        B + r"(bank_?account(_?(no|num(ber)?))?|account_?(no|num)|routing_?(no|num(ber)?)|"
            r"bank_?routing(_?num(ber)?)?|iban|swift_?(code)?|bic|sort_?code|bsb|ifsc|"
            r"so_?tai_?khoan|stk|koza_?bango|kouza|salary|income|tax_?return)" + E, re.I)),
    "credential-reversible": ("P1+ if recoverable (ASVS 5.0.0 V6 / V11)", re.compile(
        B + r"(password_?(plain|clear|raw|enc(rypted)?)|plain_?password|raw_?password|"
            r"decrypt_?password|encrypt_?password|pwd_?enc|password_?cipher)" + E, re.I)),
    "credential-storage": ("verify one-way hash (Argon2id/bcrypt/scrypt/PBKDF2); plaintext = P1+", re.compile(
        r"(?i)(?<![A-Za-z0-9])(password|passwd|pwd|pass_?hash|password_?hash|hashed_?password|pin_?code)"
        r"(?![A-Za-z0-9])\s*(?:[\"'`]?\s*(?:TEXT|VARCHAR|CHAR|STRING|NVARCHAR|BLOB|BYTEA)\b|:\s*(?:str|String|string)\b|"
        r"=\s*(?:models\.|Column\(|db\.Column\()|\s*:\s*\{\s*type:|\s+String\b|\s+string\b)")),
    "seeded-credential": ("seed/fixture password literal - default account risk; view with peek.py only", re.compile(
        r"(?i)(INSERT\s+(?:OR\s+\w+\s+|IGNORE\s+)?INTO\s+[`\"\[]?(users?|accounts?|admins?|members?|customers?|logins?|staff)\b|"
        r"(md5|sha1|sha256|crypt|password_hash|bcrypt|hashpw|make_password|encrypt)\s*\(\s*['\"][^'\"]{3,}['\"]|"
        r"(password|passwd|pwd)\s*[:=]>?\s*['\"][^'\"]{3,}['\"])")),
    "client-credential-store": ("credential/token in client storage (MASVS-STORAGE-1); P1+ if plaintext", re.compile(
        r"(?i)(putString|putStringSet|setString|UserDefaults[^;\n]*set|localStorage\.setItem|sessionStorage\.setItem|"
        r"AsyncStorage\.setItem|SharedPreferences[^;\n]*)\s*\(?\s*['\"]?[\w.]*(password|passwd|pwd|pin|token|"
        r"secret|session|auth)")),
    "credential-in-url": ("credentials embedded in a URL (userinfo); treat as committed secret", re.compile(
        r"(?i)\b[a-z][a-z0-9+.-]*://[^/\s:@'\"<>]+:[^@\s'\"/<>]{3,}@")),
    "secret-at-rest": ("P1 (ASVS 5.0.0 V13 / V14)", re.compile(
        B + r"(api_?secret|client_?secret|private_?key|access_?token|refresh_?token|"
            r"secret_?key|otp_?secret|totp_?secret|mfa_?secret)" + E, re.I)),
    "national-id-PII": ("privacy law; high-risk PII", re.compile(
        B + r"(ssn|social_?security(_?number)?|national_?id|national_?identity|passport_?(no|num(ber)?)|"
            r"driver_?licen[cs]e(_?(no|number))?|tax_?id|my_?number|mynumber|kojin_?bango|"
            r"cccd|cmnd|can_?cuoc|so_?cmnd|so_?cccd|resident_?registration)" + E, re.I)),
    "contact-PII": ("privacy law; minimisation", re.compile(
        B + r"(date_?of_?birth|birth_?date|birthday|dob|ngay_?sinh|seinengappi|"
            r"phone(_?number)?|mobile_?number|so_?dien_?thoai|home_?address|street_?address|dia_?chi|"
            r"jusho|postal_?code|zip_?code|full_?name_?kana|furigana)" + E, re.I)),
    "health-PHI": ("health-privacy law (HIPAA / APPI special care / PDPL sensitive)", re.compile(
        B + r"(diagnosis|medical_?(record|history|condition)|prescription|icd_?10|blood_?type|"
            r"patient_?id|health_?(record|insurance)|insurance_?number|disease|allergy|"
            r"medication)" + E, re.I)),
    "biometric": ("sensitive personal data", re.compile(
        B + r"(fingerprint_?(data|template|image|scan)|face_?(template|embedding|encoding)|"
            r"biometric|voice_?print|iris_?(scan|template))" + E, re.I)),
}
# 日本語 / ベトナム語の自国語表記の語（カラムのコメント、ラベル、i18n キー）
NATIVE = re.compile(r"(口座番号|給与|số tài khoản|lương|カード番号|セキュリティコード|有効期限|マイナンバー|個人番号|生年月日|電話番号|住所|"
                    r"パスワード|病名|診断|số thẻ|mã bảo mật|ngày sinh|số điện thoại|địa chỉ|"
                    r"căn cước|chứng minh nhân dân|mật khẩu|bệnh án)", re.I)

SURFACES = [
    ("migration", re.compile(r"(^|/)(migrations?|migrate|db/migrate|alembic|flyway|liquibase|"
                             r"prisma/migrations|database/migrations)(/|$)|\.sql$", re.I)),
    ("docs-text", re.compile(r"\.(txt|md|mdc|rst|adoc|ipynb)$", re.I)),
    ("data-export", re.compile(r"\.(csv|tsv|jsonl|ndjson|log)$", re.I)),
    ("schema", re.compile(r"(schema\.prisma|schema\.rb|models?\.py|/models?/|/entit(y|ies)/|/schemas?/|"
                          r"\.graphql$|\.gql$|\.proto$|\.avsc$|openapi|swagger|/domain/|/dto/)", re.I)),
]
LOG_CALL = re.compile(r"(console\.(log|info|debug|warn|error)|logger\.|log\.(info|debug|warn|error|print)|"
                      r"logging\.|print\(|println|fmt\.Print|System\.out|Log\.[dviwe]\(|NSLog|"
                      r"Rails\.logger|error_log|var_dump|winston|pino|bunyan|zap\.|slog\.)")
CACHE_CALL = re.compile(r"(redis|cache\.(set|put)|setex|memcache|lru|hset|\.set\(\s*['\"`])", re.I)
EXPORT_CALL = re.compile(r"(to_csv|csv\.writer|writerow|xlsx|exceljs|openpyxl|analytics\.|track\(|"
                         r"segment\.|mixpanel|amplitude|sentry\.(capture|set)|datadog)", re.I)
CLIENT_STORE = re.compile(r"(localStorage|sessionStorage|indexedDB|AsyncStorage|SharedPreferences|"
                          r"NSUserDefaults|UserDefaults|SecureStore|shared_preferences|Hive\.box|"
                          r"document\.cookie)", re.I)
PERSIST_CALL = re.compile(r"(\.save\(|\.create\(|\.insert|INSERT\s+INTO|\.update\(|\.upsert|"
                          r"\.put_item|\.putItem|\.add\(|repository\.|\.persist\()", re.I)
PROVIDER_RESP = re.compile(r"(stripe|braintree|adyen|paypal|square|payjp|omise|komoju|vnpay|momo|"
                           r"gateway|payment_?intent|charge|authori[sz]ation)_?(response|result|res|resp)?",
                           re.I)
DIGITS = re.compile(r"\d{6,}")
UUID = re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")
VENDOR_LIB = re.compile(r"(^|/)(jquery|bootstrap|materialize|lodash|underscore|moment|d3|chart|highcharts|"
                        r"datatables|select2|popper|modernizr|backbone|angular|react|vue)[\w.-]*\.js$", re.I)
ASSET = re.compile(r"(\.(css|scss|sass|less|svg|map)(\.erb)?$|\.min\.|(^|/)(assets|static|public|vendor|fonts?)/)", re.I)
PAN_LIT = re.compile(r"(?<!\d)(\d[ -]?){12,18}\d(?!\d)")


def host_path(p: str) -> str:
    """Windows で Git Bash 形式の /c/Users/... を受け付ける（そうしないと黙って C:/c/Users に解決される）。"""
    if os.name == "nt":
        m = re.match(r"^/([a-zA-Z])(/.*)?$", p or "")
        if m:
            return f"{m.group(1).upper()}:{m.group(2) or '/'}"
    return p


def luhn_ok(num: str) -> bool:
    d = [int(c) for c in num if c.isdigit()]
    if not 13 <= len(d) <= 19 or len(set(d)) == 1:
        return False
    s = 0
    for i, x in enumerate(reversed(d)):
        if i % 2:
            x *= 2
            if x > 9:
                x -= 9
        s += x
    return s % 10 == 0


def mask(line: str) -> str:
    line, _ = _redact(line, False)  # シークレットを先に処理する（数字のマスクでトークンの形が崩れる前に）
    line = PAN_LIT.sub("[PAN-LIKE-REDACTED]", line)
    line = DIGITS.sub(lambda m: "#" * min(len(m.group()), 8), line)
    line = re.sub(r"([\"'])[A-Za-z0-9+/_\-]{24,}([\"'])", r"\1[REDACTED]\2", line)
    line = line.strip()
    return line[:140] + ("..." if len(line) > 140 else "")


INLINE_SCHEMA = re.compile(r"(CREATE\s+TABLE|ALTER\s+TABLE|ADD\s+COLUMN|\bColumn\(|@Column\b|"
                           r"\bt\.(string|text|integer)\b|add_column|Schema\(|new\s+Schema\b|\bField\()", re.I)


def surface_of(rel: str, line: str) -> str:
    for name, rx in SURFACES:
        if rx.search(rel):
            return name
    if INLINE_SCHEMA.search(line):
        return "schema"
    if CLIENT_STORE.search(line):
        return "client-store"
    if LOG_CALL.search(line):
        return "log"
    if CACHE_CALL.search(line):
        return "cache"
    if EXPORT_CALL.search(line):
        return "export-analytics"
    if PERSIST_CALL.search(line):
        return "persistence-call"
    return "code"


def is_test(rel: str) -> bool:
    return bool(re.search(r"(^|/)(tests?|__tests__|spec|specs|fixtures?|mocks?|e2e|testdata|examples?)(/|$)|"
                          r"\.(test|spec)\.", rel, re.I))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("repo")
    ap.add_argument("--out", help="完全な JSON をここに書き出す（stdout には簡潔な要約を出す）")
    ap.add_argument("--extra-terms", default="", help="追加するプロジェクト固有のカラム名（カンマ区切り）")
    ap.add_argument("--max-hits", type=int, default=400)
    a = ap.parse_args()
    root = Path(host_path(a.repo)).resolve()
    if not root.is_dir():
        print(f"error: ディレクトリではない: {a.repo}", file=sys.stderr)
        return 2
    extra = [t.strip() for t in a.extra_terms.split(",") if t.strip()]
    classes = dict(CLASSES)
    if extra:
        classes["project-specific"] = ("user-supplied term", re.compile(
            B + "(" + "|".join(re.escape(t) for t in extra) + ")" + E, re.I))

    hits = []
    per_class = Counter()
    per_surface = Counter()
    files_scanned = 0
    surfaces_seen = Counter()
    provider_persist = []
    data_files, skipped_large, skipped_links, not_searched = [], [], [], Counter()
    for dirpath, dirnames, filenames in os.walk(root):  # os.walk はリンク先のディレクトリには降りない
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            p = Path(dirpath) / fn
            if p.is_symlink():  # 例えば ~/.aws/credentials へのコミット済みリンクは読んではならない
                try:
                    inside = root in p.resolve().parents
                except (OSError, RuntimeError):
                    inside = False
                if not inside:
                    skipped_links.append(p.relative_to(root).as_posix())
                    continue
            ext = "".join(p.suffixes[-2:]) if fn.endswith(".blade.php") else p.suffix.lower()
            low_fn = fn.lower()
            if ext in DATA_EXT or low_fn.endswith((".sql.gz", ".tar.gz.bak")):
                rel_d = p.relative_to(root).as_posix()
                if not ASSET.search(rel_d):
                    data_files.append(rel_d)
                continue
            if ext in DOC_EXT:
                try:
                    if p.stat().st_size > 500_000:
                        skipped_large.append(p.relative_to(root).as_posix())
                        continue
                except OSError:
                    continue
            elif ext not in TEXT_EXT and not low_fn.startswith(".env"):
                not_searched[ext or "(none)"] += 1
                continue
            try:
                if p.stat().st_size > 1_500_000:
                    continue
                text = p.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            files_scanned += 1
            rel = p.relative_to(root).as_posix()
            if ASSET.search(rel) or VENDOR_LIB.search(rel):
                continue  # 同梱 / 静的アセット：データクラスの手がかりにとってはノイズ
            for name, rx in SURFACES:
                if rx.search(rel):
                    surfaces_seen[name] += 1
            lines = text.splitlines()
            for i, line in enumerate(lines, 1):
                if len(line) > 2000:
                    continue
                matched = []
                for cls, (_, rx) in classes.items():
                    m = rx.search(line)
                    if m:
                        matched.append((cls, m.group(0)))
                nm = NATIVE.search(line)
                if nm:
                    matched.append(("native-language-term", nm.group(0)))
                uuids = [u.span() for u in UUID.finditer(line)]
                for m in PAN_LIT.finditer(line):
                    if any(a <= m.start() < b for a, b in uuids):
                        continue  # UUID / トレース ID（例：yor_trace）の一部であり、カード番号ではない
                    if luhn_ok(m.group(0)):
                        matched.append(("PAN-like-literal", "<luhn-valid digits, value withheld>"))
                        break
                if PROVIDER_RESP.search(line) and PERSIST_CALL.search(line):
                    provider_persist.append({"file": rel, "line": i, "snippet": mask(line),
                                             "test": is_test(rel)})
                if not matched:
                    continue
                surf = surface_of(rel, line)
                for cls, term in matched:
                    per_class[cls] += 1
                    per_surface[surf] += 1
                    if len(hits) < a.max_hits:
                        hits.append({"class": cls, "term": term, "file": rel, "line": i,
                                     "surface": surf, "test": is_test(rel), "snippet": mask(line)})

    # 優先順位：保存禁止のものを先に、次にマイグレーション / スキーマ、次にテスト以外
    order = {k: n for n, k in enumerate(["SAD-never-store", "PAN-like-literal", "credential-in-url",
                                         "client-credential-store", "PAN-must-be-unreadable",
                                         "credential-reversible", "credential-storage", "financial-account", "secret-at-rest", "health-PHI",
                                         "national-id-PII", "biometric", "native-language-term",
                                         "card-adjacent", "contact-PII", "project-specific"])}
    surf_rank = {"migration": 0, "schema": 1, "persistence-call": 2, "log": 3, "client-store": 4,
                 "cache": 5, "export-analytics": 6, "data-export": 7, "code": 8, "docs-text": 9}
    # 製品コードとデータを先に、文章とエージェントツールの複製（同梱スキル、ルール）は最後に。
    # ただしプロンプト / トランスクリプトのログは実際の保存データなので例外とする
    def tier(h):
        f = h["file"].lower()
        if re.search(r"(prompt[_-]?history|transcript|\.specstory/|chat[_-]?(log|history))", f):
            return 0
        if f.startswith((".agents/", ".claude/", ".cursor/", ".github/")) or "/skills/" in f:
            return 2
        return 1 if h["surface"] in ("docs-text",) else 0
    hits.sort(key=lambda h: (h["test"], tier(h), order.get(h["class"], 99), surf_rank.get(h["surface"], 9)))

    record = {
        "repo": str(root),
        "date": dt.date.today().isoformat(),
        "files_scanned": files_scanned,
        "migration_files": surfaces_seen.get("migration", 0),
        "schema_files": surfaces_seen.get("schema", 0),
        "patterns": {k: v[1].pattern for k, v in classes.items()} | {"native-language-term": NATIVE.pattern},
        "severity_hints": {k: v[0] for k, v in classes.items()},
        "counts_by_class": dict(per_class),
        "counts_by_surface": dict(per_surface),
        "provider_response_persistence": provider_persist[:50],
        "hits": hits,
        "data_files_committed": data_files[:100],
        "text_types_searched": sorted(TEXT_EXT | DOC_EXT),
        "not_searched_types": dict(not_searched.most_common(30)),
        "skipped_large_text": skipped_large[:50],
        "skipped_symlinks_outside_repo": len(skipped_links),
        "skipped_symlinks": skipped_links[:50],
        "truncated": sum(per_class.values()) > len(hits),
        "note": "Hits are LEADS, not verdicts. Confirm by reading what the column/field stores. "
                "Never copy values into findings - column name + file:line only.",
    }
    if a.out:
        Path(host_path(a.out)).parent.mkdir(parents=True, exist_ok=True)
        Path(host_path(a.out)).write_text(json.dumps(record, indent=1, ensure_ascii=False), encoding="utf-8")

    # stdout の簡潔な要約：優先度の高い手がかりをファイルごとにまとめる
    print(f"# 機微情報スイープ: {root.name}  （{files_scanned} ファイル、マイグレーション {record['migration_files']}、"
          f"スキーマ {record['schema_files']}）")
    if not per_class:
        print("NO MATCHES：検索対象のテキスト種別に一致なし（JSON の text_types_searched / not_searched_types を参照）"
              " - その種別に限った「該当なし」の結果である。検索していない種別は報告書に明記すること。")
    if data_files:
        print(f"コミット済みのデータファイル（名前のみ、内容は未読）: {len(data_files)} - 例: "
              + ", ".join(data_files[:5]))
    if skipped_links:
        print(f"リポジトリ外に解決されるシンボリックリンク（未読）: {len(skipped_links)}（JSON に一覧あり）")
    if per_class:  # データファイルがコミットされている場合も常に表示する
        print("クラス別の件数:", dict(per_class))
        print("検出面別の件数:", dict(per_surface))
        grouped = defaultdict(list)
        for h in hits:
            if h["class"] in ("contact-PII", "card-adjacent") and h["surface"] == "code":
                continue  # 通常のコードでは信号が弱い。JSON には含まれる
            grouped[(h["file"], h["test"])].append(h)
        shown = 0
        print("\n## 優先度の高い手がかり（テスト以外を先に。全件は --out を参照）")
        for (f, t), hs in grouped.items():
            if shown >= 40:
                print(f"... ほか {len(grouped) - shown} ファイルは JSON を参照")
                break
            shown += 1
            tags = sorted({f"{h['class']}@{h['surface']}" for h in hs})
            lines = ",".join(str(h["line"]) for h in hs[:8])
            print(f"- {f}{' [test]' if t else ''} L{lines}: {'; '.join(tags)}")
    if provider_persist:
        print(f"\n## 決済プロバイダ応答の永続化の候補: {len(provider_persist)}")
        for c in provider_persist[:10]:
            print(f"- {c['file']}:{c['line']}  {c['snippet']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
