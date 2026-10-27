#!/usr/bin/env python3
"""
Sensitive-data-at-rest sweep (Phase 2). Locations only - never values.

Searches, in priority order: migrations -> schema/model/entity definitions -> provider-response
persistence -> spill surfaces (logs, caches, exports, analytics) -> client-side stores.
Reports file:line, matched term, data class, and surface. Any digit run >= 6 is masked in the
snippet; Luhn-valid 13-19 digit literals are reported as "PAN-like literal" with NO value.

Always writes a negative-result record (what was searched, with which patterns) so a clean
result is evidence, not silence.

Usage:
  python sensitive_sweep.py <repo> [--out sweep.json] [--extra-terms term1,term2] [--max-hits 400]
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
from peek import redact as _redact  # noqa: E402  single redaction implementation

SKIP_DIRS = {".git", "node_modules", "vendor", "dist", "build", "out", "target", ".next", ".nuxt",
             ".venv", "venv", "__pycache__", "coverage", "Pods", ".gradle", ".terraform", ".dart_tool",
             "bower_components", ".svelte-kit", ".turbo", ".cache", "bin", "obj"}
TEXT_EXT = {".tfvars", ".hcl", ".ini", ".conf", ".cfg", ".toml", ".plist", ".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".go", ".java", ".kt", ".rb", ".php",
            ".cs", ".rs", ".swift", ".dart", ".sql", ".prisma", ".graphql", ".gql", ".yaml", ".yml",
            ".json", ".vue", ".svelte", ".scala", ".ex", ".exs", ".xml", ".properties", ".env",
            ".tf", ".proto", ".avsc", ".m", ".erb", ".twig", ".blade.php", ".cshtml", ".html"}
# prose / data / log text: where data at rest leaks in a repo (prompt logs, exports, notebooks, dumps)
DOC_EXT = {".txt", ".md", ".mdc", ".csv", ".tsv", ".log", ".jsonl", ".ndjson", ".ipynb", ".sh", ".bash",
           ".ps1", ".bat", ".cmd", ".rst", ".adoc"}
# binary / data files: reported by NAME only (content never read)
DATA_EXT = {".sqlite", ".sqlite3", ".db", ".mdb", ".accdb", ".xlsx", ".xls", ".parquet", ".avro", ".bak",
            ".dump", ".sql.gz", ".pgdump", ".rdb", ".pcap", ".har", ".mbox", ".pst", ".eml", ".msg"}

# data class -> (severity hint, regex). Word-ish boundaries tolerate snake/camel/kebab.
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
# Japanese / Vietnamese native-script terms (column comments, labels, i18n keys)
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
    """Accept Git-Bash style /c/Users/... on Windows (otherwise it silently resolves to C:/c/Users)."""
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
    line, _ = _redact(line, False)  # secrets first (before digit masking breaks token shapes)
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
    ap.add_argument("--out", help="write full JSON here (stdout gets a compact summary)")
    ap.add_argument("--extra-terms", default="", help="comma-separated local column names to add")
    ap.add_argument("--max-hits", type=int, default=400)
    a = ap.parse_args()
    root = Path(host_path(a.repo)).resolve()
    if not root.is_dir():
        print(f"error: not a directory: {a.repo}", file=sys.stderr)
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
    for dirpath, dirnames, filenames in os.walk(root):  # os.walk does not descend into linked dirs
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            p = Path(dirpath) / fn
            if p.is_symlink():  # a committed link to e.g. ~/.aws/credentials must not be read
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
                continue  # vendored/static assets: noise for data-class leads
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
                        continue  # part of a UUID / trace id (e.g. yor_trace), not a card number
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

    # priority: never-store first, then migrations/schema, then non-test
    order = {k: n for n, k in enumerate(["SAD-never-store", "PAN-like-literal", "credential-in-url",
                                         "client-credential-store", "PAN-must-be-unreadable",
                                         "credential-reversible", "credential-storage", "financial-account", "secret-at-rest", "health-PHI",
                                         "national-id-PII", "biometric", "native-language-term",
                                         "card-adjacent", "contact-PII", "project-specific"])}
    surf_rank = {"migration": 0, "schema": 1, "persistence-call": 2, "log": 3, "client-store": 4,
                 "cache": 5, "export-analytics": 6, "data-export": 7, "code": 8, "docs-text": 9}
    # product code and data first; prose and agent-tooling copies (vendored skills, rules) last,
    # except prompt / transcript logs, which are real data at rest
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

    # compact stdout summary: priority leads grouped by file
    print(f"# sensitive sweep: {root.name}  ({files_scanned} files; {record['migration_files']} migration, "
          f"{record['schema_files']} schema)")
    if not per_class:
        print("NO MATCHES in the searched text types (see text_types_searched / not_searched_types in the "
              "JSON) - a negative result for those types only; state the not-searched types in the report.")
    if data_files:
        print(f"data files committed (names only, content not read): {len(data_files)} - e.g. "
              + ", ".join(data_files[:5]))
    if skipped_links:
        print(f"symlinks resolving outside the repo, not read: {len(skipped_links)} (listed in the JSON)")
    if per_class:  # always shown, also when data files are committed
        print("counts by class:", dict(per_class))
        print("counts by surface:", dict(per_surface))
        grouped = defaultdict(list)
        for h in hits:
            if h["class"] in ("contact-PII", "card-adjacent") and h["surface"] == "code":
                continue  # low-signal in plain code; available in JSON
            grouped[(h["file"], h["test"])].append(h)
        shown = 0
        print("\n## priority leads (non-test first; full list in --out)")
        for (f, t), hs in grouped.items():
            if shown >= 40:
                print(f"... {len(grouped) - shown} more files in JSON")
                break
            shown += 1
            tags = sorted({f"{h['class']}@{h['surface']}" for h in hs})
            lines = ",".join(str(h["line"]) for h in hs[:8])
            print(f"- {f}{' [test]' if t else ''} L{lines}: {'; '.join(tags)}")
    if provider_persist:
        print(f"\n## provider-response persistence candidates: {len(provider_persist)}")
        for c in provider_persist[:10]:
            print(f"- {c['file']}:{c['line']}  {c['snippet']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
