#!/usr/bin/env python3
"""
マスク付きファイルビューア - シークレット / 機微データの手がかり周辺のコードを、値をトランスクリプトに
出さずに読む。シークレット、鍵、パスワード、トークン、カード番号、個人データのリテラルとして
フラグが立った file:line には、Read/sed/grep の代わりにこれを使う。

マスク対象：秘密鍵ブロック、高エントロピーのトークン、シークレットらしき名前の値（引用符の有無を問わない。
*_KEY / *_PIN / *_PASS、YAML のブロックスカラーを含む）、CLI のシークレット（--password=x, --token x, mysql -pX,
curl -u user:pass）、AWS/GCP/Azure/Stripe/GitHub/Slack/JWT のトークン形状、Luhn 検査を通るカード番号らしき数字、
長い数字列、接続文字列のパスワード、メールアドレス、電話番号、日本の住所、および個人データのキー
（氏名、カナ、生年月日、住所、メール、電話、国民 ID）の値。構造（名前、キー、行番号、パス、コード式）は
見えたまま残る。リポジトリ外を指すシンボリックリンクは読まない。

使い方:
  python peek.py <file> [<line>] [--context 8]
  python peek.py <file> --range 10-40
"""
from __future__ import annotations

import sys
sys.dont_write_bytecode = True  # インストール済みスキルに __pycache__ を作らない
for _s in (sys.stdout, sys.stderr):  # cp932 / cp1252 のコンソールやパイプでも UTF-8 で出力する
    if hasattr(_s, "reconfigure"):
        _s.reconfigure(encoding="utf-8", errors="replace")

import argparse
import os
import re
import sys
from pathlib import Path

PATTERNS = [
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "[PRIVATE KEY BLOCK - REDACTED]"),
    (re.compile(r"\b(AKIA|ASIA|AGPA|AIDA)[A-Z0-9]{16}\b"), "[AWS-KEY-ID]"),
    (re.compile(r"\bsk-(?:proj-|ant-(?:api\d+-)?)?[A-Za-z0-9_\-]{16,}"), "[API-KEY]"),
    (re.compile(r"\b(?:glpat|gho|ghs|npm|pypi)-[A-Za-z0-9_\-]{16,}"), "[TOKEN]"),
    (re.compile(r"\b(sk|rk|pk)_(live|test)_[A-Za-z0-9]{8,}\b"), "[STRIPE-KEY]"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"), "[GITHUB-TOKEN]"),
    (re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"), "[SLACK-TOKEN]"),
    (re.compile(r"\bAIza[0-9A-Za-z_\-]{30,}\b"), "[GCP-API-KEY]"),
    (re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{5,}"), "[JWT]"),
    (re.compile(r"(://[^:/\s]+:)([^@\s]{3,})(@)"), r"\1[REDACTED]\3"),
]
# 汎用の *_KEY / *_PIN / *_PWD / *_PASS 名（SENDGRID_KEY, ADMIN_PIN, DB_PASS）。インデックス系の _key 名はシークレットではない
SUFFIX_KEY = (r"[\w.-]*(?<!primary)(?<!foreign)(?<!sort)(?<!cache)(?<!partition)(?<!unique)(?<!lookup)(?<!group)"
              r"(?<!index)(?<!public)(?<!translation)(?<!i18n)(?<!idempotency)(?<!range)(?<!composite)(?<!hash)"
              r"[_-](?:key|pin|pwd|pass)(?![A-Za-z0-9])")
SECRET_NAME = re.compile(
    r"(?i)((?:pass(?:word|wd)?|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|"
    r"(?:session|signing|encryption|cookie|jwt|hmac|master|app|crypto|aes|client)[_-]?key|\bkey|" + SUFFIX_KEY + "|"
    r"client[_-]?secret|auth|credential|salt|cvv|cvc|card[_-]?number|pan|ssn|account[_-]?number)"
    r"[\w.-]*[\"']?\s*(?:[:=]|=>|:=)\s*)([\"'`])([^\"'`]{3,})([\"'`])")
# 行内の任意の位置にある引用符なしの代入：KEY=value, key: value, export KEY=value, --key=value, {key: value}
# （dotenv / YAML / shell / properties / CLI 引数）。コードやプレースホルダーである値は残す（_keep_value）
UNQUOTED_KV = re.compile(
    r"(?i)(?:^|(?<=[\s,;{(]))((?:export\s+)?(?:--?)?(?:[\w.\-]*(?:pass(?:word|wd)?|pwd|secret|token|api[_-]?key|apikey|"
    r"access[_-]?key|private[_-]?key|(?:session|signing|encryption|cookie|jwt|hmac|master|app|crypto|aes)[_-]?key|"
    r"client[_-]?secret|credential|salt|dsn|conn(?:ection)?[_-]?str(?:ing)?)|" + SUFFIX_KEY + r")[\w.\-]*"
    r"[\"']?\s*(?:=|:)\s*)(?![\"'`$({\[<%=>]|[|>][-+0-9]*\s*$|\s*$)(\S+)")
# CLI 形式：--password=x, --db-pass x, --token x、mysql -pSecret、curl -u user:pass
CLI_SECRET = re.compile(r"(?i)((?<![\w-])--?(?:[\w]+-)*(?:password|passwd|pass|pwd|token|secret|api-?key|access-?key)"
                        r"(?:=|\s+))(?![-$<{%`])(\S+)")
MYSQL_P = re.compile(r"((?i:\b(?:mysql|mysqldump|mysqladmin|mysqlimport|mysqlsh|mariadb(?:-dump)?)\b)[^\n]*?\s-p)"
                     r"(?![\s$<{%`])(\S{3,})")
USERPASS = re.compile(r"((?<![\w-])(?:-u|--user)(?:=|\s+)[^:\s/@$]+:)(?![\s$<{%`])(\S+)")
CLI_STOP = {"to", "the", "a", "an", "and", "or", "for", "with", "flag", "flags", "option", "options", "is", "in", "of",
            "on", "value", "argument", "parameter", "from", "via", "as", "\\", "|", "&&"}
# シークレットではなく、コード、型、プレースホルダーである値（根拠を読める状態に保つ）
SAFE_VALUE = re.compile(r"(?i)(?:true|false|null|none|nil|undefined|yes|no|on|off|required|optional|string|str|"
                        r"number|int|integer|long|float|bool|boolean|bytes|text|char|varchar|any|object|date|"
                        r"localdate|datetime|uuid|self|this|lambda|function|new|await|\*+|x{3,}|\.{3}|redacted|"
                        r"\[redacted[^\]]*\])\??")
SECRETISH_LINE = re.compile(r"(?i)(pass(?:word|wd)?|pwd|secret|token|api[_-]?key|private[_-]?key|credential|salt|"
                            r"(?:session|signing|encryption|cookie|jwt|hmac|master|app|crypto|aes)[_-]?key|"
                            r"secret_key_base|[\"']key[\"']\s*:)")
PATH_LINE = re.compile(r"[\w./@+ -]*[\w-]\.[A-Za-z]\w{0,5}:\d+(?:-\d+)?")  # `config/secrets.yml:12` は根拠
QUOTED = re.compile(r"([\"'`])([^\"'`\n]{6,})\1(?!\s*:)")  # 値のみ - JSON/YAML のキー名は見えたまま残す
LONG_TOKEN = re.compile(r"(?<![A-Za-z0-9/+_\-])([A-Za-z0-9+/_\-]{32,}={0,2})(?![A-Za-z0-9/+_\-])")
EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
PHONE = re.compile(r"(?<![\w-])(\+?\d{1,3}[ .-])?(\(?\d{2,4}\)?[ .-])\d{3,4}[ .-]\d{3,4}(?![\w-])")
PII_NAME = re.compile(
    r"(?i)((?:full_?name|first_?name|last_?name|family_?name|given_?name|kana\w*|furigana|dob|birth\w*|"
    r"address|addr|street|e_?mail|phone|tel|mobile|cccd|cmnd|my_?number|mynumber|passport|national_?id|ssn|"
    r"zip(?:code)?|postal\w*|ho_?ten|so_?dien_?thoai|dia_?chi|ngay_?sinh)[\w.-]*[\"']?\s*(?:[:=]|=>)\s*)"
    r"([\"'`])([^\"'`]{2,})([\"'`])")
# 引用符なしの個人データ（YAML / .properties / dotenv / フローマップ）：`- dob: 1985-03-12`, `name_kana: ヤマダ タロウ`
PII_KEY = (r"(?:[\w.-]*[_.-])?(?:full_?name|first_?name|last_?name|family_?name|given_?name|name_?kana|kana_?name|kana|"
           r"furigana|dob|birth_?(?:day|date)|birthday|date_?of_?birth|(?:street_?|home_?|postal_?|mailing_?)?address"
           r"(?:_?line_?\d?)?|addr|e_?mail(?:_?address)?|phone(?:_?(?:no|number))?|tel(?:ephone)?(?:_?no)?|"
           r"mobile(?:_?(?:no|number|phone))?|cccd|cmnd|my_?number|mynumber|passport(?:_?(?:no|number))?|"
           r"national_?id|ssn|zip_?code|zip|postal_?code|postcode|ho_?ten|so_?dien_?thoai|dia_?chi|ngay_?sinh|"
           r"seinengappi|jusho|shimei)")
PII_UNQUOTED = re.compile(r"(?i)(?:^|(?<=[\s,;{(]))(" + PII_KEY + r"[\"']?\s*(?:=|:)\s*)(?![\"'`$({\[<%=>|]|\s*$)"
                          r"(\S.*?)(?=\s*[,;]\s*[\w\"'.?-]+\s*[:=]|\s*[,;}]*\s*$)")
NOT_PERSONAL = re.compile(r"(?i)^(?:[\w.-]*[_.-])?(?:ip|mac|server|host|bind|listen|remote|local|wallet|contract|"
                          r"proxy|smtp|base|redirect|callback|node|peer|gateway|web|api|rpc|https?|tcp|udp|socket|"
                          r"memory|ether|eth|ipv4|ipv6)[_.-]?(?:address|addr)")
# それ単体で個人データとなる値の形（CSV の行）：番地付きの日本の住所、
# カタカナの姓 + 名だけから成る CSV フィールド
JP_ADDRESS = re.compile(r"(?:北海道|東京都|(?:大阪|京都)府|[一-龥]{2,3}県)[一-龥ぁ-んァ-ヶー]{0,20}?[0-9０-９]+"
                        r"(?:[-－ー‐の丁目番地号]+[0-9０-９]+)*(?:丁目|番地?|号)?")
KANA_FIELD = re.compile(r"(?:^|(?<=[,\t]))\s*[ァ-ヶー]{2,}[ 　][ァ-ヶー]{2,}\s*(?=[,\t]|$)")
PERSON = re.compile(r"(?i)(\b(?:user_?)?name[\"']?\s*(?:[:=]|=>)\s*)([\"'`])([^\"'`\n]*?\s[^\"'`\n]*?|[^\x00-\x7f\"'`\n]+)([\"'`])")
CARDLIKE = re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)")
DIGITS = re.compile(r"\d{9,}")


def host_path(p: str) -> str:
    if os.name == "nt":
        m = re.match(r"^/([a-zA-Z])(/.*)?$", p or "")
        if m:
            return f"{m.group(1).upper()}:{m.group(2) or '/'}"
    return p


def _keep_value(m: re.Match, v: str) -> bool:
    """シークレット / 個人データのキーに続く引用符なしの値が、コード、型、パス、プレースホルダー
    （値ではなく根拠）であるとき True。行の途中にある裸の識別子（`password=password`、
    `{email: user.email}`）は変数であり、行頭（dotenv / YAML）では値である。"""
    key = m.group(1).rstrip()
    v = re.sub(r"\s+(?:#|//).*$", "", v)  # 行末コメント
    core = v.rstrip(",;:)}]!")
    if not core or SAFE_VALUE.fullmatch(core) or re.search(r"[()\[\]{}\"]", v) or "REDACTED" in v:
        return True  # 式、呼び出し、f 文字列、書式指定
    if re.fullmatch(r"(?:[A-Z][a-z0-9]+){2,}|[A-Z]\w*!", core + ("!" if v.endswith("!") else "")):
        return True  # 型名（`EmailStr`、GraphQL の `String!`）
    if key.endswith(":") and re.fullmatch(r"\d+(?:-\d+)?[`'\")\],;:]*", v) and re.search(r"\.[A-Za-z]\w{0,5}\s*:$", key):
        return True  # path:line（`config/secrets.yml:12`）
    if re.search(r"(?i)(?:file|path|dir)[\"']?\s*[:=]$", key) or re.match(r"(?:\.{1,2}/|~/|/[\w.-]+/|[A-Za-z]:[\\/])", core):
        return True  # シークレットそのものではなく、ファイルパス
    if (v.endswith(";") or m.string[m.end():].lstrip().startswith(";")) and re.fullmatch(r"[A-Z][A-Za-z]*", core):
        return True  # 型注釈（`address: Address;`）
    if re.fullmatch(r"[A-Za-z_$][A-Za-z_$]*(?:\.[A-Za-z_$][A-Za-z_$]*)+", core):
        return True  # 属性パス（`process.env.DB_PASS`、`settings.SECRET_KEY`）
    midline = m.string[:m.start()].strip() not in ("", "-")
    return midline and bool(re.fullmatch(r"[A-Za-z_$][\w$]*(?:\.[\w$]+)*", core)) and not re.search(r"\d", core.split(".")[0])


def _cli(m: re.Match) -> str:
    v = m.group(2)
    if v.lower() in CLI_STOP or "REDACTED" in v or v.startswith("["):
        return m.group(0)
    return f"{m.group(1)}[REDACTED len={len(v)}]"


def redact(line: str, in_key: bool) -> tuple[str, bool]:
    if in_key:
        if "-----END" in line:
            return "[...END PRIVATE KEY]", False
        return "[key material redacted]", True
    if PATTERNS[0][0].search(line):
        return "[PRIVATE KEY BLOCK - REDACTED]", "-----END" not in line
    for rx, rep in PATTERNS[1:]:
        line = rx.sub(rep, line)
    line = SECRET_NAME.sub(lambda m: f"{m.group(1)}{m.group(2)}[REDACTED len={len(m.group(3))}]{m.group(4)}", line)
    for rx in (CLI_SECRET, MYSQL_P, USERPASS):
        line = rx.sub(_cli, line)
    line = UNQUOTED_KV.sub(lambda m: m.group(0) if _keep_value(m, m.group(2))
                           else f"{m.group(1)}[REDACTED len={len(m.group(2))}]", line)
    if SECRETISH_LINE.search(line):  # シークレット名を含む行：引用符付きリテラルは一切残さない
        line = QUOTED.sub(lambda m: f"{m.group(1)}[REDACTED len={len(m.group(2))}]{m.group(1)}"
                          if "REDACTED" not in m.group(2) and not PATH_LINE.fullmatch(m.group(2)) else m.group(0), line)
    line = PII_NAME.sub(lambda m: f"{m.group(1)}{m.group(2)}[PII len={len(m.group(3))}]{m.group(4)}", line)
    line = PERSON.sub(lambda m: f"{m.group(1)}{m.group(2)}[PII len={len(m.group(3))}]{m.group(4)}", line)
    line = PII_UNQUOTED.sub(lambda m: m.group(0) if NOT_PERSONAL.match(m.group(1)) or _keep_value(m, m.group(2))
                            else f"{m.group(1)}[PII len={len(m.group(2))}]", line)
    line = JP_ADDRESS.sub("[ADDRESS]", line)
    line = KANA_FIELD.sub(lambda m: "[PII len=%d]" % len(m.group(0).strip()), line)
    line = EMAIL.sub("[EMAIL]", line)
    line = PHONE.sub("[PHONE]", line)
    line = CARDLIKE.sub("[NUMBER-REDACTED]", line)
    line = DIGITS.sub("[DIGITS]", line)
    line = LONG_TOKEN.sub(lambda m: "[TOKEN len=%d]" % len(m.group(1))
                          if not re.fullmatch(r"[a-z_./-]+", m.group(1)) else m.group(1), line)
    return line, False


SECRET_BLOCK = re.compile(r'(?i)^\s*(variable|output|locals?|resource|data)\s+"[^"]*(pass|secret|token|key|cred|pwd)[^"]*"')


def redact_lines(lines):
    """ブロックの文脈を考慮してマスクする：例えば `variable "db_password" {` の内側では、引用符付きリテラルを
    すべてマスクする（Terraform/HCL の default は、その行自体にシークレットらしき名前を持たない）。"""
    in_key, block, depth, scalar = False, False, 0, None
    for ln in lines:
        if scalar is not None:  # シークレットらしきキー配下の YAML ブロックスカラー：インデントされた本体をマスクする
            ind = len(ln) - len(ln.lstrip())
            if not ln.strip() or ind > scalar:
                yield ln[:ind] + f"[REDACTED len={len(ln.strip())}]" if ln.strip() else ln
                continue
            scalar = None
        out, in_key = redact(ln, in_key)
        if BLOCK_SCALAR.search(ln) and SECRETISH_LINE.search(ln.split(":")[0]):
            scalar = len(ln) - len(ln.lstrip())
        if SECRET_BLOCK.search(ln):
            block, depth = True, 0
        if SECRET_BLOCK.search(ln):
            out = ln  # ブロックのヘッダー（変数名）は読める状態に保つ
        elif block and VALUE_LINE.search(ln):
            out = QUOTED_ANY.sub(lambda m: f"{m.group(1)}[REDACTED len={len(m.group(2))}]{m.group(1)}"
                                 if "REDACTED" not in m.group(2) else m.group(0), out)
            depth += ln.count("{") - ln.count("}")
            if depth <= 0 and "}" in ln:
                block = False
        yield out


BLOCK_SCALAR = re.compile(r"^\s*(?:-\s+)?[\w.\-\"']+\s*:\s*[|>][-+0-9]*\s*(?:#.*)?$")
VALUE_LINE = re.compile(r"(?i)^\s*(default|value|sensitive_value|content|password|secret)\s*=")
QUOTED_ANY = re.compile(r"([\"'])([^\"'\n]{3,})\1")


def redact_text(text: str) -> str:
    """文書全体をマスクする（sensitive_sweep、normalize_findings、validate_findings が使用）。"""
    return "\n".join(redact_lines(text.splitlines()))


def find_secrets(text: str) -> list[str]:
    """テキスト中に残っているシークレットらしき値のラベル（納品前ゲート用）。"""
    hits = []
    names = ["private-key", "aws-key-id", "api-key", "token", "stripe-key", "github-token", "slack-token",
             "gcp-api-key", "jwt", "url-credentials"]
    for (rx, _), name in zip(PATTERNS, names):
        if rx.search(text):
            hits.append(name)
    for m in SECRET_NAME.finditer(text):
        v = m.group(3)
        if "REDACTED" in v or len(v) < 8:
            continue
        if re.fullmatch(r"[\w.\-]*\{\{.*|\$\{?[\w.]+\}?|<[^>]+>|x+|\*+|\.{3}|[a-z][a-z _-]*", v):
            continue  # プレースホルダー、環境変数参照、小文字だけの普通の単語（"required"、"read only"）
        hits.append(f"secret-assignment ({m.group(1).strip()[:30]})")
    # 引用符なしと CLI の形：redact() がマスクするのと同じパターンだが、本物のシークレットらしい値に限る
    for rx, name in ((CLI_SECRET, "cli-secret"), (MYSQL_P, "cli-password"), (USERPASS, "cli-user-password"),
                     (UNQUOTED_KV, "secret-assignment")):
        for m in rx.finditer(text):
            v = m.group(2).strip("`'\".,;)}")
            if rx is UNQUOTED_KV and _keep_value(m, m.group(2)):
                continue
            if "REDACTED" in v or v.startswith(("[", "<", "$", "{")) or "/" in v or v.lower() in CLI_STOP:
                continue
            pin = re.search(r"(?i)pin\b", m.group(1)) and re.fullmatch(r"\d{4,}", v)
            if pin or (len(v) >= 8 and re.search(r"\d", v) and re.search(r"[A-Za-z]", v)):
                hits.append(f"{name} ({m.group(1).strip()[:30]})")
    for m in PII_UNQUOTED.finditer(text):
        v = m.group(2).strip()
        if NOT_PERSONAL.match(m.group(1)) or _keep_value(m, m.group(2)) or "PII" in v:
            continue
        if (re.search(r"(?i)dob|birth|ngay_?sinh|seinengappi", m.group(1)) and re.search(r"\d{4}[-/.]\d{1,2}[-/.]\d{1,2}", v)) \
                or re.fullmatch(r"[ァ-ヶー]{2,}[ 　]?[ァ-ヶー]{2,}", v):
            hits.append(f"personal-data ({m.group(1).strip()[:30]})")
    if JP_ADDRESS.search(text):
        hits.append("personal-data (address)")
    return sorted(set(hits))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("file")
    ap.add_argument("line", nargs="?", type=int)
    ap.add_argument("--context", type=int, default=8)
    ap.add_argument("--range")
    a = ap.parse_args()
    p = Path(host_path(a.file))
    if p.is_symlink():  # コミットされたリンクはホストのシークレット（~/.aws/credentials）を指しうる：リポジトリ内に留まる
        top = next((d for d in p.absolute().parents if (d / ".git").exists()), p.absolute().parent)
        if top.resolve() not in p.resolve().parents:
            print(f"error: {a.file} はリポジトリ外を指すシンボリックリンクのため読まない", file=sys.stderr)
            return 2
    try:
        lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    if a.range:
        lo, hi = (int(x) for x in a.range.split("-"))
    elif a.line:
        lo, hi = max(1, a.line - a.context), a.line + a.context
    else:
        lo, hi = 1, min(len(lines), 200)
    red = list(redact_lines(lines[:min(hi, len(lines))]))
    for i in range(1, len(red) + 1):
        text = red[i - 1]
        if i >= lo:
            print(f"{i:5d}{'>' if i == a.line else ' '} {text}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
