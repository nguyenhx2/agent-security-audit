#!/usr/bin/env python3
"""
リポジトリダイジェスト（Phase 1）- すべてのレーンが最初に読む共有マップ。N 個のサブエージェントが
それぞれ Glob/Grep で同じリポジトリを調べ直さずに済むようにする。

1 つのリポジトリについて次を書き出す:
  1. インベントリ：最上位フォルダごとにまとめたソースファイルと行数（vendor / build / テスト
     フィクスチャは件数の要約のみで、一覧にはしない）。
  2. シンク / ソースの索引：セキュリティ上重要な分類ごとの `path:line` + 一致したトークン
     （シェル実行、コードの eval / デシリアライズ、SQL の組み立て、HTML 出力、外向き HTTP、ファイル
     パス、ルート / ハンドラ、認証ヘルパー、暗号、LLM / エージェント呼び出し、エージェントの権限、CI）。
  3. シークレットを含むファイル（名前のみ - 中身は peek.py で見る。Read / cat は決して使わない）。

位置とトークンのみを出力し、行の内容は決して出さないため、シークレットの値がダイジェストに入ることはない。

使い方:
  python repo_digest.py <repo> --out <audit_dir>/<repo>/digest.md [--json <audit_dir>/<repo>/digest.json]
                        [--per-class 30] [--max-files 20000]
--json は他のスクリプト（lane_pack.py）向けに完全な索引も書き出す：{"classes": {class: [{path, line,
label}]}, "secret_files": [...], "inventory": {folder: [[path, lines]]}} - ラベルは同じくマスク済みで、行の本文は含まない。
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
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from peek import redact as _redact  # noqa: E402
import safegit  # noqa: E402

SKIP_DIRS = {".git", "node_modules", "vendor", "dist", "build", "out", "target", ".next", ".nuxt",
             ".venv", "venv", "__pycache__", "coverage", "Pods", ".gradle", ".terraform", ".dart_tool",
             "bower_components", ".svelte-kit", ".turbo", ".cache", "bin", "obj", ".idea", ".vs"}
CODE_EXT = {".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".go", ".java", ".kt", ".kts", ".rb",
            ".php", ".cs", ".rs", ".swift", ".dart", ".scala", ".ex", ".exs", ".m", ".mm", ".c", ".cc",
            ".cpp", ".h", ".ps1", ".psm1", ".sh", ".bash", ".vue", ".svelte", ".erb", ".twig", ".cshtml",
            ".html", ".sql", ".tf", ".hcl", ".bicep", ".graphql", ".proto"}
CONF_EXT = {".yml", ".yaml", ".json", ".jsonc", ".toml", ".ini", ".cfg", ".conf", ".properties", ".xml", ".plist",
            ".gradle", ".md", ".mdc"}
CONF_NAMES = {"Dockerfile", "Makefile", "Jenkinsfile", "Procfile", "Gemfile", "Pipfile", "go.mod",
              "package.json", "requirements.txt", "pom.xml", "build.gradle", "SKILL.md", "CLAUDE.md",
              "AGENTS.md", ".gitlab-ci.yml", "docker-compose.yml", "compose.yaml"}
TESTISH = re.compile(r"(^|/)(tests?|spec|__tests__|fixtures?|testdata|examples?|samples?|mocks?)(/|$)", re.I)
SECRET_FILE = re.compile(r"(^|/)(\.env[^/]*|.*\.tfvars|.*secrets?[^/]*\.(ya?ml|json)|appsettings[^/]*\.json|"
                         r"application[^/]*\.(ya?ml|properties)|config\.(json|ya?ml|js|ts|py)|settings\.py|"
                         r"credentials[^/]*|.*\.pem|.*\.p12|.*\.keystore|.*seed[^/]*|.*fixtures?/[^/]+|"
                         r"prompt[_-]?history[^/]*|[^/]*transcripts?[^/]*|\.specstory/.+|settings\.local\.json|"
                         r"\.mcp\.json|mcp\.json)$", re.I)

# 分類 -> コード行に対する正規表現。トークンは短く具体的に保つ。コードそのものはレーンが読む。
# 出力するのは短いラベル（一致部分の最初の語をマスクしたもの）のみで、一致したテキストは決して出さない。
CLASSES = {
    "shell-exec": r"\b(subprocess\.\w+|os\.system|os\.popen|shell\s*=\s*True|child_process|execSync|spawnSync|"
                  r"Runtime\.getRuntime\(\)\.exec|ProcessBuilder|Process\.Start|Invoke-Expression|iex\b|"
                  r"Start-Process|powershell(\.exe)?\b|-Command\b|exec\.Command|system\(|popen\(|`[^`]*\$\(|"
                  r"Kernel\.(system|exec|spawn)|%x\{|Open3\.|shell_exec|passthru|proc_open)",
    "code-eval-deserialise": r"\b(eval\(|exec\(|new Function\(|pickle\.loads?|yaml\.load\(|marshal\.loads|"
                             r"ObjectInputStream|BinaryFormatter|unserialize\(|Marshal\.load|vm\.run|"
                             r"importlib\.import_module|__import__\(|setTimeout\(\s*['\"]|instance_eval|class_eval|"
                             r"constantize|send\(params|torch\.load|joblib\.load)",
    "sql-build": r"(\.(execute|executemany|raw|query|exec|Query|QueryRow|Exec)\(\s*(f['\"]|['\"`][^'\"`]*['\"`]\s*(\+|%|\.format))|"
                 r"\b(SELECT|INSERT|UPDATE|DELETE)\b[^'\"\n]*['\"]\s*\+|sequelize\.query|knex\.raw|\$queryRawUnsafe|"
                 r"Sprintf\(\s*[\"`](SELECT|INSERT|UPDATE|DELETE)|\.(where|order|group|having|joins|select|pluck|exists\?)\(\s*(\x22[^\x22\n]*#\{|'[^'\n]*#\{)|find_by_sql|"
                 r"\.order\(\s*params|\.(execute|cursor\(\)\.execute)\(\s*$|text\(\s*f['\"]|"
                 r"createQuery\(\s*\"[^\"]*\"\s*\+|\$wpdb->query|mysqli_query)",
    "html-output": r"(innerHTML|outerHTML|dangerouslySetInnerHTML|v-html|\|\s*safe\b|mark_safe|Markup\(|"
                   r"html_safe|\braw\(|document\.write|insertAdjacentHTML|Content-Security-Policy|"
                   r"render_template_string|template\.HTML\(|<%==|\{\{\{|@Html\.Raw|autoescape\s*=\s*False)",
    "outbound-http": r"\b(requests\.(get|post|put|request)|urllib\.request|urlopen|httpx\.|aiohttp\.ClientSession|"
                     r"(?<![.\w])fetch\(|axios|http\.Get|http\.Post|HttpClient|RestTemplate|WebClient|Net::HTTP|open-uri|"
                     r"Faraday|HTTParty|curl_exec|file_get_contents\(\s*\$|Invoke-WebRequest|Invoke-RestMethod)",
    "file-path": r"\b(open\(|os\.path\.join|send_file|sendFile|readFile|writeFile|shutil\.(copy|move|rmtree)|"
                 r"zipfile|tarfile|extractall|File\.(Read|Write|Open)|os\.remove|unlink|send_data|File\.open|"
                 r"ioutil\.ReadFile|os\.Open|filepath\.Join|include\s*\(?\s*\$|require\s*\(?\s*\$)",
    "route-handler": r"(?i)(@(app|router|bp|api|blueprint)\.(route|get|post|put|delete|patch|websocket)|"
                     r"@(get|post|put|delete|request|patch)mapping|\b(router|app|r|e|g|mux|api)\.(get|post|put|delete|patch|use|"
                     r"handle|handlefunc|any|group)\(|handlefunc\(|\[http(get|post|put|delete)\]|"
                     r"add_(route|get|post|put|delete)\(|^\s*(get|post|put|patch|delete|resources?|namespace|match|root)\s+['\":]|"
                     r"route::(get|post|put|delete|any|resource)|\$_(get|post|request|cookie)\b|"
                     r"argparse\.argumentparser|@click\.command|webhook|st\.(text_input|chat_input|file_uploader)|gr\.interface)",
    "auth-helper": r"(?i)\b(def|function|func|public|private|protected)\s+\w*(auth|verify|validate|authori[sz]e|permission|"
                   r"is_admin|check_access|csrf|token|session|login|role|current_user)\w*|before_action|"
                   r"@login_required|@requires_auth|Depends\(\w*(auth|user|token)|@PreAuthorize|\[Authorize",
    "crypto-random": r"\b(md5|sha1\b|hashlib\.(md5|sha1)|DES\b|ECB|Math\.random|random\.(random|randint|choice)|"
                     r"jwt\.(decode|encode)|verify\s*=\s*False|rejectUnauthorized\s*:\s*false|InsecureSkipVerify|"
                     r"algorithms\s*=\s*\[\s*['\"]none|SecureRandom|rand\(\))",
    "llm-agent": r"\b(openai|anthropic|messages\.create|chat\.completions|ChatCompletion|tool_use|function_call|"
                 r"langchain|llama_index|McpServer|FastMCP|@tool\b|Tool\(|StructuredTool|bind_tools|PromptTemplate|"
                 r"SystemMessage|system_prompt|allow_dangerous_|dangerouslyAllowBrowser|trust_remote_code|"
                 r"AgentExecutor|initialize_agent|create_react_agent|from_pretrained|embeddings?\.)",
    "agent-permissions": r"(\"allow\"|\"deny\"|\"ask\"|defaultMode|PreToolUse|PostToolUse|SessionStart|UserPromptSubmit|"
                         r"allowed-tools|^tools:|permissionMode|Bash\(|disallowedTools|bypassPermissions|mcpServers|"
                         r"apiKeyHelper|statusLine|_BASE_URL|^\s*!`)",
    "ci-release": r"\b(image:|uses:|CI_JOB_TOKEN|GITHUB_TOKEN|secrets\.|release-cli|git (push|tag|add -A)|"
                  r"pull_request_target|workflow_run|issue_comment)|curl [^|\n]*\| *(ba)?sh",
}
CLASS_RX = {k: re.compile(v, re.M) for k, v in CLASSES.items()}
# agent-permissions / ci-release は設定ファイル類でのみ意味を持つ
CONFIG_ONLY = {"agent-permissions", "ci-release"}
INDEXED_LANGS = {".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".go", ".java", ".kt", ".rb", ".php",
                 ".cs", ".ps1", ".sh", ".erb", ".tf", ".yml", ".yaml", ".json"}
VENDOR = re.compile(r"(\.min\.|[-.]bundle\.js$|(^|/)(static|public|assets|wwwroot|web)/(vendor|lib|libs|js/lib|plugins|"
                    r"javascripts/(lib|vendor))/|(^|/)(jquery|bootstrap|lodash|moment|d3|angular|react|vue)[\w.-]*\.js$)", re.I)
AGENT_MD = re.compile(r"^(\.claude/|\.cursor/|\.github/(prompts|instructions|chatmodes)/|\.windsurf/)|"
                      r"(^|/)(SKILL|CLAUDE|AGENTS|GEMINI)\.md$|\.mdc$", re.I)


def label(match: str) -> str:
    """ヒットを表す短く安全なトークン：一致部分の最初の語をマスクしたもの、最大 24 文字。"""
    w = re.match(r"[\w.@$<>|:/{}%!`#\[\]()-]{1,40}", match.strip())
    tok = (w.group(0) if w else match.strip()[:24])
    tok = _redact(tok, False)[0]
    return tok[:24] if not re.search(r"[A-Za-z0-9+/_\-]{20,}", tok) else tok[:6] + "..."


def host_path(p: str) -> str:
    m = re.match(r"^/([a-zA-Z])/(.*)$", p) if os.name == "nt" else None
    return f"{m.group(1).upper()}:/{m.group(2)}" if m else p


def list_files(root: Path, max_files: int) -> list[str]:
    out = safegit.out(root, "ls-files", "-z", timeout=60)  # 読み取り専用の git：fsmonitor なし、index への書き込みなし
    if out:
        files = [f for f in out.split("\0") if f]
        files = [f for f in files if not any(part in SKIP_DIRS for part in f.split("/")[:-1])]
        return files[:max_files]
    files = []
    for dp, dns, fns in os.walk(root):
        dns[:] = [d for d in dns if d not in SKIP_DIRS]
        for fn in fns:
            files.append(Path(dp, fn).relative_to(root).as_posix())
            if len(files) >= max_files:
                return files
    return files


def kind_of(rel: str) -> str | None:
    name = rel.rsplit("/", 1)[-1]
    ext = os.path.splitext(name)[1].lower()
    if ext in CODE_EXT:
        return "code"
    if ext in CONF_EXT or name in CONF_NAMES or name.startswith("Dockerfile") or rel.startswith(".github/"):
        return "config"
    return None


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("repo")
    ap.add_argument("--out", required=True)
    ap.add_argument("--per-class", type=int, default=30, help="分類ごとに列挙する位置の最大数")
    ap.add_argument("--max-files", type=int, default=20000)
    ap.add_argument("--json", help="シンク / ソースの完全な索引を JSON でも書き出す（lane_pack.py 用）")
    a = ap.parse_args()
    root = Path(host_path(a.repo)).resolve()
    if not root.is_dir():
        print(f"error: ディレクトリではない: {a.repo}", file=sys.stderr)
        return 2

    files = list_files(root, a.max_files)
    folders: dict[str, list[tuple[str, int]]] = defaultdict(list)
    testish: dict[str, int] = defaultdict(int)
    secret_files, hits = [], defaultdict(list)
    vendored, unindexed, links_out = 0, defaultdict(int), []
    total_lines = 0
    for rel in sorted(files):
        k = kind_of(rel)
        if SECRET_FILE.search(rel):
            secret_files.append(rel)
        if not k:
            continue
        p = root / rel
        if safegit.escapes(root, p):
            links_out.append(rel)  # ~/.aws/credentials などへのシンボリックリンク：ホストのファイルは決して読まない
            continue
        try:
            if p.stat().st_size > 1_000_000:
                continue
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        lines = text.splitlines()
        total_lines += len(lines)
        top = rel.split("/", 1)[0] if "/" in rel else "."
        if TESTISH.search(rel):
            testish[top] += 1
            continue  # フィクスチャとテスト：件数のみ数え、索引には載せない（レーンが意図して開く）
        folders[top].append((rel, len(lines)))
        if VENDOR.search(rel):
            vendored += 1
            continue  # minify 済み / 同梱（vendored）のアセット：インベントリのみ
        ext = os.path.splitext(rel)[1].lower()
        md = ext in (".md", ".mdc")
        if md and not AGENT_MD.search(rel):
            continue  # 通常のドキュメント
        if not md and k == "code" and ext not in INDEXED_LANGS:
            unindexed[ext] += 1
        for i, line in enumerate(lines, 1):
            if len(line) > 600:
                line = line[:600]
            for cls, rx in CLASS_RX.items():
                if md and cls != "agent-permissions":
                    continue  # エージェントの指示ファイル：フロントマターのキーと `!` コマンドのみ
                if cls in CONFIG_ONLY and k != "config" and not rel.endswith((".ps1", ".sh")):
                    continue
                m = rx.search(line)
                if m:
                    hits[cls].append((rel, i, label(m.group(0))))

    out = [f"# Repo digest - {root.name}",
           "",
           f"{sum(len(v) for v in folders.values())} indexed files, {total_lines} lines; "
           f"tests/fixtures counted not indexed: {sum(testish.values())}. "
           f"vendored/minified (inventory only): {vendored}. "
           "Locations + a short redacted label only (no line contents). A starting index, NOT coverage: "
           "a class marked `none` still needs one targeted Grep for your lane's sinks.",
           "",
           ("Code types without index patterns (Grep them yourself): "
            + ", ".join(f"`{e}` {n}" for e, n in sorted(unindexed.items())) if unindexed else ""),
           (f"Symlinks resolving outside the repo (not read): {len(links_out)}: "
            + ", ".join(f"`{f}`" for f in links_out[:20]) if links_out else ""),
           "## Inventory (folder: file (lines))"]
    for top in sorted(folders):
        items = sorted(folders[top])
        shown = ", ".join(f"{r.split('/', 1)[-1] if top != '.' else r} ({n})" for r, n in items[:40])
        more = f", ... +{len(items) - 40} more" if len(items) > 40 else ""
        out.append(f"- `{top}/` {len(items)} files: {shown}{more}")
    if testish:
        out.append("- tests / fixtures (not indexed): " + ", ".join(f"`{t}/` {n}" for t, n in sorted(testish.items())))
    out += ["", "## Sink / source index (class: `path:line` token)"]
    for cls in CLASSES:
        rows = hits.get(cls, [])
        if not rows:
            out.append(f"- **{cls}**: none")
            continue
        by_file: dict[str, list[tuple[int, str]]] = defaultdict(list)
        for r, n, t in rows:
            by_file[r].append((n, t))
        parts = []
        for r, items in list(by_file.items())[: a.per_class]:
            lines_ = ",".join(str(n) for n, _ in items[:12]) + (f",+{len(items) - 12}" if len(items) > 12 else "")
            toks = sorted({t for _, t in items})[:3]
            parts.append(f"`{r}`:{lines_} ({', '.join(toks)})")
        more = f"; ... +{len(by_file) - a.per_class} more files" if len(by_file) > a.per_class else ""
        out.append(f"- **{cls}** ({len(rows)} in {len(by_file)} files): " + "; ".join(parts) + more)
    out += ["", "## Secret-bearing files (names only - view with peek.py, never Read/cat)"]
    out.append(", ".join(f"`{f}`" for f in secret_files[:80]) or "none matched")
    Path(host_path(a.out)).parent.mkdir(parents=True, exist_ok=True)
    Path(host_path(a.out)).write_text("\n".join(out) + "\n", encoding="utf-8")
    if a.json:
        doc = {"repo": root.name,
               "classes": {c: [{"path": r, "line": n, "label": t} for r, n, t in hits.get(c, [])[:5000]] for c in CLASSES},
               "secret_files": secret_files, "symlinks_outside": links_out,
               "inventory": {top: sorted(v) for top, v in sorted(folders.items())}}
        Path(host_path(a.json)).parent.mkdir(parents=True, exist_ok=True)
        Path(host_path(a.json)).write_text(json.dumps(doc, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"{a.out} を書き出した - ファイル {sum(len(v) for v in folders.values())} 件、"
          f"索引エントリ {sum(len(v) for v in hits.values())} 件")
    return 0


if __name__ == "__main__":
    sys.exit(main())
