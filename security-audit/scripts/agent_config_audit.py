#!/usr/bin/env python3
"""
AI inventory of a repo (Phase 1) - deterministic input for the ai-agentic lane and the report's
"AI and agent inventory" table. Run it on every repo: an empty result is the negative record.

Covers two scopes (reference/standards/ai-llm-agentic.md):
  agent tooling   Claude Code / Codex / Cursor / Copilot / Gemini / VS Code / devcontainer config:
                  permission rules and mode, hooks, helper commands that run shell (statusLine,
                  apiKeyHelper ...), env redirects (*_BASE_URL, proxies, TLS off), sandbox, plugins and
                  marketplaces, MCP servers (launch pinning, inline secrets, remote auth), subagents
                  (tools, permissionMode, memory), skills / commands (allowed-tools, `!` dynamic
                  commands, scripts, vendored), instruction files (remote includes, bypass wording),
                  CI agent actions and their triggers, dangerous CLI flags, prompt / transcript logs
                  (working tree AND git history), hidden Unicode (zero-width, bidi, tag characters).
  LLM app code    model / provider calls, dangerous framework switches (allow_dangerous_*,
                  trust_remote_code, PythonREPLTool, torch.load without weights_only, jinja2 prompt
                  templates, dangerouslyAllowBrowser), tracing / debug that ships prompts, public UI
                  or model servers (Gradio share, Ollama on 0.0.0.0).

Never prints values: env values, header values, tokens and hook commands are masked (peek.py).
Each row carries `risk` labels the lane must confirm or refute by reading the file.

Usage:
  python agent_config_audit.py <repo> --out <audit_dir>/<repo>/agent-config.md
  (also writes agent-config.json beside it; build_report reads the JSON)
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
from peek import redact as _redact  # noqa: E402
import safegit  # noqa: E402

try:
    import tomllib  # py3.11+
except ImportError:  # pragma: no cover
    tomllib = None

SKIP = {".git", "node_modules", "vendor", "dist", "build", ".venv", "venv", "__pycache__", "target",
        ".next", ".terraform", "coverage", ".cache"}
TEXT_EXT = {".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".go", ".java", ".kt", ".rb", ".php",
            ".cs", ".rs", ".sh", ".bash", ".ps1", ".psm1", ".md", ".mdc", ".json", ".jsonc", ".yml",
            ".yaml", ".toml", ".txt", ".cfg", ".ini", ".env", ".ipynb", ".swift", ".dart", ".vue", ".svelte"}
BROAD_ALLOW = re.compile(r"^(Bash|PowerShell)(\((\*|[^)]*:\*|[^)]* \*)\))?$")
RISKY_VERB = re.compile(r"\b(push|merge|approve|publish|deploy|release|apply|delete|rm\s+-rf|curl|wget|"
                        r"Invoke-WebRequest|iwr|scp|ssh|npm\s+publish|twine|docker\s+push|kubectl|terraform|"
                        r"aws|gcloud|az|gh\s+pr|glab\s+mr|git\s+tag|git\s+commit|git\s+add)\b", re.I)
EXEC_KEYS = ("apiKeyHelper", "awsAuthRefresh", "awsCredentialExport", "otelHeadersHelper")
ENV_RISK = re.compile(r"(_BASE_URL|_API_BASE|HTTPS?_PROXY|NODE_OPTIONS|NODE_TLS_REJECT_UNAUTHORIZED|"
                      r"PYTHONHTTPSVERIFY|REQUESTS_CA_BUNDLE|SSL_CERT|CLAUDE_CODE_USE_|DISABLE_)", re.I)
SECRETISH = re.compile(r"(?i)(key|token|secret|pass|auth|cred|bearer)")
DANGER_FLAGS = re.compile(r"(--dangerously-skip-permissions|--permission-mode[ =]bypassPermissions|"
                          r"bypassPermissions|--yolo\b|--full-auto|danger-full-access|approval_policy\s*=\s*\"never\"|"
                          r"--trust-all-tools|--yes-always|yes-always:\s*true|autoAccept\"?\s*:\s*true|"
                          r"--allow-all-tools|chat\.tools\.autoApprove\"?\s*:\s*true)")
LLM_SWITCH = re.compile(r"(allow_dangerous_(code|requests|deserialization)\s*=\s*True|trust_remote_code\s*=\s*True|"
                        r"PythonREPLTool|PythonAstREPLTool|LLMMathChain|PALChain|create_sql_agent|SQLDatabaseChain|"
                        r"load_tools\([^)]*terminal|PandasQueryEngine|dangerouslyAllowBrowser\s*:\s*true|"
                        r"template_format\s*=\s*[\"']jinja2|torch\.load\((?![^)]*weights_only\s*=\s*True)|"
                        r"langchain\.load\.loads?\(|set_debug\(True\)|share\s*=\s*True|"
                        r"0\.0\.0\.0:11434|OLLAMA_HOST\s*=\s*0\.0\.0\.0|LANGCHAIN_TRACING_V2|LANGSMITH_|LANGFUSE_|"
                        r"HELICONE|NEXT_PUBLIC_\w*(OPENAI|ANTHROPIC|GEMINI|API)_?KEY|VITE_\w*(OPENAI|ANTHROPIC|API)_?KEY)")
LLM_CALL = re.compile(r"(chat\.completions\.create|messages\.create|generateContent|generate_content|"
                      r"ChatOpenAI|ChatAnthropic|ChatBedrock|AzureOpenAI|Anthropic\(|OpenAI\(|streamText|generateText|"
                      r"\b(llm|chain|agent|model|graph|chat)\w*\.(a?invoke|stream)\(|create_react_agent|AgentExecutor|initialize_agent|@tool\b|StructuredTool|bind_tools|"
                      r"FastMCP|McpServer|@mcp\.tool|server\.tool\(|"
                      r"OpenAIApi\(|\.createChatCompletion\(|\.createCompletion\(|function_call\s*:\s*[\"'{])")
# direct LLM / agent SDK dependencies, so the inventory never says "none" when one is declared
LLM_DEP_NPM = re.compile(r"\"(openai|@anthropic-ai/sdk|langchain|@langchain/[\w.-]+|ai|@ai-sdk/[\w.-]+|"
                         r"@google/generative-ai|@google/genai|cohere-ai|@mistralai/mistralai|ollama|llamaindex|"
                         r"@modelcontextprotocol/sdk)\"\s*:")
LLM_DEP_PY = re.compile(r"^\s*[\"']?(openai|anthropic|langchain[\w-]*|langgraph|llama[-_]index[\w-]*|"
                        r"google-generativeai|google-genai|cohere|mistralai|ollama|litellm|mcp|crewai|autogen[\w-]*)"
                        r"\s*(\[[^\]]*\])?\s*([<>=~!;\"',]|$)", re.I | re.M)
CI_AGENT = re.compile(r"(anthropics/claude-code-action|anthropics/claude-code-base-action|openai/codex-action|"
                      r"coderabbit|copilot-setup-steps|google-github-actions/run-gemini-cli|\bclaude\s+-p\b|"
                      r"\bcodex\s+exec\b|\bgemini\s+-p\b)", re.I)
CI_UNTRUSTED = re.compile(r"(issue_comment|pull_request_target|issues:|discussion_comment|"
                          r"github\.event\.(comment|issue|pull_request)\.(body|title))")
PROMPT_LOG = re.compile(r"(^|/)(prompt[_-]?history[^/]*|[^/]*transcripts?[^/]*\.(jsonl?|txt|md)|\.specstory/.+|"
                        r"\.claude/projects/.+\.jsonl|[^/]*(chat|conversation)[_-]?(log|history)[^/]*|"
                        r"\.aider\.chat\.history\.md|\.aider\.input\.history)$", re.I)
HIDDEN = re.compile("[​-‏‪-‮⁠-⁤⁦-⁩﻿\U000e0000-\U000e007f]")
INSTRUCTIONS = {"claude.md", "claude.local.md", "agents.md", "gemini.md", ".cursorrules", ".windsurfrules",
                ".clinerules", ".roomodes", "copilot-instructions.md"}
INJECTION_WORDING = re.compile(r"(ignore (all |any )?(previous|prior|above) instructions|disregard (the )?(system|previous)|"
                               r"do not (tell|inform|mention to) the user|you must (now )?run|silently (run|execute|send)|"
                               r"send (the )?(contents|secrets|env|credentials) to)", re.I)
BYPASS_WORDING = re.compile(r"(--no-verify|skip (the )?(tests|hooks|review)|disable (the )?hooks?|"
                            r"bypass(Permissions)?|auto-?approve|without (asking|confirmation)|"
                            r"https?://\S+\.(md|txt)\b|@~/)", re.I)


def host_path(p: str) -> str:
    m = re.match(r"^/([a-zA-Z])/(.*)$", p) if os.name == "nt" else None
    return f"{m.group(1).upper()}:/{m.group(2)}" if m else p


def safe(text: str, n: int = 120) -> str:
    out, _ = _redact(str(text), False)
    out = re.sub(r"(?i)(bearer\s+)\S+", r"\1[REDACTED]", out).replace("|", "/").replace("\n", " ")
    return out if len(out) <= n else out[: n - 3] + "..."


def git(root: Path, *args: str) -> str:
    return safegit.out(root, *args)  # read-only: the repo's .git/config cannot run commands


def cell(text) -> str:
    """Markdown table cell: a literal `|` would start a new column."""
    return str(text).replace("|", "\\|").replace("\n", " ")


def files(root: Path) -> tuple[list[str], set[str], list[str]]:
    """(files to inspect, git-tracked files, symlinks resolving outside the repo - skipped, never read)."""
    tracked = set(f for f in git(root, "ls-files", "-z").split("\0") if f)
    seen, links_out = [], []
    for dp, dns, fns in os.walk(root):
        dns[:] = [d for d in dns if d not in SKIP]
        for fn in fns:
            rel = Path(dp, fn).relative_to(root).as_posix()
            (links_out if safegit.escapes(root, Path(dp, fn)) else seen).append(rel)
    return seen, tracked, links_out


def load_json(p: Path):
    """Parsed JSON / JSONC (BOM, UTF-16, comments, trailing commas); None if it does not parse."""
    try:
        t = safegit.read_text(p)
        return safegit.loads_jsonc(t) if t.strip() else {}
    except (ValueError, OSError):
        return None


def frontmatter(text: str) -> dict:
    m = re.match(r"^---\s*\n(.*?)\n---", text, re.S)
    if not m:
        return {}
    out, key = {}, None
    for ln in m.group(1).splitlines():
        km = re.match(r"^([A-Za-z][\w-]*):\s*(.*)$", ln)
        if km:
            key = km.group(1)
            out[key] = km.group(2).strip()
        elif key and ln.startswith((" ", "\t", "-")):
            out[key] = (out[key] + " " + ln.strip()).strip()
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("repo")
    ap.add_argument("--out", required=True, help="markdown path; JSON is written beside it")
    a = ap.parse_args()
    root = Path(host_path(a.repo)).resolve()
    if not root.is_dir():
        print(f"error: not a directory: {a.repo}", file=sys.stderr)
        return 2
    all_files, tracked, links_out = files(root)
    rows: list[dict] = []

    def add(surface, file, item, detail="", risk=()):
        rows.append({"surface": surface, "file": file, "item": item, "detail": detail,
                     "risk": sorted(set(r for r in risk if r)), "tracked": (file in tracked) if tracked else None})

    def jload(p: Path, rel: str, surface: str) -> dict:
        """load_json, but a config that does not parse becomes a row instead of silently vanishing."""
        d = load_json(p)
        if d is None:
            add(surface, rel, "unparseable - review manually", "", ["unparseable - review manually"])
        return d if isinstance(d, dict) else {}

    # ---- settings files (Claude Code, Gemini, VS Code, devcontainer, Codex)
    for rel in all_files:
        low = rel.lower()
        name = low.rsplit("/", 1)[-1]
        p = root / rel
        if low in (".claude/settings.json", ".claude/settings.local.json", ".gemini/settings.json"):
            d = jload(p, rel, "settings")
            perms = d.get("permissions", {}) if isinstance(d.get("permissions"), dict) else {}
            mode = perms.get("defaultMode") or d.get("defaultMode")
            if low.endswith("settings.local.json"):
                add("settings", rel, "local settings file", "personal overrides", ["local-settings-committed" if rel in tracked else ""])
            if mode:
                add("permissions", rel, f"defaultMode={mode}", "", ["bypass-or-auto-mode"] if mode in ("bypassPermissions", "acceptEdits", "auto", "dontAsk") else [])
            for kind in ("allow", "ask", "deny"):
                for rule in perms.get(kind, []) or []:
                    r = str(rule)
                    risk = []
                    if kind == "allow":
                        if BROAD_ALLOW.match(r) or r in ("WebFetch", "Write", "Edit"):
                            risk.append("broad-allow")
                        if re.match(r"^(Read|Edit|Write)\((~|/|[A-Za-z]:|\.\./)", r):
                            risk.append("file access outside the repo")
                        elif RISKY_VERB.search(r):
                            risk.append("write/publish/exfil verb pre-approved")
                    if kind == "deny" and r.startswith("Bash("):
                        risk.append("prefix-deny (test bypasses: git -C, env, sh -c)")
                    add("permissions", rel, f"{kind}: {safe(r, 80)}", "", risk)
            if perms.get("additionalDirectories"):
                add("permissions", rel, "additionalDirectories", safe(", ".join(map(str, perms["additionalDirectories"]))), ["reach-outside-repo"])
            allow_text = " ".join(map(str, perms.get("allow", []) or []))
            deny_text = " ".join(map(str, perms.get("deny", []) or []))
            if re.search(r"WebFetch|curl|wget|mcp__", allow_text) and not re.search(r"\.env|\.ssh|\.aws|secrets", deny_text):
                add("permissions", rel, "egress allowed, secret paths not denied", "", ["trifecta: no Read deny for .env/.ssh/.aws"])
            hooks = d.get("hooks", {}) if isinstance(d.get("hooks"), dict) else {}
            for event, entries in hooks.items():
                for ent in entries or []:
                    for h in (ent.get("hooks", []) if isinstance(ent, dict) else []):
                        cmd = str(h.get("command", ""))
                        risk = []
                        if event in ("SessionStart", "UserPromptSubmit", "Stop", "SubagentStop", "PreCompact") and re.search(r"curl|wget|Invoke-WebRequest|https?://", cmd):
                            risk.append("network call from hook")
                        if re.search(r"\bpowershell\b|\.ps1\b", cmd, re.I):
                            risk.append("needs PowerShell (macOS/Linux?)")
                        elif re.search(r"\.sh\b|\bbash\b", cmd):
                            risk.append("needs bash (Windows?)")
                        if re.search(r"git (commit|push)", cmd):
                            risk.append("auto commit/push")
                        add("hooks", rel, f"{event} [{safe(ent.get('matcher', '*'), 30)}]", safe(cmd), risk)
            for k in ("statusLine",) + EXEC_KEYS:
                v = d.get(k)
                if v:
                    cmd = v.get("command", "") if isinstance(v, dict) else v
                    add("exec-settings", rel, k, safe(cmd), ["runs a shell command"])
            env = d.get("env", {}) if isinstance(d.get("env"), dict) else {}
            for k, v in env.items():
                risk = []
                if ENV_RISK.search(k):
                    risk.append("redirect/TLS/proxy env")
                if SECRETISH.search(k) and isinstance(v, str) and v and not v.startswith("$"):
                    risk.append("inline secret value")
                host = re.sub(r"^(https?://[^/]+).*$", r"\1", v) if isinstance(v, str) and "://" in v else "[value withheld]"
                add("env", rel, k, safe(host, 60), risk)
            sb = d.get("sandbox")
            if isinstance(sb, dict):
                risk = []
                if sb.get("enabled") is False:
                    risk.append("sandbox disabled")
                if sb.get("allowUnsandboxedCommands"):
                    risk.append("unsandboxed commands allowed")
                add("sandbox", rel, "sandbox", safe(json.dumps(sb), 100), risk)
            if d.get("disableAllHooks"):
                add("hooks", rel, "disableAllHooks", "", ["all hooks disabled"])
            for k in ("enableAllProjectMcpServers", "enabledMcpjsonServers"):
                if d.get(k):
                    add("mcp", rel, k, safe(json.dumps(d[k]), 80), ["mcp auto-enabled"] if k.startswith("enableAll") else [])
            for k in ("enabledPlugins", "extraKnownMarketplaces"):
                if d.get(k):
                    add("plugins", rel, k, safe(json.dumps(d[k]), 100), ["third-party plugins for every teammate"])
        elif low in (".vscode/settings.json",):
            d = jload(p, rel, "ide")
            for k, v in d.items():
                if re.search(r"(chat\.tools\.autoApprove|autoApprove|copilot.*agent|mcp)", k, re.I):
                    add("ide", rel, k, safe(json.dumps(v), 80), ["auto-approve"] if v is True and "approve" in k.lower() else [])
        elif low == ".vscode/tasks.json":
            d = jload(p, rel, "ide")
            for t in d.get("tasks", []) if isinstance(d, dict) else []:
                if isinstance(t, dict) and (t.get("runOptions") or {}).get("runOn") == "folderOpen":
                    add("ide", rel, f"task '{safe(t.get('label', '?'), 40)}' runOn=folderOpen", safe(t.get("command", "")), ["runs on folder open"])
        elif low in (".devcontainer/devcontainer.json", ".devcontainer.json"):
            d = jload(p, rel, "ide")
            for k in ("initializeCommand", "postCreateCommand", "postStartCommand", "postAttachCommand"):
                if d.get(k):
                    add("ide", rel, k, safe(d[k] if isinstance(d[k], str) else json.dumps(d[k])),
                        ["runs on the HOST"] if k == "initializeCommand" else [])
            if d.get("mounts"):
                add("ide", rel, "mounts", safe(json.dumps(d["mounts"]), 100), ["host mounts"])
        elif low in (".codex/config.toml",) and tomllib:
            try:
                d = tomllib.loads(safegit.read_text(p))
            except (ValueError, OSError):
                d = {}
                add("permissions", rel, "unparseable - review manually", "", ["unparseable - review manually"])
            for k in ("approval_policy", "sandbox_mode"):
                if k in d:
                    add("permissions", rel, f"{k}={d[k]}", "", ["no approval / full access"] if d[k] in ("never", "danger-full-access") else [])
            for nm, srv in (d.get("mcp_servers") or {}).items():
                add("mcp", rel, nm, safe(" ".join([str(srv.get("command", ""))] + [str(x) for x in srv.get("args", [])])), [])
        # ---- MCP configs
        if name in (".mcp.json", "mcp.json", "claude_desktop_config.json", "mcp_config.json") and (
                low.count("/") == 0 or low.startswith((".cursor/", ".vscode/", ".claude/", ".gemini/", ".roo/"))):
            d = jload(p, rel, "mcp")
            servers = d.get("mcpServers") or d.get("servers") or {}
            for nm, srv in (servers.items() if isinstance(servers, dict) else []):
                if not isinstance(srv, dict):
                    continue
                cmd = " ".join([str(srv.get("command", ""))] + [str(x) for x in srv.get("args", []) or []]).strip()
                url = str(srv.get("url", "") or srv.get("serverUrl", ""))
                risk = []
                if re.search(r"\b(npx|bunx|pnpm\s+dlx|uvx|pipx\s+run)\b", cmd):
                    pkg = re.search(r"(?:npx|bunx|dlx|uvx|run)\s+(?:-y\s+|--yes\s+)?(\S+)", cmd)
                    pk = pkg.group(1) if pkg else ""
                    if pk.endswith("@latest") or not re.search(r"(@\d|==\d)", pk):
                        risk.append("unpinned launch")
                for k, v in (srv.get("env") or {}).items():
                    if SECRETISH.search(k) and isinstance(v, str) and v and not re.match(r"^\$\{?\w+\}?$", v):
                        risk.append(f"inline secret in env ({k})")
                for k, v in (srv.get("headers") or {}).items():
                    if isinstance(v, str) and not re.search(r"\$\{?\w+\}?", v):
                        risk.append(f"static header value ({k})")
                if url.startswith("http://") and "localhost" not in url and "127.0.0.1" not in url:
                    risk.append("remote MCP over plain HTTP")
                if re.search(r"(server-filesystem|filesystem)\S*\s+(/|~|[A-Za-z]:\\\\?)(\s|$)", cmd):
                    risk.append("filesystem server rooted at / or ~")
                add("mcp", rel, nm, safe(cmd or re.sub(r"\?.*$", "", url)), risk)

    # ---- subagents, skills, commands, instruction files, CI, flags, logs, hidden unicode, LLM code
    skill_dirs = {}
    for rel in all_files:
        low = rel.lower()
        name = low.rsplit("/", 1)[-1]
        p = root / rel
        ext = os.path.splitext(name)[1]
        if ext not in TEXT_EXT and name not in INSTRUCTIONS and not PROMPT_LOG.search(low) \
                and name not in ("makefile", "justfile", "dockerfile", "procfile", "jenkinsfile"):
            continue
        try:
            if p.stat().st_size > 1_500_000:
                continue
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if PROMPT_LOG.search(low):
            add("prompt-logs", rel, "prompt / transcript log", f"{len(text.splitlines())} lines (content not shown; peek.py)",
                ["committed" if rel in tracked else "untracked (not in git)"])
        if low.startswith(".claude/agents/") and name.endswith(".md"):
            fm = frontmatter(text)
            tools = fm.get("tools", "")
            risk = []
            if not tools:
                risk.append("no tools list = inherits ALL tools")
            elif re.search(r"\b(Bash|Write|Edit|PowerShell)\b", tools) and re.search(r"(?i)read-?only|review|audit", fm.get("description", "")):
                risk.append("reviewer/read-only role holds write/exec tools")
            if fm.get("permissionMode") in ("bypassPermissions", "acceptEdits", "auto", "dontAsk"):
                risk.append(f"permissionMode={fm['permissionMode']}")
            if fm.get("memory"):
                risk.append("persistent memory (ASI06)")
            if fm.get("hooks") or fm.get("mcpServers"):
                risk.append("own hooks / MCP servers")
            add("subagents", rel, fm.get("name", name), f"tools: {safe(tools or 'ALL', 70)}; model: {fm.get('model', '-')}", risk)
        if name == "skill.md" or (low.startswith((".claude/commands/", ".cursor/commands/", ".github/prompts/")) and ext == ".md"):
            fm = frontmatter(text)
            at = fm.get("allowed-tools", "")
            dyn = len(re.findall(r"(?m)^\s*!`[^`]+`|!`[^`]+`", text))
            risk = []
            if re.search(r"(^|[\s,])(Bash|PowerShell)([\s,]|$)", at):
                risk.append("unscoped Bash pre-approved")
            if re.search(r"\b(Agent|Skill)\b", at):
                risk.append("Agent/Skill pre-approved")
            if RISKY_VERB.search(at) or re.search(r"Bash\((curl|wget|docker|awk|sed|python|node|sh|bash)\b", at):
                risk.append("exec / network / write command pre-approved")
            if dyn:
                risk.append(f"{dyn} dynamic `!` command(s) run on load")
            if fm.get("hooks"):
                risk.append("frontmatter hooks")
            surface = "skills" if name == "skill.md" else "commands"
            d = rel.rsplit("/", 1)[0] if "/" in rel else "."
            if surface == "skills":
                skill_dirs[d] = rel
                if not low.startswith(".claude/skills/"):
                    risk.append("outside .claude/skills (vendored or shipped)")
                if any(f.startswith(d + "/") and f.lower().endswith("license.txt") or f.lower() == (d + "/license").lower() for f in all_files):
                    risk.append("third-party (own LICENSE) - pin + review")
                if re.search(r"(?i)disable-model-invocation", "\n".join(fm)) is None and re.search(r"(?i)deploy|publish|release", fm.get("description", "")):
                    risk.append("deploy/publish skill without disable-model-invocation")
            add(surface, rel, fm.get("name", name), f"allowed-tools: {safe(at or '-', 70)}", risk)
        if (name in INSTRUCTIONS or name == "skill.md" or low.startswith((".claude/agents/", ".claude/commands/"))) and INJECTION_WORDING.search(text):
            add("instructions", rel, "instruction-override wording",
                safe(INJECTION_WORDING.search(text).group(0), 60), ["possible prompt injection aimed at agents (and this audit)"])
        if name in INSTRUCTIONS or low.startswith((".cursor/rules/", ".claude/rules/", ".github/instructions/", ".windsurf/rules/")):
            hits = sorted({m.group(0).lower()[:30] for m in BYPASS_WORDING.finditer(text)})
            add("instructions", rel, name, f"{len(text.splitlines())} lines", [f"wording: {', '.join(hits[:4])}"] if hits else [])
        if low.startswith(".github/workflows/") or name in (".gitlab-ci.yml", "buildspec.yml", "jenkinsfile", "azure-pipelines.yml"):
            if CI_AGENT.search(text):
                risk = ["untrusted trigger feeds agent"] if CI_UNTRUSTED.search(text) else []
                if re.search(r"contents:\s*write|id-token:\s*write|secrets\.", text):
                    risk.append("agent job holds write/secrets")
                add("ci-agents", rel, CI_AGENT.search(text).group(0), "", risk)
        if name == "package.json" or re.match(r"requirements[\w.-]*\.txt$|pyproject\.toml$", name):
            rx = LLM_DEP_NPM if name == "package.json" else LLM_DEP_PY
            for dep in sorted({m.group(1).lower() for m in rx.finditer(text)}):
                add("llm-code", rel, dep, "LLM / agent SDK dependency", [])
        for i, line in enumerate(text.splitlines(), 1):
            if len(line) > 3000:
                continue
            m = DANGER_FLAGS.search(line)
            if m and not low.startswith((".claude/settings",)):
                add("dangerous-flags", f"{rel}:{i}", m.group(0)[:40], "", ["agent safety disabled"])
            h = HIDDEN.search(line)
            if h and not (i == 1 and line.startswith("﻿") and len(HIDDEN.findall(line)) == 1):
                add("hidden-unicode", f"{rel}:{i}", f"U+{ord(h.group(0)):04X}", f"{len(HIDDEN.findall(line))} char(s)",
                    ["hidden instruction channel"])
            if ext in (".py", ".js", ".ts", ".tsx", ".jsx", ".mjs", ".go", ".java", ".rb", ".cs", ".env", ".yml", ".yaml", ".toml")                     and not re.search(r"(^|/)(tests?|spec|__tests__|e2e|fixtures?)(/|$)|\.(test|spec)\.", low):
                m2 = LLM_SWITCH.search(line)
                if m2:
                    add("llm-code", f"{rel}:{i}", m2.group(0)[:40], "", ["dangerous switch / exposure"])
                elif LLM_CALL.search(line) and ext != ".env":
                    add("llm-code", f"{rel}:{i}", LLM_CALL.search(line).group(0)[:40], "model / tool call", [])

    for d, rel in skill_dirs.items():
        scripts = [f for f in all_files if f.startswith(d + "/") and f.lower().endswith((".py", ".sh", ".ps1", ".js", ".ts", ".mjs"))]
        if scripts:
            add("skills", rel, f"{len(scripts)} script(s) in skill", ", ".join(s.rsplit('/', 1)[-1] for s in scripts[:5]), ["scripts run by the agent - review like code"])
    for lock in ("skills-lock.json", ".skills.json", "skills.lock"):
        if any(f.lower().endswith(lock) for f in all_files):
            add("skills", lock, "skills lock file present", "", [])

    # ---- prompt logs removed from HEAD but still in history
    # -z: raw UTF-8 names (C-quoted names like "\343\203..." would miss PROMPT_LOG and `tracked`)
    hist = git(root, "log", "--all", "--name-only", "--diff-filter=AD", "--format=", "-z")
    names = {f.strip("\n") for f in hist.split("\0")}
    gone = sorted({f for f in names if f and PROMPT_LOG.search(f.lower()) and f not in tracked})
    for f in gone[:20]:
        add("prompt-logs", f, "in git history only", "deleted at HEAD; still in history", ["history: rewrite or accept"])

    counts = {}
    for r in rows:
        counts[r["surface"]] = counts.get(r["surface"], 0) + 1
    flagged = [r for r in rows if r["risk"]]
    out = Path(host_path(a.out))
    out.parent.mkdir(parents=True, exist_ok=True)
    out.with_suffix(".json").write_text(json.dumps({"repo": root.name, "counts": counts, "flagged": len(flagged),
                                                    "rows": rows, "symlinks_outside_repo": links_out},
                                                   indent=1, ensure_ascii=False), encoding="utf-8")
    md = [f"# AI and agent inventory - {root.name}", "",
          f"{len(rows)} items, {len(flagged)} with risk labels. Labels are leads: confirm each by reading the "
          "file (the lane), never by trusting this table. Values (env, headers, tokens, commands) are masked.", ""]
    if links_out:
        md += [f"Symlinks resolving outside the repo (skipped, not read): {len(links_out)}: "
               + ", ".join(f"`{f}`" for f in links_out[:20]), ""]
    if not rows:
        md.append("No AI components found: no LLM calls, agent frameworks, MCP, or AI coding-agent configuration. "
                  "Record this negative result in the report.")
    order = ["permissions", "exec-settings", "env", "sandbox", "plugins", "hooks", "mcp", "subagents", "skills",
             "commands", "instructions", "ci-agents", "ide", "dangerous-flags", "prompt-logs", "hidden-unicode",
             "settings", "llm-code"]
    for surf in sorted(counts, key=lambda s: order.index(s) if s in order else 99):
        md += ["", f"## {surf} ({counts[surf]})", "", "| file | item | detail | risk |", "|---|---|---|---|"]
        items = [r for r in rows if r["surface"] == surf]
        items.sort(key=lambda r: (not r["risk"], r["file"]))
        for r in items[:60]:
            md.append(f"| `{cell(r['file'])}` | {cell(safe(r['item'], 70))} | {cell(r['detail'])} | "
                      f"{cell('; '.join(r['risk']) or '-')} |")
        if len(items) > 60:
            md.append(f"| ... | +{len(items) - 60} more in the JSON | | |")
    out.write_text("\n".join(md) + "\n", encoding="utf-8")
    print(f"wrote {out} - {len(rows)} items, {len(flagged)} flagged: " + ", ".join(f"{k} {v}" for k, v in counts.items()))
    return 0


if __name__ == "__main__":
    sys.exit(main())
