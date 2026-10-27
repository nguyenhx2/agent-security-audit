# Module: ai-llm-agentic - LLM Top 10 2026, Agentic Top 10 2026, MCP Top 10 (beta), AISVS 1.01

Apply when code calls an LLM, builds prompts, does RAG/embeddings, runs agents/tools, ships an MCP
server/client, or the repo commits AI coding-agent tooling (detect `ai_scope`: `llm-app`,
`agentic-app`, `mcp`, `agent-tooling` - cover every scope listed). Cite `OWASP Top 10 for LLM Applications 2026 LLM0x`, `OWASP Top 10 for Agentic
Applications 2026 ASI0x`, `OWASP MCP Top 10 (beta) MCP0x` (official IDs are written `MCPxx:2025`),
`OWASP AISVS 1.01 C<n>`. Versions per
`reference/standards/index.md`. Nearly all rows are **Manual**: SAST sees the API call, not the trust flow.

## Contents
- Method: trace the untrusted-content path
- LLM Top 10 2026
- Agentic Top 10 2026
- MCP Top 10 (beta)
- AI coding-agent tooling in the repo (`agent-tooling` scope)
- AISVS 1.01 chapter router
- Severity guidance

## Method: trace the untrusted-content path
1. **Inventory model calls:** grep `chat.completions`, `messages.create`, `generateContent`,
   `invoke(`, `ChatOpenAI`, `Anthropic(`, `streamText`, `generateText`, `run_agent`, `Agent(`.
2. **For each call, list inputs:** system prompt source; user input; retrieved docs (RAG); tool
   results; web pages; emails/files. Everything not authored by the developer is untrusted.
3. **List what output can do:** rendered as HTML/markdown? executed (code, SQL, shell)? passed to
   tools? written to memory/DB? used for an authz or money decision?
4. **The vulnerability is the path** from untrusted input to a privileged sink without a gate
   (allow-list, human approval, sandbox, output encoding, scoped credentials).
5. **Authorization must live outside the prompt.** If "only show the current user's data" exists
   only as a system-prompt sentence while the tool accepts any `user_id`, that is broken object-level
   authz (P0/P1, LLM01 + ASI03 + API1): bind identity in the tool from the session, never from model
   arguments.
6. **Provider data flow:** which provider / region receives prompts (cross-border transfer for the
   privacy module); API keys only server-side; retention / training opt-out configured; prompts and
   completions not logged with personal data or secrets (LLM02).

Agent-loop patterns to check explicitly:
- **ReAct / text-protocol agents** (`Thought:` / `Action:` / `Observation:` parsed from model text):
  user input or tool output containing those markers can forge the agent's own scratchpad (fake
  `Observation:` or `Action:` lines). Look for string-built transcripts and regex action parsers;
  structured tool-calling APIs are the remedy.
- **Tool argument trust:** model-chosen arguments flowing into SQL/shell/paths/URLs are injection
  sinks (LLM10 Improper Output Handling) - same rules as request parameters.
- **Auto-approve loops:** `while` loops dispatching tools without a step cap, budget, or human gate
  for write/financial actions (ASI08, LLM03, LLM06). Bounds to find: `max_iterations`,
  `max_execution_time`, LangGraph `recursion_limit`, `max_tokens`, client timeouts, retry caps,
  per-user budgets.
- **Lethal trifecta:** one agent or tool set that combines private data + untrusted content + an
  exfiltration channel (HTTP fetch, email, markdown images, webhooks), even with no traced exploit
  (floor: `reference/method/triage.md`).

## LLM application checks beyond the Top 10 table (`llm-app` / `agentic-app`)
`agent-config.md` (llm-code rows) lists calls and switches; confirm each by reading.
| Check | What to look for | Cite |
|-------|------------------|------|
| Dangerous framework switches (P0/P1 floor when reachable) | `allow_dangerous_code/requests/deserialization=True`, `PythonREPLTool`, `LLMMathChain`, `PALChain`, `create_sql_agent` / `SQLDatabaseChain` with a read-write role, `load_tools(["terminal"])`, `PandasQueryEngine`, `trust_remote_code=True`, `torch.load` without `weights_only=True`, `langchain.load(s)` on untrusted JSON | LLM10, LLM04, ASI05; CWE-94/502 |
| Prompt-template injection | `PromptTemplate(template_format="jinja2")` or f-string templates built from user input (SSTI -> RCE); user-controlled `base_url` / `api_base` (key sent to attacker) or `model` (cost escalation) | LLM01, LLM06; CWE-1336 |
| Client-side keys and open proxies | `dangerouslyAllowBrowser: true`, `NEXT_PUBLIC_*` / `VITE_*` provider keys, server proxies forwarding to the provider without per-user auth and quotas | LLM02, LLM06; API4 |
| Unauthenticated model / UI servers | Ollama `0.0.0.0:11434`, vLLM / TGI / LM Studio ports, Gradio `share=True`, Streamlit / Chainlit without auth | LLM06; API2; A01 |
| Cross-user state | module-level memory (`ConversationBufferMemory`, globals in Streamlit / Gradio), semantic / prompt caches keyed without the user, LangGraph `thread_id` from the client, chat-history and share-link IDOR | LLM02, ASI06; API1 |
| RAG specifics | ACLs enforced at query time from the source system (not copied at ingest); deletion / revocation reaches chunks, embeddings and caches (GDPR erasure; embeddings are personal data); loader SSRF (`WebBaseLoader`, URL loaders to 169.254.169.254); hidden-text, PDF and image injection sources | LLM09, LLM02, LLM01; A01 SSRF |
| Guardrails as controls | moderation / Llama Guard / NeMo / content-safety calls fail **closed** on exception or timeout and also run on tool and RAG output - otherwise a dead control (P1 floor) | LLM01, LLM10; A10 |
| Generated-code sandbox | no docker socket, no egress, no provider or cloud keys in the sandbox env; restricted `exec` globals are not a sandbox | ASI05; CWE-94 |
| Observability data flow | LangSmith / Langfuse / Helicone / OpenTelemetry tracing ships full prompts and PII to a third party (processor, transfer, retention); `verbose=True` / `set_debug(True)` in production | LLM02; privacy module |
| Approval integrity | approval binds to the exact tool arguments (no TOCTOU between approval and execution); the UI shows raw arguments, not a model summary | ASI09 |
| Model pinning | dated model snapshots instead of floating aliases where behaviour matters; local weights hash-pinned, `safetensors` | LLM04 |
| Regulation | EU AI Act Art. 50 transparency and risk class; GDPR Art. 22 automated decisions - route to `reference/standards/privacy.md` | EU AI Act; GDPR |
| Testing | prompt-injection / jailbreak tests in CI (promptfoo, garak, PyRIT) - note when absent (Info) | AISVS 1.01 C11 |
Mark prompt-injection findings `needs-runtime-check` unless the path was traced statically end to end.

## LLM Top 10 2026
Final 2026 edition (published 2026-08 in github.com/GenAI-Security-Project/GenAI-LLM-Top10 `2026/final`;
genai.owasp.org pages may still show 2025 slugs). IDs were renumbered - never reuse 2025 IDs.

| ID | Risk | What to verify | Where / grep hints |
|----|------|----------------|--------------------|
| LLM01 | Prompt Injection (direct + indirect) | Untrusted content (user, RAG docs, web, email, tool output) cannot change instructions that gate privileged actions; privileged actions need deterministic checks outside the model | prompt templates concatenating `user_input`/`context`/`docs`; agents that browse or read inbox |
| LLM02 | Sensitive Information Disclosure | No secrets/PII/other tenants' data in prompts or context; per-user retrieval filters; outputs scrubbed | system prompts with keys, RAG queries without tenant filter, prompt/response logging with PII |
| LLM03 | Excessive Agency | Tools least-privilege (read-only where possible), scoped credentials, human approval for destructive/financial actions | tool definitions with broad DB/FS/HTTP/shell access; `auto_approve`; agents holding admin tokens |
| LLM04 | Supply Chain | Models/datasets/adapters from trusted sources, pinned by hash; no `trust_remote_code=True` on untrusted repos; no pickle weights | `from_pretrained(`, `trust_remote_code`, `.pt`/`.pkl` loads, hub pulls |
| LLM05 | Data and Model Poisoning | Fine-tune/RAG ingestion validated, provenance tracked; user-writable sources cannot poison shared indexes | ingestion pipelines, feedback loops writing to training/RAG stores |
| LLM06 | Unbounded Consumption | Per-user token/request quotas, `max_tokens`, timeouts, input size limits, cost alerts | LLM calls in unauthenticated or unthrottled routes; loops calling the model |
| LLM07 | Misinformation | Outputs that drive decisions are grounded/cited and verified; UI signals uncertainty | auto-applied model decisions in finance/health/legal flows |
| LLM08 | Hidden Context Exposure (was System Prompt Leakage; now any non-user-facing context) | System prompts, tool schemas, retrieved context and memory contain no secrets or authz logic; leakage grants nothing | secrets/role rules in prompt strings, hidden context returned in debug output |
| LLM09 | Vector and Embedding Weaknesses | Vector store access control per tenant/user; no cross-tenant retrieval | vector queries without metadata filter; shared namespaces |
| LLM10 | Improper Output Handling | Model output treated as untrusted: encoded before HTML render, never `eval`/`exec`/SQL/shell without validation | `innerHTML = completion`, `dangerouslySetInnerHTML`, `exec(response)`, `cursor.execute(llm_sql)`, markdown renderers allowing raw HTML/images (exfil) |

## Agentic Top 10 2026

| ID | Risk | What to verify |
|----|------|----------------|
| ASI01 | Agent Goal Hijack | Goals/plans cannot be rewritten by content the agent reads; plan changes on privileged paths need re-authorization |
| ASI02 | Tool Misuse (and Exploitation) | Tool arguments validated server-side; tools cannot be chained into unintended capabilities (read file -> HTTP post = exfil) |
| ASI03 | Identity and Privilege Abuse | Agent acts with the *user's* scoped identity, not a shared super-credential; no confused-deputy across users |
| ASI04 | Agentic Supply Chain Vulnerabilities | Third-party tools, MCP servers, prompts, plugins pinned and verified; dynamic tool loading restricted |
| ASI05 | Unexpected Code Execution | Generated code runs only in a sandbox (no host FS/network/creds); no `exec` of model output in-process |
| ASI06 | Memory and Context Poisoning | Long-term memory writes validated and attributable; memory scoped per user; poisoned memory cannot persist instructions |
| ASI07 | Insecure Inter-Agent Communication | Agent-to-agent messages authenticated, integrity-protected, and treated as untrusted input |
| ASI08 | Cascading Failures | Circuit breakers, step/iteration limits, budget caps; one agent's failure cannot fan out unbounded |
| ASI09 | Human-Agent Trust Exploitation | Approval prompts show the real action and its effects; no rubber-stamp approvals; high-impact actions need explicit confirmation |
| ASI10 | Rogue Agents | Monitoring and kill-switch; agent actions logged with identity; behaviour drift detectable |

Where to look: agent loops (`while` + tool dispatch), tool registries, approval/HITL code, sandbox
config (containers, `subprocess`, E2B/Firecracker), memory stores, orchestration graphs (LangGraph,
CrewAI, Agents SDK), credential plumbing for tools.

## MCP Top 10 (beta, living document - cite as `OWASP MCP Top 10 (beta) MCP0x`; official IDs are written `MCPxx:2025`)

| ID | Risk | What to verify in an MCP server/client |
|----|------|----------------------------------------|
| MCP01 | Token Mismanagement and Secret Exposure | Tokens not logged, not passed through to tools, not stored in plaintext config; no token passthrough to upstream APIs |
| MCP02 | Privilege Escalation via Scope Creep | Server requests minimum scopes; tools do not exceed declared capability |
| MCP03 | Tool Poisoning | Tool descriptions/metadata cannot carry hidden instructions; descriptions pinned and reviewed; changes ("rug pull") detected |
| MCP04 | Software Supply Chain Attacks and Dependency Tampering | Server packages pinned; `npx -y some-server@latest` style launches flagged |
| MCP05 | Command Injection and Execution | Tool args never concatenated into shell/SQL/paths; stdio servers spawn with fixed argv |
| MCP06 | Prompt Injection via Contextual Payloads | Resource/tool outputs treated as untrusted data by the client |
| MCP07 | Insufficient Authentication and Authorization | Remote (HTTP) servers require auth (OAuth 2.1 per spec), validate audience, enforce per-user authz |
| MCP08 | Lack of Audit and Telemetry | Tool invocations logged with caller identity and arguments (minus secrets) |
| MCP09 | Shadow MCP Servers | Inventory of configured servers; no unapproved servers in shared configs (`.mcp.json`, `claude_desktop_config.json`) |
| MCP10 | Context Injection and Over-Sharing | Servers return minimum data; no cross-session/cross-user context bleed |

Grep: `@modelcontextprotocol/sdk`, `FastMCP`, `server.tool(`, `@mcp.tool`, `.mcp.json`, `mcpServers`.

## AI coding-agent tooling in the repo (`agent-tooling` scope)
Repos increasingly commit configuration that lets AI coding agents (Claude Code, Codex / AGENTS.md,
Cursor, Copilot, Windsurf, Gemini CLI) run commands on developer machines and in CI. Treat it as
**executable configuration plus supply chain**: whoever can change these files can steer what an
agent runs with a developer's credentials. Inventory comes from detect's `agent_tooling` counts and
the digest's `agent-permissions` index. Prompt-only rules ("never push to main" in CLAUDE.md) are
guidance, not controls - a finding that relies on them is unmitigated.

| Surface | Files | What to verify | Primary citation |
|---------|-------|----------------|------------------|
| Permissions | `.claude/settings.json` (`permissions.allow/deny/ask`, `defaultMode`), `.codex/config.toml`, `.gemini/settings.json` | No broad allow (`Bash(*)`, `Bash(git:*)`, `Bash(python *)`, `Bash(curl:*)`, `WebFetch` to any host) for actions that write, publish, merge, deploy, or exfiltrate; no `defaultMode: bypassPermissions` / `acceptEdits` committed for everyone; `enableAllProjectMcpServers` off; deny rules are prefix matches - test bypasses (`git -C . push`, `env git push`, `sh -c "..."`, `bash -lc`, aliases) | ASI02, ASI03; LLM03 |
| Local settings committed | `.claude/settings.local.json`, `*.local.*` | Personal overrides and allow-lists are not tracked (check `git ls-files`); none contain tokens or paths of a person | ASI03; LLM02 |
| Hooks | `.claude/hooks/*`, `hooks` blocks in settings | Hook input (tool JSON from the model) never reaches a shell unquoted (`$(jq -r .tool_input.command)` in `eval`/`bash -c`); blocking hooks fail **closed** (Claude Code: exit 2 blocks, any other non-zero only warns); run on every platform the team uses (a `.sh` hook on Windows without bash, `powershell` on macOS = dead control); no network calls with repo data; hook scripts come from the working tree, so a branch can change them before they run | ASI02, ASI05; CWE-78, CWE-636 |
| Subagents | `.claude/agents/*.md` | `tools` match the role (a "reviewer" or "read-only" agent has no Bash/Write/Edit); agents that read untrusted content (issues, MR text, web, documents) hold no write/exec/publish tools; `permissionMode` not raised | ASI03, LLM03 |
| Skills / commands | `.claude/skills/*/SKILL.md`, `.claude/commands/*.md`, `.agents/skills/*`, other `SKILL.md` | `allowed-tools` scoped to exact commands (unscoped `Bash`, `Agent`, `Skill` = pre-approved everything); scripts the skill runs are reviewed like product code; skill text holds no hidden instructions (zero-width / bidi / tag Unicode, HTML comments) | ASI04, LLM01 |
| Vendored third-party skills / plugins | skills not written in this repo (LICENSE from another author, `.agents/skills/<name>` copied from a marketplace) | Source, version and commit recorded; pinned (no "copy latest"); scripts reviewed; update process exists; license compatible | ASI04, LLM04; OWASP Top 10 2025 A03 |
| MCP servers | `.mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`, `claude_desktop_config.json` | Every server known and approved; launched pinned (`npx -y pkg@latest` / unpinned `uvx` = MCP04); no tokens inline (env refs only); remote servers use HTTPS + auth | MCP04, MCP09, MCP01 |
| Instruction files | `CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, `.cursorrules`, `.cursor/rules/*`, `.github/copilot-instructions.md`, `.claude/rules/*` | No secrets, internal hostnames, customer names or credentials; no instructions that disable safety ("skip tests", "use --no-verify", "auto-approve"); security rules that matter are also enforced by a control (hook, CI, branch protection) | LLM02, LLM08; ASI09 |
| Prompt / transcript logs | `prompt_history*`, `*transcript*`, `.specstory/`, `.claude/projects/**/*.jsonl`, chat exports | Not committed; if committed, peek for secrets, personal data, customer content, internal URLs (sensitive-data lane owns the spill finding; gitleaks covers only token shapes) | LLM02; privacy module; CWE-532 |
| AI-assisted development workflow | git history, CI, branch rules, agent allow-lists | Agents cannot approve / merge / deploy their own output; AI-authored commits reviewed by a distinct human; commits co-authored by agents land through MRs (`git log --first-parent` on the default branch) | AISVS 1.01 AC.4.1, AC.8.1, AC.8.4; CICD-SEC-1 |
| Settings that execute or redirect | `statusLine.command`, `apiKeyHelper`, `awsAuthRefresh`, `awsCredentialExport`, `otelHeadersHelper`; `env` with `*_BASE_URL` (whole transcript + key to a proxy), `HTTPS_PROXY`, `NODE_OPTIONS`, `NODE_TLS_REJECT_UNAUTHORIZED=0`; `additionalDirectories`, `Read(~/.ssh/**)`; `sandbox.enabled:false`, `allowUnsandboxedCommands`; `disableAllHooks`; `enabledPlugins` / `extraKnownMarketplaces` (third-party plugins for every teammate) | Commands reviewed like code; no redirect of model traffic; secret paths denied (`Read(.env*)`, `~/.ssh`, `~/.aws`) whenever egress is allowed | ASI02, ASI04, LLM02 |
| Dynamic context and memory | `` !`cmd` `` lines in SKILL.md / commands run on load; hooks or MCP servers in skill / agent frontmatter; agent `memory:`; deploy / publish skills without `disable-model-invocation`; over-broad skill descriptions that capture unrelated requests or shadow user skills | Every `!` command reviewed; persistent memory scoped; deploy skills manual-only | ASI04, ASI06, LLM01 |
| Hook events | `SessionStart` / `UserPromptSubmit` / `Stop` hooks that fetch from or send to the network (opening the repo is enough - P0 when it exfiltrates); `PostToolUse` auto-commit / push | No network in hooks; no automatic publish | ASI02, ASI05 |
| CI-run agents | `anthropics/claude-code-action`, `openai/codex-action`, Copilot coding agent (`copilot-setup-steps.yml`), CodeRabbit / BugBot, `claude -p` in pipelines | Triggers `issue_comment` / `pull_request_target` / `issues` feeding `${{ github.event.*.body }}` to an agent that holds `contents: write` or secrets = CICD-SEC-4 + ASI01 (P1, P0 with deploy secrets); `allowed_tools` scoped; non-write users not allowed to trigger | CICD-SEC-4, ASI01, ASI03 |
| Dangerous CLI flags | scripts, Makefile, package.json, CI, docs: `--dangerously-skip-permissions`, `bypassPermissions`, `--yolo`, `--full-auto`, `danger-full-access`, `approval_policy="never"`, `--trust-all-tools`, Aider `yes-always`, Gemini `autoAccept` (the 2025 Nx "s1ngularity" malware drove installed agents with such flags) | None outside an isolated sandbox | ASI02, ASI03 |
| IDE and other agent surfaces | `.vscode/tasks.json` (`runOn: folderOpen`), `.vscode/settings.json` (`chat.tools.autoApprove`), `.devcontainer/devcontainer.json` (`initializeCommand` runs on the host, mounts), `.continue/config.*`, `.aider.conf.yml`, `.clinerules`, `.roomodes`, `.github/prompts/`, `.github/instructions/`, `CLAUDE.local.md` | Nothing runs on open; no auto-approve | ASI02, ASI04 |
| Who can change the rules | CODEOWNERS / branch protection covering `.claude/**`, `CLAUDE.md`, `AGENTS.md`, workflows; remote includes ("fetch rules from https://...") and `@~/` imports in instruction files | Changes to agent configuration need owner review | CICD-SEC-1; SLSA v1.2 Source |
| MCP depth | local stdio servers: read their tool descriptions (poisoning, MCP03); static `headers` bearer tokens; `env` passthrough of the whole environment; filesystem servers rooted at `/` or `~`; DB servers with production connection strings; browser servers (injection + exfiltration); remote servers not reviewed = stated gap | MCP03, MCP01, MCP02, MCP10 |
| Hidden Unicode | zero-width, bidi (Trojan Source) and tag characters (U+E0000-E007F) in instruction files, skills and code - listed by `agent_config_audit.py` (`hidden-unicode`) | Any hit in an instruction file = P1 lead | LLM01; CWE-1007 |
| Logs in history | prompt logs deleted at HEAD but present in git history (`agent_config_audit.py` lists them) | Rewrite history or accept with rotation of anything leaked | LLM02; CWE-532 |

Severity for tooling: untrusted content reaching a pre-approved write / exec / publish action, a
blocking hook or deny rule that fails open, committed prompt logs with secrets or personal data
(floor: `reference/method/triage.md`); broad allow-lists without an untrusted-input path, unpinned
vendored skills, unpinned MCP launches = P2; missing provenance notes = Info.

## AISVS 1.01 chapter router (cite for verifiable requirements)
Latest stable: **1.01** (OWASP/AISVS README); 1.0 released 2026-06. Chapters: C1 Training Data, C2 Input
Validation, C3 Model Lifecycle, C4 Infrastructure, C5 Access Control, C6 Model Supply Chain, C7 Model
Behavior/Output, C8 Memory/Vector DB, C9 Orchestration and Agentic, C10 MCP Security, C11 Adversarial
Robustness, C12 Monitoring/Logging. Confirm sub-requirement IDs in the published text before citing.
**Appendix C = AI-Assisted Secure Coding.** Its separation-of-duties controls - AC.4.1 (AI-generated
code reviewed by a distinct human), AC.8.1 (agents cannot approve/merge/deploy their own output),
AC.8.4 (generation, review, approval, deployment by distinct principals) - are why this skill is
read-only on what it audits, and are themselves audit checks for repos where AI agents commit code.

## Which standard is primary
LLM-specific weakness (prompt injection, excessive agency, output handling, unbounded consumption,
agent identity) -> primary `OWASP Top 10 for LLM Applications 2026` / `Agentic 2026`, with the web
category in `also_maps_to`. Classic web bug that the model merely reaches (SQL injection via a tool
argument, IDOR in a tool) -> primary `OWASP Top 10 2025` / `API Security Top 10 2023`, with the LLM
or Agentic ID in `also_maps_to`. Either way both IDs appear.

## Severity guidance
- Indirect prompt injection reaching a tool with write/financial/exfil capability -> P0/P1.
- Model output to `eval`/shell/SQL -> treat as injection (P0/P1 by reachability).
- Missing quotas on a public LLM endpoint -> P1 when cost-bearing (LLM06 + API4).
- Secrets in system prompts -> P1 (P0 if the prompt is client-side).
- Private data + untrusted content + exfiltration channel in one agent ("lethal trifecta") (floor:
  `reference/method/triage.md`).
- Guardrail that fails open -> dead control, P1 floor.
