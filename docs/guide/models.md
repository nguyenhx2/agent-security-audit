# Models and cost

**English** · [日本語](ja/models.md)

The skill gives each task the model it needs. Deterministic scripts do the discovery without any model; models are spent on judgement: reading code, refuting candidates, writing findings.

![Model allocation per depth. Recon: the lead inline at Quick, recon-mapper on Sonnet medium at Standard and Deep. Design lanes (authz-logic, sensitive-data, ai-agentic): lead at Quick, Sonnet high at Standard, Opus high at Deep. Other lanes: lead at Quick, Sonnet medium at Standard, Sonnet high at Deep. Verifier: the lead re-checks P0 and P1 at Quick, Sonnet high on P0 and P1 at Standard, Opus high on P0 to P2 at Deep. Translator, only with two or more report languages: Sonnet medium. Below: the scripts that do discovery without a model, and the rules every subagent runs under.](../assets/model-allocation.svg)

## Model and effort per depth

| Role | Quick | Standard | Deep (default) |
|---|---|---|---|
| Recon | The lead, inline | `recon-mapper`: Sonnet / medium | `recon-mapper`: Sonnet / medium |
| Design lanes (`authz-logic`, `sensitive-data`, `ai-agentic`) | The lead, inline (up to three lanes in total) | `lane-reviewer`: Sonnet / high | `lane-reviewer`: **Opus / high** |
| Other lanes (`injection-dataflow`, `mobile`, `supply-chain-infra`, `perf-quality`) | The lead, inline | `lane-reviewer`: Sonnet / medium | `lane-reviewer`: Sonnet / high |
| Verifier | The lead re-checks P0 and P1 | `finding-verifier`: Sonnet / high, on P0 and P1 | `finding-verifier`: **Opus / high**, on P0 to P2 |
| Translator (two or more report languages) | `report-translator` when the Agent tool is available, else inline | `report-translator`: Sonnet / medium | `report-translator`: Sonnet / medium |

"The lead" is the main Claude Code session, running whatever model you started it with. A lane group that contains a design lane runs at the design-lane setting.

Why this split: design-level lanes need multi-file reasoning, where Opus pays off at Deep; scanner-assisted and configuration lanes are well scoped, so Sonnet is enough. Haiku is not used for security judgement.

## The subagents

| Subagent | Tools | Turn cap | Job |
|---|---|---|---|
| `security-audit-recon-mapper` | Read, Grep, Glob, Bash, Write | 60 | Attack-surface map: entry points, trust boundaries, abuse cases, hypotheses |
| `security-audit-lane-reviewer` | Read, Grep, Glob, Bash, Write | 120 | One lane or lane group: confirm or refute scanner candidates, hunt what scanners miss |
| `security-audit-finding-verifier` | Read, Grep, Glob, Bash, Write | 100 | Try to refute each candidate, merge duplicates, draft the findings |
| `security-audit-report-translator` | Read, Write, Bash | 20 | Translate `findings.json` and `narrative.json` into one other language |

Every subagent has Edit, NotebookEdit and Agent disallowed, a `maxTurns` cap, and `omitClaudeMd`, so your `CLAUDE.md` is not loaded into each one. Subagents never talk to you; every scoping decision is passed in their prompt. The skill passes `model` and `effort` explicitly on every call; an environment override such as `CLAUDE_CODE_EFFORT_LEVEL` wins, and the report records the model that actually ran.

If the named subagents are not installed yet, or were installed into a folder created during the session, the skill uses the general-purpose subagent with the same brief: the same result, more tokens. See [Install](install.md#install-the-subagents).

## How tokens are saved

- **Scripts hand subagents what they would otherwise discover.** Every lane gets the repository digest, the route map, the platform inventory, the advisory match and a redacted lane pack of code excerpts, which replace its first 20-40 Read and Grep turns. Every subagent turn re-sends its whole context, so saved turns are most of the saving.
- **Lane groups.** Lanes on a small repository read the same files, so they share subagents: three groups for a small repository (under 150 files), about five for a medium one, one subagent per lane for a large one (5000 files or more).
- **Auto-refuted candidates.** `normalize_findings.py` marks scanner candidates that are almost surely not real (placeholder secrets, vendored docs, production-only rules in test files); no lane spends turns on them, and they still appear under Refuted in the report.
- **The verifier reads one table.** `collect_lanes.py` condenses every lane file into `lanes/candidates.md`, about five times smaller.

## Measured cost and time

The repository's live benchmark runs real, headless Claude Code audits of three deliberately vulnerable projects pinned to exact commits (DVWA, NodeGoat, OWASP Juice Shop), at Quick depth, three runs per project and version. For the current version it measured, per audit:

| Measure | Value |
|---|---|
| Recall against ten documented vulnerability classes per project | <!--n:bench_recall_pct-->97<!--/n-->% |
| Mean cost | US$<!--n:bench_cost_usd-->2.52<!--/n--> |
| Mean wall-clock time | <!--n:bench_minutes-->8<!--/n--> minutes |
| Runs | <!--n:bench_runs-->9<!--/n--> |

Recall is scored by a script, never by a model. Precision is not measured: these projects have more bugs than their documentation lists, so a finding outside the ten classes is not necessarily a false positive. Three projects and three runs per cell are a small sample. Standard and Deep are not benchmarked.

Per-run numbers, the comparison with the previous version and the history of the benchmark: [benchmark/RESULTS.md](https://github.com/nguyenhx2/agent-security-audit/blob/main/benchmark/RESULTS.md). Method and how to reproduce it: [benchmark/README.md](https://github.com/nguyenhx2/agent-security-audit/blob/main/benchmark/README.md). The benchmark costs money and never runs in CI.

## See also

- [How an audit runs](how-it-works.md)
- [orchestration.md](https://github.com/nguyenhx2/agent-security-audit/blob/main/security-audit/reference/method/orchestration.md): the matrix, lane groups and prompt templates
- [Your first audit](first-audit.md#depths)
