# Orchestration - subagents for Standard and Deep depth

Read this at Deep (the default) or Standard depth; Quick runs everything inline except translation (see Translator below). Procedure context:
`SKILL.md` Phases 0, 1, 4, 5, 7. `<skill_dir>` = the absolute path that `${CLAUDE_SKILL_DIR}` expanded
to in SKILL.md (forward slashes on Windows).

## Rules
- **Named agents first.** `scripts/install_agents.py` installs the four briefs in `agents/` as
  `security-audit-recon-mapper`, `-lane-reviewer`, `-finding-verifier`, `-report-translator`
  (`~/.claude/agents/security-audit/`). Use them as `subagent_type` when they appear in the Agent
  tool's list: each has its own tool allow-list (no Agent, no Edit), `maxTurns`, `omitClaudeMd`
  (CLAUDE.md is not loaded into every subagent), and the brief is already its system prompt, so the
  delegation prompt carries only parameters. **Fallback** (not installed, or installed this session
  in a folder that did not exist at start): `general-purpose` with "Read `<skill_dir>/agents/<brief>.md`
  and follow it." prepended - same result, more tokens.
- Launch independent subagents in ONE message so they run in parallel; each writes its result file
  and returns <= 5 lines. Do not poll or sleep: completions arrive as notifications; meanwhile do
  something else (sweep confirmation, data-model reading, narrative notes).
- Subagents cannot ask the user (AskUserQuestion is unavailable to them). Put every scoping
  decision (depth, focus, jurisdiction, format) into the delegation prompt.
- Pass `model` and `effort` on every Agent call per the matrix below - this skill explicitly
  requests these effort levels; the call overrides the agent file's defaults (environment overrides
  such as `CLAUDE_CODE_EFFORT_LEVEL` win; record the model that actually ran in the report's lanes line).
- Every lane and recon prompt gets the digest path (`<audit_dir>/work/<repo>/digest.md`) and the route map
  (`routes.md`), the platform inventory (`platform.md`) and, for lanes, the advisory match
  (`work/intel.md`); every lane group also gets its lane pack (`packs/<group>.md`). They replace each
  subagent's own Glob/Grep discovery: every subagent turn re-sends its whole context, so turns saved
  are most of the token saving (lanes are ~60% of a Deep audit's tokens).
- If the Agent tool is unavailable (this skill itself runs inside a subagent), run the lanes inline
  in the Quick order (authz-logic, the archetype's main lane, injection-dataflow, then the rest), do the verifier
  step yourself, and note "lanes run inline" in the report.

## Lane groups (token budget)
detect_stack's `lane_groups` packs lanes per repo size, because lanes on a small repo read the same
files: small (< 150 files) -> 3 subagents (`authz-logic+injection-dataflow`,
`sensitive-data+supply-chain-infra`, `ai-agentic|mobile+perf-quality`); medium -> one per design lane
plus `supply-chain-infra+perf-quality`; large (>= 5000 files) -> one per lane. Measured on a 36-file
agentic repo: 6 lanes x 140-170k tokens -> the same files read six times. Override only when the user
asks for maximum separation.

## Model / effort matrix

| Role | subagent_type (fallback: general-purpose) | Standard (model / effort) | Deep (model / effort) |
|------|-------------------------------------------|---------------------------|-----------------------|
| Recon (every repo at Standard/Deep) | `security-audit-recon-mapper` | sonnet / medium | sonnet / medium |
| Lane group containing authz-logic, sensitive-data or ai-agentic | `security-audit-lane-reviewer` | sonnet / high | opus / high |
| Other lane groups (injection-dataflow, mobile, supply-chain-infra, perf-quality) | `security-audit-lane-reviewer` | sonnet / medium | sonnet / high |
| Verifier | `security-audit-finding-verifier` | sonnet / high | opus / high |
| Translator (one per extra report language, 2+ languages only) | `security-audit-report-translator` | sonnet / medium | sonnet / medium |

Why: design-level lanes need multi-file reasoning (Opus pays off in Deep); SAST-assisted and config
lanes are well-scoped (Sonnet). Haiku is not used for security judgement - deterministic work is
already in scripts (Haiku did complete a Quick IaC audit in testing, so the skill degrades
gracefully, but lane judgement is weaker).

## Prompt templates (named agents; for the fallback prepend "Read <skill_dir>/agents/<brief>.md and follow it.")
Recon:
```
repo=<repo_path> profile=<audit_dir>/work/profile.md digest=<audit_dir>/work/<repo>/digest.md
routes=<audit_dir>/work/<repo>/routes.md platform=<audit_dir>/work/<repo>/platform.md
skill_dir=<skill_dir> out=<audit_dir>/work/<repo>/recon.md
```
Before launching the lanes (after recon returns), the lead runs once per lane group, all in one Bash call:
```
python <skill_dir>/scripts/lane_pack.py <repo_path> --digest-json <audit_dir>/work/<repo>/digest.json --routes <audit_dir>/work/<repo>/routes.json --lane <group> --out <audit_dir>/work/<repo>/packs/<group>.md
```
(`py -3` on Windows; default budget 60 KB; `--budget-kb 90` for a large-repo single-lane group.) The lead does
not Read the packs.

Lane group (one per `lane_groups` entry, all in one message):
```
repo=<repo_path> lane=<group, e.g. authz-logic+injection-dataflow> skill_dir=<skill_dir>
ai_scope=<detect ai_scope, for a group containing ai-agentic>
digest=<audit_dir>/work/<repo>/digest.md recon=<audit_dir>/work/<repo>/recon.md
pack=<audit_dir>/work/<repo>/packs/<group>.md routes=<audit_dir>/work/<repo>/routes.md
agent_config=<audit_dir>/work/<repo>/agent-config.md (group with ai-agentic)
platform=<audit_dir>/work/<repo>/platform.md intel=<audit_dir>/work/intel.md (every group; the
supply-chain-infra group owns the findings, others only follow pointers)
candidates=<audit_dir>/work/<repo>/candidates.jsonl (assigned: <categories / cids>)
sweep=<audit_dir>/work/<repo>/sweep.json standards=<module files in scope>
scope=<depth, focus, jurisdiction> out=<audit_dir>/work/<repo>/lanes/<group>.md
scratch=<audit_dir>/work/<repo>/scratch/<group>
```
Verifier (after all lanes return and `collect_lanes.py` has written `lanes/candidates.md`):
```
repo=<repo_path> repo_name=<repo> skill_dir=<skill_dir> candidates=<audit_dir>/work/<repo>/lanes/candidates.md
lanes_dir=<audit_dir>/work/<repo>/lanes min=<P2 Deep | P1 Standard>
lang=<source language: en, or the one report language when exactly one was chosen>
out=<audit_dir>/work/<repo>/lanes/verifier.md draft=<audit_dir>/work/<repo>/findings.draft.json
scratch=<audit_dir>/work/<repo>/scratch/verifier
```
Translator (only when two or more report languages were chosen; one per non-source language, all in
ONE message as soon as `<work>/narrative.json` exists - SKILL.md Phase 7 step 2b; build the
source-language set while they run. With one report language the verifier drafts in it and no
translator runs. At Quick, translation also uses translator subagents when the Agent tool is
available; inline only otherwise):
```
work=<audit_dir>/work source=<source lang> lang=<L>
out_findings=<audit_dir>/work/findings_<L>.json out_narrative=<audit_dir>/work/narrative_<L>.json
```
(`findings.json` / `narrative.json` are the canonical source - the source-language set is built from
them directly, never translated.)

Assign scanner candidates by `category` (secret -> sensitive-data, dependency/config ->
supply-chain-infra, code -> `mobile` for mobsfscan, else authz-logic or injection-dataflow by rule;
agent/LLM config hits -> ai-agentic) so no candidate is unowned;
with groups, give a group the union of its members' candidates. Skip candidates with `auto_refuted`
(already refuted by rule; they reach the report via the verifier's Refuted list).

## Running inside a harness-bootstrap control plane (optional)
If the workspace already has an audit control plane (read-only auditor agents, a findings tree, a
`protect-repos` hook), write findings into its tree and follow its task loop; everything else is the
same. If a hook guards the audit, test it on both sides - a block case exits non-zero AND a pass case
exits zero - before trusting it. A hook that blocks everything and one that blocks nothing both pass
one-sided tests.
