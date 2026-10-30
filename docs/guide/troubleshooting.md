# Troubleshooting and FAQ

**English** · [日本語](ja/troubleshooting.md)

Start with `env_check.py --pretty` (see [Install](install.md#check-your-machine-with-env_checkpy)): most problems show up in its `choices` and `notes`.

## Scanners

### "no container engine answers" (run_scanners exit 3)

`run_scanners.py --mode container` found no Docker or Podman daemon. In the default `--mode auto`, the skill falls back to native scanners instead.

- If `env_check.py` shows `engine_installed_not_running`, start the engine: Docker Desktop, Podman Desktop or Rancher Desktop on Windows; Docker Desktop, OrbStack, `colima start` or `podman machine start` on macOS; `sudo systemctl start docker` on Linux. Then re-run.
- Or install the scanners natively (`env_check.py` prints per-tool commands for your OS under `install`).
- Or continue reading-only: the audit runs, and every scanner is listed as a coverage gap.

The skill offers these three options and asks before installing anything.

### "mount verification failed: /src resolved to 0 files" (exit 4)

The container saw an empty folder, so any scan result would be meaningless; the skill never reports such a scan. Causes and fixes:

- **File sharing.** The engine only sees shared host folders. Docker Desktop on macOS shares `/Users`, `/Volumes`, `/private` and `/tmp` by default; Colima and Lima mount `$HOME` (keep the repository and the audit folder under `$HOME`); podman machine on macOS shares `/Users`, `/private` and `/var/folders`. Add the share, or move the repository.
- **Wrong path.** Check that the path exists and uses the right form for your OS (next section).
- **SELinux.** The runner already adds `label=disable`; do not add `:z`.

### "no tool ran" (exit 5)

Every selected scanner failed or was skipped. Look at the per-tool lines `run_scanners.py` prints and at `coverage_gaps` in `work/<repo>/scanners.json`. With `--offline`, an image that is not cached is skipped, never pulled; run once online to pull it.

### "--out must be OUTSIDE the audited repo"

The runner refuses to write into the repository it audits. Use the default audit folder beside the repository.

### "pin for <tool> must carry an explicit tag (never :latest)"

`--pin` needs `image:tag` or `image:tag@sha256:...`. Use `run_scanners.py --check-updates` to find a tag, and see [Scanners](scanners.md#checking-for-newer-scanners).

### Coverage gap: "git history unavailable (no .git or shallow clone)"

The secret scan covered only the working tree. Deleted credentials stay in every clone's history, so audit a full clone (`git fetch --unshallow`) when you can.

### Coverage gap: "repo scanner config may suppress results"

The repository has a scanner config the skill cannot neutralise (`.gitleaksignore`, `.checkov.yaml`, `.semgrepignore`). Review what it suppresses; the report lists it.

## Paths and shells on Windows

- **Use `C:/Users/...` with forward slashes** in script arguments. Git Bash `/c/Users/...` is accepted and converted by the scripts (without that, it would silently resolve to `C:/c/Users`).
- **Never `/tmp`.** In Git Bash, `/tmp` points to a different folder for the Write tool and for Python, so files go missing.
- **Git Bash path conversion** can rewrite arguments such as `/src` or `C:\...` passed to `docker -v`. `run_scanners.py` builds container commands in Python without a shell, so this cannot happen to the scan; avoid calling `docker` by hand from Git Bash with such paths.
- **PowerShell prompts.** The skill runs its scripts through the Bash tool (Git Bash), which is pre-approved by the skill. PowerShell calls ask for permission. If Git Bash is missing, the wait loop falls back to PowerShell.
- **WSL.** Use the Linux `python3` and the Linux docker CLI with `/mnt/c/...` or `~/...` paths; a Windows `docker.exe` called from WSL needs `C:/...` paths instead. Repositories under `/mnt/c` scan slowly.

## Python

- **"no Python >= 3.9 found".** Install Python 3.9 or newer. On Windows the skill prefers the `py -3` launcher and avoids the Microsoft Store stub, so install Python with the `py` launcher.
- **"openpyxl missing".** Excel output needs `py -3 -m pip install openpyxl` (or `python3 -m pip install openpyxl`). The skill asks first; with `--yes` it skips Excel and says so in the reply. `env_check.py` prefers an interpreter that already has openpyxl.
- **`VERIFY SKIPPED`.** Neither Excel nor LibreOffice was found, so the workbook was rendered but not recalculated. Install LibreOffice (`soffice` on `PATH`) or accept the note in the reply.

## Japanese text and cp932 consoles

All scripts write UTF-8 to stdout and stderr, even on cp932 or cp1252 consoles and pipes, so they do not crash on Japanese text, and all files they write are UTF-8. If Japanese text looks garbled, the viewer is decoding UTF-8 as cp932: open the file as UTF-8, or switch the console to UTF-8 (`chcp 65001` in cmd).

## Advisory feeds

- **A feed is listed as a gap.** It timed out, answered with an error page, or is suspended. This is by design: the report states the gap rather than claiming the feed is clean. Re-running later usually fills it; a cached copy is reused and marked stale when available.
- **JVN iPedia is missing.** Its feed can be suspended; JVN and JPCERT/CC cover most of the gap.
- **The advisory step is slow.** NVD is rate-limited without a key. Set `NVD_API_KEY` in the environment to raise the limit.
- **No network allowed.** Say so when you start; the advisory step runs with `--offline` (cache only) and the report states it as a gap.
- **"named in alerts, version match unconfirmed".** A national alert names the product, but NVD's CPE data does not confirm the version yet. The lane compares the advisory's affected versions with the pin by reading it.

See [Live threat intelligence](threat-intelligence.md).

## Large repositories

- **Scans take longer.** Scanners run in the background with a 900-second timeout per tool (`--timeout`). The first image pull adds 1-5 minutes.
- **File caps.** `detect_stack.py` stops at 60,000 files and marks the profile `TRUNCATED`; `repo_digest.py` and `route_map.py` stop at 20,000, `platform_inventory.py` at 50,000. Each takes `--max-files` to raise the cap.
- **Lanes.** A repository with 5000 files or more gets one subagent per lane, and lane packs can be given a larger budget (`--budget-kb 90`).
- **Scope it.** Audit the services that matter as separate repositories in one run (`/security-audit ../api ../web`) rather than a whole monorepo at Deep.

## Subagents

- **The names are not in the Agent tool's list.** `install_agents.py` created `~/.claude/agents/security-audit/` during this session; Claude Code sees a new agents folder only after a restart. The skill uses the general-purpose fallback for this run; restart Claude Code before the next one.
- **"a file with the same name that it did not write".** `install_agents.py` never overwrites an agent file it does not own. Rename or remove your file if you want the skill's version.

## Cleanup

- **`prune_work.py` exits 1.** Some files could not be deleted (root-owned scanner output on Linux, read-only or locked files on Windows). It prints the exact fix command for your OS; run it and re-run `prune_work.py`.
- **"Refuses to run".** `prune_work.py` only runs once `reports/md/*.md` exists, that is, when the run is finished.

## The run

- **The skill warns that the target's hooks and instructions are live.** You started Claude Code inside the repository you are auditing, and it has `.claude/`, `.mcp.json` or `CLAUDE.md`. Start again from the parent folder.
- **An unattended run must not stop on a question.** Pass `--yes` (and a depth) so Phase 0 uses the defaults. After Phase 0 the skill never stops to ask.
- **The standards date is old.** More than 90 days after the standards baseline, the skill re-verifies the rows in scope before citing them. Update the skill to get a fresh baseline.

## FAQ

**Does it change my code?** No. It never edits, formats, commits, builds or runs audited code. All output goes to a folder beside the repository.

**Does it send my code anywhere?** No. Only product names and versions go to the advisory feeds; OSV-Scanner sends package names and versions to osv.dev. See [Security and privacy](security-and-privacy.md).

**Can I audit several repositories at once?** Yes: `/security-audit ../api ../web ../infra`. One audit folder, one report, cross-repo findings in section 5.

**Can I get Japanese reports from the English edition?** Yes. The English edition writes English, Japanese or both. The Japanese edition only changes the language of the skill's own instructions.

**Why does a finding say `needs-runtime-check`?** It depends on something a static audit cannot see, such as whether a port is published in production. Its Verification section names that fact and who can check it.

**Why was `perf-quality` not run?** It runs at Standard and Deep only; at Quick it is listed as a gap.

**Is the report a certificate?** No. It is evidence for a human decision. The verifier, the validator and the coverage-gaps table reduce misses and misjudgements; they do not remove them.

## See also

- [Install](install.md)
- [Scanners](scanners.md)
- [`platforms.md`](https://github.com/nguyenhx2/agent-security-audit/blob/main/security-audit/reference/tooling/platforms.md)
- [Contributing](contributing.md): report a bug
