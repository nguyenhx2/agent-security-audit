# Install

**English** · [日本語](ja/install.md)

There are two ways to install the skill: as a Claude Code plugin, or from a release zip. Both give you the same skill, named `security-audit`.

## Requirements

| Need | Details |
|---|---|
| Claude Code | The skill uses Claude Code features (`when_to_use`, `argument-hint`, named subagents with `effort` and `omitClaudeMd`). Older versions ignore the last two. |
| Python 3.9 or newer | Standard library only. `py -3` on Windows, `python3` on macOS and Linux. |
| `openpyxl` | Only for the Excel report: `python -m pip install openpyxl` (on Windows `py -3 -m pip install openpyxl`). |
| git | Git for Windows, Xcode command line tools or `brew install git` on macOS, the distro package on Linux. |
| Container engine (optional) | Docker or Podman runs the pinned scanners. Without one, native scanner installs work too; with neither, the audit runs reading-only and states every scanner as a gap. |
| Excel or LibreOffice (optional) | Only for `render_xlsx.py --verify`, which recalculates the workbook. |

### Per operating system

| | Windows | macOS | Linux and WSL |
|---|---|---|---|
| Python command | `py -3` (the launcher), else `python`; never the Microsoft Store stub | `python3` | `python3` |
| Shell the skill uses | Bash tool (Git Bash); PowerShell calls prompt for permission | bash or zsh | bash or sh |
| Paths in script arguments | `C:/Users/...` with forward slashes. Git Bash `/c/Users/...` is accepted. Never `/tmp`. | `/Users/...` | `/home/...`; in WSL, Windows drives are `/mnt/c/...` |
| Container engines | Docker Desktop, Podman Desktop, Rancher Desktop | Docker Desktop, OrbStack, Colima, Podman machine, Rancher Desktop | Docker Engine (rootful or rootless), Podman; in WSL, Docker Desktop's WSL integration or an engine inside WSL |
| Excel verify | Excel through COM | LibreOffice | LibreOffice |

The full table, with container engine caveats, is in [`platforms.md`](https://github.com/nguyenhx2/agent-security-audit/blob/main/security-audit/reference/tooling/platforms.md).

## Option 1: Claude Code plugin

In Claude Code:

```text
/plugin marketplace add nguyenhx2/agent-security-audit
/plugin install security-audit@agent-security-audit
```

The plugin is the English edition. To update later, run `/plugin update`.

## Option 2: release zip

Download a zip from the [latest release](https://github.com/nguyenhx2/agent-security-audit/releases/latest) and unzip it into your skills folder. Every release also carries an unversioned copy of each zip, so these permanent links always point at the newest one:

- English edition: `https://github.com/nguyenhx2/agent-security-audit/releases/latest/download/security-audit.zip`
- Japanese edition: `https://github.com/nguyenhx2/agent-security-audit/releases/latest/download/security-audit-ja.zip`

macOS, Linux, WSL and Git Bash:

```bash
unzip security-audit-X.Y.Z.zip -d ~/.claude/skills/
```

Windows PowerShell:

```powershell
Expand-Archive security-audit-X.Y.Z.zip -DestinationPath $HOME\.claude\skills\
```

Replace `X.Y.Z` with the version you downloaded. The archive holds one folder, `security-audit/`, with a `VERSION` file inside, so you can always tell which release is installed.

### Which zip to pick

| Zip | Pick it when |
|---|---|
| `security-audit-X.Y.Z.zip` (English edition) | Recommended for everyone. It writes reports in English, Japanese or both. |
| `security-audit-ja-X.Y.Z.zip` (Japanese edition) | Your team wants to read and maintain the skill's own instructions and reference material in Japanese. |

Both editions have the same code and pass the same self-test. Both install as `security-audit`, so install one or the other, never both. If you only need Japanese reports, the English edition is enough.

### Verify the download

Each release publishes `SHA256SUMS`, which lists the SHA-256 of every zip (versioned and unversioned). Download it next to the zip, then:

```bash
# Linux, WSL, Git Bash
sha256sum -c SHA256SUMS --ignore-missing

# macOS
shasum -a 256 security-audit-X.Y.Z.zip     # compare with the line in SHA256SUMS
```

```powershell
# Windows PowerShell
Get-FileHash security-audit-X.Y.Z.zip -Algorithm SHA256   # compare with the line in SHA256SUMS
```

With the GitHub CLI you can fetch both in one step: `gh release download vX.Y.Z -R nguyenhx2/agent-security-audit -p "security-audit-X.Y.Z.zip" -p SHA256SUMS`.

## Check your machine with env_check.py

The skill runs `env_check.py` as the first step of every audit. You can run it yourself to see what it will find. With a zip install:

```bash
py -3 ~/.claude/skills/security-audit/scripts/env_check.py --pretty      # Windows
python3 ~/.claude/skills/security-audit/scripts/env_check.py --pretty    # macOS, Linux, WSL
```

It probes the host in a few seconds, installs nothing and uses no network. The JSON ends with a `choices` block:

| Field | What it tells you |
|---|---|
| `scanner_mode` | `container` (an engine answers), `native` (scanners on `PATH`), or `reading-only` (neither). When an engine is installed but not running, `engine_installed_not_running` names it. |
| `script_prefix` | The Python command the skill will use, for example `py -3`. |
| `wait_loop` | How the skill waits for background scanners on this shell. |
| `path_format` | The path form to use in script arguments. |
| `excel_verify` | How the Excel workbook can be recalculated: Excel, LibreOffice, or not at all. |
| `install` | Per-tool install commands for missing scanners, when no engine is available. |
| `notes` | Warnings, for example "openpyxl missing" or "SELinux enforcing". |

### Container engine, native scanners or reading-only

- **Container engine (preferred).** Docker or Podman runs each scanner from an image pinned by digest, with the repository mounted read-only. Nothing else to install.
- **Native scanners.** With no engine, the skill uses scanners it finds on `PATH`. Install commands per OS are in `env_check.py`'s `install` block and in [`platforms.md`](https://github.com/nguyenhx2/agent-security-audit/blob/main/security-audit/reference/tooling/platforms.md). Installing software is your call; the skill asks first.
- **Reading-only.** With neither, the audit still runs: models read the code, the platform inventory and threat intelligence still work, and every scanner is listed as a coverage gap. A skipped scanner is never reported as clean.

See [Scanners](scanners.md) for details.

## Install the subagents

At Standard and Deep depth the skill uses four named subagents: `security-audit-recon-mapper`, `security-audit-lane-reviewer`, `security-audit-finding-verifier` and `security-audit-report-translator`. The skill installs them itself in Phase 0 by running `install_agents.py`, which writes only `~/.claude/agents/security-audit/*.md` and says so in one line.

To install or check them by hand (zip install path shown):

```bash
py -3 ~/.claude/skills/security-audit/scripts/install_agents.py --check   # exit 0 = installed and current, 1 = missing or outdated
py -3 ~/.claude/skills/security-audit/scripts/install_agents.py           # install or update (idempotent)
```

Claude Code picks up changes in an existing agents folder within seconds. If the folder is created during a session, the new names appear only after a restart; until then the skill uses the general-purpose subagent with the same brief, which gives the same result with more tokens.

`install_agents.py` writes only files it owns (each carries an `installed-by: security-audit` stamp). A file with the same name that it did not write is left alone and reported.

## Update

- **Plugin:** `/plugin update`.
- **Zip:** download the new zip, remove the old `~/.claude/skills/security-audit/` folder, and unzip the new one. Then run `install_agents.py` once (or let the next Standard or Deep audit do it), so the subagents match the new version.

Only the latest release receives fixes ([SECURITY.md](https://github.com/nguyenhx2/agent-security-audit/blob/main/SECURITY.md#supported-versions)).

## Uninstall

1. Remove the subagents: `py -3 <skill_dir>/scripts/install_agents.py --uninstall` (before removing the skill).
2. Remove the skill: `/plugin uninstall security-audit@agent-security-audit` for the plugin, or delete `~/.claude/skills/security-audit/` for a zip install.
3. Optional: delete the advisory feed cache at `~/.cache/security-audit/intel`.

Your audit folders (`<project>-security-audit/` beside each audited repository) are yours; delete them when you no longer need them.

## See also

- [Your first audit](first-audit.md)
- [Troubleshooting and FAQ](troubleshooting.md)
- [Releasing](https://github.com/nguyenhx2/agent-security-audit/blob/main/docs/RELEASING.md): what a release contains
