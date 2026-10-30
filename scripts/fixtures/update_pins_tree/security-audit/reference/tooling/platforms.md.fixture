# Platforms - Windows, macOS, Linux (incl. WSL)

Run `env_check.py` first; use its `choices`. It probes the host in a few seconds (no install, no
network) and prints the Python command, scanner mode, wait loop, path format, Excel verify method
and per-tool install routes for THIS OS. The table below is the fallback when a probe is unclear.

## Decision table

| | Windows | macOS | Linux / WSL |
|---|---|---|---|
| Python for scripts | `py -3` (launcher) else `python`; never the MS Store stub | `python3` | `python3` |
| Shell | Bash tool (Git Bash) - pre-approved; PowerShell prompts | bash / zsh | bash / sh |
| Wait for `scanners.json` (background) | Git Bash: `until [ -f "<f>" ]; do sleep 5; done`; PowerShell only: `while (-not (Test-Path "<f>")) { Start-Sleep 5 }` | `until [ -f "<f>" ]; do sleep 5; done` | same |
| Script path args | `C:/Users/...` (forward slashes). Git Bash `/c/Users/...` is converted by the scripts, but never `/tmp` (Write tool and Python disagree) | `/Users/...` | `/home/...`; WSL: Windows drives are `/mnt/c/...` |
| Container engine | Docker Desktop, Podman Desktop, Rancher Desktop | Docker Desktop, OrbStack, Colima, Podman machine, Rancher Desktop | Docker Engine (rootful / rootless), Podman; WSL: Docker Desktop WSL integration or an engine inside WSL |
| Excel verify | `excel-com` (`render_xlsx.py --verify`) | `libreoffice` | `libreoffice` |
| git | Git for Windows | Xcode CLT `git` or `brew install git` | distro `git` |

Script prefix stays exactly `<python> "${CLAUDE_SKILL_DIR}/scripts/<script>.py"` - the pre-approved
`allowed-tools` patterns match that form; the scripts disable `__pycache__` themselves (no `-B` needed).

## Container engine caveats

- Selection: `run_scanners.py --engine auto` = docker if its daemon answers, else podman (a `docker`
  that is really podman is treated as podman). Force with `--engine docker|podman`. Exit 3 = no engine
  answers: tell the user which one is installed but stopped (`env_check` -> `engine_installed_not_running`).
- File sharing: the engine sees only shared host folders. Docker Desktop (macOS) shares `/Users`,
  `/Volumes`, `/private`, `/tmp` by default; Colima and Lima mount `$HOME` (plus `/tmp/colima`) - keep
  repo and `--out` under `$HOME`; OrbStack shares the whole Mac filesystem; podman machine (macOS) shares `/Users`, `/private`, `/var/folders`.
  A missing share shows as exit 4 (mount verification: 0 files) - fix the share, never trust the scan.
- Root-owned output (Linux rootful Docker): run_scanners runs every container as your `uid:gid` with
  `HOME=/tmp`, chowns the trivy cache volume once, and afterwards chowns anything still foreign back
  with an already-pinned image. Rootless Docker: container root is you (no `--user`). Podman rootless:
  `--userns=keep-id`. Decisions land in `scanners.json` -> `container`.
- SELinux enforcing (Fedora, RHEL, podman machine): `--security-opt label=disable`. Never `:z` / `:Z` -
  relabelling writes xattrs into the audited repo.
- WSL: use the Linux `python3` and the Linux docker CLI with `/mnt/c/...` or `~/...` paths. A Windows
  `docker.exe` called from WSL needs `C:/...` paths instead. Repos on `/mnt/c` scan slowly.
- Windows: unchanged - Docker Desktop maps ownership; no `--user`.

## Native scanner installs (only when the user agrees - installing is their call)

| Tool | Windows | macOS | Linux |
|---|---|---|---|
| gitleaks | `winget install Gitleaks.Gitleaks` / scoop / choco | `brew install gitleaks` | pacman, brew, `go install github.com/zricethezav/gitleaks/v8@v8.30.1`, release binary |
| semgrep | container or WSL (native is beta: `pipx install semgrep==1.181.0`) | `brew install semgrep` / pipx | `pipx install semgrep==1.181.0` |
| trivy | `winget install AquaSecurity.Trivy` / scoop / choco | `brew install trivy` | aquasecurity apt / rpm repo, pacman, release binary |
| osv-scanner | `winget install Google.OSVScanner` / scoop | `brew install osv-scanner` | `go install github.com/google/osv-scanner/v2/cmd/osv-scanner@v2.7.0`, release binary |
| checkov | `pipx install checkov==3.3.29` | brew / pipx | pipx |
| zizmor | `pipx install zizmor==1.31.1` | brew / pipx | pipx, pacman, cargo |
| mobsfscan | `pipx install mobsfscan==1.0.1` | pipx | pipx |
| hadolint | scoop / release binary | `brew install hadolint` | release binary, brew |

pipx itself: `py -m pip install --user pipx` (Windows), `brew install pipx`, `apt install pipx` /
`dnf install pipx`. Release binaries: download from the project's GitHub releases and verify the checksum.

## Excel verify alternatives

1. `excel-com` (Windows + Excel): `render_xlsx.py <report.md> --verify` - real Excel recalculation.
2. `libreoffice` (`soffice` on PATH, or `/Applications/LibreOffice.app/Contents/MacOS/soffice`):
   `--verify` picks it automatically (or `--verify-with libreoffice`); runs headless with a throw-away
   profile (always-recalculate), then checks formula errors, the total and the 4 charts.
3. `none`: render without `--verify` (it prints `VERIFY SKIPPED`, exit 0) and say "workbook not
   recalculated" in the reply. Missing openpyxl: `<python> -m pip install openpyxl` (ask first).
