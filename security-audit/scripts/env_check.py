#!/usr/bin/env python3
"""
Probe the host once (Phase 0) and print JSON the agent follows: OS, the Python command for the
skill's scripts, openpyxl, shells, container engine, SELinux, native scanners, Excel verify method,
git - then a `choices` block (scanner mode, command prefix, wait loop, per-OS install alternatives).

Never installs anything, never uses the network. Every probe is time-bound (<= 10 s, run in parallel).
run_scanners.py imports detect_engine() / selinux_enforcing() from here so both agree.

Usage:
  python env_check.py [--pretty] [--engine auto|docker|podman]
"""
from __future__ import annotations

import sys
sys.dont_write_bytecode = True  # keep the installed skill free of __pycache__
for _s in (sys.stdout, sys.stderr):  # UTF-8 output even on cp932 / cp1252 consoles and pipes
    if hasattr(_s, "reconfigure"):
        _s.reconfigure(encoding="utf-8", errors="replace")

import argparse
import concurrent.futures as cf
import json
import os
import platform
import re
import shutil
import subprocess
from pathlib import Path

PROBE_TIMEOUT = 10
HERE = Path(__file__).resolve().parent  # probes run with this cwd (never the audited repo)
SCANNERS = ["gitleaks", "semgrep", "trivy", "osv-scanner", "checkov", "zizmor", "mobsfscan", "hadolint"]
CORE = ["gitleaks", "semgrep", "trivy", "osv-scanner"]  # run_scanners DEFAULT_TOOLS
REL = "release binary: https://github.com/{}/releases (checksum-verify; put on PATH)"
# tool -> manager -> install command. Versions match the pinned images where the manager can pin.
INSTALL = {
    "gitleaks": {"brew": "brew install gitleaks", "winget": "winget install Gitleaks.Gitleaks",
                 "scoop": "scoop install gitleaks", "choco": "choco install gitleaks",
                 "pacman": "sudo pacman -S gitleaks",
                 "go": "go install github.com/zricethezav/gitleaks/v8@v8.30.1",
                 "release": REL.format("gitleaks/gitleaks")},
    "semgrep": {"pipx": "pipx install semgrep==1.182.1", "brew": "brew install semgrep",
                "note_windows": "native Windows support is beta: prefer the container or WSL"},
    "trivy": {"brew": "brew install trivy", "winget": "winget install AquaSecurity.Trivy",
              "scoop": "scoop install trivy", "choco": "choco install trivy", "pacman": "sudo pacman -S trivy",
              "apt": "add the aquasecurity apt repo (trivy docs), then sudo apt-get install trivy",
              "dnf": "add the aquasecurity rpm repo (trivy docs), then sudo dnf install trivy",
              "release": REL.format("aquasecurity/trivy")},
    "osv-scanner": {"brew": "brew install osv-scanner", "winget": "winget install Google.OSVScanner",
                    "scoop": "scoop install osv-scanner",
                    "go": "go install github.com/google/osv-scanner/v2/cmd/osv-scanner@v2.7.0",
                    "release": REL.format("google/osv-scanner")},
    "checkov": {"pipx": "pipx install checkov==3.3.30", "brew": "brew install checkov"},
    "zizmor": {"pipx": "pipx install zizmor==1.31.1", "brew": "brew install zizmor",
               "pacman": "sudo pacman -S zizmor", "cargo": "cargo install zizmor --version 1.31.1"},
    "mobsfscan": {"pipx": "pipx install mobsfscan==1.0.1"},
    "hadolint": {"brew": "brew install hadolint", "scoop": "scoop install hadolint",
                 "release": REL.format("hadolint/hadolint")},
}
MANAGER_ORDER = {"windows": ["winget", "scoop", "choco", "pipx", "go", "cargo", "release"],
                 "macos": ["brew", "pipx", "go", "cargo", "release"],
                 "linux": ["apt", "dnf", "pacman", "brew", "pipx", "go", "cargo", "release"]}
MANAGER_BIN = {"apt": "apt-get"}


def probe(cmd: list[str], timeout: int = PROBE_TIMEOUT) -> subprocess.CompletedProcess | None:
    """Run a probe; None when the binary is missing, hangs, or cannot start."""
    try:
        return subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace",
                              timeout=timeout, cwd=str(HERE), stdin=subprocess.DEVNULL)
    except (OSError, subprocess.SubprocessError, ValueError):
        return None


def first_line(r: subprocess.CompletedProcess | None) -> str:
    if r is None or r.returncode != 0:
        return ""
    lines = ((r.stdout or "") + "\n" + (r.stderr or "")).strip().splitlines()
    return lines[0].strip()[:100] if lines else ""


def os_family() -> str:
    return {"win32": "windows", "darwin": "macos"}.get(sys.platform, "linux")


def detect_os() -> dict:
    fam = os_family()
    info = {"family": fam, "arch": platform.machine(), "wsl": False}
    if fam == "windows":
        info["version"] = f"Windows {platform.release()} ({platform.version()})"
        info["git_bash"] = bool(os.environ.get("MSYSTEM"))
    elif fam == "macos":
        info["version"] = "macOS " + (platform.mac_ver()[0] or platform.release())
    else:
        rel = ""
        try:
            rel = Path("/proc/sys/kernel/osrelease").read_text(encoding="utf-8", errors="replace").lower()
        except OSError:
            pass
        info["in_container"] = Path("/.dockerenv").exists() or Path("/run/.containerenv").exists()
        # a container on Docker Desktop also sees the WSL2 kernel ("microsoft" in osrelease): not WSL itself
        info["wsl"] = bool(os.environ.get("WSL_DISTRO_NAME")) or (
            "microsoft" in rel and not info["in_container"]
            and (Path("/proc/sys/fs/binfmt_misc/WSLInterop").exists() or Path("/run/WSL").exists()))
        osr = {}
        try:
            for line in Path("/etc/os-release").read_text(encoding="utf-8", errors="replace").splitlines():
                k, _, v = line.partition("=")
                osr[k] = v.strip().strip('"')
        except OSError:
            pass
        info["version"] = osr.get("PRETTY_NAME") or f"Linux {platform.release()}"
        info["distro_id"] = osr.get("ID", "")
    if fam != "windows":
        info["uid"], info["gid"] = os.getuid(), os.getgid()
    return info


_PY_PROBE = ("import sys,json\ntry:\n import openpyxl; o=openpyxl.__version__\nexcept Exception:\n o=None\n"
             "print(json.dumps({'v': list(sys.version_info[:3]), 'exe': sys.executable, 'openpyxl': o}))")


def python_candidates() -> list[list[str]]:
    c = [["py", "-3"], ["python"], ["python3"]] if os_family() == "windows" else [["python3"], ["python"]]
    return [x for x in c if shutil.which(x[0])]


def detect_python() -> dict:
    def one(cmd):
        r = probe(cmd + ["-B", "-E", "-c", _PY_PROBE])
        try:
            d = json.loads((r.stdout or "").strip().splitlines()[-1]) if r and r.returncode == 0 else None
        except (ValueError, IndexError):
            d = None
        if not d:
            return {"cmd": " ".join(cmd), "ok": False}
        return {"cmd": " ".join(cmd), "ok": tuple(d["v"]) >= (3, 9), "version": ".".join(map(str, d["v"])),
                "exe": d["exe"], "openpyxl": d["openpyxl"]}
    cands = list(_pool_map(one, python_candidates()))
    good = [c for c in cands if c["ok"]]
    pick = next((c for c in good if c["openpyxl"]), good[0] if good else None)
    return {"candidates": cands, "chosen": pick["cmd"] if pick else None,
            "version": pick["version"] if pick else None, "openpyxl": bool(pick and pick["openpyxl"]),
            "openpyxl_version": pick["openpyxl"] if pick else None}


def detect_shells() -> dict:
    return {"bash": bool(shutil.which("bash")), "pwsh": bool(shutil.which("pwsh")),
            "powershell": bool(shutil.which("powershell")), "SHELL": os.environ.get("SHELL", "")}


def selinux_enforcing() -> bool | None:
    """True/False on Linux; None elsewhere or when unknown."""
    if os_family() != "linux":
        return None
    try:
        return Path("/sys/fs/selinux/enforce").read_text(encoding="ascii").strip() == "1"
    except OSError:
        pass
    r = probe(["getenforce"]) if shutil.which("getenforce") else None
    if r is not None and r.returncode == 0:
        return r.stdout.strip().lower() == "enforcing"
    return False if not Path("/sys/fs/selinux").exists() else None


def _engine_info(binary: str, timeout: int = PROBE_TIMEOUT) -> dict:
    d = {"cmd": binary, "path": shutil.which(binary)}
    if not d["path"]:
        return d
    ver = first_line(probe([binary, "--version"]))
    d["version"] = ver
    d["is_podman"] = "podman" in ver.lower()
    r = probe([binary, "info", "--format", "{{json .}}"], timeout=timeout)
    d["daemon_ok"] = bool(r is not None and r.returncode == 0)
    if r is None:
        d["daemon_error"] = "no answer within %ss" % timeout
    elif r.returncode != 0:
        d["daemon_error"] = ((r.stderr or r.stdout or "").strip().splitlines() or [""])[-1][:200]
    if not d["daemon_ok"]:
        return d
    try:
        info = json.loads(r.stdout)
    except ValueError:
        info = {}
    low = r.stdout.lower()
    if d["is_podman"] or "podman" in low:
        d["is_podman"] = True
        host = info.get("host") or {}
        d["rootless"] = bool((host.get("security") or {}).get("rootless"))
        d["server_version"] = (info.get("version") or {}).get("Version", "")
        d["os"] = (host.get("distribution") or {}).get("distribution", "")
    else:
        d["rootless"] = any("rootless" in str(s) for s in info.get("SecurityOptions") or [])
        d["server_version"] = info.get("ServerVersion", "")
        d["os"] = info.get("OperatingSystem", "")
    ctx = first_line(probe([binary, "context", "show"])) if not d["is_podman"] else ""
    d["context"] = ctx
    hint = (d["os"] + " " + ctx).lower()
    d["runtime"] = next((n for k, n in (("docker desktop", "Docker Desktop"), ("desktop-linux", "Docker Desktop"),
                                        ("orbstack", "OrbStack"), ("colima", "Colima"),
                                        ("rancher", "Rancher Desktop"), ("lima", "Lima")) if k in hint),
                        "Podman" if d["is_podman"] else ("rootless Docker" if d["rootless"] else "Docker Engine"))
    return d


def detect_engine(prefer: str = "auto", timeout: int = PROBE_TIMEOUT) -> dict:
    """Container engine choice shared with run_scanners: docker (daemon answers) -> podman -> none.
    A `docker` that is really podman (podman-docker shim / alias) is reported as podman."""
    order = {"auto": ["docker", "podman"], "docker": ["docker"], "podman": ["podman"]}[prefer]
    infos = dict(zip(order, _pool_map(lambda b: _engine_info(b, timeout), order)))
    chosen = next((infos[b] for b in order if infos[b].get("daemon_ok")), None)
    res = {"installed": [b for b in order if infos[b].get("path")], "probes": infos}
    if chosen:
        res.update(engine="podman" if chosen["is_podman"] else "docker", cmd=chosen["cmd"],
                   runtime=chosen.get("runtime"), rootless=chosen.get("rootless", False),
                   podman_alias=chosen["is_podman"] and chosen["cmd"] == "docker", daemon_ok=True)
    else:
        res.update(engine=None, cmd=None, daemon_ok=False)
    return res


def detect_scanners() -> dict:
    def one(tool):
        p = shutil.which(tool)
        if not p:
            return tool, None
        for flag in (["--version"], ["version"]):
            v = first_line(probe([tool] + flag))
            if v:
                return tool, {"path": p, "version": v}
        return tool, {"path": p, "version": "unknown"}
    return dict(_pool_map(one, SCANNERS))


def _excel_registered() -> bool:
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, r"Excel.Application\CLSID"):
            return True
    except OSError:
        return False
    except ImportError:
        return False


def detect_excel_verify() -> dict:
    fam = os_family()
    res = {"excel_com": False, "libreoffice": None}
    if fam == "windows":  # ProgID lookup in the registry: never starts Excel or any UI
        res["excel_com"] = _excel_registered() and bool(shutil.which("powershell") or shutil.which("pwsh"))
    for name in ("soffice", "libreoffice"):
        if shutil.which(name):
            res["libreoffice"] = shutil.which(name)
            break
    if not res["libreoffice"]:
        extra = {"macos": ["/Applications/LibreOffice.app/Contents/MacOS/soffice"],
                 "windows": ["C:/Program Files/LibreOffice/program/soffice.exe",
                             "C:/Program Files (x86)/LibreOffice/program/soffice.exe"]}.get(fam, [])
        res["libreoffice"] = next((p for p in extra if Path(p).is_file()), None)
    res["method"] = "excel-com" if res["excel_com"] else ("libreoffice" if res["libreoffice"] else "none")
    return res


def detect_managers() -> dict:
    names = {"winget", "scoop", "choco", "brew", "apt", "dnf", "pacman", "pipx", "go", "cargo"}
    return {m: bool(shutil.which(MANAGER_BIN.get(m, m))) for m in sorted(names)}


def _pool_map(fn, items):
    items = list(items)
    if not items:
        return []
    with cf.ThreadPoolExecutor(max_workers=min(8, len(items))) as ex:
        return list(ex.map(fn, items))


def install_options(tool: str, fam: str, managers: dict) -> dict:
    table = INSTALL.get(tool, {})
    opts = []
    for m in MANAGER_ORDER[fam]:
        if m in table and not (fam == "windows" and m in ("apt", "dnf", "pacman", "brew")):
            opts.append({"via": m, "cmd": table[m], "available": m == "release" or managers.get(m, False)})
    rec = next((o for o in opts if o["available"]), None)
    if rec is None and opts:  # nothing usable yet: name the first route and what it needs
        rec = dict(opts[0], cmd=f"{opts[0]['cmd']}  (install {opts[0]['via']} first)")
    out = {"recommended": rec["cmd"] if rec else None, "alternatives": opts}
    if fam == "windows" and "note_windows" in table:
        out["note"] = table["note_windows"]
    return out


def choices(osi: dict, py: dict, sh: dict, eng: dict, scan: dict, xl: dict, managers: dict, sel) -> dict:
    fam = osi["family"]
    native = [t for t in CORE if scan.get(t)]
    if eng.get("daemon_ok"):
        mode = {"mode": "container", "engine": eng["engine"],
                "flags": "" if eng["engine"] == "docker" else "--engine podman"}
    elif native:
        mode = {"mode": "native", "flags": "--mode native", "tools_present": native}
    else:
        mode = {"mode": "reading-only", "flags": "",
                "say": "no container engine answers and no core scanner is on PATH: offer start engine / "
                       "install natively / reading-only with every scanner stated as a gap"}
    if eng.get("installed") and not eng.get("daemon_ok"):
        mode["engine_installed_not_running"] = eng["installed"]
    pwsh_only = fam == "windows" and not sh["bash"]
    shell = "powershell" if pwsh_only else ("bash" if sh["bash"] else "sh")
    wait = ('while (-not (Test-Path "<work>/<repo>/scanners.json")) { Start-Sleep 5 }' if pwsh_only
            else 'until [ -f "<work>/<repo>/scanners.json" ]; do sleep 5; done')
    paths = {"windows": "C:/... with forward slashes (Git Bash /c/... is accepted by the scripts; "
                        "never /tmp)",
             "macos": "/Users/... absolute; keep repo and --out under a path the container engine shares",
             "linux": "absolute POSIX paths"}[fam]
    if osi.get("wsl"):
        paths = ("absolute POSIX paths; Windows drives are /mnt/c/... (a Windows docker.exe needs C:/... "
                 "instead - use the Linux docker CLI from WSL)")
    missing = [t for t in SCANNERS if not scan.get(t)]
    notes = []
    if py["chosen"] and not py["openpyxl"]:
        notes.append(f"openpyxl missing: Excel output needs `{py['chosen']} -m pip install openpyxl` "
                     "(ask the user; with --yes skip Excel and say so)")
    if not py["chosen"]:
        notes.append("no Python >= 3.9 found: the skill's scripts cannot run - ask the user to install Python 3.9+")
    if sel:
        notes.append("SELinux enforcing: run_scanners adds --security-opt label=disable (never :z/:Z relabel)")
    if osi.get("wsl"):
        notes.append("WSL: run the skill's scripts with Linux python; repos under /mnt/c are slow to scan - "
                     "the Docker Desktop WSL integration mounts them fine")
    if eng.get("engine") == "podman" and eng.get("rootless"):
        notes.append("rootless podman: run_scanners adds --userns=keep-id so output stays owned by you")
    return {"scanner_mode": mode,
            "script_prefix": (py["chosen"] or "python3") + ' "${CLAUDE_SKILL_DIR}/scripts/<script>.py"',
            "wait_loop": {"shell": shell, "cmd": wait},
            "path_format": paths,
            "excel_verify": {"excel-com": "render_xlsx.py --verify",
                             "libreoffice": "render_xlsx.py without --verify, then the LibreOffice headless "
                                            "check in reference/tooling/platforms.md",
                             "none": "render_xlsx.py without --verify; state 'not recalculated in Excel'"}[xl["method"]],
            "install": {t: install_options(t, fam, managers) for t in missing} if mode["mode"] != "container" else {},
            "notes": notes}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--engine", choices=["auto", "docker", "podman"], default="auto")
    ap.add_argument("--pretty", action="store_true", help="indent the JSON")
    a = ap.parse_args()
    with cf.ThreadPoolExecutor(max_workers=6) as ex:
        f = {"os": ex.submit(detect_os), "python": ex.submit(detect_python), "engine": ex.submit(detect_engine, a.engine),
             "scanners": ex.submit(detect_scanners), "excel": ex.submit(detect_excel_verify),
             "git": ex.submit(lambda: first_line(probe(["git", "--version"])) or None)}
        r = {k: v.result() for k, v in f.items()}
    r["shells"], r["managers"], r["selinux_enforcing"] = detect_shells(), detect_managers(), selinux_enforcing()
    r["choices"] = choices(r["os"], r["python"], r["shells"], r["engine"], r["scanners"], r["excel"],
                           r["managers"], r["selinux_enforcing"])
    order = ["os", "python", "shells", "engine", "selinux_enforcing", "scanners", "excel", "git", "managers", "choices"]
    print(json.dumps({k: r[k] for k in order}, indent=1 if a.pretty else None, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
