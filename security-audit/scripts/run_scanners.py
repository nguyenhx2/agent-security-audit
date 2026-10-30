#!/usr/bin/env python3
"""
Run the deterministic scanner layer (Phase 3) against one repo, read-only.

Mode resolution: --mode auto tries a container engine (docker, else podman; daemon reachable) ->
native binaries on PATH -> none. Container runs mount the source READ-ONLY and verify the mount
resolved (file count > 0) before any result is believed. Image digests and native versions are
recorded for re-scan reproducibility. Tools run in parallel.
Output: <out>/raw/<tool>.(sarif|json) + <out>/scanners.json manifest.

Linux / macOS: containers run as your uid:gid (HOME=/tmp, trivy cache volume chowned once) so no
root-owned output is left; rootless docker runs as container root (= you); podman gets
--userns=keep-id. SELinux enforcing (or podman): --security-opt label=disable - never :z/:Z, which
would relabel (write xattrs into) the audited repo. Anything still not owned by you afterwards is
chowned back with an already-pinned image. Decisions are recorded under "container" in scanners.json.

Usage:
  python run_scanners.py <repo> --out <dir> [--tools gitleaks,semgrep,trivy,osv-scanner,checkov,
        hadolint,zizmor] [--mode auto|container|docker|native] [--engine auto|docker|podman]
        [--pin tool=image:tag ...] [--timeout 900] [--offline] [--list]
  python run_scanners.py --check-updates [--offline] [--json PATH]
        report-only: newest stable tag per pinned image; never pulls, never changes a pin, exit 0

Python is used (not a shell script) so Windows paths reach `docker -v` unmangled - Git Bash's MSYS
path conversion is the classic cause of a silently-empty /src mount.
"""
from __future__ import annotations

import sys
sys.dont_write_bytecode = True  # keep the installed skill free of __pycache__
for _s in (sys.stdout, sys.stderr):  # UTF-8 output even on cp932 / cp1252 consoles and pipes
    if hasattr(_s, "reconfigure"):
        _s.reconfigure(encoding="utf-8", errors="replace")

import argparse
import concurrent.futures as cf
import datetime as dt
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import env_check  # noqa: E402
import safegit  # noqa: E402

TRIVY_CACHE_VOLUME = "security-audit-trivy-cache"  # trivy DB lives in <volume>/trivy (mounted at /cache)
CHOWN_IMAGES = ["gitleaks", "trivy", "semgrep", "checkov", "osv-scanner"]  # images with sh + chown
# Set once in main() from detect_engine(); module-level so the parallel workers share them.
ENGINE = "docker"   # binary that is invoked (docker / podman / a docker alias of podman)
RUN_OPTS: list[str] = []   # engine-wide run options (SELinux label, userns)
USER_OPTS: list[str] = []  # non-root identity for the scan containers (POSIX hosts only)

PINS_VERIFIED = "2026-10-30"  # re-verify tags when this date is old; override with --pin
# tool -> docker image:tag. Never use :latest (Trivy's March 2026 compromise shipped via tags).
IMAGES = {  # tag for humans + digest for reproducibility (recorded on first verified pull)
    "gitleaks": "ghcr.io/gitleaks/gitleaks:v8.30.1@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f",
    "semgrep": "semgrep/semgrep:1.182.1@sha256:451b3d875c00dac7ed5db5293e584a07de11449a409c10b3c2d2652f429630b6",
    "trivy": "aquasec/trivy:0.76.1@sha256:790fd66d1697395d8693d1acaa1ea702406a20f109b6fc7bac8db623eca6c06c",
    "osv-scanner": "ghcr.io/google/osv-scanner:v2.7.0@sha256:4f3b7e2c64b9d38a5febc5a7e4a3dfef1d1362f726dea7a2ef4762b46469fcd0",
    "checkov": "bridgecrew/checkov:3.3.30@sha256:4b65e89f1fde292249fc0aa0d0db43302c036dfe39f7370b2d3517571082b894",
    "hadolint": "hadolint/hadolint:v2.15.1@sha256:32dac94127fd60b7b7e3fbfc65e1383b9b5e25c9bfd7b8536de7a539fe68a12d",
    "zizmor": "ghcr.io/zizmorcore/zizmor:1.31.1@sha256:42d409dbb851d4c5d35a058cf042b828bea1e3f2884378c526eb0974780e18d9",
    "mobsfscan": "opensecurity/mobsfscan:1.0.1@sha256:2e613d872b8199b092f96676e8525464d8319ef588541e8b5b2a2efff7cd8d39",
}
DEFAULT_TOOLS = ["gitleaks", "semgrep", "trivy", "osv-scanner"]
EXPECTED = {
    "gitleaks": ["gitleaks-git.sarif", "gitleaks-dir.sarif"], "semgrep": ["semgrep.sarif", "semgrep.json"],
    "trivy": ["trivy.sarif"], "osv-scanner": ["osv-scanner.sarif"], "checkov": ["checkov/results_sarif.sarif"],
    "zizmor": ["zizmor.sarif"], "hadolint": ["hadolint.sarif"], "mobsfscan": ["mobsfscan.sarif"],
}
# safe.directory=* lets gitleaks read a repo owned by another user; fsmonitor off so its .git/config
# cannot start a command. Diff drivers are switched off per call (GIT_LOG_OPTS).
GIT_SAFE_ENV = {"GIT_CONFIG_COUNT": "2", "GIT_CONFIG_KEY_0": "safe.directory", "GIT_CONFIG_VALUE_0": "*",
                "GIT_CONFIG_KEY_1": "core.fsmonitor", "GIT_CONFIG_VALUE_1": "false"}
GIT_LOG_OPTS = "--log-opts=--all --no-textconv --no-ext-diff"  # repo textconv / external diff never run
# Repo files that can suppress results. Ours replace the repo's where the tool has a flag (written into
# raw/ at run time, verified against the pinned versions); the rest are honoured and stated as a gap.
GITLEAKS_TOML = ('title = "security-audit: gitleaks default rules (the repo .gitleaks.toml is not used)"\n\n'
                 '[extend]\nuseDefault = true\n')
OWN_CONFIGS = {"gitleaks-config.toml": GITLEAKS_TOML, "empty.gitleaksignore": "", "osv-scanner.toml": ""}
REPO_CONFIGS_NEUTRALISED = [".gitleaks.toml", "zizmor.yml", ".github/zizmor.yml", "osv-scanner.toml",
                            ".trivyignore", "trivy.yaml"]  # --config / --no-config / cwd outside the repo
REPO_CONFIGS_HONOURED = [".gitleaksignore", ".checkov.yaml", ".checkov.yml", ".semgrepignore"]
COVERAGE = {
    "gitleaks": "secrets: full git history (all refs) + working tree",
    "semgrep": "SAST p/default ruleset; weak/no coverage for some languages - see detect_stack gaps",
    "trivy": "dependency CVEs (lockfiles), IaC/Dockerfile misconfig, licenses",
    "osv-scanner": "dependency CVEs via OSV.dev (lockfile-precise)",
    "checkov": "IaC misconfig: Terraform, CloudFormation, K8s, Helm, Dockerfile, GH Actions",
    "hadolint": "Dockerfile best practices + embedded ShellCheck",
    "zizmor": "GitHub Actions workflow security (offline audits only)",
    "mobsfscan": "mobile source SAST: Android Java/Kotlin, iOS Swift/ObjC, manifests, plists",
}


def host_path(p: str) -> str:
    """Accept Git-Bash style /c/Users/... on Windows (otherwise it silently resolves to C:/c/Users)."""
    if os.name == "nt":
        m = re.match(r"^/([a-zA-Z])(/.*)?$", p or "")
        if m:
            return f"{m.group(1).upper()}:{m.group(2) or '/'}"
    return p


def gitleaks_cfg(o: str) -> list[str]:
    """Our default-rules config + an empty ignore file (both in raw/) instead of the repo's; inline
    gitleaks:allow comments are ignored too. <repo>/.gitleaksignore is still read (no flag) - stated."""
    return ["--config", f"{o}/gitleaks-config.toml", "--gitleaks-ignore-path", f"{o}/empty.gitleaksignore",
            "--ignore-gitleaks-allow"]


def repo_scanner_configs(root: Path) -> dict:
    """Repo files that can suppress scanner results (recorded in scanners.json; honoured ones are a gap)."""
    return {"neutralised": [f for f in REPO_CONFIGS_NEUTRALISED if (root / f).is_file()],
            "honoured": [f for f in REPO_CONFIGS_HONOURED if (root / f).is_file()]}


def sh(cmd: list[str], timeout: int = 60, env: dict | None = None, cwd=None) -> subprocess.CompletedProcess:
    full_env = None
    if env:
        full_env = dict(os.environ)
        full_env.update(env)
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=full_env, cwd=cwd,
                          encoding="utf-8", errors="replace")


def container_plan(eng: dict) -> dict:
    """Engine-wide options and the identity scan containers run as. Windows hosts: unchanged (none)."""
    plan = {"engine": eng.get("engine"), "cmd": eng.get("cmd"), "runtime": eng.get("runtime"),
            "rootless": eng.get("rootless", False), "podman_alias": eng.get("podman_alias", False),
            "run_opts": [], "user_opts": [], "user": "image default"}
    podman = eng.get("engine") == "podman"
    sel = env_check.selinux_enforcing()
    plan["selinux_enforcing"] = sel
    if sel or podman:  # read the ro mount without relabelling it (podman machines run SELinux too)
        plan["run_opts"] += ["--security-opt", "label=disable"]
    if os.name == "nt":
        plan["user"] = "image default (Windows host: Docker Desktop maps ownership)"
        return plan
    uid, gid = os.getuid(), os.getgid()
    if podman and plan["rootless"]:
        plan["run_opts"].append("--userns=keep-id")
        plan["user_opts"] = ["--user", f"{uid}:{gid}", "-e", "HOME=/tmp"]
        plan["user"] = f"{uid}:{gid} (podman keep-id)"
    elif uid == 0:
        plan["user"] = "root (invoked as root)"
    elif plan["rootless"]:
        plan["user"] = "container root = you (rootless docker)"
    else:
        plan["user_opts"] = ["--user", f"{uid}:{gid}", "-e", "HOME=/tmp"]
        plan["user"] = f"{uid}:{gid}"
    return plan


def prep_trivy_cache(image: str) -> bool:
    """Give the scan uid the trivy cache volume (one root shot on a named volume, never the repo)."""
    if not USER_OPTS:
        return True
    ug = USER_OPTS[1]
    try:
        r = sh([ENGINE, "run", "--rm", *RUN_OPTS, "--user", "0:0", "-v", f"{TRIVY_CACHE_VOLUME}:/cache",
                "--entrypoint", "sh", image, "-c", f"mkdir -p /cache/trivy && chown -R {ug} /cache"], timeout=300)
        return r.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def foreign_owned(out: Path) -> list[str]:
    """Paths under out/ not owned by the current uid (POSIX). Root-owned scanner output blocks cleanup."""
    if os.name == "nt":
        return []
    uid, bad = os.getuid(), []
    for dirpath, dirnames, filenames in os.walk(out):
        for n in dirnames + filenames:
            p = Path(dirpath, n)
            try:
                if p.lstat().st_uid != uid:
                    bad.append(str(p))
            except OSError:
                pass
    return bad


def fix_ownership(out: Path, a) -> dict:
    """Fallback: chown out/ back to the current uid with an already-cached pinned image."""
    bad = foreign_owned(out)
    rec = {"foreign_before": len(bad)}
    if not bad:
        return rec
    ug = f"{os.getuid()}:{os.getgid()}"
    for tool in CHOWN_IMAGES:
        image = a.pins.get(tool, IMAGES[tool])
        try:
            if sh([ENGINE, "image", "inspect", image], timeout=60).returncode != 0:
                continue
            r = sh([ENGINE, "run", "--rm", *RUN_OPTS, "--user", "0:0", "--network", "none", "-v", f"{out}:/fix",
                    "--entrypoint", "chown", image, "-R", ug, "/fix"], timeout=300)
        except (OSError, subprocess.TimeoutExpired):
            continue
        if r.returncode == 0:
            rec["chowned_with"] = image
            break
    left = foreign_owned(out)
    rec["remaining"] = len(left)
    if left:
        rec["fix_cmd"] = f"sudo chown -R {ug} '{out}'"
    return rec


def docker_ok() -> bool:
    """Kept for callers of the old API: True when any container engine answers."""
    return bool(env_check.detect_engine("auto", timeout=20).get("daemon_ok"))


def docker_cmds(tool: str, offline: bool) -> tuple[list[str], list[str], dict]:
    """Return (extra docker run args, container args, env)."""
    if tool == "gitleaks":
        # two passes are joined in run_tool; this is the history pass
        return ["--network", "none"], ["git", "/src", GIT_LOG_OPTS] + gitleaks_cfg("/out") + [
            "--redact", "--no-banner", "-f", "sarif", "-r", "/out/gitleaks-git.sarif", "--exit-code", "0"], GIT_SAFE_ENV
    if tool == "semgrep":
        return ["-e", "SEMGREP_SEND_METRICS=off"], [
            "semgrep", "scan", "--config", "p/default", "--metrics", "off", "--quiet", "--disable-nosem",
            "--sarif-output=/out/semgrep.sarif", "--json-output=/out/semgrep.json", "/src"], {}
    if tool == "trivy":
        extra = ["-v", f"{TRIVY_CACHE_VOLUME}:/cache"]  # same volume as before (was mounted at /root/.cache)
        args = ["fs", "--cache-dir", "/cache/trivy", "--scanners", "vuln,misconfig", "--quiet", "--format", "sarif",
                "--output", "/out/trivy.sarif"]
        if offline:
            args += ["--skip-db-update", "--skip-check-update", "--offline-scan"]
        return extra, args + ["/src"], {}
    if tool == "osv-scanner":
        args = ["scan", "source", "-r", "--config", "/out/osv-scanner.toml", "--format", "sarif",
                "--output-file", "/out/osv-scanner.sarif"]
        if offline:
            args += ["--offline-vulnerabilities"]
        return [], args + ["/src"], {}
    if tool == "checkov":
        return [], ["-d", "/src", "-o", "sarif", "--output-file-path", "/out/checkov", "--quiet",
                    "--compact", "--soft-fail"], {}
    if tool == "zizmor":
        return [], ["--offline", "--no-config", "--no-ignores", "--format", "sarif", "/src"], {}  # stdout to file
    if tool == "mobsfscan":
        return [], ["/src", "--sarif", "-o", "/out/mobsfscan.sarif"], {}
    if tool == "hadolint":
        return [], [], {}  # handled specially (per Dockerfile)
    raise ValueError(tool)


def native_cmds(tool: str, src: str, out: Path, offline: bool) -> tuple[list[str], dict] | None:
    o = str(out)
    if tool == "gitleaks" and shutil.which("gitleaks"):
        return ["gitleaks", "git", src, GIT_LOG_OPTS] + gitleaks_cfg(o) + [
            "--redact", "--no-banner", "-f", "sarif", "-r", f"{o}/gitleaks-git.sarif", "--exit-code", "0"], {}
    if tool == "semgrep" and shutil.which("semgrep"):
        return ["semgrep", "scan", "--config", "p/default", "--metrics", "off", "--quiet", "--disable-nosem",
                f"--sarif-output={o}/semgrep.sarif", f"--json-output={o}/semgrep.json", src], \
            {"SEMGREP_SEND_METRICS": "off"}
    if tool == "trivy" and shutil.which("trivy"):
        args = ["trivy", "fs", "--scanners", "vuln,misconfig", "--quiet", "--format", "sarif",
                "--output", f"{o}/trivy.sarif"]
        if offline:
            args += ["--skip-db-update", "--skip-check-update", "--offline-scan"]
        return args + [src], {}
    if tool == "osv-scanner" and shutil.which("osv-scanner"):
        args = ["osv-scanner", "scan", "source", "-r", "--config", f"{o}/osv-scanner.toml", "--format", "sarif",
                "--output-file", f"{o}/osv-scanner.sarif"]
        if offline:
            args += ["--offline-vulnerabilities"]
        return args + [src], {}
    if tool == "checkov" and shutil.which("checkov"):
        return ["checkov", "-d", src, "-o", "sarif", "--output-file-path", f"{o}/checkov", "--quiet",
                "--compact", "--soft-fail"], {}
    if tool == "zizmor" and shutil.which("zizmor"):
        return ["zizmor", "--offline", "--no-config", "--no-ignores", "--format", "sarif", src], {}
    if tool == "mobsfscan" and shutil.which("mobsfscan"):
        return ["mobsfscan", src, "--sarif", "-o", f"{o}/mobsfscan.sarif"], {}
    if tool == "hadolint" and shutil.which("hadolint"):
        return ["hadolint"], {}
    return None


def image_digest(image: str) -> str:
    r = sh([ENGINE, "image", "inspect", "--format", "{{json .RepoDigests}}", image])
    try:
        digests = json.loads(r.stdout.strip() or "[]")
        return digests[0] if digests else "unknown"
    except ValueError:
        return "unknown"


def native_version(binary: str) -> str:
    for flag in ("--version", "version"):
        try:
            r = sh([binary, flag], timeout=30)
            text = (r.stdout or r.stderr).strip().splitlines()
            if r.returncode == 0 and text:
                return text[0][:80]
        except (OSError, subprocess.TimeoutExpired):
            pass
    return "unknown"


def verify_mount(src: str, image: str) -> int:
    """Count files visible at /src inside a container. 0 => mount failed; never trust a clean scan."""
    for entry in (["--entrypoint", "sh", image, "-c", "find /src -type f 2>/dev/null | wc -l"],
                  ["--entrypoint", "sh", IMAGES["gitleaks"], "-c", "find /src -type f | wc -l"]):
        try:
            r = sh([ENGINE, "run", "--rm", *RUN_OPTS, *USER_OPTS, "-v", f"{src}:/src:ro"] + entry, timeout=300)
            if r.returncode == 0 and r.stdout.strip().isdigit():
                return int(r.stdout.strip())
        except subprocess.TimeoutExpired:
            pass
    return -1


def find_dockerfiles(root: Path) -> list[str]:
    hits = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in {".git", "node_modules", "vendor"}]
        for fn in filenames:
            n = fn.lower()
            if n == "dockerfile" or n.endswith(".dockerfile") or n.startswith("dockerfile."):
                hits.append(Path(dirpath, fn).relative_to(root).as_posix())
    return hits[:50]


def run_tool(tool: str, mode: str, root: Path, raw: Path, a) -> dict:
    rec = {"tool": tool, "mode": mode, "coverage": COVERAGE.get(tool, ""), "outputs": []}
    if tool == "osv-scanner" and a.offline:
        # OSV has no bundled DB: offline it silently finds nothing, which would read as "clean".
        rec.update(status="skipped", reason="osv-scanner needs network (no local vulnerability DB) - "
                                            "dependency coverage from trivy's cached DB only")
        return rec
    t0 = time.time()
    src = str(root)
    try:
        if mode == "docker":
            image = a.pins.get(tool, IMAGES[tool])
            rec["image"] = image
            have = sh([ENGINE, "image", "inspect", image], timeout=60).returncode == 0
            if not have:
                if a.offline:
                    rec.update(status="skipped", reason=f"--offline and image not cached: {image}")
                    return rec
                pull = sh([ENGINE, "pull", "-q", image], timeout=900)
                if pull.returncode != 0:
                    rec.update(status="failed", reason=f"pull failed: {pull.stderr.strip()[:300]}")
                    return rec
            rec["digest"] = image_digest(image)
            user = USER_OPTS
            if tool == "trivy" and USER_OPTS and not prep_trivy_cache(image):
                user = []  # cache volume not ours: run as image default; fix_ownership() chowns the output
                rec["user"] = "image default (trivy cache prep failed)"
            base = [ENGINE, "run", "--rm", *RUN_OPTS, *user, "-v", f"{src}:/src:ro", "-v", f"{raw}:/out"]
            if tool == "hadolint":
                files = find_dockerfiles(root)
                results = []
                for f in files:
                    r = sh(base + ["--network", "none", image, "hadolint", "-f", "sarif", f"/src/{f}"], timeout=a.timeout)
                    results.append(r.stdout)
                merged = merge_sarif(results)
                (raw / "hadolint.sarif").write_text(json.dumps(merged), encoding="utf-8")
                rec.update(status="ok", targets=files)
            else:
                extra, args, env = docker_cmds(tool, a.offline)
                envargs = sum((["-e", f"{k}={v}"] for k, v in env.items()), [])
                cmd = base + extra + envargs + [image] + args
                r = sh(cmd, timeout=a.timeout)
                rec["exit_code"] = r.returncode
                if tool == "zizmor":
                    (raw / "zizmor.sarif").write_text(r.stdout, encoding="utf-8")
                if tool == "gitleaks":  # second pass: working tree (catches untracked/ignored files)
                    r2 = sh(base + extra + envargs + [image, "dir", "/src"] + gitleaks_cfg("/out") + [
                        "--redact", "--no-banner", "-f", "sarif", "-r", "/out/gitleaks-dir.sarif", "--exit-code",
                        "0"], timeout=a.timeout)
                    rec["exit_code_dir"] = r2.returncode
                rec["stderr_tail"] = (r.stderr or "").strip()[-400:]
        else:
            nc = native_cmds(tool, src, raw, a.offline)
            if nc is None:
                rec.update(status="skipped", reason=f"{tool} not on PATH" +
                           ("" if a.mode == "native" else " and Docker unavailable"))
                return rec
            cmd, env = nc
            rec["version"] = native_version(cmd[0])
            if tool == "hadolint":
                results = [sh(["hadolint", "-f", "sarif", str(root / f)], timeout=a.timeout, cwd=raw).stdout
                           for f in find_dockerfiles(root)]
                (raw / "hadolint.sarif").write_text(json.dumps(merge_sarif(results)), encoding="utf-8")
            else:
                # cwd = raw/: repo-relative tool configs (trivy.yaml, .trivyignore ...) in the caller's cwd are not read
                r = sh(cmd, timeout=a.timeout, env={**env, **(GIT_SAFE_ENV if tool == "gitleaks" else {})}, cwd=raw)
                rec["exit_code"] = r.returncode
                rec["stderr_tail"] = (r.stderr or "").strip()[-400:]
                if tool == "zizmor":
                    (raw / "zizmor.sarif").write_text(r.stdout, encoding="utf-8")
                if tool == "gitleaks":
                    sh(["gitleaks", "dir", src] + gitleaks_cfg(str(raw)) + [
                        "--redact", "--no-banner", "-f", "sarif", "-r", str(raw / "gitleaks-dir.sarif"),
                        "--exit-code", "0"], timeout=a.timeout, cwd=raw)
    except subprocess.TimeoutExpired:
        rec.update(status="failed", reason=f"timeout after {a.timeout}s")
        return rec
    finally:
        rec["seconds"] = round(time.time() - t0, 1)
    outs = [o for o in EXPECTED[tool] if (raw / o).is_file()]
    rec["outputs"] = outs
    nonempty = [o for o in outs if (raw / o).stat().st_size > 20]
    rec.setdefault("status", "ok" if nonempty else "failed")
    if rec["status"] == "failed" and "reason" not in rec:
        rec["reason"] = "no output produced; see stderr_tail"
    return rec


def merge_sarif(docs: list[str]) -> dict:
    runs = []
    for d in docs:
        try:
            runs += json.loads(d).get("runs", [])
        except (ValueError, AttributeError):
            pass
    return {"version": "2.1.0", "runs": runs}


# ---------------- --check-updates: report-only lookup of newer stable scanner tags ----------------
REGISTRY_TIMEOUT = 10  # seconds per request; one attempt, no retries
REGISTRY_MAX_BYTES = 5_000_000
REGISTRY_MAX_PAGES = 10
REGISTRIES = {  # registry -> (API host, anonymous pull-token URL); only these hosts are ever contacted
    "docker.io": ("registry-1.docker.io",
                  "https://auth.docker.io/token?service=registry.docker.io&scope=repository:{repo}:pull"),
    "ghcr.io": ("ghcr.io", "https://ghcr.io/token?service=ghcr.io&scope=repository:{repo}:pull"),
}
REGISTRY_HOSTS = {"registry-1.docker.io", "auth.docker.io", "ghcr.io"}
STABLE_TAG = re.compile(r"(v?)([0-9]{1,6})\.([0-9]{1,6})\.([0-9]{1,6})")  # X.Y.Z only: no rc/beta/arch suffix
NOT_CHECKED = "not checked (offline)"


def split_image(image: str) -> tuple[str, str, str]:
    """'ghcr.io/a/b:v1@sha256:..' -> ('ghcr.io', 'a/b', 'v1'); a bare Docker Hub name gets 'library/'."""
    name, tag = image.split("@", 1)[0], ""
    if ":" in name.rsplit("/", 1)[-1]:
        name, tag = name.rsplit(":", 1)
    first, _, rest = name.partition("/")
    reg, repo = (first, rest) if rest and ("." in first or ":" in first or first == "localhost") \
        else ("docker.io", name)
    if reg == "docker.io" and "/" not in repo:
        repo = "library/" + repo
    return reg, repo, tag


def stable_key(tag, prefix: str | None = None) -> tuple | None:
    m = STABLE_TAG.fullmatch(tag) if isinstance(tag, str) else None
    if not m or (prefix is not None and m.group(1) != prefix):
        return None
    return tuple(int(x) for x in m.group(2, 3, 4))


def pick_update(pinned: str, tags) -> tuple[str, str]:
    """-> (newest stable tag in the pin's style, status). Pure, so the selftest feeds it canned lists.
    A tag older than the pin is never 'newer'; an unusable list is 'lookup failed', never 'current'."""
    m = STABLE_TAG.fullmatch(pinned or "")
    tags = [t for t in (tags or []) if isinstance(t, str)]
    if not m:
        return "", "lookup failed"
    best, best_key = "", None
    for t in tags:
        k = stable_key(t, m.group(1))
        if k is not None and (best_key is None or k > best_key):
            best, best_key = t, k
    if best_key is not None and best_key > stable_key(pinned):
        return best, "newer available"
    if pinned in tags:
        return pinned, "current"
    return best, "lookup failed"  # pin missing from the list: an incomplete answer is not "current"


def _clean(s, n: int = 100) -> str:
    """Untrusted registry text -> one printable line."""
    s = re.sub(r"\s+", " ", "".join(c if c.isprintable() else " " for c in str(s or ""))).strip()
    return s[:n] + ("..." if len(s) > n else "")


class _RegistryRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        p = urllib.parse.urlparse(newurl)
        if p.scheme != "https" or p.hostname not in REGISTRY_HOSTS:
            raise urllib.error.HTTPError(newurl, code, "redirect off the registry refused", headers, fp)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_REG_OPENER = urllib.request.build_opener(_RegistryRedirect)


def _registry_get(url: str, headers: dict | None = None) -> tuple[bytes, str]:
    p = urllib.parse.urlparse(url)
    if p.scheme != "https" or p.hostname not in REGISTRY_HOSTS:
        raise ValueError("host not allowed")
    req = urllib.request.Request(url, headers={"User-Agent": "security-audit-skill (scanner pin check)",
                                               "Accept": "application/json", **(headers or {})})
    with _REG_OPENER.open(req, timeout=REGISTRY_TIMEOUT) as r:
        data, link = r.read(REGISTRY_MAX_BYTES + 1), r.headers.get("Link", "")
    if len(data) > REGISTRY_MAX_BYTES:
        raise ValueError("response too large")
    return data, link


def registry_tags(image: str) -> list[str]:
    """All tags of the image's repository (Registry v2 tags list, anonymous bearer token)."""
    reg, repo, _ = split_image(image)
    if reg not in REGISTRIES:
        raise ValueError(f"registry {reg} not supported")
    if not re.fullmatch(r"[a-z0-9]+(?:[._/-][a-z0-9]+)*", repo):
        raise ValueError("unexpected repository name")
    host, token_url = REGISTRIES[reg]
    token = json.loads(_registry_get(token_url.format(repo=repo))[0]).get("token")
    if not isinstance(token, str) or not token:
        raise ValueError("no anonymous token")
    url, tags = f"https://{host}/v2/{repo}/tags/list?n=10000", []
    for _ in range(REGISTRY_MAX_PAGES):
        data, link = _registry_get(url, {"Authorization": "Bearer " + token})
        page = json.loads(data).get("tags") or []
        if not isinstance(page, list):
            raise ValueError("malformed tag list")
        tags += [t for t in page if isinstance(t, str)]
        nxt = re.search(r'<([^>]+)>\s*;\s*rel="?next"?', link or "")
        if not nxt:
            return tags
        url = urllib.parse.urljoin(f"https://{host}/", nxt.group(1))
    raise ValueError("too many pages")


def check_one(tool: str, offline: bool) -> dict:
    image = IMAGES[tool]
    row = {"tool": tool, "image": image, "pinned": split_image(image)[2], "newest": "", "status": NOT_CHECKED,
           "detail": ""}
    if offline:
        return row
    try:
        tags = registry_tags(image)
    except Exception as e:  # report-only: any failure is a stated "lookup failed", never "current"
        why = f"HTTP {e.code}" if isinstance(e, urllib.error.HTTPError) else \
            getattr(e, "reason", None) or f"{type(e).__name__}: {e}"
        row.update(status="lookup failed", detail=_clean(why, 80))
        return row
    row["newest"], row["status"] = pick_update(row["pinned"], tags)
    if row["status"] == "lookup failed":
        row["detail"] = "pinned tag not in the registry list"
    return row


def check_updates(offline: bool, json_path: str | None) -> int:
    """Report-only: never pulls, never changes IMAGES. Exit 0 whether updates exist or lookups fail."""
    with cf.ThreadPoolExecutor(max_workers=4) as ex:
        rows = list(ex.map(lambda t: check_one(t, offline), IMAGES))
    print(f"Scanner pin update check - report only: nothing is pulled, no pin is changed "
          f"(pins verified {PINS_VERIFIED}).")
    if offline:
        print("offline: no registry lookups were made (--offline). Run without --offline to check.")
    w = [max(len(h), *(len(r[k]) for r in rows)) for h, k in (("tool", "tool"), ("pinned", "pinned"),
                                                              ("newest stable", "newest"))]
    print(f"{'tool':<{w[0]}}  {'pinned':<{w[1]}}  {'newest stable':<{w[2]}}  status")
    for r in rows:
        st = r["status"] + (f" ({r['detail']})" if r["detail"] else "")
        print(f"{r['tool']:<{w[0]}}  {r['pinned']:<{w[1]}}  {r['newest'] or '-':<{w[2]}}  {st}")
    n = {s: sum(r["status"] == s for r in rows) for s in ("newer available", "lookup failed")}
    if not offline:
        print(f"{n['newer available']} newer available, {n['lookup failed']} lookup failed.")
    print("The default pins are the verified ones and audits keep using them. To try a newer one deliberately, "
          "pass it for one run: --pin tool=image:tag@sha256:<digest> (digest: "
          "`docker buildx imagetools inspect image:tag`).")
    if json_path:
        Path(host_path(json_path)).write_text(json.dumps(
            {"checked": dt.datetime.now().isoformat(timespec="seconds"), "pins_verified": PINS_VERIFIED,
             "offline": offline, "tools": rows}, indent=1), encoding="utf-8")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("repo", nargs="?")
    ap.add_argument("--out", help="output dir (OUTSIDE the audited repo)")
    ap.add_argument("--tools", default=",".join(DEFAULT_TOOLS))
    ap.add_argument("--mode", choices=["auto", "container", "docker", "native"], default="auto",
                    help="container = docker = require a container engine")
    ap.add_argument("--engine", choices=["auto", "docker", "podman"], default="auto",
                    help="container engine (auto: docker if its daemon answers, else podman)")
    ap.add_argument("--pin", action="append", default=[], help="tool=image:tag override")
    ap.add_argument("--timeout", type=int, default=900)
    ap.add_argument("--offline", action="store_true", help="use cached DBs; no network rule/DB updates")
    ap.add_argument("--jobs", type=int, default=3)
    ap.add_argument("--list", action="store_true", help="print pinned images and exit")
    ap.add_argument("--check-updates", action="store_true",
                    help="report newer stable tags of the pinned images (report only; never pulls or changes pins)")
    ap.add_argument("--json", metavar="PATH", help="with --check-updates: also write the result as JSON")
    a = ap.parse_args()
    if a.json and not a.check_updates:
        ap.error("--json needs --check-updates")
    if a.check_updates:
        return check_updates(a.offline, a.json)
    if a.list:
        print(json.dumps({"pins_verified": PINS_VERIFIED, "images": IMAGES}, indent=1))
        return 0
    if not a.repo or not a.out:
        ap.error("repo and --out are required")
    root = Path(host_path(a.repo)).resolve()
    out = Path(host_path(a.out)).resolve()
    if not root.is_dir():
        print(f"error: not a directory: {root}", file=sys.stderr)
        return 2
    if out == root or root in out.parents:
        print("error: --out must be OUTSIDE the audited repo (read-only on product source)", file=sys.stderr)
        return 2
    raw = out / "raw"
    raw.mkdir(parents=True, exist_ok=True)
    for fn, body in OWN_CONFIGS.items():
        (raw / fn).write_text(body, encoding="utf-8")
    a.pins = dict(p.split("=", 1) for p in a.pin)
    for k, v in a.pins.items():
        if v.endswith(":latest") or (":" not in v.split("/")[-1] and "@sha256:" not in v):
            print(f"error: pin for {k} must carry an explicit tag (never :latest): {v}", file=sys.stderr)
            return 2
    tools = [t.strip() for t in a.tools.split(",") if t.strip()]
    unknown = [t for t in tools if t not in IMAGES]
    if unknown:
        print(f"error: unknown tools {unknown}; known: {sorted(IMAGES)}", file=sys.stderr)
        return 2

    global ENGINE, RUN_OPTS, USER_OPTS
    mode, plan = a.mode, None
    if mode in ("auto", "container", "docker"):
        eng = env_check.detect_engine(a.engine, timeout=20)
        if eng.get("daemon_ok"):
            mode, plan = "docker", container_plan(eng)  # "docker" = the container code path
            ENGINE, RUN_OPTS, USER_OPTS = plan["cmd"], plan["run_opts"], plan["user_opts"]
        elif a.mode != "auto":
            hint = {"windows": "start Docker Desktop / Podman Desktop",
                    "macos": "start Docker Desktop, OrbStack, Colima (`colima start`) or `podman machine start`",
                    "linux": "start the daemon (`sudo systemctl start docker`) or use podman"}[env_check.os_family()]
            if not eng.get("installed"):
                hint = "none installed: use --mode native, or see env_check.py choices / platforms.md"
            print(f"error: no container engine answers ({a.engine}; installed: {eng.get('installed') or 'none'}) "
                  f"- {hint}", file=sys.stderr)
            return 3
        else:
            mode = "native"

    manifest = {"repo": str(root), "date": dt.datetime.now().isoformat(timespec="seconds"),
                "mode": plan["engine"] if plan else mode, "pins_verified": PINS_VERIFIED, "offline": a.offline,
                "git_history": (root / ".git").is_dir() and not (root / ".git" / "shallow").exists(),
                "repo_scanner_configs": repo_scanner_configs(root)}
    head, dirty = safegit.head_dirty(root)
    if head:  # audited commit at scan time (build_report prefers it to a live lookup at rebuild time)
        manifest.update(commit=head, dirty=dirty)
    if plan:  # engine / user / SELinux decisions, for the report and for re-scans
        manifest["container"] = {k: plan[k] for k in ("engine", "cmd", "runtime", "rootless", "podman_alias",
                                                      "user", "selinux_enforcing", "run_opts")}
    if mode == "docker":
        n = verify_mount(str(root), a.pins.get(tools[0], IMAGES[tools[0]]))
        manifest["mount_file_count"] = n
        if n <= 0:
            manifest["fatal"] = ("mount verification failed: /src resolved to 0 files. Any scan result "
                                 "would be meaningless. Check the path and the engine's file sharing "
                                 "(Docker Desktop / Colima / OrbStack / podman machine share only some host "
                                 "folders; SELinux needs label=disable).")
            (out / "scanners.json").write_text(json.dumps(manifest, indent=1), encoding="utf-8")
            print(json.dumps(manifest, indent=1))
            return 4

    with cf.ThreadPoolExecutor(max_workers=max(1, a.jobs)) as ex:
        futs = {ex.submit(run_tool, t, mode, root, raw, a): t for t in tools}
        results = [f.result() for f in cf.as_completed(futs)]
    manifest["tools"] = sorted(results, key=lambda r: r["tool"])
    if plan and os.name != "nt":  # safety net: never leave root-owned files the user cannot delete
        manifest["container"]["ownership"] = own = fix_ownership(out, a)
        if own.get("remaining"):
            print(f"warning: {own['remaining']} output files are not yours; fix: {own['fix_cmd']}", file=sys.stderr)
    ran = [r["tool"] for r in results if r.get("status") == "ok"]
    manifest["coverage_gaps"] = [f"{r['tool']}: {r.get('reason', r.get('status'))}" for r in results
                                 if r.get("status") != "ok"]
    if not manifest["git_history"]:
        manifest["coverage_gaps"].append("git history unavailable (no .git or shallow clone): "
                                         "secret scan covered working tree only")
    if manifest["repo_scanner_configs"]["honoured"]:  # stable English text; i18n.gap_text localises it
        manifest["coverage_gaps"].append("repo scanner config may suppress results (review it): "
                                         + ", ".join(manifest["repo_scanner_configs"]["honoured"]))
    (out / "scanners.json").write_text(json.dumps(manifest, indent=1), encoding="utf-8")
    print(f"mode={mode} mount_files={manifest.get('mount_file_count', 'n/a')} ok={ran}")
    for r in manifest["tools"]:
        ident = r.get("digest") or r.get("version") or r.get("image") or ""
        secs = f"{r['seconds']}s " if "seconds" in r else ""
        print(f"- {r['tool']}: {r.get('status')} {secs}{ident} {r.get('reason', '')}".rstrip())
    if manifest["repo_scanner_configs"]["neutralised"]:
        print("repo scanner configs not used (ours replace them):",
              ", ".join(manifest["repo_scanner_configs"]["neutralised"]))
    if manifest["coverage_gaps"]:
        print("coverage gaps (state in report):", *manifest["coverage_gaps"], sep="\n  ")
    return 0 if ran else 5


if __name__ == "__main__":
    sys.exit(main())
