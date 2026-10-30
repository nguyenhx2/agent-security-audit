#!/usr/bin/env python3
"""Check the pinned scanner images for newer stable releases and, on request, move every pin.

The skill runs eight scanners from container images pinned by tag AND sha256 digest
(security-audit/scripts/run_scanners.py IMAGES). A pin nobody re-checks goes stale; a pin moved
the day a release lands takes whatever was pushed that day, including a hijacked release. This
script does the boring half of the job deterministically and leaves the judgement to a human:

  latest eligible   the highest stable semver tag (no rc / beta / alpha / dev / latest / edge /
                    sha-like / arch-suffixed tags), in the same style as the current tag (`v`
                    prefix or not), published at least --cooldown-days ago (default 7). Never a
                    downgrade. The publication date is the registry's (Docker Hub tag push date,
                    GHCR image config `created`), or the GitHub release date when that is later
                    or the registry has none.
  digest            the digest of the multi-arch image index (manifest list) for that tag: the
                    same kind of digest every current pin records. A tag that is not an index is
                    an error, not an update.

Registries are read anonymously over the Docker Registry HTTP API v2 (Docker Hub via auth.docker.io
+ registry-1.docker.io, GHCR via ghcr.io/token). Docker Hub tag dates come from hub.docker.com;
release notes and dates from api.github.com (GITHUB_TOKEN is used when set, for rate limits).
Everything a registry or API returns is untrusted data: tags, digests, dates and URLs are matched
against strict patterns before they are used, nothing is evaluated, printed text is sanitised.

--write rewrites every location that quotes a pinned version, in both editions (security-audit/
and editions/ja/security-audit/) and both READMEs:

  scripts/run_scanners.py         IMAGES entry (tag + digest) and PINS_VERIFIED
  scripts/env_check.py            native install hints (pipx ==, go install @v, cargo --version)
  reference/tooling/scanners.md   image:tag in the tool matrix, "pins verified" date in the TOC
  reference/tooling/platforms.md  native install hints
  SKILL.md                        metadata.scanner-pins-verified and the headline date
  README.md, README.ja.md         scanner table ("Trivy 0.76.1") and the "last verified" date

The dates move to today (UTC) only when a pin moved. CHANGELOG history is never rewritten. After
the edit, any line elsewhere in the repo that still names a tool next to its old version is
reported as a possible stale mention.

Exit codes: 0 = everything current (or --write had nothing to do), 10 = updates available (--check)
or written (--write), 2 = at least one lookup failed (the others are still reported, and with
--write still applied; a failed lookup is never "current").

    py -3 scripts/update_pins.py --check [--json PATH] [--cooldown-days 7] [--tool NAME ...]
    py -3 scripts/update_pins.py --write [--json PATH] [--pr-body PATH] [--cooldown-days 7]
    py -3 scripts/update_pins.py --check --root COPY --offline-fixture FIXTURE.json --today 2026-10-30
"""
from __future__ import annotations

import argparse
import ast
import datetime as dt
import hashlib
import json
import os
import pathlib
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

sys.dont_write_bytecode = True
for _s in (sys.stdout, sys.stderr):
    if hasattr(_s, "reconfigure"):
        _s.reconfigure(encoding="utf-8", errors="replace")

DEFAULT_ROOT = pathlib.Path(__file__).resolve().parent.parent
EDITIONS = ("security-audit", "editions/ja/security-audit")
EXIT_OK, EXIT_UPDATES, EXIT_ERROR = 0, 10, 2
TIMEOUT, RETRIES = 20, 2
MAX_BODY = 8 * 1024 * 1024
MAX_CANDIDATES = 20
UA = "agent-security-audit-update-pins/1"

# Upstream metadata per tool. github = release notes + dates; display = README scanner table name;
# pypi / go / cargo = native install hints that quote the version.
TOOLS = {
    "gitleaks": {"display": "Gitleaks", "github": "gitleaks/gitleaks", "go": "github.com/zricethezav/gitleaks"},
    "semgrep": {"display": "Semgrep", "github": "semgrep/semgrep", "pypi": "semgrep"},
    "trivy": {"display": "Trivy", "github": "aquasecurity/trivy"},
    "osv-scanner": {"display": "OSV-Scanner", "github": "google/osv-scanner", "go": "github.com/google/osv-scanner"},
    "checkov": {"display": "Checkov", "github": "bridgecrewio/checkov", "pypi": "checkov"},
    "hadolint": {"display": "hadolint", "github": "hadolint/hadolint"},
    "zizmor": {"display": "zizmor", "github": "zizmorcore/zizmor", "pypi": "zizmor", "cargo": "zizmor"},
    "mobsfscan": {"display": "mobsfscan", "github": "MobSF/mobsfscan", "pypi": "mobsfscan"},
}

STABLE = re.compile(r"^(v?)(\d{1,6})\.(\d{1,6})\.(\d{1,6})$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
PIN = re.compile(r"^(?P<image>[a-z0-9][a-z0-9./_-]*):(?P<tag>[\w][\w.-]{0,127})@(?P<digest>sha256:[0-9a-f]{64})$")
ISO = re.compile(r"^(\d{4})-(\d{2})-(\d{2})(?:[T ](\d{2}):(\d{2}):(\d{2})(?:\.\d+)?)?(Z|[+-]\d{2}:?\d{2})?$")
NOTES_URL = re.compile(r"^https://github\.com/[\w.-]+/[\w.-]+/releases(?:/tag/[\w.+-]+)?$")
INDEX_TYPES = ("application/vnd.oci.image.index.v1+json",
               "application/vnd.docker.distribution.manifest.list.v2+json")
MANIFEST_TYPES = ("application/vnd.oci.image.manifest.v1+json",
                  "application/vnd.docker.distribution.manifest.v2+json")
ALLOWED_HOSTS = {"auth.docker.io", "registry-1.docker.io", "hub.docker.com", "ghcr.io", "api.github.com"}
DATE = r"\d{4}-\d{2}-\d{2}"


class LookupFailed(Exception):
    """A registry or API answer that could not be used; the message is safe to print."""


def clean(text, limit: int = 200) -> str:
    """Untrusted text made printable: control and non-printable characters dropped, length capped."""
    s = "".join(ch if ch.isprintable() else " " for ch in str(text))
    s = re.sub(r"\s+", " ", s).strip()
    return s if len(s) <= limit else s[:limit - 3] + "..."


def vtuple(tag: str):
    m = STABLE.match(tag)
    return (int(m.group(2)), int(m.group(3)), int(m.group(4))) if m else None


def bare(tag: str) -> str:
    return tag[1:] if tag.startswith("v") else tag


def stable_tags(tags, prefix: str) -> list[str]:
    """Stable semver tags in the current style (`v` prefix or not), newest first. Pre-releases,
    floating names (latest, edge, develop), sha-like and arch-suffixed tags never match STABLE."""
    out = {t for t in tags if isinstance(t, str) and STABLE.match(t) and STABLE.match(t).group(1) == prefix}
    return sorted(out, key=vtuple, reverse=True)


def parse_date(value):
    """An ISO 8601 date or timestamp as an aware UTC datetime, or None when it is not one."""
    if not isinstance(value, str):
        return None
    m = ISO.match(value.strip())
    if not m:
        return None
    y, mo, d, hh, mm, ss, tz = m.groups()
    try:
        t = dt.datetime(int(y), int(mo), int(d), int(hh or 0), int(mm or 0), int(ss or 0), tzinfo=dt.timezone.utc)
    except ValueError:
        return None
    if tz and tz != "Z":
        sign = 1 if tz[0] == "+" else -1
        h, mi = int(tz[1:3]), int(tz[-2:])
        t -= sign * dt.timedelta(hours=h, minutes=mi)
    return t if t.year >= 2015 else None  # reproducible builds stamp 1970: not a publication date


def split_image(image: str):
    """(registry host, repository) for an image name without tag."""
    first, _, rest = image.partition("/")
    if "." in first and rest:
        return first, rest
    return "registry-1.docker.io", image if "/" in image else "library/" + image


# ------------------------------------------------------------------ network

def http_get(url: str, headers: dict | None = None, auth: str | None = None):
    """GET with timeout and retries. Returns (headers, body bytes). Only allowlisted hosts."""
    host = urllib.parse.urlsplit(url).hostname or ""
    if urllib.parse.urlsplit(url).scheme != "https" or host not in ALLOWED_HOSTS:
        raise LookupFailed(f"refusing to fetch {clean(url, 120)} (host not allowlisted)")
    last = ""
    for attempt in range(RETRIES + 1):
        req = urllib.request.Request(url, headers={"User-Agent": UA, **(headers or {})})
        if auth:  # not forwarded on redirects (blob downloads redirect to a CDN)
            req.add_unredirected_header("Authorization", auth)
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
                body = r.read(MAX_BODY + 1)
                if len(body) > MAX_BODY:
                    raise LookupFailed(f"{host}: response larger than {MAX_BODY} bytes")
                return r.headers, body
        except urllib.error.HTTPError as e:
            last = f"{host}: HTTP {e.code}"
            if e.code not in (429, 500, 502, 503, 504):
                raise LookupFailed(last) from None
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            last = f"{host}: {clean(getattr(e, 'reason', e), 120)}"
        if attempt < RETRIES:
            time.sleep(1.5 * (attempt + 1))
    raise LookupFailed(f"{last} (after {RETRIES + 1} attempts)")


def get_json(url: str, headers: dict | None = None, auth: str | None = None):
    _, body = http_get(url, headers, auth)
    try:
        return json.loads(body)
    except ValueError:
        raise LookupFailed(f"{urllib.parse.urlsplit(url).hostname}: answer is not JSON") from None


class LiveSource:
    """Registries and the GitHub API, read anonymously."""

    def __init__(self):
        self._tokens: dict = {}
        self._releases: dict = {}
        self.warnings: list[str] = []

    def _auth(self, host: str, repo: str) -> str:
        key = (host, repo)
        if key not in self._tokens:
            scope = urllib.parse.quote(f"repository:{repo}:pull", safe=":/")
            if host == "ghcr.io":
                url = f"https://ghcr.io/token?service=ghcr.io&scope={scope}"
            else:
                url = f"https://auth.docker.io/token?service=registry.docker.io&scope={scope}"
            data = get_json(url)
            tok = data.get("token") or data.get("access_token") if isinstance(data, dict) else None
            if not isinstance(tok, str) or not tok:
                raise LookupFailed(f"{host}: no anonymous pull token for {repo}")
            self._tokens[key] = "Bearer " + tok
        return self._tokens[key]

    def tags(self, image: str) -> list[str]:
        host, repo = split_image(image)
        path, out = f"/v2/{repo}/tags/list?n=1000", []
        for _ in range(100):
            hdrs, body = http_get(f"https://{host}{path}", auth=self._auth(host, repo))
            try:
                data = json.loads(body)
            except ValueError:
                raise LookupFailed(f"{host}: tag list is not JSON") from None
            out += [t for t in (data.get("tags") or []) if isinstance(t, str)]
            m = re.search(r'<([^>]+)>\s*;\s*rel="?next"?', hdrs.get("Link") or "")
            if not m:
                return out
            nxt = urllib.parse.urlsplit(m.group(1))
            if nxt.netloc not in ("", host) or not nxt.path.startswith(f"/v2/{repo}/tags/list"):
                raise LookupFailed(f"{host}: unexpected pagination link")
            path = nxt.path + ("?" + nxt.query if nxt.query else "")
        raise LookupFailed(f"{host}: tag list did not end after 100 pages")

    def _manifest(self, host: str, repo: str, ref: str, accept) -> tuple[str, bytes, str]:
        hdrs, body = http_get(f"https://{host}/v2/{repo}/manifests/{ref}",
                              {"Accept": ", ".join(accept)}, self._auth(host, repo))
        digest = "sha256:" + hashlib.sha256(body).hexdigest()
        said = (hdrs.get("Docker-Content-Digest") or "").strip()
        if said and said != digest:
            raise LookupFailed(f"{host}: manifest digest header does not match the content for {repo}:{ref}")
        if ref.startswith("sha256:") and ref != digest:
            raise LookupFailed(f"{host}: manifest content does not match the requested digest")
        ctype = (hdrs.get("Content-Type") or "").split(";")[0].strip()
        if not ctype:
            try:
                ctype = json.loads(body).get("mediaType", "")
            except (ValueError, AttributeError):
                ctype = ""
        return ctype, body, digest

    def index_digest(self, image: str, tag: str) -> str:
        host, repo = split_image(image)
        ctype, _, digest = self._manifest(host, repo, tag, INDEX_TYPES + MANIFEST_TYPES)
        if ctype not in INDEX_TYPES:
            raise LookupFailed(f"{repo}:{tag} is not a multi-arch index ({clean(ctype, 80) or 'unknown type'}); "
                               "the pins record index digests")
        return digest

    def registry_date(self, image: str, tag: str):
        host, repo = split_image(image)
        if host == "registry-1.docker.io":
            data = get_json(f"https://hub.docker.com/v2/repositories/{repo}/tags/{urllib.parse.quote(tag)}")
            if isinstance(data, dict):
                return parse_date(data.get("tag_last_pushed")) or parse_date(data.get("last_updated"))
            return None
        # GHCR: the image config's `created`, from the linux/amd64 manifest of the index
        ctype, body, _ = self._manifest(host, repo, tag, INDEX_TYPES + MANIFEST_TYPES)
        doc = json.loads(body)
        if ctype in INDEX_TYPES:
            pick = None
            for m in doc.get("manifests") or []:
                p = m.get("platform") or {}
                if p.get("os") == "linux" and p.get("architecture") == "amd64":
                    pick = m.get("digest")
                    break
            if not isinstance(pick, str) or not DIGEST.match(pick):
                return None
            _, body, _ = self._manifest(host, repo, pick, MANIFEST_TYPES)
            doc = json.loads(body)
        cfg = (doc.get("config") or {}).get("digest")
        if not isinstance(cfg, str) or not DIGEST.match(cfg):
            return None
        _, blob = http_get(f"https://{host}/v2/{repo}/blobs/{cfg}", auth=self._auth(host, repo))
        if "sha256:" + hashlib.sha256(blob).hexdigest() != cfg:
            raise LookupFailed(f"{host}: config blob does not match its digest for {repo}:{tag}")
        try:
            return parse_date(json.loads(blob).get("created"))
        except (ValueError, AttributeError):
            return None

    def releases(self, tool: str) -> list:
        if tool not in self._releases:
            gh = TOOLS[tool]["github"]
            headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
            token = os.environ.get("GITHUB_TOKEN", "").strip()
            try:
                data = get_json(f"https://api.github.com/repos/{gh}/releases?per_page=100", headers,
                                f"Bearer {token}" if token else None)
                self._releases[tool] = data if isinstance(data, list) else []
            except LookupFailed as e:
                self.warnings.append(f"{tool}: GitHub releases unavailable ({e})")
                self._releases[tool] = []
        return self._releases[tool]


class FixtureSource:
    """Canned registry answers for offline tests. Shape:
    {"tools": {"<tool>": {"tags": [...], "dates": {"<tag>": "<iso>"}, "digests": {"<tag>": "sha256:..."},
                          "index": {"<tag>": false}, "error": "<message>"}},
     "github": {"<tool>": [{"tag_name", "published_at", "html_url", "prerelease"}]}}"""

    def __init__(self, path: pathlib.Path):
        self.data = json.loads(path.read_text(encoding="utf-8"))
        self.warnings: list[str] = []
        self._by_image: dict = {}

    def bind(self, image: str, tool: str):
        self._by_image[image] = tool

    def _tool(self, image: str) -> dict:
        t = self.data.get("tools", {}).get(self._by_image.get(image, ""), None)
        if t is None:
            raise LookupFailed(f"fixture has no answer for {image}")
        if t.get("error"):
            raise LookupFailed(clean(t["error"]))
        return t

    def tags(self, image):
        return list(self._tool(image).get("tags") or [])

    def index_digest(self, image, tag):
        t = self._tool(image)
        if (t.get("index") or {}).get(tag) is False:
            raise LookupFailed(f"{image}:{tag} is not a multi-arch index; the pins record index digests")
        d = (t.get("digests") or {}).get(tag)
        if not d:
            raise LookupFailed(f"fixture has no digest for {image}:{tag}")
        return d

    def registry_date(self, image, tag):
        return parse_date((self._tool(image).get("dates") or {}).get(tag))

    def releases(self, tool):
        return list(self.data.get("github", {}).get(tool) or [])


# ------------------------------------------------------------------ lookup

def read_pins(root: pathlib.Path) -> dict:
    """IMAGES from both editions' run_scanners.py, read with ast (never imported). They must agree."""
    found = []
    for ed in EDITIONS:
        p = root / ed / "scripts" / "run_scanners.py"
        tree = ast.parse(p.read_text(encoding="utf-8"))
        val = None
        for node in tree.body:
            if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "IMAGES" for t in node.targets):
                val = ast.literal_eval(node.value)
        if not isinstance(val, dict):
            raise SystemExit(f"error: {p} no longer defines IMAGES")
        found.append(val)
    if found[0] != found[1]:
        raise SystemExit("error: IMAGES differ between the English and Japanese editions; fix that first")
    return found[0]


def release_info(source, tool: str, tag: str):
    """(published datetime or None, notes URL) for a version, from the upstream GitHub releases."""
    want = vtuple(tag)
    for rel in source.releases(tool):
        if not isinstance(rel, dict) or rel.get("draft") or rel.get("prerelease"):
            continue
        name = rel.get("tag_name")
        if isinstance(name, str) and vtuple(name) == want:
            url = rel.get("html_url")
            if not (isinstance(url, str) and NOTES_URL.match(url)):
                url = f"https://github.com/{TOOLS[tool]['github']}/releases/tag/{name}"
            return parse_date(rel.get("published_at")), url
    return None, f"https://github.com/{TOOLS[tool]['github']}/releases"


def check_tool(source, tool: str, ref: str, cutoff: dt.datetime) -> dict:
    """One tool's verdict: {"status": update|current|cooldown, ...}. Raises LookupFailed."""
    m = PIN.match(ref)
    if not m or not STABLE.match(m.group("tag")):
        raise LookupFailed(f"current pin is not image:stable-tag@sha256:digest ({clean(ref, 120)})")
    image, cur_tag, cur_digest = m.group("image"), m.group("tag"), m.group("digest")
    if hasattr(source, "bind"):
        source.bind(image, tool)
    prefix, cur_v = STABLE.match(cur_tag).group(1), vtuple(cur_tag)
    tags = stable_tags(source.tags(image), prefix)
    if not tags:
        raise LookupFailed(f"no stable {'v-prefixed ' if prefix else ''}semver tags listed for {image}")
    newer = [t for t in tags if vtuple(t) > cur_v]
    res = {"tool": tool, "image": image, "old_tag": cur_tag, "old_digest": cur_digest,
           "newest_seen": tags[0], "notes": []}
    undated, cooling = [], []
    for cand in newer[:MAX_CANDIDATES]:
        reg = source.registry_date(image, cand)
        gh, url = release_info(source, tool, cand)
        known = [d for d in (reg, gh) if d]
        if not known:
            undated.append(cand)
            continue
        released = max(known)  # the later date: a re-push or a late release restarts the cooldown
        if released > cutoff:
            cooling.append(cand)
            continue
        res.update(status="update", new_tag=cand, new_digest=source.index_digest(image, cand),
                   released=released.date().isoformat(), notes_url=url)
        if gh is None:
            res["notes"].append(f"{cand} has no GitHub release (registry-only tag): check the upstream "
                                "changelog before merging")
        if cooling:
            res["notes"].append(f"newer {', '.join(cooling)} still in cooldown")
        break
    else:
        if undated and not cooling:
            raise LookupFailed(f"no publication date for newer tag(s) {', '.join(undated[:3])}")
        res["status"] = "cooldown" if cooling else "current"
        if cooling:
            res["notes"].append(f"newer {', '.join(cooling)} still in cooldown")
        res["notes_url"] = release_info(source, tool, cur_tag)[1] if cooling else ""
    if undated:
        res["notes"].append(f"skipped {', '.join(undated[:3])}: no publication date")
    if newer[MAX_CANDIDATES:]:
        res["notes"].append(f"only the newest {MAX_CANDIDATES} newer tags were considered")
    try:  # drift: the pinned tag re-pushed upstream (informational; the digest pin still holds)
        now = source.index_digest(image, cur_tag)
        if now != cur_digest:
            res["notes"].append(f"tag {cur_tag} now points to {now[:19]}..., the pin keeps the old digest")
    except LookupFailed:
        pass
    return res


# ------------------------------------------------------------------ rewrite

def _go_rule(module: str, old: str, new: str):
    """`go install <module>[/vN][/cmd/x]@v<old>`: the major-version suffix follows the new major."""
    pat = re.compile(re.escape(module) + r"(/v\d+)?((?:/[\w.-]+)*)@v" + re.escape(old) + r"(?![\w.])")
    major = int(new.split(".")[0])

    def sub(mm):
        return f"{module}{f'/v{major}' if major >= 2 else ''}{mm.group(2)}@v{new}"
    return pat, sub


def version_rules(u: dict) -> list:
    """(name, pattern, replacement) for one tool update, applied to every managed file."""
    t, image = TOOLS[u["tool"]], u["image"]
    old, new = bare(u["old_tag"]), bare(u["new_tag"])
    end = r"(?![\w.])"
    rules = [
        ("image+digest", re.compile(re.escape(f"{image}:{u['old_tag']}@{u['old_digest']}") + r"(?![0-9a-f])"),
         f"{image}:{u['new_tag']}@{u['new_digest']}"),
        ("image tag", re.compile(re.escape(f"{image}:{u['old_tag']}") + r"(?![\w.@-])"), f"{image}:{u['new_tag']}"),
        ("readme table", re.compile(r"\| " + re.escape(t["display"]) + " " + re.escape(old) + r" \|"),
         f"| {t['display']} {new} |"),
    ]
    if t.get("pypi"):
        rules.append(("pipx", re.compile(r"(?<![\w.-])" + re.escape(t["pypi"]) + "==" + re.escape(old) + end),
                      f"{t['pypi']}=={new}"))
    if t.get("cargo"):
        rules.append(("cargo", re.compile(r"cargo install " + re.escape(t["cargo"]) + r" --version " + re.escape(old) + end),
                      f"cargo install {t['cargo']} --version {new}"))
    if t.get("go"):
        pat, fn = _go_rule(t["go"], old, new)
        rules.append(("go install", pat, fn))
    return rules


def date_rules(today: str) -> list:
    """(file relative to root, pattern, replacement, required) for the "pins verified" dates."""
    out = []
    for ed in EDITIONS:
        out += [
            (f"{ed}/scripts/run_scanners.py", re.compile(r'(PINS_VERIFIED = ")' + DATE + '"'), rf'\g<1>{today}"', True),
            (f"{ed}/SKILL.md", re.compile(r'(scanner-pins-verified: ")' + DATE + '"'), rf'\g<1>{today}"', True),
        ]
    en, ja = EDITIONS
    out += [
        (f"{en}/SKILL.md", re.compile(r"(scanner pins verified )" + DATE), rf"\g<1>{today}", True),
        (f"{ja}/SKILL.md", re.compile(r"(スキャナのピン検証日 )" + DATE), rf"\g<1>{today}", True),
        (f"{en}/reference/tooling/scanners.md", re.compile(r"(\(pins verified )" + DATE + r"\)"), rf"\g<1>{today})", False),
        (f"{ja}/reference/tooling/scanners.md", re.compile(r"(ピン留めは )" + DATE + "( に検証)"), rf"\g<1>{today}\g<2>", False),
        ("README.md", re.compile(r"(re-verified for every release\s+\(last:\s+)" + DATE + r"\)"), rf"\g<1>{today})", False),
        ("README.ja.md", re.compile(r"(（最新の検証日：)" + DATE + "）"), rf"\g<1>{today}）", False),
    ]
    return out


def managed_files(root: pathlib.Path) -> list[str]:
    rel = []
    for ed in EDITIONS:
        rel += [f"{ed}/scripts/run_scanners.py", f"{ed}/scripts/env_check.py", f"{ed}/SKILL.md",
                f"{ed}/reference/tooling/scanners.md", f"{ed}/reference/tooling/platforms.md"]
    return rel + ["README.md", "README.ja.md"]


def plan_write(root: pathlib.Path, updates: list, today: str):
    """All edits computed in memory first: (new texts by path, per-location log, problems)."""
    texts, log, problems = {}, [], []
    for rel in managed_files(root):
        p = root / rel
        if p.is_file():
            texts[rel] = p.read_bytes().decode("utf-8")
        else:
            problems.append(f"missing managed file {rel}")
    if problems:
        return texts, log, problems
    original = dict(texts)
    for u in updates:
        for name, pat, repl in version_rules(u):
            for rel in texts:
                new, n = pat.subn(repl, texts[rel])
                if n:
                    texts[rel] = new
                    log.append(f"{rel}: {u['tool']} {name} ({n}x)")
        for ed in EDITIONS:  # the pin itself must have moved, in both editions
            rs = f"{ed}/scripts/run_scanners.py"
            if f"{u['image']}:{u['new_tag']}@{u['new_digest']}" not in texts[rs]:
                problems.append(f"{rs}: IMAGES entry for {u['tool']} not found as "
                                f"{u['image']}:{u['old_tag']}@{u['old_digest'][:19]}...")
    if updates:
        for rel, pat, repl, required in date_rules(today):
            if rel not in texts:
                continue
            new, n = pat.subn(repl, texts[rel])
            if n:
                if new != texts[rel]:
                    log.append(f"{rel}: pins-verified date -> {today} ({n}x)")
                texts[rel] = new
            elif required:
                problems.append(f"{rel}: pins-verified date pattern not found ({pat.pattern})")
    changed = {rel: t for rel, t in texts.items() if t != original[rel]}
    return changed, log, problems


SKIP_DIRS = {".git", "dist", "node_modules", "__pycache__", ".venv"}
TEXT_SUFFIX = {".md", ".py", ".json", ".yml", ".yaml", ".toml", ".txt", ".html", ".sh", ".ps1", ".cfg"}


def stale_mentions(root: pathlib.Path, updates: list, pending: dict) -> list[str]:
    """Lines anywhere (CHANGELOGs, benchmark runs and dist excluded) that still name an updated
    tool next to its old version: a location this script does not know about."""
    out = []
    checks = []
    for u in updates:
        names = {u["tool"], TOOLS[u["tool"]]["display"], u["image"].split("/")[-1]}
        ver = re.compile(r"(?<![\w.])v?" + re.escape(bare(u["old_tag"])) + r"(?![\w.])")
        checks.append((u["tool"], [n.lower() for n in names], ver))
    for p in root.rglob("*"):
        parts = p.relative_to(root).parts
        if not p.is_file() or p.suffix.lower() not in TEXT_SUFFIX or SKIP_DIRS & set(parts) \
                or parts[:2] == ("benchmark", "runs") or p.name.upper().startswith("CHANGELOG"):
            continue
        rel = "/".join(parts)
        try:
            text = pending.get(rel) or p.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for i, line in enumerate(text.splitlines(), 1):
            low = line.lower()
            for tool, names, ver in checks:
                if ver.search(line) and any(n in low for n in names):
                    out.append(f"{rel}:{i}: {tool}: {clean(line.strip(), 140)}")
    return out


# ------------------------------------------------------------------ output

def table(rows: list) -> str:
    head = ("tool", "current", "latest eligible", "released", "status")
    w = [max(len(head[i]), *(len(r[i]) for r in rows)) if rows else len(head[i]) for i in range(5)]
    fmt = "  ".join("{:<%d}" % x for x in w)
    lines = [fmt.format(*head), fmt.format(*("-" * x for x in w))]
    return "\n".join([*lines, *(fmt.format(*r) for r in rows)])


def pr_body(result: dict, today: str) -> str:
    ups, cd = result["updates"], result["cooldown_days"]
    out = [f"# Scanner pin update ({today})", "",
           f"Proposed by `scripts/update_pins.py --write`. Cooldown: {cd} days - only stable releases "
           f"published at least {cd} days ago are taken; the digest is the multi-arch image index.", ""]
    if ups:
        out += ["| Scanner | Image | Old | New | Released | Release notes |", "|---|---|---|---|---|---|"]
        for u in ups:
            out.append(f"| {u['tool']} | `{u['image']}` | `{u['old_tag']}` | `{u['new_tag']}` | {u['released']} "
                       f"| [{u['new_tag']}]({u['notes_url']}) |")
        out += ["", "Digests:", ""]
        out += [f"- {u['tool']}: `{u['old_digest']}` -> `{u['new_digest']}`" for u in ups]
    else:
        out.append("No eligible updates.")
    if result["errors"]:
        out += ["", "## Lookups that failed (not updated, not known to be current)", ""]
        out += [f"- {e['tool']}: {clean(e['error'])}" for e in result["errors"]]
    if result.get("notes"):
        out += ["", "## Notes", ""]
        out += [f"- {n['tool']}: {clean(n['note'], 300)}" for n in result["notes"]]
    out += ["", "## Before merging - a human must review this PR", "",
            "Scanner images are a supply-chain link: whatever these digests contain runs against every "
            "audited repository. Do not auto-merge.", "",
            "- [ ] Read each release's notes for breaking changes, removed or renamed rules, changed output "
            "formats or CLI flags.",
            "- [ ] Confirm each new digest independently, e.g. `docker buildx imagetools inspect <image>:<tag>`.",
            "- [ ] Run `py -3 security-audit/tests/selftest.py`, the same for `editions/ja/security-audit`, "
            "`py -3 scripts/check_editions.py` and `py -3 scripts/validate_release.py`.",
            "- [ ] Add the CHANGELOG bullets below to both editions' CHANGELOG.md.", ""]
    if ups:
        en = ", ".join(f"{u['tool']} {bare(u['old_tag'])} -> {bare(u['new_tag'])}" for u in ups)
        ja = "、".join(f"{u['tool']} {bare(u['old_tag'])} -> {bare(u['new_tag'])}" for u in ups)
        out += ["## Draft CHANGELOG bullets", "", "English (`security-audit/CHANGELOG.md`):", "", "```markdown",
                f"- Scanner pins updated and verified {today} (cooldown {cd} days, multi-arch index digests): {en}.",
                "```", "", "Japanese (`editions/ja/security-audit/CHANGELOG.md`):", "", "```markdown",
                f"- スキャナのピンを {today} に更新・検証（クールダウン {cd} 日、マルチアーキテクチャのインデックスのダイジェスト）：{ja}。",
                "```", ""]
    return "\n".join(out).replace("\u2014", "-")


def write_text(path: pathlib.Path, text: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(text.replace("\r\n", "\n").encode("utf-8"))


# ------------------------------------------------------------------ main

def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Check (and optionally move) the pinned scanner images.",
                                 epilog="Exit 0 = current / nothing written, 10 = updates available or "
                                        "written, 2 = a lookup failed.")
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true", help="report only")
    mode.add_argument("--write", action="store_true", help="apply eligible updates in both editions + READMEs")
    ap.add_argument("--json", metavar="PATH", help="write the machine-readable result here")
    ap.add_argument("--pr-body", metavar="PATH", help="write a Markdown pull-request body here")
    ap.add_argument("--cooldown-days", type=int, default=7, help="minimum release age in days (default 7)")
    ap.add_argument("--tool", nargs="+", metavar="NAME", help="limit to these tools")
    ap.add_argument("--root", default=str(DEFAULT_ROOT), help="repository root (default: this script's repo)")
    ap.add_argument("--offline-fixture", metavar="PATH", help="canned registry answers (tests; no network)")
    ap.add_argument("--today", metavar="YYYY-MM-DD", help="pretend today is this date, UTC (tests)")
    a = ap.parse_args(argv)
    if a.cooldown_days < 0:
        ap.error("--cooldown-days must be >= 0")

    root = pathlib.Path(a.root).resolve()
    if a.today:
        if not re.fullmatch(DATE, a.today):
            ap.error("--today must be YYYY-MM-DD")
        now = dt.datetime.strptime(a.today, "%Y-%m-%d").replace(tzinfo=dt.timezone.utc)
    else:
        now = dt.datetime.now(dt.timezone.utc)
    today = now.date().isoformat()
    cutoff = now - dt.timedelta(days=a.cooldown_days)

    pins = read_pins(root)
    tools = a.tool or list(pins)
    unknown = [t for t in tools if t not in pins or t not in TOOLS]
    if unknown:
        ap.error(f"unknown tools {unknown}; known: {sorted(set(pins) & set(TOOLS))}")
    source = FixtureSource(pathlib.Path(a.offline_fixture)) if a.offline_fixture else LiveSource()

    updates, current, errors, rows, notes = [], [], [], [], []
    for tool in tools:
        try:
            r = check_tool(source, tool, pins[tool], cutoff)
        except LookupFailed as e:
            errors.append({"tool": tool, "error": clean(e)})
            m = PIN.match(pins[tool])
            rows.append((tool, m.group("tag") if m else "?", "-", "-", "ERROR"))
            continue
        except Exception as e:  # noqa: BLE001 - a malformed answer is a failed lookup, never "current"
            errors.append({"tool": tool, "error": clean(f"{type(e).__name__}: {e}")})
            rows.append((tool, "?", "-", "-", "ERROR"))
            continue
        if r["status"] == "update":
            updates.append({k: r[k] for k in ("tool", "image", "old_tag", "new_tag", "old_digest", "new_digest",
                                              "released", "notes_url")})
            rows.append((tool, r["old_tag"], r["new_tag"], r["released"], "update"))
        else:
            current.append({"tool": tool, "image": r["image"], "tag": r["old_tag"], "digest": r["old_digest"],
                            "status": r["status"], "newest_seen": r["newest_seen"], "notes": r["notes"]})
            rows.append((tool, r["old_tag"], "-", "-", r["status"]))
        notes += [{"tool": tool, "note": n} for n in r["notes"]]

    print(f"scanner pins, cooldown {a.cooldown_days} days, checked {today}"
          f"{' (offline fixture)' if a.offline_fixture else ''}")
    print(table(rows))
    for e in errors:
        print(f"error: {e['tool']}: {e['error']}", file=sys.stderr)
    notes += [{"tool": w.split(":", 1)[0], "note": w.split(":", 1)[-1].strip()} for w in source.warnings]
    for n in notes:
        print(f"note: {n['tool']}: {clean(n['note'], 300)}")

    result = {"checked": today, "cooldown_days": a.cooldown_days, "updates": updates,
              "current": current, "errors": errors, "notes": notes}
    rc = EXIT_UPDATES if updates else EXIT_OK

    if a.write:
        changed, log, problems = plan_write(root, updates, today)
        if problems:
            for p in problems:
                print(f"error: {p}", file=sys.stderr)
            print("nothing written: the edit plan is incomplete", file=sys.stderr)
            return EXIT_ERROR
        for rel, text in changed.items():
            write_text(root / rel, text)
        for line in log:
            print(f"wrote {line}")
        stale = stale_mentions(root, updates, {})
        for s in stale:
            print(f"warning: possible stale mention {s}")
        result["written"] = sorted(changed)
        result["stale_mentions"] = stale
        rc = EXIT_UPDATES if changed else EXIT_OK
        print(f"{len(changed)} file(s) changed" if changed else "nothing to write")

    if a.json:
        write_text(pathlib.Path(a.json), json.dumps(result, indent=1, ensure_ascii=False) + "\n")
    if a.pr_body:
        write_text(pathlib.Path(a.pr_body), pr_body(result, today))
    return EXIT_ERROR if errors else rc


if __name__ == "__main__":
    sys.exit(main())
