#!/usr/bin/env python3
"""
Route map (Phase 1) - a static, regex-based endpoint table: method, full path, handler `file:line`
and the auth / authz markers seen near each route. Recon and the authz lane start from it instead of
re-discovering routes with Glob / Grep turns.

Parsed: FastAPI, Flask, Django (+ DRF), Express / Koa / Fastify, NestJS, Spring, Laravel, Rails.
Prefixes are applied where statically visible (include_router, blueprint url_prefix, Django include(),
app.use('/p', router), fastify register prefix, @Controller / class @RequestMapping, Route::prefix /
group, routes.rb namespace / scope). A marker is a NAME seen near the route (dependency, decorator,
middleware, guard, annotation, before_action) - it does not prove the control works. "No auth marker"
is a lead, not a verdict. Dynamic registration is missed; frameworks seen but not parsed are listed.

Never executes repo code; read-only; skips vendored / test dirs and symlinks resolving outside the
repo; paths and markers pass through peek.redact.

Usage:
  python route_map.py <repo> --out <work>/<repo>/routes.md [--max-rows 250]   (also writes routes.json)
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
import posixpath
import re
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from peek import redact as _redact  # noqa: E402
import safegit  # noqa: E402
from repo_digest import TESTISH, VENDOR, host_path, list_files  # noqa: E402

AUTH_RX = re.compile(r"(?i)auth|login|logged_?in|jwt|bearer|token|guard|permission|role|admin|current_?user|"
                     r"session|verify|protect|secur|api_?key|oauth|scope|signature|hmac|\bacl|polic|sanctum|"
                     r"passport|signed|staff|superuser|owner|tenant|devise|can\?|authorize")
NOT_AUTH = re.compile(r"(?i)(?:db|database|sql|async|orm)_?session|get_session\b|session_?local|sessionmaker|"
                      r"accesslog|tokeniz|csrf_?token\b|security_?headers")
NEG_RX = re.compile(r"(?i)\b(AllowAny|permitAll|Public|SkipAuth|AllowAnonymous|skip_before_action|withoutMiddleware|"
                    r"csrf_exempt|NoAuth|skip_?auth)\b|permission_classes=\[\]")
# string literal; a backslash is only ever an escape (no overlapping branches, so no exponential backtracking
# on hostile lines such as `"\a\a\a...`); `\\?` keeps the old match for an unterminated `"abc\"`
STR = re.compile(r"([\"'`])(?:\\.|(?!\1)[^\\\n])*\\?\1")
HTTP = ("get", "post", "put", "delete", "patch", "head", "options")
SRC_EXT = {".py", ".js", ".mjs", ".cjs", ".ts", ".jsx", ".tsx", ".java", ".kt", ".php", ".rb"}


def short(n: str) -> str:
    return _redact(re.sub(r"\s+", " ", n.strip()), False)[0][:60]


def spath(p: str) -> str:
    """Redact a URL path per segment (a long hyphenated segment is not a token)."""
    return "/".join(short(x) if x else x for x in re.sub(r"\s+", "", p).split("/"))[:200]


def mark(names, tag="") -> list[str]:
    """Auth-ish names -> markers; opt-outs (AllowAny, permitAll, @Public, skip_before_action) -> `!name`."""
    out = []
    for n in names:
        n = (n or "").strip()
        if not n:
            continue
        if NEG_RX.search(n):
            out.append("!" + short(n))
        elif AUTH_RX.search(n) and not NOT_AUTH.search(n):
            out.append(tag + short(n))
    return out


def uniq(xs):
    return list(dict.fromkeys(xs))


def has_auth(markers) -> bool:
    return any(not m.startswith("!") for m in markers)


def stmt(lines, i, limit=25, end=None):
    """Text from line i until brackets balance (a multi-line call / decorator / signature)."""
    buf, depth, j = [], 0, i
    for j in range(i, min(len(lines), i + limit)):
        ln = lines[j][:400].strip()
        buf.append(ln)
        bare = STR.sub("", ln)
        depth += sum(bare.count(c) for c in "([{") - sum(bare.count(c) for c in ")]}")
        if depth <= 0 and (end is None or end in bare):
            break
    return " ".join(buf), j


def call_args(lines, i, start, limit=25):
    """Arguments of the call whose `(` opens before `start` on line i, up to its own `)`: strings blanked,
    comments dropped, so names in literals, comments or the next statement never count."""
    out, depth = [], 1
    for j in range(i, min(len(lines), i + limit)):
        ln = lines[j][start:] if j == i else lines[j]
        ln = re.sub(r"//.*$", "", STR.sub('""', ln[:400]))
        out.append(ln)
        text = re.sub(r"/\*.*?\*/", " ", " ".join(out))
        for k, c in enumerate(text):
            depth += c in "([{"
            depth -= c in ")]}"
            if depth <= 0:
                return text[:k]
        depth = 1
    return re.sub(r"/\*.*?\*/", " ", " ".join(out))


def lit(text, key=None):
    """First string literal after `(` (or after `key=` / `key:` / `'key' =>`)."""
    if key:
        m = re.search(r"[\"']?\b%s[\"']?\s*(?:=>|[=:])\s*\[?\s*[rRbBuU]?([\"'`])(.*?)\1" % key, text)
    else:
        m = re.search(r"\(\s*[rRbBuU]?([\"'`])(.*?)\1", text)
    return m.group(2) if m else None


def join(*parts) -> str:
    ps = [p for p in parts if p]
    body = "/".join(p.strip("/") for p in ps if p.strip("/"))
    return "/" + body + ("/" if body and ps and ps[-1].endswith("/") else "")


class Map:
    def __init__(self, root: Path, files: dict[str, list[str]]):
        self.root, self.files = root, files
        self.routes, self.globals, self.notes, self.gaps = [], [], [], []

    def add(self, fw, method, path, rel, line, markers, handler="", mount=""):
        self.routes.append({"framework": fw, "method": method.upper(), "path": spath(path) or "/", "file": rel,
                            "line": line, "handler": short(handler), "auth": uniq(markers), "mount": mount})

    def glob(self, fw, rel, line, what):
        self.globals.append({"framework": fw, "at": f"{rel}:{line}", "what": short(what)})

    def of(self, *exts):
        return [(r, ls) for r, ls in sorted(self.files.items()) if r.endswith(exts)]


# ---------------------------------------------------------------- Python (FastAPI / Flask / Django)
PY_DEF = re.compile(r"^(\s*)(async\s+def|def|class)\s+(\w+)")
PY_ROUTE = re.compile(r"^@([\w.]+)\.(route|get|post|put|delete|patch|head|options|websocket|api_route)\(")
DEP = re.compile(r"\b(?:Depends|Security)\(\s*([\w.]+)")
ROUTER_DEF = re.compile(r"^\s*(\w+)\s*(?::\s*[\w.]+)?\s*=\s*(?:\w+\.)?(APIRouter|FastAPI|Blueprint|Flask)\(")


def py_defs(lines):
    """[(line, kind, name, indent, [(dec_line, dec_text)], signature_text)]"""
    out, decs, i = [], [], 0
    while i < len(lines):
        s = lines[i].strip()
        if s.startswith("@"):
            text, j = stmt(lines, i)
            decs.append((i + 1, text))
            i = j + 1
            continue
        m = PY_DEF.match(lines[i])
        if m:
            sig, j = stmt(lines, i)
            out.append((i + 1, "class" if m.group(2) == "class" else "def", m.group(3), len(m.group(1)), decs, sig))
            decs, i = [], j + 1
            continue
        if s and not s.startswith("#"):
            decs = []
        i += 1
    return out


def py_imports(lines):
    imp = {}
    for i, ln in enumerate(lines):
        m = re.match(r"\s*from\s+([\w.]+)\s+import\s+(.*)", ln)
        if m:
            names = stmt(lines, i)[0].split(" import ", 1)[1] if "(" in m.group(2) else m.group(2)
            for part in re.sub(r"[()\\]", " ", names).split(","):
                w = part.split()
                if w and w[0] != "*":
                    imp[w[-1]] = (m.group(1), w[0])
        m = re.match(r"\s*import\s+([\w.]+)(?:\s+as\s+(\w+))?", ln)
        if m:
            imp[m.group(2) or m.group(1).split(".")[0]] = (m.group(1), None)
    return imp


def parse_python(M: Map):
    py = M.of(".py")
    defs = {r: py_defs(ls) for r, ls in py}
    imports = {r: py_imports(ls) for r, ls in py}
    routers, mounts = {}, defaultdict(list)
    fw_of = {}
    for r, ls in py:
        head = "\n".join(ls[:80])
        fw_of[r] = "FastAPI" if re.search(r"\bfastapi\b", head) else "Flask" if re.search(r"\bflask\b", head) else ""
        for i, ln in enumerate(ls):
            m = ROUTER_DEF.match(ln)
            if m:
                t = stmt(ls, i)[0]
                deps = mark(DEP.findall(t.split("dependencies", 1)[1]) if "dependencies" in t else [], "router:")
                routers[(r, m.group(1))] = {"kind": m.group(2), "prefix": lit(t, "url_prefix") or lit(t, "prefix") or "",
                                            "markers": deps, "line": i + 1}
                if m.group(2) == "FastAPI" and deps:
                    M.glob("FastAPI", r, i + 1, "FastAPI(dependencies=" + ", ".join(deps) + ")")
            m = re.search(r"\b(\w+)\.(include_router|register_blueprint)\(\s*([\w.]+)", ln)
            if m:
                t = stmt(ls, i)[0]
                deps = mark(DEP.findall(t), "include:")
                tgt = resolve_py(r, m.group(3), imports, routers_hint=py)
                for tr, tv in tgt:
                    mounts[(tr, tv)].append((r, m.group(1), lit(t, "url_prefix") or lit(t, "prefix") or "", deps, i + 1,
                                             m.group(2) == "register_blueprint"))
            m = re.search(r"\.add_middleware\(\s*([\w.]+)", stmt(ls, i)[0]) if ".add_middleware(" in ln else None
            if m and mark([m.group(1)]):
                M.glob(fw_of[r] or "FastAPI", r, i + 1, f"add_middleware({m.group(1)})")
    for r, ds in defs.items():
        for line, kind, name, _, decs, _ in ds:
            for dl, dt in decs:
                m = re.match(r"@([\w.]+)\.(middleware|before_request|before_app_request)\b", dt)
                if m and (mark([name]) or m.group(2) != "middleware"):
                    M.glob(fw_of[r] or "Flask", r, dl, f"{m.group(2)}: {name}")

    def eff(r, var, seen=()):
        info = routers.get((r, var), {"kind": "", "prefix": "", "markers": []})
        ms = mounts.get((r, var))
        if not ms or (r, var) in seen:
            return [(info["prefix"], info["markers"], "")]
        out = []
        for pr, pv, pre, deps, ln, is_bp in ms[:3]:
            for ppre, pmk, _ in eff(pr, pv, seen + ((r, var),)):
                own = "" if (is_bp and pre) else info["prefix"]
                out.append((join(ppre, pre, own) if (ppre or pre or own) else "", pmk + deps + info["markers"], f"{pr}:{ln}"))
        return out

    for r, ds in defs.items():
        for line, kind, name, _, decs, sig in ds:
            routes = [(dl, dt, PY_ROUTE.match(dt)) for dl, dt in decs]
            routes = [(dl, dt, m) for dl, dt, m in routes if m]
            if not routes:
                continue
            others = [re.match(r"@([\w.]+)", dt).group(1) for dl, dt in decs if not PY_ROUTE.match(dt)]
            for dl, dt, m in routes:
                var, verb = m.group(1), m.group(2)
                key = (r, var)
                if key not in routers:
                    tgt = resolve_py(r, var, imports, py)
                    key = tgt[0] if tgt else key
                fw = {"APIRouter": "FastAPI", "FastAPI": "FastAPI", "Blueprint": "Flask", "Flask": "Flask"}.get(
                    routers.get(key, {}).get("kind"), fw_of[r] or "FastAPI")
                if verb in ("route", "api_route"):
                    ms = re.search(r"methods\s*=\s*[\[(]([^\])]*)", dt)
                    methods = re.findall(r"[\"'](\w+)[\"']", ms.group(1)) if ms else ["GET"]
                else:
                    methods = ["WS" if verb == "websocket" else verb]
                deps = DEP.findall(dt) + DEP.findall(sig)
                own = mark(deps) + mark(others)
                for pre, mk, mount in eff(*key):
                    for meth in methods:
                        M.add(fw, meth, join(pre, lit(dt) or ""), r, line, mk + own, name, mount)


def resolve_py(r, expr, imports, routers_hint):
    """`diary.router` / `diary_router` / `bp` -> [(file, var)] using the file's imports and file stems."""
    imp = imports.get(r, {})
    head, _, rest = expr.partition(".")
    if rest:
        mod, orig = imp.get(head, (head, None))
        stem, var = (orig or mod.split(".")[-1]), rest
    elif head in imp:
        mod, orig = imp[head]
        stem, var = mod.split(".")[-1], orig or head
        if orig and not any(Path(f).stem == stem for f, _ in routers_hint):
            stem = orig
    else:
        return [(r, head)]
    cands = [f for f, _ in routers_hint if Path(f).stem == stem or f.endswith(f"/{stem}/__init__.py")]
    cands = [f for f in cands if re.search(r"(?m)^\s*%s\s*(?::\s*[\w.]+)?\s*=" % re.escape(var),
                                           "\n".join(dict(routers_hint)[f]))] or cands
    return [(f, var) for f in cands[:2]]


def parse_django(M: Map):
    py = M.of(".py")
    urls = [(r, ls) for r, ls in py if r.endswith("urls.py") or "/urls/" in r]
    if not urls:
        return
    dotted = {r[:-3].replace("/", ".").removesuffix(".__init__"): r for r, _ in py}

    def mod_file(mod):
        return next((r for d, r in sorted(dotted.items()) if d == mod or d.endswith("." + mod)), None)

    # view index: name -> (file, line, kind, decorators, signature, class body)
    index = {}
    for r, ls in py:
        for line, kind, name, ind, decs, sig in py_defs(ls):
            body = []
            if kind == "class":
                for ln in ls[line:line + 200]:
                    if ln.strip() and len(ln) - len(ln.lstrip()) <= ind:
                        break
                    body.append(ln)
            prev = index.get(name)
            if not prev or ("view" in r and "view" not in prev[0]):
                index[name] = (r, line, kind, decs, sig, body)
    defaults, rows, edges, drf = [], [], [], {}
    for r, ls in py:
        for i, ln in enumerate(ls):
            m = re.match(r"\s*[\"']?(DEFAULT_PERMISSION_CLASSES|DEFAULT_AUTHENTICATION_CLASSES)[\"']?\s*[:=]", ln)
            if m:
                names = [n.split(".")[-1] for n in re.findall(r"[\"']([\w.]+)[\"']", stmt(ls, i)[0])]
                M.glob("Django", r, i + 1, f"{m.group(1)}: " + ", ".join(names))
                if m.group(1) == "DEFAULT_PERMISSION_CLASSES":
                    defaults = [n for n in names if n != "AllowAny"]
            if re.match(r"\s*MIDDLEWARE\s*=", ln):
                for n in re.findall(r"[\"']([\w.]+)[\"']", stmt(ls, i)[0]):
                    if mark([n.split(".")[-1]]):
                        M.glob("Django", r, i + 1, "MIDDLEWARE " + n.split(".")[-1])
    for r, ls in urls:
        for i, ln in enumerate(ls):
            m = re.search(r"\b(path|re_path|url)\(\s*[rRuU]?([\"'])(.*?)\2\s*,\s*(.*)", stmt(ls, i)[0]) \
                if re.search(r"\b(path|re_path|url)\(", ln) else None
            if m:
                p = m.group(3).lstrip("^").rstrip("$") if m.group(1) != "path" else m.group(3)
                rest = re.sub(r"\.as_view\((?:[^()]|\([^()]*\))*\)", "", m.group(4))
                inc = re.match(r"include\(\s*\(?\s*[rRuU]?[\"']([\w.]+)[\"']", rest)
                if inc:
                    edges.append((r, i + 1, p, mod_file(inc.group(1))))
                    continue
                inc = re.match(r"include\(\s*([\w]+)\.urls", rest)
                if inc:
                    drf[(r, inc.group(1))] = p
                    continue
                h = re.match(r"((?:[\w.]+\()*)([\w.]+)", rest)
                if h:
                    rows.append((r, i + 1, p, h.group(2), re.findall(r"([\w.]+)\(", h.group(1)), None))
            m = re.search(r"\b(\w+)\.register\(\s*[rRuU]?([\"'])(.*?)\2\s*,\s*([\w.]+)", ln)
            if m:
                rows.append((r, i + 1, m.group(3), m.group(4), [], m.group(1)))
    targets = {c for _, _, _, c in edges if c}
    pre = {}

    def prefixes(f, seen=()):
        if f in pre:
            return pre[f]
        ps = [join(pp, p) for (pr, _, p, c) in edges if c == f and pr not in seen
              for pp in prefixes(pr, seen + (f,))][:3] or ([""] if f not in targets else [""])
        pre[f] = ps
        return ps
    for r, line, p, handler, wrappers, router in rows:
        name = handler.split(".")[-1]
        v = index.get(name)
        mk = mark(wrappers)
        meth = "VIEWSET" if router else "ANY"
        loc_r, loc_l = r, line
        if v:
            loc_r, loc_l, kind, decs, sig, body = v
            mk += mark([re.match(r"@([\w.]+)", d).group(1) + (re.search(r"\((.*)\)", d) or [""])[0][:40]
                        for _, d in decs if d.startswith("@")])
            text = "\n".join(body)
            for key in ("permission_classes", "authentication_classes"):
                pm = re.search(r"\b%s\s*=\s*[\[(]([^\])]*)" % key, text)
                if pm:
                    names = re.findall(r"[\w.]+", pm.group(1))
                    mk += mark(names) if names else ["!" + key + "=[]"]
            mk += mark(re.findall(r"@method_decorator\(\s*([\w.]+)", text))
            bases = re.search(r"\((.*)\)", sig)
            mk += mark(re.findall(r"\w+Mixin", bases.group(1)) if bases else [])
            drf_view = bases and re.search(r"APIView|ViewSet|GenericAPIView", bases.group(1)) or \
                any("api_view" in d for _, d in decs)
            if defaults and drf_view and not re.search(r"\bpermission_classes\s*=", text):
                mk += ["default:" + "/".join(defaults)]
            ms = [m for m in ("get", "post", "put", "patch", "delete") if re.search(r"(?m)^\s+(?:async\s+)?def %s\(" % m, text)]
            av = next((re.findall(r"[\"'](\w+)[\"']", d) for _, d in decs if re.match(r"@(api_view|require_http_methods)", d)), None)
            meth = "VIEWSET" if router else ",".join(x.upper() for x in (ms or av or [])) or "ANY"
        base = drf.get((r, router), "") if router else ""
        for pp in prefixes(r):
            M.add("Django", meth, join(pp, base, p), loc_r, loc_l, mk, handler, f"{r}:{line}")


# ---------------------------------------------------------------- Express / Koa / Fastify
JS_CLIENTS = {"axios", "http", "https", "client", "request", "superagent", "ky", "got", "fetch", "api", "instance",
              "cy", "map", "cache", "headers", "params", "query", "searchParams", "config", "store", "redis",
              "session", "localStorage", "sessionStorage", "Object", "Reflect", "this", "req", "res", "ctx",
              "response", "result", "data", "form", "formData", "url", "env", "process", "jest", "vi", "sinon"}
JS_ROUTE = re.compile(r"\b([A-Za-z_$][\w$]*)\.(get|post|put|delete|patch|all|options|head)\(\s*([\"'`])(/[^\"'`]*|\*)\3")
JS_WORDS = {"req", "res", "next", "ctx", "async", "await", "return", "const", "let", "request", "reply", "err", "function"}


def js_imports(lines):
    imp = {}
    for ln in lines:
        for m in re.finditer(r"(?:const|let|var)\s+(\w+)\s*=\s*require\(\s*[\"']([^\"']+)[\"']\s*\)", ln):
            imp[m.group(1)] = m.group(2)
        for m in re.finditer(r"import\s+(\w+)(?:\s*,\s*\{[^}]*\})?\s+from\s+[\"']([^\"']+)[\"']", ln):
            imp[m.group(1)] = m.group(2)
        for m in re.finditer(r"import\s*\{([^}]*)\}\s*from\s+[\"']([^\"']+)[\"']", ln):
            for part in m.group(1).split(","):
                w = part.split()
                if w:
                    imp[w[-1]] = m.group(2)
    return imp


def js_resolve(rel, spec, fileset):
    if not spec or not spec.startswith("."):
        return None
    base = posixpath.normpath(posixpath.join(posixpath.dirname(rel), spec))
    for ext in ("", ".js", ".ts", ".mjs", ".cjs", "/index.js", "/index.ts"):
        if base + ext in fileset:
            return base + ext
    return None


def parse_js(M: Map):
    js = [(r, ls) for r, ls in M.of(".js", ".mjs", ".cjs", ".ts")
          if re.search(r"require\([\"'](express|koa|@koa/router|koa-router|fastify)[\"']\)|from [\"'](express|koa|"
                       r"@koa/router|koa-router|fastify)[\"']|\bRouter\(|fastify", "\n".join(ls))]
    if not js:
        return
    fileset = set(M.files)
    mounts, uses, own, rows = defaultdict(list), defaultdict(list), {}, []
    fw_of = {}
    for r, ls in js:
        text = "\n".join(ls)
        fw_of[r] = "Fastify" if "fastify" in text else "Koa" if re.search(r"\bkoa\b", text) else "Express"
        imp = js_imports(ls)
        m = re.search(r"new\s+Router\(\s*\{[^}]*prefix\s*:\s*[\"'`]([^\"'`]+)", text)
        if m:
            own[r] = m.group(1)

        def target(tok):
            req = re.match(r"require\(\s*[\"']([^\"']+)", tok)
            return js_resolve(r, req.group(1) if req else imp.get(tok.split(".")[0]), fileset)
        for i, ln in enumerate(ls):
            m = re.search(r"\b[\w$]+\.use\(\s*(.*)", ln)
            if m:
                t = stmt(ls, i)[0]
                args = t.split(".use(", 1)[1]
                pm = re.match(r"\s*([\"'`])([^\"'`]*)\1\s*,", args)
                prefix = pm.group(2) if pm else ""
                toks = re.findall(r"require\(\s*[\"'][^\"']+[\"']\s*\)|[A-Za-z_$][\w$.]*", args[pm.end():] if pm else args)
                tgts = [x for x in (target(tk) for tk in toks) if x]
                mws = mark([tk for tk in toks if not target(tk) and tk not in JS_WORDS])
                if tgts:
                    for tf in tgts:
                        mounts[tf].append((r, prefix, mws, i + 1))
                elif mws:
                    uses[r].append((i + 1, prefix, mws))
                    M.glob(fw_of[r], r, i + 1, f"use({prefix + ', ' if prefix else ''}{', '.join(mws)})")
            m = re.search(r"\.register\(\s*(require\(\s*[\"'][^\"']+[\"']\s*\)|[\w$.]+)\s*,\s*\{([^}]*)\}", stmt(ls, i)[0]) \
                if ".register(" in ln else None
            if m and target(m.group(1)):
                mounts[target(m.group(1))].append((r, lit(m.group(2), "prefix") or "", [], i + 1))
            m = re.search(r"\.addHook\(\s*[\"'](onRequest|preHandler|preValidation)[\"']\s*,\s*([\w$.]+)", ln)
            if m and mark([m.group(2)]):
                uses[r].append((i + 1, "", mark([m.group(2)])))
                M.glob("Fastify", r, i + 1, f"addHook({m.group(1)}, {m.group(2)})")
            for m in JS_ROUTE.finditer(ln):
                if m.group(1) in JS_CLIENTS or "test" in m.group(1).lower():
                    continue
                args = call_args(ls, i, m.end())
                cut = re.search(r"\basync\b|=>|\bfunction\b", args)
                pre = args[:cut.start()] if cut else args
                toks = [x for x in re.findall(r"[A-Za-z_$][\w$.]*", pre) if x not in JS_WORDS]
                handler = "" if cut or not toks else toks.pop()
                rows.append((r, i + 1, m.group(2), m.group(4), mark(toks), handler))
            m = re.search(r"\.route\(\s*\{", ln)
            if m:
                t = stmt(ls, i)[0]
                url = lit(t, "url") or lit(t, "path")
                if url:
                    meths = re.findall(r"[\"'](GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)[\"']", t.split("url", 1)[0]) or ["ANY"]
                    hooks = re.findall(r"(?:preHandler|onRequest|preValidation)\s*:\s*\[?([^\]\n,}]+)", t)
                    for meth in meths:
                        rows.append((r, i + 1, meth, url, mark(re.findall(r"[\w$.]+", " ".join(hooks))), ""))

    def eff(f, seen=()):
        ms = mounts.get(f)
        if not ms or f in seen:
            return [(own.get(f, ""), [], "")]
        out = []
        for pf, pre, mws, ln in ms[:3]:
            inherited = [x for l2, p2, mk in uses.get(pf, []) if l2 < ln and not p2 for x in mk]
            scoped = [x for l2, p2, mk in uses.get(pf, []) if p2 and pre.startswith(p2) for x in mk]
            for ppre, pmk, _ in eff(pf, seen + (f,)):
                out.append((join(ppre, pre, own.get(f, "")), pmk + inherited + scoped + mws, f"{pf}:{ln}"))
        return out
    for r, line, meth, path, mk, handler in rows:
        local = [x for l2, p2, m2 in uses.get(r, []) if l2 < line and (not p2 or path.startswith(p2)) for x in m2]
        for pre, pmk, mount in eff(r):
            M.add(fw_of[r], "ANY" if meth == "all" else meth, join(pre, path), r, line, pmk + local + mk, handler, mount)


# ---------------------------------------------------------------- fetch handlers (Workers / Deno / Bun)
FETCH_ENTRY = re.compile(r"(?m)^\s*(async\s+)?fetch\s*\(\s*(request|req)\b[^)]*\)\s*(:[^{]*)?\{|"
                         r"\bfetch\s*:\s*(async\s*)?\(\s*(request|req)\b|addEventListener\(\s*[\"']fetch[\"']|"
                         r"\b(Deno|Bun)\.serve\(")
FETCH_PATH = [  # literal routes only; anything computed stays a gap
    re.compile(r"^\s*\[\s*([\"'`])(/[^\"'`]*)\1\s*,"),  # new Map([["/path", handler], ...])
    re.compile(r"^\s*([\"'`])(/[^\"'`]*)\1\s*:"),  # { "/path": handler }
    re.compile(r"\bpathname\s*===?\s*([\"'`])(/[^\"'`]*)\1"),
    re.compile(r"([\"'`])(/[^\"'`]*)\1\s*===?\s*[\w.]*pathname\b"),
    re.compile(r"\bcase\s+([\"'`])(/[^\"'`]*)\1\s*:"),
    re.compile(r"\bpathname\.startsWith\(\s*([\"'`])(/[^\"'`]*)\1"),
]


def parse_fetch(M: Map):
    for r, ls in M.of(".js", ".mjs", ".cjs", ".ts"):
        text = "\n".join(ls)
        if not FETCH_ENTRY.search(text) or re.search(r"new Hono\(", text):
            continue
        fw = "Fetch handler (Workers / Deno / Bun)"
        n = 0
        for i, ln in enumerate(ls):
            for k, rx in enumerate(FETCH_PATH):
                m = rx.search(ln)
                if m:
                    meth = re.search(r"\bmethod\s*===?\s*[\"'](GET|POST|PUT|DELETE|PATCH)[\"']", ln)
                    path = m.group(2) + ("*" if k == len(FETCH_PATH) - 1 else "")
                    M.add(fw, meth.group(1) if meth else "ANY", path, r, i + 1, [])
                    n += 1
                    break
        if not n:
            M.gaps.append(f"{fw}: entry point in `{r}` but 0 literal routes parsed - map its dispatch by hand")
        else:
            M.notes.append(f"`{r}`: fetch handler; routes are literal paths only (auth is checked inside the "
                           f"handler, so no marker is taken) - read the dispatch for computed routes")


# ---------------------------------------------------------------- NestJS / Spring (annotations)
ANN = re.compile(r"@([\w.]+)(\((?:[^()]|\((?:[^()]|\([^()]*\))*\))*\))?")
SPRING_MAP = {"GetMapping": "GET", "PostMapping": "POST", "PutMapping": "PUT", "DeleteMapping": "DELETE",
              "PatchMapping": "PATCH", "RequestMapping": "ANY"}
NEST_MAP = {"Get": "GET", "Post": "POST", "Put": "PUT", "Delete": "DELETE", "Patch": "PATCH", "All": "ANY",
            "Options": "OPTIONS", "Head": "HEAD"}
SEC_ANN = {"PreAuthorize", "PostAuthorize", "Secured", "RolesAllowed", "DenyAll", "UseGuards", "Roles", "Permissions"}


def annotated(lines):
    """Yield (line, [(name, args)], target_text) for every annotated class / member."""
    decs, i = [], 0
    while i < len(lines):
        s = lines[i].strip()
        if s.startswith("@"):
            text, j = stmt(lines, i)
            m = re.match(r"((?:@[\w.]+(?:\((?:[^()]|\((?:[^()]|\([^()]*\))*\))*\))?\s*)+)(.*)$", text)
            decs += [(a.group(1).split(".")[-1], a.group(2) or "") for a in ANN.finditer(m.group(1) if m else text)]
            rest = (m.group(2) if m else "").strip()
            i = j + 1
            if rest and decs:
                yield i, decs, rest
                decs = []
            continue
        if s and not s.startswith(("//", "*", "/*")) and decs:
            yield i + 1, decs, s
            decs = []
        i += 1


def ann_markers(decs):
    out = []
    for name, args in decs:
        if name in SPRING_MAP or name in NEST_MAP or name in ("Controller", "RestController"):
            continue
        if name == "UseGuards":
            out += mark(re.findall(r"[\w.]+", args)) or ["UseGuards" + args[:40]]
        elif "permitAll" in args:
            out.append("!" + short(name + args)[:59])
        elif name in SEC_ANN or NEG_RX.search(name) or mark([name]):
            out += mark([name + args]) or [short(name + args)]
    return out


def parse_annotations(M: Map):
    nest_prefix = ""
    for r, ls in M.of(".ts", ".js"):
        text = "\n".join(ls)
        g = re.search(r"setGlobalPrefix\(\s*[\"'`]([^\"'`]+)", text)
        nest_prefix = g.group(1) if g else nest_prefix
        for i, ln in enumerate(ls):
            if "useGlobalGuards(" in ln or re.search(r"provide\s*:\s*APP_GUARD", ln):
                M.glob("NestJS", r, i + 1, short(stmt(ls, i)[0])[:60])
    for r, ls in M.of(".ts", ".js", ".java", ".kt"):
        text = "\n".join(ls)
        spring = r.endswith((".java", ".kt"))
        if spring:
            for i, ln in enumerate(ls):
                for m in re.finditer(r"(requestMatchers|antMatchers|mvcMatchers|pathMatchers|regexMatchers)\(([^)]*)\)\s*"
                                     r"\.\s*(permitAll|authenticated|hasRole|hasAnyRole|hasAuthority|hasAnyAuthority|denyAll|access)", ln):
                    M.notes.append(f"Spring security `{r}:{i + 1}` {short(m.group(2))[:50]} -> {m.group(3)}")
                for m in re.finditer(r"authorize\(\s*\"([^\"]+)\"\s*,\s*(permitAll|authenticated|hasRole|hasAuthority|denyAll)", ln):
                    M.notes.append(f"Spring security `{r}:{i + 1}` {short(m.group(1))} -> {m.group(2)}")
                m = re.search(r"anyRequest\(\)\s*\.\s*(\w+)|\bSecurityFilterChain\b|@Enable(Web|Method|GlobalMethod)Security", ln)
                if m:
                    M.glob("Spring", r, i + 1, short(m.group(0)))
        if not re.search(r"@(Rest)?Controller\b", text):
            continue
        fw = "Spring" if spring else "NestJS"
        ctx = None
        for line, decs, target in annotated(ls):
            names = {n for n, _ in decs}
            if re.search(r"\bclass\s+\w+", target):
                ctrl = next(((n, a) for n, a in decs if n in ("Controller", "RestController")), None)
                ctx = None
                if ctrl:
                    if spring:
                        rm = next((a for n, a in decs if n == "RequestMapping"), "")
                        cpre = (re.findall(r"\"([^\"]*)\"", rm) or [""])[0]
                    else:
                        cpre = (re.findall(r"[\"'`]([^\"'`]*)[\"'`]", ctrl[1]) or [""])[0]
                        cpre = join(nest_prefix, cpre) if nest_prefix else cpre
                    ctx = (cpre, ann_markers(decs))
                continue
            if not ctx:
                continue
            mp = SPRING_MAP if spring else NEST_MAP
            for n, a in decs:
                if n not in mp or (not spring and n not in names):
                    continue
                if spring:
                    a2 = re.split(r",\s*(?:method|produces|consumes|params|headers|name)\s*=", a)[0]
                    paths = re.findall(r"\"([^\"]*)\"", a2) or [""]
                    meths = re.findall(r"RequestMethod\.(\w+)", a) or [mp[n]]
                else:
                    paths = (re.findall(r"[\"'`]([^\"'`]*)[\"'`]", a) or [""])[:1]
                    meths = [mp[n]]
                hname = re.search(r"(\w+)\s*\(", target)
                for p in paths:
                    for meth in meths:
                        M.add(fw, meth, join(ctx[0], p), r, line, ctx[1] + ann_markers(decs), hname.group(1) if hname else "")


# ---------------------------------------------------------------- Laravel
def parse_laravel(M: Map):
    php = M.of(".php")
    route_files = [(r, ls) for r, ls in php if re.search(r"(^|/)routes/", r)]
    if not route_files:
        return
    ctrl_index = {Path(r).stem: (r, ls) for r, ls in php if "Controller" in Path(r).stem}
    for r, ls in php:
        if r.endswith("Http/Kernel.php"):
            for i, ln in enumerate(ls):
                for n in re.findall(r"([\w\\]+)::class", ln):
                    if mark([n.split("\\")[-1]]):
                        M.glob("Laravel", r, i + 1, "Kernel middleware " + n.split("\\")[-1])
    for r, ls in route_files:
        base = "/api" if r.endswith("routes/api.php") else ""
        if base:
            M.notes.append(f"Laravel `{r}`: default `/api` prefix and `api` middleware group assumed (RouteServiceProvider)")
        stack, depth = [], 0
        i = 0
        while i < len(ls):
            ln = ls[i]
            bare = STR.sub("", ln)
            opens, closes = bare.count("{"), bare.count("}")
            if re.search(r"Route::.*->group\(|Route::group\(|\$router->group\(", ln):
                t = stmt(ls, i, end="{")[0] if "{" not in bare else ln
                pre = lit(t, "prefix") or (re.search(r"prefix\(\s*[\"']([^\"']*)", t) or [None, ""])[1]
                mws = re.findall(r"[\"']([\w:.,-]+)[\"']", " ".join(re.findall(r"middleware[\"']?\s*(?:=>\s*|\()\s*(\[[^\]]*\]|[\"'][^\"']*[\"'])", t)))
                stack.append((depth + opens, pre or "", mark(mws)))
            m = re.search(r"(?:Route::|\$router->)(get|post|put|patch|delete|options|any|match|resource|apiResource)\(", ln)
            if m:
                t, _ = stmt(ls, i, end=";")
                verb = m.group(1)
                if verb == "match":
                    meths = re.findall(r"[\"'](\w+)[\"']", t.split("]", 1)[0])
                    p = (re.findall(r"\]\s*,\s*[\"']([^\"']*)", t) or [""])[0]
                else:
                    meths, p = [verb.upper() if verb not in ("any", "resource", "apiResource") else verb.upper()], lit(t) or ""
                mws = re.findall(r"[\"']([\w:.,-]+)[\"']", " ".join(re.findall(r"->middleware\(([^)]*)\)", t)))
                mk = mark(mws) + ["!" + short(x) for x in re.findall(r"->withoutMiddleware\(([^)]*)\)", t)]
                h = re.search(r"\[\s*([\w\\]+)::class\s*,\s*[\"'](\w+)[\"']|[\"']([\w\\]+)@(\w+)[\"']|([\w\\]+)::class", t)
                hr, hl, hname = r, i + 1, ""
                if h:
                    cls = (h.group(1) or h.group(3) or h.group(5)).split("\\")[-1]
                    act = h.group(2) or h.group(4) or ""
                    hname = f"{cls}@{act}" if act else cls
                    if cls in ctrl_index:
                        cr, cls_ls = ctrl_index[cls]
                        hr, hl = cr, next((k + 1 for k, x in enumerate(cls_ls) if re.search(r"function\s+%s\s*\(" % act, x)), 1) if act else 1
                        mk += mark(re.findall(r"\$this->middleware\(\s*[\"']([^\"']+)", "\n".join(cls_ls)), "ctor:")
                pre = join(base, *[s[1] for s in stack]) if (base or stack) else ""
                for meth in meths:
                    M.add("Laravel", meth, join(pre, p), hr, hl, [x for s in stack for x in s[2]] + mk, hname, f"{r}:{i + 1}")
            depth += opens - closes
            while stack and depth < stack[-1][0]:
                stack.pop()
            i += 1


# ---------------------------------------------------------------- Rails
RAILS_ACTIONS = {"index": ("GET", ""), "show": ("GET", "/:id"), "new": ("GET", "/new"), "edit": ("GET", "/:id/edit"),
                 "create": ("POST", ""), "update": ("PATCH", "/:id"), "destroy": ("DELETE", "/:id")}


def parse_rails(M: Map):
    rb = M.of(".rb")
    routes = [(r, ls) for r, ls in rb if re.search(r"(^|/)config/routes(\.rb|/)", r)]
    if not routes:
        return
    ctrls = {}
    for r, ls in rb:
        m = re.search(r"controllers/(.+)_controller\.rb$", r)
        if not m:
            continue
        acts, sk, sup = [], [], ""
        for i, ln in enumerate(ls):
            c = re.match(r"\s*class\s+\S+\s*<\s*(\S+)", ln)
            sup = c.group(1) if c and not sup else sup
            for kind, name, opts in re.findall(r"^\s*(before_action|skip_before_action|before_filter)\s+:(\w+[!?]?)(.*)", ln):
                only = re.findall(r":(\w+)", (re.search(r"only:\s*(\[[^\]]*\]|:\w+)", opts) or [None, ""])[1])
                exc = re.findall(r":(\w+)", (re.search(r"except:\s*(\[[^\]]*\]|:\w+)", opts) or [None, ""])[1])
                (sk if kind.startswith("skip") else acts).append((name, only, exc))
        defs = {d: i + 1 for i, ln in enumerate(ls) for d in re.findall(r"^\s*def\s+(\w+)", ln)}
        ctrls[m.group(1)] = (r, acts, sk, sup, defs)
    app = ctrls.get("application")
    if app:
        for name, _, _ in app[1]:
            if mark([name]):
                M.glob("Rails", app[0], 1, f"ApplicationController before_action :{name}")

    def applies(only, exc, act):
        return (not only or act in only) and act not in exc

    def markers(ctrl, act):
        c = ctrls.get(ctrl)
        if not c:
            return [], None
        chain = list(c[1]) + (list(app[1]) if app and c is not app and c[3] == "ApplicationController" else [])
        mk = [x for n, o, e in chain if applies(o, e, act) for x in mark([n])]
        for n, o, e in c[2]:
            if applies(o, e, act) and mark([n]):
                mk = [x for x in mk if x != n] + [f"!skip_before_action:{n}"]
        return mk, (c[0], c[4].get(act, 1))
    for r, ls in routes:
        stack = []  # (prefix, module)
        for i, ln in enumerate(ls):
            s = re.sub(r"#.*$", "", ln).strip()
            if s == "end":
                if stack:
                    stack.pop()
                continue
            pre = join(*[x[0] for x in stack]) if stack else ""
            mod = "/".join(x[1] for x in stack if x[1])
            push = None
            m = re.match(r"namespace\s+:(\w+)", s)
            if m:
                push = ("/" + m.group(1), m.group(1))
            m = re.match(r"scope\s+(?:path:\s*)?[\"'](/?[^\"']*)[\"']", s) or re.match(r"scope\s+module:\s*[\"':](\w+)", s)
            if m and not push:
                push = (m.group(1), "") if "module" not in s else ("", m.group(1))
            m = re.match(r"(resources?)\s+:(\w+)(.*)", s)
            if m:
                plural = m.group(1) == "resources"
                only = re.findall(r":(\w+)", (re.search(r"only:\s*(\[[^\]]*\]|:\w+)", m.group(3)) or [None, ""])[1])
                exc = re.findall(r":(\w+)", (re.search(r"except:\s*(\[[^\]]*\]|:\w+)", m.group(3)) or [None, ""])[1])
                ctrl = "/".join(x for x in (mod, m.group(2) if plural else m.group(2) + "s") if x)
                for act, (meth, sub) in RAILS_ACTIONS.items():
                    if (only and act not in only) or act in exc or (not plural and act == "index"):
                        continue
                    mk, loc = markers(ctrl, act)
                    hr, hl = loc or (r, i + 1)
                    M.add("Rails", meth, join(pre, m.group(2), sub if plural else sub.replace("/:id", "")), hr, hl, mk,
                          f"{ctrl}#{act}", f"{r}:{i + 1}")
                push = (f"/{m.group(2)}/:{m.group(2).rstrip('s')}_id" if plural else f"/{m.group(2)}", "")
            m = re.match(r"(get|post|put|patch|delete|match|root)\b\s*\(?\s*(?:[\"']([^\"']*)[\"'])?(.*)", s)
            if m and not s.startswith("resources"):
                to = re.search(r"(?:to:\s*|=>\s*)[\"'](\S+?)#(\w+)[\"']", s) or re.search(r"[\"']([\w/]+)#(\w+)[\"']", s)
                p = m.group(2) or ("" if m.group(1) == "root" else "")
                ctrl, act = (("/".join(x for x in (mod, to.group(1)) if x), to.group(2)) if to else ("", ""))
                mk, loc = markers(ctrl, act) if ctrl else ([], None)
                hr, hl = loc or (r, i + 1)
                meth = {"root": "GET", "match": "ANY"}.get(m.group(1), m.group(1))
                M.add("Rails", meth, join(pre, p), hr, hl, mk, f"{ctrl}#{act}" if ctrl else "", f"{r}:{i + 1}")
            if s.startswith("devise_for"):
                M.glob("Rails", r, i + 1, s)
            elif s.startswith("mount "):
                M.notes.append(f"Rails mount `{r}:{i + 1}` {short(s)} (engine routes not parsed)")
            if re.search(r"\bdo(\s*\|[^|]*\|)?\s*$", s):
                stack.append(push or ("", ""))


# ---------------------------------------------------------------- detection + output
DETECT = {  # framework -> manifest / code signal
    "FastAPI": r"\bfastapi\b", "Flask": r"(?i)^flask\b|\bflask[=<>~ ]|\"flask\"", "Django": r"(?i)\bdjango\b",
    "Express": r"\"express\"\s*:", "Koa": r"\"koa\"\s*:|\"@koa/router\"", "Fastify": r"\"fastify\"\s*:",
    "NestJS": r"\"@nestjs/core\"", "Spring": r"spring-boot|org\.springframework", "Laravel": r"laravel/framework",
    "Rails": r"\brails\b",
}
UNPARSED = {  # framework -> code / path signal (detected, never parsed)
    "Go net/http / gin / echo / chi / fiber": (r"\.go$", r"\b(HandleFunc|gin\.Default|echo\.New|chi\.NewRouter|fiber\.New|mux\.NewRouter)\("),
    "ASP.NET": (r"\.cs$", r"\[(Http(Get|Post|Put|Delete)|ApiController|Route)\b|\.Map(Get|Post|Put|Delete)\("),
    "Next.js route handlers / pages/api": (r"(^|/)(pages/api/|app/.*/route\.(js|ts)$)", r"."),
    "Hono": (r"\.(ts|js)$", r"new Hono\("),
    "GraphQL resolvers": (r"\.(py|ts|js|java|kt|rb|go)$", r"@Resolver\(|typeDefs|graphene\.|strawberry\.|GraphQLSchema"),
    "gRPC services": (r"\.proto$", r"^\s*service\s+\w+"),
    "Serverless / Lambda HTTP events": (r"serverless\.ya?ml$|template\.ya?ml$", r"httpApi|\bhttp:|Events:"),
    "Symfony": (r"\.php$", r"#\[Route\("),
    "Phoenix": (r"router\.ex$", r"."),
    "Sinatra": (r"\.rb$", r"Sinatra::Base"),
}


def detect(M: Map, raw_names):
    manifests = "\n".join("\n".join(ls) for r, ls in M.files.items()
                          if Path(r).name in ("requirements.txt", "pyproject.toml", "Pipfile", "setup.py", "package.json",
                                              "pom.xml", "build.gradle", "build.gradle.kts", "composer.json", "Gemfile"))
    found = {fw for fw, rx in DETECT.items() if re.search(rx, manifests, re.M)}
    unparsed = []
    for fw, (prx, crx) in UNPARSED.items():
        hits = [r for r in raw_names if re.search(prx, r) and (crx == "." or re.search(crx, "\n".join(M.files.get(r, [])), re.M))]
        if hits:
            unparsed.append(f"{fw}: {len(hits)} file(s), e.g. `{hits[0]}`")
    return found, unparsed


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("repo")
    ap.add_argument("--out", required=True, help="routes.md (routes.json is written beside it)")
    ap.add_argument("--max-rows", type=int, default=250, help="route rows in the md (all go to the json)")
    ap.add_argument("--max-files", type=int, default=20000)
    a = ap.parse_args()
    root = Path(host_path(a.repo)).resolve()
    if not root.is_dir():
        print(f"error: not a directory: {a.repo}", file=sys.stderr)
        return 2
    files, names = {}, []
    for rel in sorted(list_files(root, a.max_files)):
        if TESTISH.search(rel) or VENDOR.search(rel):
            continue
        p = root / rel
        name = Path(rel).name
        keep = os.path.splitext(rel)[1].lower() in SRC_EXT or name in (
            "requirements.txt", "pyproject.toml", "Pipfile", "package.json", "pom.xml", "build.gradle",
            "build.gradle.kts", "composer.json", "Gemfile") or re.search(r"\.(go|cs|proto|ex|ya?ml)$", rel)
        if not keep or safegit.escapes(root, p):
            continue
        try:
            if p.stat().st_size > 1_000_000:
                continue
            files[rel] = safegit.read_text(p).splitlines()
            names.append(rel)
        except OSError:
            continue
    M = Map(root, files)
    for fn in (parse_python, parse_django, parse_js, parse_fetch, parse_annotations, parse_laravel, parse_rails):
        try:
            fn(M)
        except Exception as e:  # one parser's bug must not lose the others' routes
            M.gaps.append(f"{fn.__name__} failed ({type(e).__name__}: {short(str(e))}) - read that framework's routes yourself")
    found, unparsed = detect(M, names)
    seen = {r["framework"] for r in M.routes}
    for fw in sorted(found - seen):
        M.gaps.append(f"{fw}: dependency detected but 0 routes parsed (dynamic registration or unusual layout)")
    M.gaps += [f"not parsed: {u}" for u in unparsed]
    key = lambda r: (r["framework"], r["file"], r["line"], r["path"], r["method"])  # noqa: E731
    M.routes = sorted({json.dumps(r, sort_keys=True): r for r in M.routes}.values(), key=key)
    noauth = [r for r in M.routes if not has_auth(r["auth"])]

    out_md = Path(host_path(a.out))
    out_md.parent.mkdir(parents=True, exist_ok=True)
    js = {"repo": root.name, "frameworks": {fw: sum(1 for r in M.routes if r["framework"] == fw) for fw in sorted(seen)},
          "routes": M.routes, "no_auth_marker": [f"{r['method']} {r['path']}" for r in noauth],
          "global_auth": M.globals, "notes": M.notes, "gaps": M.gaps}
    out_md.with_suffix(".json").write_text(json.dumps(js, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")

    o = [f"# Route map - {root.name}", "",
         "Static regex extraction (no code run). `auth` = names seen near the route (dependency, decorator, middleware, "
         "guard, annotation, before_action); `!x` = an explicit opt-out. A marker does not prove the control works and "
         "\"no marker\" is a lead, not a verdict: read the control. Dynamic registration is missed.", "",
         "Parsed: " + (", ".join(f"{fw} {n}" for fw, n in js["frameworks"].items()) or "no routes found"), "",
         "## Global auth mechanisms (may cover routes below)"]
    o += [f"- `{g['at']}` {g['framework']}: {g['what']}" for g in M.globals[:30]] or ["- none detected"]
    o += ["", f"## Routes with NO auth marker found ({len(noauth)}) - leads, not verdicts"]
    o += [f"- {r['method']} `{r['path']}` -> `{r['file']}:{r['line']}`" + (f" ({', '.join(r['auth'])})" if r["auth"] else "")
          for r in noauth[:80]] or ["- none"]
    if len(noauth) > 80:
        o.append(f"- ... +{len(noauth) - 80} more in routes.json")
    shown = 0
    for fw in sorted(seen):
        rows = [r for r in M.routes if r["framework"] == fw]
        o += ["", f"## {fw} ({len(rows)} routes)", "| file | line | method | path | auth |", "|---|---|---|---|---|"]
        last = None
        for r in rows:
            if shown >= a.max_rows:
                break
            shown += 1
            o.append(f"| {'`' + r['file'] + '`' if r['file'] != last else ''} | {r['line']} | {r['method']} | "
                     f"`{r['path']}` | {', '.join(r['auth'][:4]) or '-'} |")
            last = r["file"]
    if shown < len(M.routes):
        o += ["", f"{len(M.routes) - shown} route rows omitted (cap {a.max_rows}) - all are in routes.json."]
    if M.notes:
        o += ["", "## Notes"] + [f"- {n}" for n in M.notes[:30]]
    o += ["", "## Gaps"] + ([f"- {g}" for g in M.gaps] or ["- none detected"])
    out_md.write_text("\n".join(o) + "\n", encoding="utf-8")
    print(f"wrote {a.out} (+ routes.json) - {len(M.routes)} routes, {len(noauth)} without an auth marker, "
          f"{len(M.globals)} global mechanisms, {len(M.gaps)} gaps")
    return 0


if __name__ == "__main__":
    sys.exit(main())
