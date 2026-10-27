#!/usr/bin/env python3
"""
プラットフォーム一覧（Phase 1）- リポジトリがデプロイするランタイム、サーバー、データストア、ベースイメージ、
フレームワークを、指定しているバージョンとその箇所とともに一覧にし、露出とハードニングの手掛かりも挙げる。
threat_intel.py はこの一覧を最新の勧告（KEV、NVD、EPSS、サポート終了データ、IPA / JPCERT/CC / JVN の
注意喚起）と照合する。supply-chain-infra レーンはここから始める。

理由：SCA スキャナはロックファイルを読むため、インタプリタやサーバーの不具合（PHP、Node.js、OpenSSL、nginx の
リリース、データベースのイメージ）は見えない。これらは Dockerfile、compose / Kubernetes / Helm のファイル、
バージョンファイル、CI のセットアップ手順、サーバーレスのランタイム、フレームワークのロックファイルの項目で
指定されている。

構成要素：product（カタログのキー）、version、precision（exact x.y.z / minor x.y / major x / range 範囲指定 /
floating タグ追従 / distro ディストリビューションのパッケージ / managed マネージドランタイム）、context
（deploy = 最終イメージ、compose、マニフェスト、サーバーレス。build = ビルダーステージ。ci。dev = 開発 / テスト用の
compose。declared = バージョンファイルまたは範囲指定）、source `path:line`。
シグナル（判定ではなく手掛かり）：root で動くコンテナ、実行イメージ内のダウンロードツール、リモートの ADD、
ダイジェストのないベースイメージ、危険な php.ini 設定、Web ルート配下の機微なファイル、phpinfo、
ディレクトリ一覧表示、デプロイ用ファイル内の管理 / BI ツール、公開されたデータストアのポート、Spring actuator の
露出、Tomcat manager のロール、Kubernetes の NetworkPolicy なし、セキュリティグループの全宛先への egress、
ベースイメージの自動更新なし。

読み取り専用。追跡対象のファイルのみ（git ls-files、なければ走査）。リポジトリのコードは決して実行しない。
値は peek.redact を通す。ネットワークは使わない。

使い方:
  python platform_inventory.py <repo> --out <work>/<repo>/platform.md   （platform.json も書き出す）
"""
from __future__ import annotations

import sys
sys.dont_write_bytecode = True  # インストール済みスキルに __pycache__ を作らない
for _s in (sys.stdout, sys.stderr):  # cp932 / cp1252 のコンソールやパイプでも UTF-8 で出力する
    if hasattr(_s, "reconfigure"):
        _s.reconfigure(encoding="utf-8", errors="replace")

import argparse
import datetime as dt
import json
import re
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from peek import redact as _redact  # noqa: E402
from repo_digest import host_path, list_files  # noqa: E402

# 製品キー -> endoflife.date の ID、NVD CPE の vendor:product（application）、フィード上の別名、種別
CATALOG = {
    "php": ("php", "php:php", ["PHP"], "runtime"),
    "node": ("nodejs", "nodejs:node.js", ["Node.js", "nodejs"], "runtime"),
    "python": ("python", "python:python", ["Python"], "runtime"),
    "ruby": ("ruby", "ruby-lang:ruby", ["Ruby"], "runtime"),
    "go": ("go", "golang:go", ["Golang", "Go言語"], "runtime"),
    "java": ("eclipse-temurin", "oracle:openjdk", ["Java SE", "OpenJDK", "Oracle Java", "JDK", "JRE"], "runtime"),
    "dotnet": ("dotnet", "microsoft:.net", [".NET"], "runtime"),
    "nginx": ("nginx", "f5:nginx", ["nginx"], "server"),
    "httpd": ("apache-http-server", "apache:http_server", ["Apache HTTP Server", "Apache httpd"], "server"),
    "tomcat": ("tomcat", "apache:tomcat", ["Apache Tomcat", "Tomcat"], "server"),
    "openssl": ("openssl", "openssl:openssl", ["OpenSSL"], "library"),
    "haproxy": ("haproxy", "haproxy:haproxy", ["HAProxy"], "server"),
    "traefik": ("traefik", "traefik:traefik", ["Traefik"], "server"),
    "caddy": ("caddy", None, ["Caddy"], "server"),
    "postgres": ("postgresql", "postgresql:postgresql", ["PostgreSQL"], "datastore"),
    "mysql": ("mysql", "oracle:mysql", ["MySQL"], "datastore"),
    "mariadb": ("mariadb", "mariadb:mariadb", ["MariaDB"], "datastore"),
    "redis": ("redis", "redis:redis", ["Redis"], "datastore"),
    "valkey": ("valkey", None, ["Valkey"], "datastore"),
    "mongodb": ("mongodb", "mongodb:mongodb", ["MongoDB"], "datastore"),
    "elasticsearch": ("elasticsearch", "elastic:elasticsearch", ["Elasticsearch"], "datastore"),
    "memcached": ("memcached", "memcached:memcached", ["Memcached"], "datastore"),
    "rabbitmq": ("rabbitmq", "vmware:rabbitmq", ["RabbitMQ"], "datastore"),
    "alpine": ("alpine-linux", None, ["Alpine Linux"], "os"),
    "debian": ("debian", None, ["Debian"], "os"),
    "ubuntu": ("ubuntu", None, ["Ubuntu"], "os"),
    "amazonlinux": ("amazon-linux", None, ["Amazon Linux"], "os"),
    "wordpress": ("wordpress", "wordpress:wordpress", ["WordPress"], "app"),
    "drupal": ("drupal", "drupal:drupal", ["Drupal"], "app"),
    "movabletype": (None, "sixapart:movable_type", ["Movable Type", "MovableType"], "app"),
    "metabase": ("metabase", "metabase:metabase", ["Metabase"], "app"),
    "grafana": ("grafana", "grafana:grafana", ["Grafana"], "app"),
    "kibana": ("kibana", "elastic:kibana", ["Kibana"], "app"),
    "jenkins": ("jenkins", "jenkins:jenkins", ["Jenkins"], "app"),
    "keycloak": ("keycloak", "redhat:keycloak", ["Keycloak"], "app"),
    "gitlab": ("gitlab", "gitlab:gitlab", ["GitLab"], "app"),
    "phpmyadmin": (None, "phpmyadmin:phpmyadmin", ["phpMyAdmin"], "app"),
    "laravel": ("laravel", "laravel:framework", ["Laravel"], "framework"),
    "symfony": ("symfony", "sensiolabs:symfony", ["Symfony"], "framework"),
    "django": ("django", "djangoproject:django", ["Django"], "framework"),
    "rails": ("rails", "rubyonrails:rails", ["Ruby on Rails"], "framework"),
    "spring-boot": ("spring-boot", "vmware:spring_boot", ["Spring Boot"], "framework"),
    "nextjs": ("nextjs", "vercel:next.js", ["Next.js"], "framework"),
    "nuxt": ("nuxt", None, ["Nuxt"], "framework"),
    "angular": ("angular", None, ["Angular"], "framework"),
}

# イメージのパス（レジストリを除く）-> 製品
IMAGES = {
    "php": "php", "node": "node", "python": "python", "ruby": "ruby", "golang": "go", "openjdk": "java",
    "eclipse-temurin": "java", "amazoncorretto": "java", "ibm-semeru-runtimes": "java", "java": "java",
    "dotnet/aspnet": "dotnet", "dotnet/runtime": "dotnet", "dotnet/sdk": "dotnet", "nginx": "nginx",
    "nginxinc/nginx-unprivileged": "nginx", "bitnami/nginx": "nginx", "httpd": "httpd", "tomcat": "tomcat",
    "haproxy": "haproxy", "traefik": "traefik", "caddy": "caddy", "postgres": "postgres",
    "postgis/postgis": "postgres", "bitnami/postgresql": "postgres", "mysql": "mysql", "mariadb": "mariadb",
    "redis": "redis", "bitnami/redis": "redis", "redis/redis-stack": "redis", "valkey/valkey": "valkey",
    "mongo": "mongodb", "bitnami/mongodb": "mongodb", "elasticsearch": "elasticsearch",
    "elasticsearch/elasticsearch": "elasticsearch", "memcached": "memcached", "rabbitmq": "rabbitmq",
    "alpine": "alpine", "debian": "debian", "ubuntu": "ubuntu", "amazonlinux": "amazonlinux",
    "wordpress": "wordpress", "drupal": "drupal", "metabase/metabase": "metabase", "grafana/grafana": "grafana",
    "grafana": "grafana", "kibana": "kibana", "kibana/kibana": "kibana", "jenkins/jenkins": "jenkins",
    "keycloak/keycloak": "keycloak", "gitlab/gitlab-ce": "gitlab", "gitlab/gitlab-ee": "gitlab",
    "phpmyadmin": "phpmyadmin", "phpmyadmin/phpmyadmin": "phpmyadmin",
}
ADMIN_IMAGES = re.compile(r"(^|/)(metabase|grafana|kibana|jenkins|phpmyadmin|adminer|portainer|pgadmin4?|"
                          r"mongo-express|redis-commander|redisinsight|keycloak|tomcat|rabbitmq:[^\s\"']*management|"
                          r"elasticvue|cerebro|gitlab-c[ee])\b", re.I)
DEBIAN = {"trixie": "13", "bookworm": "12", "bullseye": "11", "buster": "10", "stretch": "9"}
UBUNTU = {"noble": "24.04", "jammy": "22.04", "focal": "20.04", "bionic": "18.04"}
TOOLS = {"nodejs": "node", "node": "node", "php": "php", "python": "python", "ruby": "ruby", "golang": "go",
         "go": "go", "java": "java", "dotnet": "dotnet", "dotnet-core": "dotnet"}
VERSION_FILES = {".php-version": "php", ".nvmrc": "node", ".node-version": "node", ".python-version": "python",
                 ".ruby-version": "ruby", ".java-version": "java", ".go-version": "go"}
DATASTORE_PORTS = {"5432", "3306", "6379", "27017", "9200", "9300", "11211", "5672", "15672", "5984", "8086"}
WEBROOT = re.compile(r"(^|/)(public|public_html|htdocs|www|web|wwwroot|html|static|webroot)/", re.I)
WEBROOT_SENSITIVE = re.compile(r"(^|/)(\.env[^/]*|\.git/.*|\.htpasswd|composer\.(json|lock)|"
                               r"[^/]+\.(bak|old|orig|save|swp|sql|sql\.gz|dump|tar|tar\.gz|tgz|zip|7z|log|ini|"
                               r"sqlite3?|db|pem|key))$", re.I)
DEV_NAME = re.compile(r"(^|[./_-])(dev|local|test|tests|ci|e2e|example|sample)([./_-]|$)", re.I)
CI_PATH = re.compile(r"^(\.github/|\.gitlab-ci|\.circleci/|bitbucket-pipelines|azure-pipelines|Jenkinsfile|"
                     r"\.buildkite/|\.drone)", re.I)
MAX_BYTES = 2_000_000
LOCK_BYTES = 30_000_000


def red(s: str) -> str:
    return _redact(s, False)[0]


def read(root: Path, rel: str, limit: int = MAX_BYTES) -> list[str] | None:
    p = root / rel
    try:
        if p.is_symlink() and root.resolve() not in p.resolve().parents:
            return None  # リポジトリ外へのリンクは決してたどらない
        if not p.is_file() or p.stat().st_size > limit:
            return None
        return p.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None


def precision(v: str) -> str:
    if re.search(r"[\^~<>=|*xX ]", v) or v.endswith(".x"):
        return "range"
    n = re.match(r"v?(\d+(?:\.\d+)*)", v)
    if not n:
        return "floating"
    k = n.group(1).count(".")
    return "exact" if k >= 2 else ("minor" if k == 1 else "major")


def numeric(v: str) -> str:
    m = re.match(r"v?(\d+(?:\.\d+)*)", v.strip())
    return m.group(1) if m else v.strip()


class Inv:
    def __init__(self):
        self.components: list[dict] = []
        self.signals: list[dict] = []
        self.deps: set[str] = set()
        self.seen: set = set()

    def comp(self, product, version, prec, context, path, line, raw="", managed=False, note=""):
        key = (product, version, context, path, line)
        if key in self.seen or product not in CATALOG:
            return
        self.seen.add(key)
        self.components.append({"product": product, "version": red(version)[:40], "precision": prec,
                                "context": context, "source": f"{path}:{line}", "raw": red(raw)[:80],
                                "kind": CATALOG[product][3], **({"managed": True} if managed else {}),
                                **({"note": note} if note else {})})

    def sig(self, sid, path, line, detail=""):
        key = (sid, path, line)
        if key not in self.seen:
            self.seen.add(key)
            self.signals.append({"id": sid, "source": f"{path}:{line}", "detail": red(detail)[:120]})


def image_ref(ref: str):
    """'registry/ns/name:tag@sha256:..' -> (製品, タグ, ダイジェストの有無, パス)。"""
    ref = ref.strip().strip("\"'")
    digest = "@sha256:" in ref
    ref = ref.split("@", 1)[0]
    parts = ref.split("/")
    if len(parts) > 1 and ("." in parts[0] or ":" in parts[0] or parts[0] == "localhost"):
        reg, parts = parts[0], parts[1:]
    else:
        reg = ""
    path = "/".join(parts)
    tag = ""
    if ":" in path.rsplit("/", 1)[-1]:
        path, tag = path.rsplit(":", 1)
    path = re.sub(r"^library/", "", path.lower())
    if reg.startswith("mcr.microsoft.com") and path.startswith("dotnet/"):
        path = "/".join(path.split("/")[:2])
    if reg == "public.ecr.aws":
        path = re.sub(r"^docker/library/", "", path)
    prod = IMAGES.get(path) or IMAGES.get(path.rsplit("/", 1)[-1] if path.count("/") == 1 and
                                          path.split("/")[0] in ("bitnami", "library") else "")
    return prod, tag, digest, path


def add_image(inv: Inv, ref: str, context: str, path: str, line: int):
    prod, tag, digest, ipath = image_ref(ref)
    if ADMIN_IMAGES.search(ipath + (":" + tag if tag else "")) and context in ("deploy", "dev"):
        inv.sig("admin-tool-image", path, line, ref)
    if not prod:
        return
    stage = context
    if context == "build" and prod == "go":  # ツールチェーンの標準ライブラリは出荷するバイナリに組み込まれる
        context = "deploy"
    code = re.match(r"[a-z]+", tag or "")
    osmap = DEBIAN if prod == "debian" else UBUNTU if prod == "ubuntu" else {}
    if code and code.group(0) in osmap:  # debian:bookworm-slim, ubuntu:jammy
        inv.comp(prod, osmap[code.group(0)], "major" if prod == "debian" else "minor", context, path, line, ref)
    elif not tag or tag == "latest":
        inv.comp(prod, tag or "latest", "floating", context, path, line, ref)
    else:
        num = numeric(tag)
        inv.comp(prod, num if re.match(r"\d", num) else tag, precision(num) if re.match(r"\d", num) else "floating",
                 context, path, line, ref)
        rest = tag[len(num):] if re.match(r"\d", num) else tag
        m = re.search(r"alpine(\d+\.\d+)?", rest)
        if m and m.group(1) and prod != "alpine":  # 単なる "-alpine" の派生はバージョン情報を加えない
            inv.comp("alpine", m.group(1), precision(m.group(1)), stage, path, line, ref, note="base OS from tag")
        for code_, ver in DEBIAN.items():
            if code_ in rest and prod != "debian":
                inv.comp("debian", ver, "major", stage, path, line, ref, note="base OS from tag")
        for code_, ver in UBUNTU.items():
            if code_ in rest and prod != "ubuntu":
                inv.comp("ubuntu", ver, "minor", stage, path, line, ref, note="base OS from tag")
    if stage == "deploy" and not digest:
        inv.sig("unpinned-base-image", path, line, ref)


def ctx_for(rel: str) -> str:
    if CI_PATH.search(rel):
        return "ci"
    return "dev" if DEV_NAME.search(rel.rsplit("/", 1)[-1]) else "deploy"


def scan_dockerfile(inv: Inv, rel: str, lines: list[str]):
    args, stages, cur = {}, [], None
    for i, ln in enumerate(lines, 1):
        s = ln.strip()
        m = re.match(r"(?i)ARG\s+(\w+)\s*=\s*\"?([^\"\s]+)", s)
        if m:
            args[m.group(1)] = m.group(2)
        m = re.match(r"(?i)FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?", s)
        if m:
            ref = re.sub(r"\$\{?(\w+)\}?", lambda x: args.get(x.group(1), x.group(0)), m.group(1))
            cur = {"ref": ref, "line": i, "user": None, "user_line": None, "tools": [], "alias": m.group(2), "pkgs": []}
            stages.append(cur)
            continue
        if cur is None:
            continue
        m = re.match(r"(?i)USER\s+(\S+)", s)
        if m:
            cur["user"], cur["user_line"] = m.group(1), i
        if re.match(r"(?i)(RUN|ENV|ARG)\b", s):
            for m in re.finditer(r"\b(PHP|NODE|PYTHON|RUBY|GOLANG|GO|JAVA|NGINX|OPENSSL|TOMCAT)_VERSION[= ]\"?([\d.]+)",
                                 s, re.I):
                prod = TOOLS.get(m.group(1).lower(), m.group(1).lower())
                cur["pkgs"].append((prod, m.group(2), precision(m.group(2)), i, m.group(0), ""))
            if re.search(r"\b(apt-get|apt|apk|yum|dnf|microdnf)\b.*\b(install|add)\b", s):
                for m in re.finditer(r"(?<![\w-])(php(\d)\.?(\d)?|nginx|apache2|httpd|nodejs|openjdk-(\d+)-\w+|"
                                     r"tomcat(\d+)|openssl|redis(?:-server)?|postgresql(?:-(\d+))?)(?=[\s=]|$)", s):
                    name = m.group(1)
                    prod = ("php" if name.startswith("php") else "httpd" if name in ("apache2", "httpd") else
                            "node" if name == "nodejs" else "java" if name.startswith("openjdk") else
                            "tomcat" if name.startswith("tomcat") else "redis" if name.startswith("redis") else
                            "postgres" if name.startswith("postgresql") else name)
                    ver = ".".join(x for x in (m.group(2), m.group(3)) if x) or m.group(4) or m.group(5) or m.group(6) \
                        or "distro"
                    cur["pkgs"].append((prod, ver, "distro", i, name, "OS package: distro backports apply"))
                if re.search(r"(?<![\w-])(curl|wget|netcat|nc|ncat|socat)(?=[\s=]|$)", s):
                    cur["tools"].append(i)
        if re.match(r"(?i)ADD\s+https?://", s):
            inv.sig("remote-add", rel, i, s[:100])
    by_alias = {st["alias"]: st for st in stages if st["alias"]}
    runtime = stages[-1] if stages else None
    seen, chain = set(), [runtime] if runtime else []
    while runtime and runtime["ref"] in by_alias and runtime["ref"] not in seen:  # FROM base AS runner の形
        seen.add(runtime["ref"])
        runtime = by_alias[runtime["ref"]]
        chain.append(runtime)
    for st in stages:  # 最終イメージが継承するステージで導入したパッケージはデプロイされる
        for prod, ver, prec, ln, raw, note in st["pkgs"]:
            inv.comp(prod, ver, prec, "deploy" if any(st is c for c in chain) else "build", rel, ln, raw, note=note)
    for st in stages:
        if st["ref"] in by_alias:
            continue  # FROM <前のステージ>：そのベースイメージはそのステージで一度だけ記録する
        add_image(inv, st["ref"], "deploy" if st is runtime else "build", rel, st["line"])
    if stages:
        last = stages[-1]
        if not last["user"] or last["user"] in ("root", "0", "0:0"):
            inv.sig("container-runs-as-root", rel, last["user_line"] or last["line"],
                    "no USER in final stage" if not last["user"] else f"USER {last['user']}")
        for ln in last["tools"]:
            inv.sig("download-tools-in-runtime-image", rel, ln, "curl/wget/nc installed in the final stage")


def scan_yaml(inv: Inv, rel: str, lines: list[str], ctx: str):
    kinds = []
    for i, ln in enumerate(lines, 1):
        m = re.match(r"\s*-?\s*image:\s*[\"']?([^\s\"'#]+)", ln)
        if m and "{{" not in m.group(1) and "${" not in m.group(1):
            add_image(inv, m.group(1), ctx, rel, i)
        m = re.match(r"(\s*)repository:\s*[\"']?([\w./-]+)", ln)
        if m:
            for j in range(i, min(i + 4, len(lines))):
                t = re.match(r"\s*tag:\s*[\"']?([\w.-]+)", lines[j])
                if t:
                    add_image(inv, f"{m.group(2)}:{t.group(1)}", ctx, rel, i)
                    break
        m = re.match(r"\s*-?\s*[\"']?(?:(\d+\.\d+\.\d+\.\d+|\[?::\]?):)?(\d+):(\d+)[\"']?\s*$", ln)
        if m and m.group(3) in DATASTORE_PORTS and m.group(1) not in ("127.0.0.1", "[::1]", "::1"):
            inv.sig("datastore-port-published", rel, i, ln.strip())
        m = re.match(r"\s*kind:\s*(\w+)", ln)
        if m:
            kinds.append((m.group(1), i))
        m = re.search(r"(?i)\b(runtime|Runtime):\s*[\"']?(nodejs\d+(?:\.x)?|python3\.\d+|java\d+|ruby\d\.\d|dotnet\d+|"
                      r"php\d{2}|go1\.x|python\d{2,3})\b", ln)
        if m:
            add_runtime(inv, m.group(2), rel, i)
        m = re.search(r"(php|node|python|ruby|go|java|dotnet)-version:\s*[\"']?([\d][\w.]*)", ln)
        if m and ctx == "ci":
            inv.comp(TOOLS.get(m.group(1), m.group(1)), numeric(m.group(2)), precision(m.group(2)), "ci", rel, i, ln.strip())
        if re.search(r"exposure\.include\s*[:=]\s*[\"']?\*|^\s*include:\s*[\"']\*[\"']", ln) and \
                ("exposure" in ln or any("exposure" in lines[k] for k in range(max(0, i - 4), i - 1))):
            inv.sig("actuator-exposed", rel, i, ln.strip())
    return kinds


def add_runtime(inv: Inv, rt: str, rel: str, line: int):
    rt = rt.lower()
    m = re.match(r"(nodejs|python|java|ruby|dotnet|php|go)(\d+)(?:\.(\d+|x))?", rt)
    if not m:
        return
    prod = {"nodejs": "node"}.get(m.group(1), m.group(1))
    major, minor = m.group(2), m.group(3)
    if prod == "php" and len(major) == 2:
        ver = f"{major[0]}.{major[1]}"
    elif prod == "python" and not minor and len(major) >= 2:
        ver = f"{major[0]}.{major[1:]}"
    else:
        ver = major + (f".{minor}" if minor and minor != "x" else "")
    inv.comp(prod, ver, "managed", "deploy", rel, line, rt, managed=True,
             note="managed runtime: provider patches; deprecation dates apply")


def find_line(lines: list[str], needle: str) -> int:
    for i, ln in enumerate(lines, 1):
        if needle in ln:
            return i
    return 1


def scan_manifests(inv: Inv, rel: str, name: str, lines: list[str]):
    text = "\n".join(lines)
    if name == "composer.json":
        try:
            j = json.loads(text)
        except ValueError:
            return
        req = j.get("require", {}) if isinstance(j.get("require"), dict) else {}
        if "php" in req:
            inv.comp("php", str(req["php"]), "range", "declared", rel, find_line(lines, '"php"'), f"php {req['php']}")
        plat = (j.get("config") or {}).get("platform", {}) if isinstance(j.get("config"), dict) else {}
        if isinstance(plat, dict) and plat.get("php"):
            inv.comp("php", numeric(str(plat["php"])), precision(str(plat["php"])), "declared", rel,
                     find_line(lines, '"platform"'), "config.platform.php")
        inv.deps.update(k.split("/")[-1].lower() for k in req if k != "php" and not k.startswith("ext-"))
    elif name == "package.json":
        try:
            j = json.loads(text)
        except ValueError:
            return
        eng = j.get("engines") if isinstance(j.get("engines"), dict) else {}
        if eng.get("node"):
            inv.comp("node", str(eng["node"]), precision(str(eng["node"])), "declared", rel,
                     find_line(lines, '"node"'), f"engines.node {eng['node']}")
        deps = j.get("dependencies") if isinstance(j.get("dependencies"), dict) else {}
        inv.deps.update(k.split("/")[-1].lstrip("@").lower() for k in deps)
    elif name == "pyproject.toml":
        for i, ln in enumerate(lines, 1):
            m = re.match(r"\s*requires-python\s*=\s*[\"']([^\"']+)", ln) or \
                re.match(r"\s*python\s*=\s*[\"']([^\"']+)", ln)
            if m:
                inv.comp("python", m.group(1), precision(m.group(1)), "declared", rel, i, m.group(0).strip())
            m = re.match(r"\s*[\"']([A-Za-z0-9][\w.-]+)\s*[<>=~!\[;\"']", ln)
            if m:
                inv.deps.add(m.group(1).lower())
    elif name == "runtime.txt":
        for i, ln in enumerate(lines, 1):
            m = re.match(r"\s*python-(\d[\d.]*)", ln)
            if m:
                inv.comp("python", m.group(1), precision(m.group(1)), "deploy", rel, i, ln.strip())
    elif name == "Gemfile":
        for i, ln in enumerate(lines, 1):
            m = re.match(r"\s*ruby\s+[\"']([^\"']+)", ln)
            if m:
                inv.comp("ruby", numeric(m.group(1)), precision(m.group(1)), "declared", rel, i, ln.strip())
            m = re.match(r"\s*gem\s+[\"']([\w.-]+)", ln)
            if m:
                inv.deps.add(m.group(1).lower())
    elif name == "go.mod":
        for i, ln in enumerate(lines, 1):
            m = re.match(r"\s*go\s+(\d[\d.]*)\s*$", ln) or re.match(r"\s*toolchain\s+go(\d[\d.]*)", ln)
            if m:
                inv.comp("go", m.group(1), precision(m.group(1)), "declared", rel, i, ln.strip())
            m = re.match(r"\s*(?:require\s+)?([\w.-]+\.[\w.-]+/[\w./-]+)\s+v\d", ln)
            if m:
                inv.deps.add(m.group(1).rsplit("/", 1)[-1].lower())
    elif re.fullmatch(r"requirements[\w.-]*\.txt", name):
        for i, ln in enumerate(lines, 1):
            m = re.match(r"\s*([A-Za-z0-9][\w.-]+)\s*(?:==\s*([\d.]+))?", ln)
            if m and not ln.lstrip().startswith(("#", "-")):
                inv.deps.add(m.group(1).lower())
                if m.group(1).lower() == "django" and m.group(2):
                    inv.comp("django", m.group(2), precision(m.group(2)), "declared", rel, i, ln.strip())
    elif name == "composer.lock":
        try:
            j = json.loads(text)
        except ValueError:
            return
        fw = {"laravel/framework": "laravel", "symfony/http-kernel": "symfony", "drupal/core": "drupal",
              "drupal/core-recommended": "drupal", "johnpbloch/wordpress-core": "wordpress"}
        for pkg in j.get("packages", []) if isinstance(j.get("packages"), list) else []:
            if isinstance(pkg, dict) and pkg.get("name") in fw:
                v = numeric(str(pkg.get("version", "")))
                inv.comp(fw[pkg["name"]], v, precision(v), "deploy", rel, find_line(lines, f'"{pkg["name"]}"'),
                         pkg["name"])
    elif name == "package-lock.json":
        try:
            j = json.loads(text)
        except ValueError:
            return
        fw = {"node_modules/next": "nextjs", "node_modules/nuxt": "nuxt", "node_modules/@angular/core": "angular"}
        pk = j.get("packages") if isinstance(j.get("packages"), dict) else {}
        for k, prod in fw.items():
            if isinstance(pk.get(k), dict) and pk[k].get("version"):
                v = numeric(pk[k]["version"])
                inv.comp(prod, v, precision(v), "deploy", rel, find_line(lines, f'"{k}"'), k.split("/", 1)[1])
    elif name == "Gemfile.lock":
        for i, ln in enumerate(lines, 1):
            m = re.match(r"    rails \((\d[\d.]*)\)", ln)
            if m:
                inv.comp("rails", m.group(1), precision(m.group(1)), "deploy", rel, i, ln.strip())
    elif name in ("poetry.lock", "Pipfile.lock", "uv.lock"):
        for i, ln in enumerate(lines, 1):
            if re.match(r'\s*name\s*=\s*"django"', ln, re.I) or re.match(r'\s*"django":\s*\{', ln, re.I):
                for j in range(i, min(i + 6, len(lines))):
                    v = re.search(r'version"?\s*[=:]\s*"=?=?(\d[\d.]*)', lines[j])
                    if v:
                        inv.comp("django", v.group(1), precision(v.group(1)), "deploy", rel, i, "django")
                        break
    elif name == "pom.xml":
        for i, ln in enumerate(lines, 1):
            if "<artifactId>spring-boot-starter-parent</artifactId>" in ln or \
                    "<artifactId>spring-boot-dependencies</artifactId>" in ln:
                for j in range(i, min(i + 4, len(lines))):
                    v = re.search(r"<version>([\d.]+)", lines[j])
                    if v:
                        inv.comp("spring-boot", v.group(1), precision(v.group(1)), "deploy", rel, i, "spring-boot")
                        break
            m = re.search(r"<(java\.version|maven\.compiler\.(?:release|target))>(\d+)", ln)
            if m:
                inv.comp("java", m.group(2), "major", "declared", rel, i, m.group(0))
            m = re.search(r"<artifactId>([\w.-]+)</artifactId>", ln)
            if m:
                inv.deps.add(m.group(1).lower())
    elif name.endswith((".gradle", ".gradle.kts")):
        for i, ln in enumerate(lines, 1):
            m = re.search(r"org\.springframework\.boot[\"')]*\s*version\s*[\"'(]*([\d.]+)", ln)
            if m:
                inv.comp("spring-boot", m.group(1), precision(m.group(1)), "deploy", rel, i, "spring-boot")
            m = re.search(r"languageVersion\.set\(JavaLanguageVersion\.of\((\d+)\)|sourceCompatibility\s*=\s*"
                          r"(?:JavaVersion\.VERSION_)?['\"]?(\d+)", ln)
            if m:
                inv.comp("java", m.group(1) or m.group(2), "major", "declared", rel, i, m.group(0))


def scan_text_configs(inv: Inv, rel: str, name: str, lines: list[str]):
    low = name.lower()
    if low.startswith("php") and low.endswith((".ini", ".ini-production", ".ini-development")) or \
            ("/conf.d/" in rel and low.endswith(".ini")) or low == ".user.ini":
        prod_file = "development" not in low
        has_df = False
        for i, ln in enumerate(lines, 1):
            m = re.match(r"\s*([\w.]+)\s*=\s*\"?([^\";]*)", ln)
            if not m:
                continue
            k, v = m.group(1).lower(), m.group(2).strip().lower()
            if k == "allow_url_include" and v in ("on", "1", "true"):
                inv.sig("php-ini:allow_url_include", rel, i, ln.strip())
            if k == "display_errors" and v in ("on", "1", "true", "stdout") and prod_file:
                inv.sig("php-ini:display_errors", rel, i, ln.strip())
            if k == "expose_php" and v in ("on", "1", "true"):
                inv.sig("php-ini:expose_php", rel, i, ln.strip())
            if k == "disable_functions":
                has_df = True
                if not v:
                    inv.sig("php-ini:disable_functions-empty", rel, i, ln.strip())
        if low.startswith("php.ini") and not has_df and prod_file:
            inv.sig("php-ini:disable_functions-absent", rel, 1, "no disable_functions line")
    if low.endswith(".conf") or low in ("nginx.conf", "httpd.conf", "apache2.conf", ".htaccess", "default"):
        php_loc = None
        for i, ln in enumerate(lines, 1):
            s = ln.strip()
            if re.match(r"autoindex\s+on\b", s):
                inv.sig("directory-listing", rel, i, s)
            if re.match(r"(?i)Options\b.*(?<![-\w])\+?Indexes\b", s):
                inv.sig("directory-listing", rel, i, s)
            if re.match(r"server_tokens\s+on\b", s) or re.match(r"(?i)ServerTokens\s+Full", s):
                inv.sig("server-version-disclosed", rel, i, s)
            if re.match(r"location\s+~\*?\s+.*\\\.php", s):
                php_loc = i
            if php_loc and "fastcgi_pass" in s:
                block = "\n".join(lines[php_loc - 1:i])
                if "try_files" not in block and "fastcgi_split_path_info" not in block:
                    inv.sig("nginx-php-without-try_files", rel, php_loc, "location ~ \\.php without try_files")
                php_loc = None
    if low == "tomcat-users.xml":
        for i, ln in enumerate(lines, 1):
            if re.search(r"roles=\"[^\"]*manager-(gui|script)", ln) and not ln.strip().startswith("<!--"):
                inv.sig("tomcat-manager-enabled", rel, i, "manager role granted")
    if low.endswith(".properties"):
        for i, ln in enumerate(lines, 1):
            if re.match(r"\s*management\.endpoints\.web\.exposure\.include\s*=\s*\*", ln):
                inv.sig("actuator-exposed", rel, i, ln.strip())
    if low.endswith((".tf", ".tf.json")):
        for i, ln in enumerate(lines, 1):
            m = re.search(r"\bruntime\s*=\s*\"(nodejs\d+(?:\.x)?|python3\.\d+|java\d+|ruby\d\.\d|dotnet\d+|php\d{2}|"
                          r"python\d{2,3})\"", ln)
            if m:
                add_runtime(inv, m.group(1), rel, i)
            if re.match(r"\s*egress\s*\{", ln):
                block = "\n".join(lines[i - 1:i + 10])
                if re.search(r"cidr_blocks\s*=\s*\[\s*\"0\.0\.0\.0/0\"", block) and re.search(
                        r"protocol\s*=\s*\"(-1|all)\"", block):
                    inv.sig("sg-egress-any", rel, i, "egress all protocols to 0.0.0.0/0")


def scan(root: Path, max_files: int) -> dict:
    inv = Inv()
    files = list_files(root, max_files)
    k8s_workloads, netpol = [], False
    has_docker = False
    automation = {"tools": [], "covers_images": False}
    for rel in files:
        name = rel.rsplit("/", 1)[-1]
        low = name.lower()
        if WEBROOT.search(rel) and WEBROOT_SENSITIVE.search(rel[WEBROOT.search(rel).end():]) and \
                not re.search(r"(^|/)(tests?|spec|fixtures?|examples?|docs?)/", rel, re.I):
            inv.sig("webroot-sensitive-file", rel, 1, "committed under a web root")
        if low == "dockerfile" or low.endswith(".dockerfile") or low.startswith("dockerfile.") or \
                low.startswith("containerfile"):
            lines = read(root, rel)
            if lines is not None:
                has_docker = True
                scan_dockerfile(inv, rel, lines)
            continue
        if name in VERSION_FILES:
            lines = read(root, rel) or []
            for i, ln in enumerate(lines, 1):
                v = ln.strip().lstrip("v")
                if v and not v.startswith("#"):
                    if re.match(r"\d", v):
                        inv.comp(VERSION_FILES[name], numeric(v), precision(numeric(v)), "declared", rel, i, ln.strip())
                    break
            continue
        if name == ".tool-versions":
            for i, ln in enumerate(read(root, rel) or [], 1):
                m = re.match(r"\s*([\w-]+)\s+(\S+)", ln)
                if m and m.group(1) in TOOLS:
                    v = re.search(r"\d[\d.]*", m.group(2))
                    if v:
                        inv.comp(TOOLS[m.group(1)], v.group(0), precision(v.group(0)), "declared", rel, i, ln.strip())
            continue
        if low in ("renovate.json", "renovate.json5", ".renovaterc", ".renovaterc.json") or \
                rel in (".github/renovate.json", ".github/renovate.json5", ".gitlab/renovate.json"):
            automation["tools"].append("renovate")
            automation["covers_images"] = True
            continue
        if rel in (".github/dependabot.yml", ".github/dependabot.yaml"):
            automation["tools"].append("dependabot")
            if re.search(r"package-ecosystem:\s*[\"']?docker", "\n".join(read(root, rel) or [])):
                automation["covers_images"] = True
            continue
        if name in ("composer.json", "package.json", "pyproject.toml", "runtime.txt", "Gemfile", "go.mod",
                    "pom.xml") or re.fullmatch(r"requirements[\w.-]*\.txt", name) or \
                low.endswith((".gradle", ".gradle.kts")):
            lines = read(root, rel)
            if lines is not None and "node_modules/" not in rel:
                scan_manifests(inv, rel, name, lines)
            continue
        if name in ("composer.lock", "package-lock.json", "Gemfile.lock", "poetry.lock", "Pipfile.lock", "uv.lock"):
            lines = read(root, rel, LOCK_BYTES)
            if lines is not None:
                scan_manifests(inv, rel, name, lines)
            continue
        if low.endswith((".yml", ".yaml")):
            lines = read(root, rel)
            if lines is None:
                continue
            ctx = ctx_for(rel)
            kinds = scan_yaml(inv, rel, lines, ctx)
            for kind, ln in kinds:
                if kind in ("Deployment", "StatefulSet", "DaemonSet", "Pod", "CronJob", "Job"):
                    k8s_workloads.append((rel, ln))
                if kind == "NetworkPolicy":
                    netpol = True
            continue
        if low.endswith((".ini", ".conf", ".xml", ".properties", ".tf", ".tf.json")) or low in (
                ".htaccess", ".user.ini") or (rel.startswith(("nginx/", "etc/nginx/")) and "." not in low):
            lines = read(root, rel)
            if lines is not None:
                scan_text_configs(inv, rel, name, lines)
            continue
        if low.endswith(".php") and WEBROOT.search(rel):
            lines = read(root, rel) or []
            for i, ln in enumerate(lines, 1):
                if re.search(r"\bphpinfo\s*\(", ln) and not ln.lstrip().startswith(("//", "#", "*")):
                    inv.sig("phpinfo-exposed", rel, i, "phpinfo() in a web-root script")
                    break
    if k8s_workloads and not netpol:
        rel, ln = k8s_workloads[0]
        inv.sig("k8s-no-networkpolicy", rel, ln, f"{len(k8s_workloads)} workload(s), no NetworkPolicy (egress open)")
    if has_docker and not automation["covers_images"]:
        df = next((c["source"] for c in inv.components if c["context"] == "deploy" and
                   re.search(r"(?i)(dockerfile|containerfile)[^/]*:\d+$", c["source"])), None)
        if df:
            p, _, ln = df.rpartition(":")
            inv.sig("no-image-update-automation", p, int(ln),
                    "no Renovate / Dependabot docker updates: base-image patches depend on manual rebuilds")
    stop = {"core", "client", "server", "common", "utils", "util", "http", "https", "api", "app", "web", "cli",
            "test", "tests", "types", "config", "plugin", "framework", "support", "tools", "sdk", "base", "data"}
    deps = sorted(d for d in inv.deps if len(d) >= 4 and d not in stop)[:800]
    return {"components": inv.components, "signals": inv.signals, "direct_deps": deps,
            "patch_automation": automation, "files_considered": len(files)}


def render(repo: str, res: dict) -> str:
    L = [f"# Platform inventory - {repo}\n",
         "Versions the repo pins for runtimes, servers, datastores, base OS and frameworks (SCA scanners do not "
         "see these), and exposure / hardening leads. Leads, not verdicts: confirm what is actually deployed "
         "(a floating tag or a managed runtime resolves at build or run time; distro packages carry backports). "
         "threat_intel.py matches this file against live advisories.\n",
         "## Components\n", "| product | version | precision | context | source | note |", "|---|---|---|---|---|---|"]
    for c in sorted(res["components"], key=lambda c: (c["context"] != "deploy", c["kind"], c["product"])):
        L.append(f"| {c['product']} | `{c['version']}` | {c['precision']} | {c['context']} | `{c['source']}` | "
                 f"{c.get('note', '')} |")
    if not res["components"]:
        L.append("| - | - | - | - | - | no runtime / image / framework pin found (state as a gap if the "
                 "deployment is defined elsewhere) |")
    L.append("\n## Exposure and hardening leads\n")
    if res["signals"]:
        L += ["| signal | source | detail |", "|---|---|---|"]
        for s in res["signals"]:
            L.append(f"| {s['id']} | `{s['source']}` | {s['detail'].replace('|', '/')} |")
    else:
        L.append("none")
    pa = res["patch_automation"]
    L.append(f"\nPatch automation: {', '.join(sorted(set(pa['tools']))) or 'none'}; base images covered: "
             f"{'yes' if pa['covers_images'] else 'no'}.")
    L.append(f"Direct dependencies recorded for advisory keyword matching: {len(res['direct_deps'])}.")
    return "\n".join(L) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("repo")
    ap.add_argument("--out", required=True, help="<work>/<repo>/platform.md（platform.json はその隣に書き出す）")
    ap.add_argument("--max-files", type=int, default=50000)
    a = ap.parse_args()
    root = Path(host_path(a.repo)).resolve()
    if not root.is_dir():
        print(f"error: ディレクトリではない: {root}", file=sys.stderr)
        return 2
    res = scan(root, a.max_files)
    res = {"repo": root.name, "date": dt.date.today().isoformat(), **res}
    out = Path(host_path(a.out))
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render(root.name, res), encoding="utf-8")
    out.with_suffix(".json").write_text(json.dumps(res, indent=1, ensure_ascii=False), encoding="utf-8")
    dep = sum(1 for c in res["components"] if c["context"] == "deploy")
    print(f"{out}（+ platform.json）を書き出した - 構成要素 {len(res['components'])} 件（deploy {dep} 件）、シグナル {len(res['signals'])} 件")
    return 0


if __name__ == "__main__":
    sys.exit(main())
