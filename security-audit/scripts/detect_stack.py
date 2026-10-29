#!/usr/bin/env python3
"""
Fingerprint one or more repositories for a security audit.

Reads files only (never executes project code). Prints a compact JSON profile per repo:
languages, frameworks, ecosystems, IaC, CI, data-sensitivity signals, AI/LLM signals, git
history, plus derived recommendations (standards modules, scanners, review lanes, defaults
for the scoping questions).

Usage:
  python detect_stack.py <repo> [<repo> ...] [--format json|md] [--max-files N]

Stdlib only. Safe on Windows / macOS / Linux.
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
import re
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import safegit  # noqa: E402

SKIP_DIRS = {
    ".git", "node_modules", "vendor", "dist", "build", "out", "target", ".next", ".nuxt",
    ".venv", "venv", "env", "__pycache__", ".tox", ".mypy_cache", ".pytest_cache", "coverage",
    "Pods", ".gradle", ".idea", "bin", "obj", ".terraform", ".dart_tool",
    ".angular", ".svelte-kit", ".turbo", ".cache", "bower_components", "jspm_packages",
}

EXT_LANG = {
    ".py": "python", ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".jsx": "javascript", ".ts": "typescript", ".tsx": "typescript", ".go": "go",
    ".java": "java", ".kt": "kotlin", ".kts": "kotlin", ".scala": "scala", ".rb": "ruby",
    ".php": "php", ".cs": "csharp", ".vb": "vbnet", ".fs": "fsharp", ".rs": "rust",
    ".swift": "swift", ".m": "objective-c", ".mm": "objective-c", ".dart": "dart",
    ".c": "c", ".h": "c", ".cpp": "cpp", ".cc": "cpp", ".hpp": "cpp", ".ex": "elixir",
    ".exs": "elixir", ".erl": "erlang", ".clj": "clojure", ".lua": "lua", ".pl": "perl",
    ".sh": "shell", ".bash": "shell", ".ps1": "powershell", ".psm1": "powershell",
    ".sql": "sql", ".tf": "terraform", ".hcl": "hcl", ".bicep": "bicep", ".sol": "solidity",
    ".vue": "vue", ".svelte": "svelte", ".html": "html", ".cshtml": "razor",
    ".jsp": "jsp", ".apex": "apex", ".cls": "apex", ".groovy": "groovy", ".r": "r",
}

# Semgrep CE rule coverage is meaningful for these; others are a stated coverage gap.
SEMGREP_LANGS = {
    "python", "javascript", "typescript", "go", "java", "kotlin", "scala", "ruby", "php",
    "csharp", "rust", "swift", "c", "cpp", "terraform", "solidity", "elixir", "apex",
    "html", "vue", "shell", "dart", "lua", "clojure",
}
WEAK_SAST_LANGS = {"dart", "lua", "clojure", "objective-c", "erlang", "perl", "vbnet",
                   "fsharp", "groovy", "r", "powershell", "bicep", "razor", "jsp"}

# dependency name -> (signal, label)
DEP_SIGNALS = {
    # web frameworks
    "express": ("framework", "Express"), "fastify": ("framework", "Fastify"),
    "koa": ("framework", "Koa"), "@nestjs/core": ("framework", "NestJS"),
    "next": ("framework", "Next.js"), "nuxt": ("framework", "Nuxt"),
    "@remix-run/node": ("framework", "Remix"), "hono": ("framework", "Hono"),
    "react": ("frontend", "React"), "vue": ("frontend", "Vue"), "@angular/core": ("frontend", "Angular"),
    "svelte": ("frontend", "Svelte"), "react-native": ("mobile", "React Native"),
    "expo": ("mobile", "Expo"), "electron": ("desktop", "Electron"), "@tauri-apps/api": ("desktop", "Tauri"),
    "streamlit": ("framework", "Streamlit"), "gradio": ("framework", "Gradio"),
    "chainlit": ("framework", "Chainlit"), "ollama": ("llm", "Ollama"), "litellm": ("llm", "LiteLLM"),
    "vllm": ("llm", "vLLM"), "mcp": ("mcp", "MCP SDK"), "fastmcp": ("mcp", "FastMCP"),
    "@modelcontextprotocol/sdk": ("mcp", "MCP SDK"), "django": ("framework", "Django"), "flask": ("framework", "Flask"), "fastapi": ("framework", "FastAPI"),
    "starlette": ("framework", "Starlette"), "aiohttp": ("framework", "aiohttp"),
    "bottle": ("framework", "Bottle"), "pyramid": ("framework", "Pyramid"), "sanic": ("framework", "Sanic"),
    "quart": ("framework", "Quart"), "falcon": ("framework", "Falcon"), "litestar": ("framework", "Litestar"),
    "djangorestframework": ("framework", "Django REST"), "@hapi/hapi": ("framework", "hapi"),
    "restify": ("framework", "restify"), "@adonisjs/core": ("framework", "AdonisJS"),
    "github.com/gorilla/mux": ("framework", "gorilla/mux"),
    "github.com/julienschmidt/httprouter": ("framework", "httprouter"),
    "github.com/go-chi/chi/v5": ("framework", "chi"), "github.com/gin-gonic/gin/v2": ("framework", "Gin"), "github.com/go-chi/chi": ("framework", "chi"),
    "quarkus-resteasy": ("framework", "Quarkus"), "micronaut-http": ("framework", "Micronaut"),
    "ktor-server-core": ("framework", "Ktor"), "phoenix": ("framework", "Phoenix"),
    "slim/slim": ("framework", "Slim"), "codeigniter4/framework": ("framework", "CodeIgniter"), "tornado": ("framework", "Tornado"),
    "rails": ("framework", "Rails"), "sinatra": ("framework", "Sinatra"),
    "laravel/framework": ("framework", "Laravel"), "symfony/framework-bundle": ("framework", "Symfony"),
    "github.com/gin-gonic/gin": ("framework", "Gin"), "github.com/labstack/echo": ("framework", "Echo"),
    "github.com/gofiber/fiber": ("framework", "Fiber"), "spring-boot": ("framework", "Spring Boot"),
    "actix-web": ("framework", "Actix"), "axum": ("framework", "Axum"), "rocket": ("framework", "Rocket"),
    # data
    "prisma": ("orm", "Prisma"), "@prisma/client": ("orm", "Prisma"), "typeorm": ("orm", "TypeORM"),
    "sequelize": ("orm", "Sequelize"), "mongoose": ("orm", "Mongoose"), "drizzle-orm": ("orm", "Drizzle"),
    "knex": ("orm", "Knex"), "sqlalchemy": ("orm", "SQLAlchemy"), "gorm.io/gorm": ("orm", "GORM"),
    "redis": ("cache", "Redis"), "ioredis": ("cache", "Redis"),
    # payments
    "stripe": ("payments", "Stripe"), "@stripe/stripe-js": ("payments", "Stripe"),
    "braintree": ("payments", "Braintree"), "@paypal/checkout-server-sdk": ("payments", "PayPal"),
    "paypalrestsdk": ("payments", "PayPal"), "@adyen/api-library": ("payments", "Adyen"),
    "adyen": ("payments", "Adyen"), "square": ("payments", "Square"), "razorpay": ("payments", "Razorpay"),
    # sectors (industry-specific standards modules)
    "@shopify/shopify-api": ("sector:ecommerce", "Shopify app"), "@medusajs/medusa": ("sector:ecommerce", "Medusa"),
    "sylius/sylius": ("sector:ecommerce", "Sylius"), "ec-cube/ec-cube": ("sector:ecommerce", "EC-CUBE"),
    "magento/product-community-edition": ("sector:ecommerce", "Magento"), "spree_core": ("sector:ecommerce", "Spree"),
    "solidus": ("sector:ecommerce", "Solidus"), "saleor": ("sector:ecommerce", "Saleor"),
    "woocommerce/woocommerce": ("sector:ecommerce", "WooCommerce"),
    "bitcoinjs-lib": ("sector:crypto", "bitcoinjs"), "ethers": ("sector:crypto", "ethers"), "web3": ("sector:crypto", "web3"),
    "@solana/web3.js": ("sector:crypto", "Solana"), "bip32": ("sector:crypto", "BIP32"), "bip39": ("sector:crypto", "BIP39"),
    "tiny-secp256k1": ("sector:crypto", "secp256k1"), "bitgo": ("sector:crypto", "BitGo"),
    "@fireblocks/fireblocks-sdk": ("sector:crypto", "Fireblocks"), "ccxt": ("sector:crypto", "ccxt"),
    "bitcoinlib": ("sector:crypto", "bitcoinlib"), "eth-account": ("sector:crypto", "eth-account"),
    "ims-lti": ("sector:education", "LTI"), "ltijs": ("sector:education", "LTI"), "pylti1p3": ("sector:education", "LTI 1.3"),
    "paho-mqtt": ("sector:iot", "MQTT"), "mqtt": ("sector:iot", "MQTT"), "aws-iot-device-sdk": ("sector:iot", "AWS IoT"),
    "awsiotsdk": ("sector:iot", "AWS IoT"), "azure-iot-device": ("sector:iot", "Azure IoT"),
    "@azure/iot-device": ("sector:iot", "Azure IoT"), "aiocoap": ("sector:iot", "CoAP"), "bleak": ("sector:iot", "BLE"),
    "@abandonware/noble": ("sector:iot", "BLE"),
    "pymodbus": ("sector:ot", "Modbus"), "modbus-serial": ("sector:ot", "Modbus"), "asyncua": ("sector:ot", "OPC UA"),
    "opcua": ("sector:ot", "OPC UA"), "node-opcua": ("sector:ot", "OPC UA"), "python-snap7": ("sector:ot", "S7"),
    "bacpypes": ("sector:ot", "BACnet"), "pycomm3": ("sector:ot", "EtherNet/IP"),
    "python-can": ("sector:automotive", "CAN"), "cantools": ("sector:automotive", "CAN"),
    "udsoncan": ("sector:automotive", "UDS"), "can-isotp": ("sector:automotive", "ISO-TP"),
    "fhir.resources": ("sector:medical", "FHIR"), "fhirclient": ("sector:medical", "FHIR"),
    "hl7": ("sector:medical", "HL7"), "python-hl7": ("sector:medical", "HL7"), "fhir-kit-client": ("sector:medical", "FHIR"),
    "plaid": ("sector:finance", "Plaid"), "plaid-python": ("sector:finance", "Plaid"),
    "zengin-code": ("sector:finance", "Zengin"),
    "payjp": ("payments", "PAY.JP"), "omise": ("payments", "Omise"), "komoju": ("payments", "KOMOJU"),
    "github.com/stripe/stripe-go": ("payments", "Stripe"), "com.stripe": ("payments", "Stripe"),
    "vnpay": ("payments", "VNPay"), "momo": ("payments", "MoMo"),
    # AI / LLM / agents
    "openai": ("llm", "OpenAI SDK"), "@anthropic-ai/sdk": ("llm", "Anthropic SDK"),
    "anthropic": ("llm", "Anthropic SDK"), "@anthropic-ai/claude-agent-sdk": ("agentic", "Claude Agent SDK"),
    "claude-agent-sdk": ("agentic", "Claude Agent SDK"), "langchain": ("llm", "LangChain"),
    "@langchain/core": ("llm", "LangChain"), "langgraph": ("agentic", "LangGraph"),
    "@langchain/langgraph": ("agentic", "LangGraph"), "llama-index": ("llm", "LlamaIndex"),
    "llamaindex": ("llm", "LlamaIndex"), "ai": ("llm", "Vercel AI SDK"), "@ai-sdk/openai": ("llm", "Vercel AI SDK"),
    "@google/generative-ai": ("llm", "Gemini SDK"), "@google/genai": ("llm", "Gemini SDK"),
    "google-genai": ("llm", "Gemini SDK"), "transformers": ("llm", "HF Transformers"),
    "crewai": ("agentic", "CrewAI"), "autogen": ("agentic", "AutoGen"), "pyautogen": ("agentic", "AutoGen"),
    "@modelcontextprotocol/sdk": ("mcp", "MCP SDK"), "mcp": ("mcp", "MCP SDK"), "fastmcp": ("mcp", "FastMCP"),
    "openai-agents": ("agentic", "OpenAI Agents SDK"), "@openai/agents": ("agentic", "OpenAI Agents SDK"),
    # auth
    "passport": ("auth", "Passport"), "jsonwebtoken": ("auth", "JWT"), "jose": ("auth", "JOSE"),
    "next-auth": ("auth", "NextAuth"), "@auth/core": ("auth", "Auth.js"), "pyjwt": ("auth", "JWT"),
    "devise": ("auth", "Devise"), "spring-boot-starter-security": ("auth", "Spring Security"),
    "@clerk/nextjs": ("auth", "Clerk"), "firebase-admin": ("auth", "Firebase"),
    "@supabase/supabase-js": ("auth", "Supabase"),
    # cloud SDKs
    "aws-sdk": ("cloud", "AWS"), "@aws-sdk/client-s3": ("cloud", "AWS"), "boto3": ("cloud", "AWS"),
    "@google-cloud/storage": ("cloud", "GCP"), "@azure/identity": ("cloud", "Azure"),
}

# word boundaries are letters/digits only, so snake_case ids such as patient_id or kanja_id match
KEYWORD_SIGNALS = {
    "payments": re.compile(r"(?<![A-Za-z0-9])(card_?number|cardnumber|cvv|cvc2?|pan_?hash|primary_account|"
                           r"credit_?card|payment_?method|checkout_?session|charge_?id|refund)(?![A-Za-z0-9])", re.I),
    "pii": re.compile(r"(?<![A-Za-z0-9])(date_?of_?birth|dob|birth_?date|national_?id|ssn|passport_?(no|number)|"
                      r"my_?number|mynumber|phone_?number|home_?address|cccd|cmnd|so_?dien_?thoai|"
                      r"ngay_?sinh|kojin|furigana|postal_?code|zip_?code)(?![A-Za-z0-9])", re.I),
    "financial": re.compile(r"(?<![A-Za-z0-9])(bank_?account|routing_?(no|num|number)|iban|swift_?code|account_?number|"
                            r"salary|payroll|so_?tai_?khoan|zengin|furikomi|kouza(_?bango)?|branch_?code|bank_?code|"
                            r"kinyu_?kikan|iso_?20022)(?![A-Za-z0-9])", re.I),
    "health": re.compile(r"(?<![A-Za-z0-9])(diagnosis|patients?|medical_?record|prescription|icd_?10|blood_?type|"
                         r"health_?record|insurance_?number|medical_?facility|hospital_?id|clinic_?id|karte|"
                         r"monshin(_?hyo)?|shinryo|kanja|medication|allerg(y|ies)|vital_?signs?|"
                         r"medical_?history|symptoms?|ehr|emr|fhir|hl7)(?![A-Za-z0-9])", re.I),
    # no bare "sku" / "coupon": cloud SDKs use SKUs (Azure), marketing tools use coupons
    "sector_ecommerce": re.compile(r"(?<![A-Za-z0-9])(cart_?items?|order_?items?|shipping_?address|product_?variants?|"
                                   r"coupon_?codes?|add_?to_?cart|eccube|ec_?cube|woocommerce|magento|"
                                   r"three_?d_?secure|3ds2|tds2|emv_?3ds)(?![A-Za-z0-9])", re.I),
    # weak shop vocabulary: counts only next to a payment flow (see sectors in recommend)
    "shop": re.compile(r"(?<![A-Za-z0-9])(carts?|orders?|order_?(id|items?|status)|coupons?|shipping(_?\w+)?|"
                       r"line_?items?|fulfil+ments?)(?![A-Za-z0-9])", re.I),
    "sector_crypto": re.compile(r"(?<![A-Za-z0-9])(hot_?wallet|cold_?wallet|xpub|xprv|mnemonic|seed_?phrase|multisig|"
                                r"deposit_?address|withdrawal_?address|txid|block_?height)(?![A-Za-z0-9])", re.I),
    "sector_education": re.compile(r"(?<![A-Za-z0-9])(students?|student_?id|guardians?|gradebook|enrollments?|classrooms?|"
                                   r"teachers?|school_?id|seito|jidou|hogosha|seiseki|oneroster)(?![A-Za-z0-9])", re.I),
    "sector_government": re.compile(r"(?<![A-Za-z0-9])(lgwan|ismap|gov_?cloud|govcloud|jpki|myna_?portal|jichitai|"
                                    r"[\w-]+\.lg\.jp|gov\.vn)(?![A-Za-z0-9])", re.I),
    # no bare "firmware" / "secure_boot": server inventories report firmware versions, cloud VMs set secure boot
    "sector_iot": re.compile(r"(?<![A-Za-z0-9])(firmware_?(update|upgrade|image|flash)|ota_?update|mqtt|coap|esp_?idf|freertos|zephyr|yocto|buildroot|"
                             r"openwrt|device_?provisioning|onvif|rtsp)(?![A-Za-z0-9])", re.I),
    "sector_ot": re.compile(r"(?<![A-Za-z0-9])(modbus|opc_?ua|dnp3|iec_?61850|iec_?104|iec_?60870|bacnet|profinet|ethercat|"
                            r"scada|snap7)(?![A-Za-z0-9])", re.I),
    "sector_automotive": re.compile(r"(?<![A-Za-z0-9])(autosar|socketcan|cantools|doip|iso_?14229|secoc|uptane|ecu_?id)(?![A-Za-z0-9])", re.I),
    "money_movement": re.compile(r"(?<![A-Za-z0-9])(ledger|wallet|payout|transfer_?funds|balance_?update|"
                                 r"idempotency[_-]?key|refund)(?![A-Za-z0-9])", re.I),
    "llm": re.compile(r"(?<![A-Za-z0-9])(system_?prompt|chat\.completions|messages\.create|embeddings?|"
                      r"vector_?store|rag|tool_?calls?|function_?call)(?![A-Za-z0-9])", re.I),
    "file_upload": re.compile(r"(?<![A-Za-z0-9])(multer|upload_?file|multipart|FileUpload|MultipartFile|UploadFile)(?![A-Za-z0-9])"),
    "http_routes": re.compile(r"(@app\.(route|get|post)|app\.(get|post|put|delete|use)\(|router\.(get|post|put|delete)\(|"
                              r"@(Get|Post|Put|Delete|Request)Mapping|@RestController|Route::(get|post)|"
                              r"http\.HandleFunc|router\.(GET|POST|PUT|DELETE|Handle)\(|mux\.Handle|urlpatterns|@(Get|Post|Controller)\(|export\s+(async\s+)?function\s+(GET|POST))"),
    "deserialization": re.compile(r"(?<![A-Za-z0-9])(pickle\.loads|yaml\.load\(|ObjectInputStream|"
                                  r"unserialize\(|Marshal\.load|BinaryFormatter)(?![A-Za-z0-9])"),
}

VENDOR_PATH = re.compile(r"(^|/)(static|public|assets|wwwroot|web)/(vendor|lib|libs|js/lib|plugins|"
                         r"bower|third[_-]?party)/|(^|/)(third[_-]?party|external|deps)/|"
                         r"(^|/)(jquery|bootstrap|angular|fontawesome|font-awesome|materialize|lodash|underscore|moment|d3|"
                         r"chart|highcharts|popper|select2|datatables|modernizr|require|backbone|knockout|"
                         r"vue|react|react-dom|semantic|foundation|uikit|swagger-ui|ace|codemirror|tinymce|"
                         r"ckeditor|pdf|three|socket\.io)([.-][^/]*)?\.(js|css)$", re.I)

TEXT_EXT_FOR_KEYWORDS = {
    ".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".java", ".kt", ".rb", ".php", ".cs", ".rs",
    ".swift", ".dart", ".sql", ".prisma", ".graphql", ".yaml", ".yml", ".json", ".vue",
    ".svelte", ".scala", ".ex", ".exs",
}


def host_path(p: str) -> str:
    """Accept Git-Bash style /c/Users/... on Windows (otherwise it silently resolves to C:/c/Users)."""
    if os.name == "nt":
        m = re.match(r"^/([a-zA-Z])(/.*)?$", p or "")
        if m:
            return f"{m.group(1).upper()}:{m.group(2) or '/'}"
    return p


def walk(root: Path, max_files: int):
    count = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".terraform")]
        for fn in filenames:
            count += 1
            if count > max_files:
                return
            yield Path(dirpath) / fn


def read_text(p: Path, limit: int = 400_000) -> str:
    try:
        if p.stat().st_size > limit:
            return ""
        return safegit.read_text(p)  # BOM / UTF-16 files written on Windows decode too
    except OSError:
        return ""


def parse_deps(p: Path, text: str, bad: list | None = None) -> set[str]:
    """Dependency names of one manifest; a manifest that does not parse is appended to `bad`."""
    name = p.name.lower()
    deps: set[str] = set()
    try:
        if name == "package.json":
            data = safegit.loads_jsonc(text or "{}")
            for k in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
                deps.update((data.get(k) or {}).keys())
        elif name in ("requirements.txt", "requirements-dev.txt", "constraints.txt") or (
                name.startswith("requirements") and name.endswith(".txt")):
            for line in text.splitlines():
                m = re.match(r"\s*([A-Za-z0-9_.\-]+)", line)
                if m and not line.strip().startswith(("#", "-")):
                    deps.add(m.group(1).lower())
        elif name in ("pyproject.toml", "pipfile", "setup.py", "setup.cfg"):
            deps.update(x.lower() for x in re.findall(r"[\"']([A-Za-z0-9_.\-]+)\s*[<>=~!\[;\"']", text))
            deps.update(x.lower() for x in re.findall(r"^\s*([A-Za-z0-9_.\-]+)\s*=", text, re.M))
        elif name == "go.mod":
            text = "\n".join(l for l in text.splitlines() if "// indirect" not in l)
            deps.update(re.findall(r"^\s*(?:require\s+)?([a-z0-9.\-]+\.[a-z]+/[^\s]+)\s+v", text, re.M))
            deps = {re.sub(r"/v\d+$", "", d) for d in deps}
        elif name in ("pom.xml",):
            deps.update(re.findall(r"<artifactId>([^<]+)</artifactId>", text))
            deps.update(re.findall(r"<groupId>([^<]+)</groupId>", text))
        elif name.endswith((".gradle", ".gradle.kts")) or name == "libs.versions.toml":
            for group, artifact in re.findall(r"[\"']([\w.\-]+):([\w.\-]+)", text):
                deps.update((group, artifact))
        elif name == "gemfile":
            deps.update(re.findall(r"^\s*gem\s+[\"']([^\"']+)", text, re.M))
        elif name == "composer.json":
            data = safegit.loads_jsonc(text or "{}")
            for k in ("require", "require-dev"):
                deps.update((data.get(k) or {}).keys())
        elif name == "cargo.toml":
            deps.update(re.findall(r"^\s*([A-Za-z0-9_\-]+)\s*=", text, re.M))
        elif name == "pubspec.yaml":
            deps.update(re.findall(r"^\s{2}([a-z0-9_]+):", text, re.M))
        elif name.endswith(".csproj"):
            deps.update(re.findall(r'PackageReference\s+Include="([^"]+)"', text))
    except (ValueError, TypeError, AttributeError):
        if bad is not None:
            bad.append(str(p))
    return deps


LOCKFILES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb", "bun.lock", "poetry.lock",
    "pipfile.lock", "uv.lock", "requirements.txt", "go.sum", "cargo.lock", "gemfile.lock",
    "composer.lock", "pubspec.lock", "packages.lock.json", "gradle.lockfile", "mix.lock",
    "podfile.lock", "package.resolved", "pom.xml",
}
MANIFESTS = {
    "package.json", "requirements.txt", "pyproject.toml", "pipfile", "setup.py", "setup.cfg",
    "go.mod", "pom.xml", "build.gradle", "build.gradle.kts", "gemfile", "composer.json",
    "cargo.toml", "pubspec.yaml", "libs.versions.toml",
}


def git_info(root: Path) -> dict:
    info = {"is_git": (root / ".git").exists(), "commits": 0, "shallow": False}
    if not info["is_git"]:
        return info
    # safegit: the repo's .git/config cannot run commands (fsmonitor) and the index is never rewritten
    try:
        info["commits"] = int(safegit.out(root, "rev-list", "--all", "--count", timeout=30).strip() or 0)
    except ValueError:
        pass
    info["shallow"] = (root / ".git" / "shallow").exists()
    info["head"], dirty = safegit.head_dirty(root)
    if dirty is not None:
        info["dirty"] = dirty
    return info


# AI coding-agent tooling committed to a repo (Claude Code, Codex/AGENTS.md, Cursor, Copilot, Windsurf,
# Gemini CLI, MCP clients). Audited by the ai-agentic lane as configuration + supply chain, not as an
# LLM product.
INSTRUCTION_FILES = {"claude.md", "agents.md", "gemini.md", ".cursorrules", ".windsurfrules",
                     "copilot-instructions.md", ".clinerules"}
MCP_CONFIGS = {".mcp.json", "claude_desktop_config.json", "mcp.json", "mcp_config.json"}
PROMPT_LOG = re.compile(r"(^|/)(prompt[_-]?history[^/]*|[^/]*transcripts?[^/]*\.(jsonl?|txt|md)|"
                        r"\.specstory/.*|\.claude/projects/.*\.jsonl|[^/]*(chat|conversation)[_-]?(log|history)[^/]*)$", re.I)


def agent_surface(rel: str, name: str) -> str | None:
    """Kind of AI-agent tooling file, or None."""
    low = rel.lower()
    if PROMPT_LOG.search(low):
        return "prompt_logs"
    if name in INSTRUCTION_FILES or low.startswith((".cursor/rules/", ".claude/rules/", ".windsurf/rules/")):
        return "instructions"
    if name in MCP_CONFIGS and (low.count("/") == 0 or low.startswith((".cursor/", ".vscode/", ".claude/", ".gemini/"))):
        return "mcp_configs"
    if low in (".claude/settings.json", ".gemini/settings.json", ".codex/config.toml"):
        return "settings"
    if low == ".claude/settings.local.json":
        return "settings_local"
    if low.startswith(".claude/hooks/"):
        return "hooks"
    if low.startswith(".claude/agents/") and name.endswith(".md"):
        return "subagents"
    if low.startswith((".claude/commands/", ".cursor/commands/")) and name.endswith(".md"):
        return "commands"
    if name == "skill.md":
        return "skills_project" if low.startswith(".claude/skills/") else "skills_other"
    return None


def profile(root: Path, max_files: int) -> dict:
    langs: Counter = Counter()
    deps: set[str] = set()
    signals: dict[str, set[str]] = {}
    iac: set[str] = set()
    ci: set[str] = set()
    containers: set[str] = set()
    lockfiles: list[str] = []
    manifest_names: set[str] = set()
    data_files: list[str] = []
    mobile: set[str] = set()
    agent_cfg: set[str] = set()
    tooling: Counter = Counter()
    skill_dirs: set[str] = set()
    script_dirs: set[str] = set()
    keyword_hits: Counter = Counter()
    unparseable: list[str] = []
    keyword_budget = 3000  # files scanned for keywords; bounds runtime on huge repos
    total = 0

    for p in walk(root, max_files):
        total += 1
        rel = p.relative_to(root).as_posix()
        name = p.name.lower()
        ext = p.suffix.lower()
        try:
            size = p.stat().st_size
        except OSError:
            continue
        vendored = (".min." in name or name.endswith(("-bundle.js", ".bundle.js", ".map"))
                    or VENDOR_PATH.search(rel) is not None)
        if ext in EXT_LANG and not vendored and size < 1_000_000:
            langs[EXT_LANG[ext]] += max(size, 1)
        sample = re.search(r"(^|/)(fixtures?|samples?|examples?|testdata|tests?|demo)(/|$)", rel, re.I)
        if (name in MANIFESTS or name.endswith(".csproj")) and not sample:
            deps |= parse_deps(p, read_text(p), unparseable)
            manifest_names.add(name)
        if name in LOCKFILES:
            lockfiles.append(rel)
        # IaC / containers / CI
        if ext == ".tf":
            iac.add("terraform")
        elif ext == ".bicep":
            iac.add("bicep")
        elif name in ("cdk.json",):
            iac.add("aws-cdk")
        elif name in ("serverless.yml", "serverless.yaml"):
            iac.add("serverless-framework")
        elif name == "chart.yaml":
            iac.add("helm")
        elif name in ("pulumi.yaml", "pulumi.yml"):
            iac.add("pulumi")
        elif name in ("wrangler.toml", "wrangler.jsonc", "wrangler.json"):
            iac.add("cloudflare-wrangler")
        if name == "dockerfile" or name.endswith(".dockerfile") or name.startswith("dockerfile."):
            containers.add("dockerfile")
        if name in ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"):
            containers.add("compose")
        if rel.startswith(".github/workflows/"):
            ci.add("github-actions")
        elif name == ".gitlab-ci.yml":
            ci.add("gitlab-ci")
        elif name == "jenkinsfile":
            ci.add("jenkins")
        elif name in ("azure-pipelines.yml", "azure-pipelines.yaml"):
            ci.add("azure-pipelines")
        elif name == "bitbucket-pipelines.yml":
            ci.add("bitbucket")
        elif rel.startswith(".circleci/"):
            ci.add("circleci")
        elif name == "buildspec.yml":
            ci.add("aws-codebuild")
        kind = agent_surface(rel, name)
        if kind:
            tooling[kind] += 1
            agent_cfg.add(rel.split("/")[0] if rel.startswith(".") else name)
            if kind.startswith("skills_"):
                skill_dirs.add(rel.rsplit("/", 1)[0] if "/" in rel else ".")
        if "/scripts/" in rel and ext in (".py", ".sh", ".ps1", ".js", ".ts", ".mjs"):
            script_dirs.add(rel.split("/scripts/", 1)[0])
        if name == "androidmanifest.xml":
            mobile.add("android")
        if ext in (".xcodeproj", ".plist") or name == "podfile":
            mobile.add("ios")
        if name == "pubspec.yaml":
            mobile.add("flutter")
        # schema / migration surfaces
        low = rel.lower()
        if ("migration" in low or "migrate" in low or name == "schema.prisma" or ext == ".sql"
                or "/entities/" in low or "/models/" in low or name.endswith(("schema.rb", "models.py"))):
            if len(data_files) < 400:
                data_files.append(rel)
        if ext in (".yaml", ".yml", ".json", ".template") and size < 400_000 and len(iac) < 20:
            if ext in (".yaml", ".yml", ".json") and ("template" in name or "cloudformation" in low
                                                      or "cfn" in low or "k8s" in low or "kubernetes" in low
                                                      or "manifests" in low or "deploy" in low):
                t = read_text(p, 200_000)
                if "AWSTemplateFormatVersion" in t or "AWS::" in t:
                    iac.add("cloudformation")
                if re.search(r"^apiVersion:\s*\S+\s*$", t, re.M) and re.search(r"^kind:\s*\w+", t, re.M):
                    iac.add("kubernetes")
        # keyword signals (bounded)
        if keyword_budget > 0 and ext in TEXT_EXT_FOR_KEYWORDS and size < 300_000:
            keyword_budget -= 1
            t = read_text(p, 300_000)
            for sig, rx in KEYWORD_SIGNALS.items():
                if rx.search(t):
                    keyword_hits[sig] += 1

    for d in deps:
        key = d.lower() if d.lower() in DEP_SIGNALS else d
        if key in DEP_SIGNALS:
            sig, label = DEP_SIGNALS[key]
            signals.setdefault(sig, set()).add(label)
        elif d.startswith("org.springframework.boot"):
            signals.setdefault("framework", set()).add("Spring Boot")
        elif d.startswith("Microsoft.AspNetCore"):
            signals.setdefault("framework", set()).add("ASP.NET Core")

    total_bytes = sum(langs.values()) or 1
    lang_share = {k: round(v * 100 / total_bytes, 1) for k, v in langs.most_common(12)}
    main_langs = [k for k, v in lang_share.items() if v >= 2.0]

    return {
        "repo": str(root),
        "name": root.name,
        "files_seen": total,
        "truncated": total >= max_files,
        "languages_pct": lang_share,
        "signals": {k: sorted(v) for k, v in sorted(signals.items())},
        "keyword_hits": dict(keyword_hits),
        "iac": sorted(iac),
        "containers": sorted(containers),
        "ci": sorted(ci),
        "mobile": sorted(mobile),
        "agent_config": sorted(agent_cfg),
        "agent_tooling": dict(sorted(tooling.items())) | (
            {"skills_with_scripts": sum(1 for d in skill_dirs if d in script_dirs)} if skill_dirs else {}),
        "lockfiles": lockfiles[:30],
        # deps of these are unknown, so stack flags may be missing: review manually
        "unparseable_manifests": sorted(Path(x).relative_to(root).as_posix() for x in unparseable)[:30],
        "manifests_without_lock": sorted(manifest_names - {"requirements.txt", "pom.xml"})
        if manifest_names and not lockfiles else [],
        "schema_and_migration_files": len(data_files),
        "schema_samples": data_files[:15],
        "git": git_info(root),
        "_main_langs": main_langs,
    }


# Lane subagents per repo size (Standard / Deep). Small repos: lanes that read the same files share
# one subagent, so the repo is read 3 times instead of 6-7; large repos: one subagent per lane.
GROUPS_BY_SIZE = {
    "small": [("authz-logic", "injection-dataflow"), ("sensitive-data", "supply-chain-infra"),
              ("ai-agentic", "mobile", "perf-quality")],
    "medium": [("authz-logic",), ("injection-dataflow",), ("sensitive-data",), ("ai-agentic",), ("mobile",),
               ("supply-chain-infra", "perf-quality")],
}


def lane_groups(lanes: list[str], size: str) -> list[str]:
    """Pack review lanes into subagent groups ("a+b") by repo size; every lane appears exactly once."""
    if size not in GROUPS_BY_SIZE:
        return list(lanes)
    out, used = [], set()
    for grp in GROUPS_BY_SIZE[size]:
        members = [l for l in grp if l in lanes]
        if size == "small" and "ai-agentic" in members and "mobile" in members:
            out.append("ai-agentic")       # both present: keep the two specialist lanes apart
            members.remove("ai-agentic")
        if members:
            out.append("+".join(members))
            used.update(members)
    out += [l for l in lanes if l not in used]
    return out


def recommend(p: dict) -> dict:
    s = p["signals"]
    kh = p["keyword_hits"]
    langs = set(p["_main_langs"])
    code_langs = langs - {"terraform", "hcl", "bicep", "shell", "powershell", "html", "sql"}
    has_web = bool(s.get("framework")) or (kh.get("http_routes", 0) >= 1 and bool(code_langs))
    iac_dominant = sum(p["languages_pct"].get(l, 0) for l in ("terraform", "hcl", "bicep")) >= 60
    payments = bool(s.get("payments")) or kh.get("payments", 0) >= 2
    financial = kh.get("financial", 0) >= 2
    pii = kh.get("pii", 0) >= 2 or payments or financial or bool(s.get("auth"))
    health = kh.get("health", 0) >= 3
    llm = bool(s.get("llm")) or kh.get("llm", 0) >= 3
    agentic = bool(s.get("agentic")) or bool(s.get("mcp"))  # an agent / MCP product, not dev tooling
    tooling = p.get("agent_tooling", {})
    agent_tooling = bool(tooling)
    mobile = bool(p["mobile"]) or bool(s.get("mobile"))
    iac = bool(p["iac"]) or bool(p["containers"])
    ci = bool(p["ci"])
    money = payments or kh.get("money_movement", 0) >= 3

    modules = ["owasp-web"] if code_langs and not iac_dominant else []  # Top 10 2025 + ASVS 5.0 baseline
    if has_web and not iac_dominant:
        modules.append("owasp-api")
    if payments:
        modules.append("pci-dss")
    if pii or health:
        modules.append("privacy")
    # industry sectors: a dependency signal, or keyword hits in enough files; each maps to a standards module
    sec = s.get  # dependency-signal sets, e.g. s["sector:crypto"] = {"ethers"}
    sector_files = {"ecommerce": 3, "crypto": 2, "education": 3, "government": 2, "iot": 2, "ot": 2, "automotive": 2}
    sectors = {}
    for name, need in sector_files.items():
        hits, deps_ = kh.get(f"sector_{name}", 0), sorted(sec(f"sector:{name}") or [])
        if deps_ or hits >= need:
            sectors[name] = {"dependencies": deps_, "files_with_keywords": hits}
    if health or sec("sector:medical"):
        sectors["medical"] = {"dependencies": sorted(sec("sector:medical") or []), "files_with_keywords": kh.get("health", 0)}
    # a small custom shop keeps its vocabulary in 1-2 files: with a payment flow that is enough
    if "ecommerce" not in sectors and payments and (kh.get("sector_ecommerce", 0) >= 1 or kh.get("shop", 0) >= 2):
        sectors["ecommerce"] = {"dependencies": [], "files_with_keywords": kh.get("sector_ecommerce", 0) + kh.get("shop", 0)}
    # finance: banking, securities or ledger signals; card payments and refunds alone are ecommerce / PCI DSS
    ledger = kh.get("money_movement", 0) >= 3 and "ecommerce" not in sectors
    if financial or ledger or sec("sector:finance"):
        sectors["finance"] = {"dependencies": sorted(sec("sector:finance") or []),
                              "files_with_keywords": kh.get("financial", 0) + kh.get("money_movement", 0)}
    if "medical" in sectors and "privacy" not in modules:
        modules.append("privacy")
    for name, module in (("medical", "medical"), ("finance", "finance"), ("crypto", "finance"),
                         ("ecommerce", "ecommerce"), ("government", "public-sector"), ("education", "education"),
                         ("iot", "iot-ot"), ("ot", "iot-ot"), ("automotive", "iot-ot")):
        if name in sectors and module not in modules:
            modules.append(module)
    if llm or agentic or agent_tooling:
        modules.append("ai-llm-agentic")
    if mobile:
        modules.append("mobile")
    if iac:
        modules.append("cloud-iac")
    if ci or p["lockfiles"]:
        modules.append("supply-chain")

    scanners = ["gitleaks"]
    sast_langs = [l for l in langs if l in SEMGREP_LANGS]
    if sast_langs:
        scanners.append("semgrep")
    if p["lockfiles"] or p["containers"]:
        scanners += ["trivy", "osv-scanner"]
    if p["iac"] or p["containers"]:
        scanners.append("checkov")
    if "dockerfile" in p["containers"]:
        scanners.append("hadolint")
    if "github-actions" in p["ci"]:
        scanners.append("zizmor")
    if mobile:
        scanners.append("mobsfscan")

    lanes = ["authz-logic", "injection-dataflow"] if code_langs and not iac_dominant else []
    lanes.append("sensitive-data")  # owns secret, credential and PII leads in every repo (IaC too: tfvars, keys)
    if llm or agentic or agent_tooling:
        lanes.append("ai-agentic")
    if iac or ci or p["lockfiles"]:
        lanes.append("supply-chain-infra")
    if mobile:
        lanes.append("mobile")
    if code_langs and not iac_dominant:
        lanes.append("perf-quality")

    if iac_dominant:
        archetype = "infrastructure-as-code"
    elif mobile:
        archetype = "mobile-app"
    elif agentic or s.get("mcp"):
        archetype = "agentic-or-mcp"
    elif has_web:
        archetype = "web-app-or-api"
    elif s.get("frontend"):
        archetype = "frontend-spa"
    elif llm:
        archetype = "llm-app"
    elif agent_tooling and (tooling.get("skills_other", 0) + tooling.get("skills_project", 0)) >= 1:
        archetype = "agent-skills-or-tooling"
    else:
        archetype = "library-cli-or-scripts"
    # what the ai-agentic lane must cover (reference/standards/ai-llm-agentic.md sections)
    ai_scope = ([x for x, on in (("llm-app", llm), ("agentic-app", bool(s.get("agentic"))),
                                 ("mcp", bool(s.get("mcp"))), ("agent-tooling", agent_tooling)) if on])

    manifests_only = p.get("manifests_without_lock", [])

    gaps = sorted(l for l in langs if l in WEAK_SAST_LANGS or l not in SEMGREP_LANGS)
    size = p["files_seen"]
    depth = "deep"  # skill default; the size hint below helps the user decide whether Quick suffices
    size_hint = "small" if size < 150 else ("medium" if size < 5000 else "large")
    return {
        "archetype": archetype,
        "standards_modules": modules,
        "scanners": scanners,
        "review_lanes": lanes,
        "lane_groups": lane_groups(lanes, size_hint),
        "sast_coverage_gaps": [g for g in gaps if g not in ("html", "sql", "hcl")],
        "sca_gaps": ([f"no lockfile for {', '.join(manifests_only)}: no SCA scanner can resolve these versions - "
                      f"review declared versions manually (or state the gap)"] if manifests_only else []),
        "ai_scope": ai_scope,
        "sectors": sectors,
        "flags": {"payments": payments, "financial": financial, "pii": pii, "health": health, "llm": llm,
                  "agentic": agentic, "agent_tooling": agent_tooling, "mobile": mobile, "iac": iac, "ci": ci, "money_movement": money},
        "suggested_depth": depth,
        "size": size_hint,
        "secret_history_scan": "full" if p["git"]["is_git"] and not p["git"]["shallow"] else
                               ("shallow-clone: history incomplete, state as gap" if p["git"]["is_git"]
                                else "no .git: filesystem-only, state as gap"),
    }


def to_md(results: list[dict]) -> str:
    out = []
    for r in results:
        rec = r["recommendations"]
        out.append(f"## {r['name']}  ({r['files_seen']} files{' TRUNCATED' if r['truncated'] else ''})")
        out.append(f"- languages: {', '.join(f'{k} {v}%' for k, v in r['languages_pct'].items())}")
        for k, v in r["signals"].items():
            out.append(f"- {k}: {', '.join(v)}")
        for k in ("iac", "containers", "ci", "mobile", "agent_config"):
            if r[k]:
                out.append(f"- {k}: {', '.join(r[k])}")
        if r.get("agent_tooling"):
            out.append("- AI agent tooling: " + ", ".join(f"{k} {v}" for k, v in r["agent_tooling"].items()))
        out.append(f"- keyword hits: {r['keyword_hits']}")
        out.append(f"- git: {r['git']}  -> secret scan: {rec['secret_history_scan']}")
        out.append(f"- archetype: {rec['archetype']}")
        out.append(f"- flags: {', '.join(k for k, v in rec['flags'].items() if v) or 'none'}")
        out.append(f"- sectors: {', '.join(rec.get('sectors', {})) or 'none detected'} (industry modules; confirm "
                   f"with the user - a sector the code does not show can still apply)")
        out.append(f"- standards modules: {', '.join(rec['standards_modules'])}")
        out.append(f"- scanners: {', '.join(rec['scanners'])}")
        out.append(f"- review lanes: {', '.join(rec['review_lanes'])}")
        if rec.get("ai_scope"):
            out.append(f"- ai-agentic scope: {', '.join(rec['ai_scope'])}")
        out.append(f"- lane subagents (standard/deep, size {rec['size']}): {', '.join(rec['lane_groups'])}")
        for g in rec["sca_gaps"]:
            out.append(f"- SCA gap: {g}")
        if r.get("unparseable_manifests"):
            out.append(f"- unparseable - review manually (dependency signals may be missing): "
                       f"{', '.join(r['unparseable_manifests'])}")
        if rec["sast_coverage_gaps"]:
            out.append(f"- SAST coverage gaps (manual review needed): {', '.join(rec['sast_coverage_gaps'])}")
        out.append(f"- suggested depth: {rec['suggested_depth']} (repo size: {rec['size']})")
        out.append("")
    return "\n".join(out)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("repos", nargs="+")
    ap.add_argument("--format", choices=["json", "md"], default="md")
    ap.add_argument("--max-files", type=int, default=60_000)
    a = ap.parse_args()
    results = []
    for r in a.repos:
        root = Path(host_path(r)).resolve()
        if not root.is_dir():
            print(f"error: not a directory: {r}", file=sys.stderr)
            return 2
        prof = profile(root, a.max_files)
        if prof["files_seen"] == 0:
            print(f"warning: 0 files under {root} - check the path", file=sys.stderr)
        prof["recommendations"] = recommend(prof)
        prof.pop("_main_langs", None)
        results.append(prof)
    if a.format == "json":
        print(json.dumps(results, indent=1, ensure_ascii=False))
    else:
        print(to_md(results))
    return 0


if __name__ == "__main__":
    sys.exit(main())
