# Coverage checklist - grading the audit against a technique catalogue

**This is a CROSS-CHECK, not the audit's spine.** The versioned standards
(`reference/standards/index.md`) remain the anchor for every finding - a finding still cites `standard + version +
requirement id`. This checklist exists for the opposite failure mode: a vulnerability **class that falls
between the standards you mapped** is invisible, because the standards you chose determine what you look
at. Use this list to grade your own pass - "did I actually cover open redirects? host-header poisoning?
mass assignment?" - rather than trusting that the chosen standard implied them.

**Source:** the Hacksplaining vulnerability catalogue (https://www.hacksplaining.com/lessons), a
practical, technique-oriented lesson set. Such catalogues **drift** - lessons are added and renamed as
the threat landscape moves (the AI classes below are recent arrivals). Treat this as a **living
checklist**, not a fixed one: re-check the source at audit time and add classes it has grown.

## Contents
How to use it; Access control & authentication; Injection & data flow; Transport & network;
Cross-origin & browser; Supply chain & operations; Exposure, patch level and blast radius;
AI-specific; Feeding the report.

## How to use it
Walk every row. For each: did this audit look at this class in the repos where it could apply? Mark
covered / not-applicable / **gap**. A gap is a coverage finding in its own right - state it in the
report's coverage section (`templates/audit-report.md.template` section 2), the same way an uncovered
language is stated. The `Seen by` column tells you whether a clean SAST run is even evidence: **SAST**
= a scanner can catch it (still confirm by reading); **Manual** = deterministic tools structurally
cannot see it, so silence means nothing - hunt it by reading (`reference/method/design-flaws.md`);
**SAST+Manual** = scanners find some instances, design flaws need reading; **Script+Manual** = a
bundled script lists the leads (`platform_inventory.py`, `threat_intel.py`), reading decides.

Standard column maps into the versioned table in `reference/standards/index.md` - carry the version when you cite it in
a finding (e.g. `OWASP ASVS 5.0.0`, `OWASP API Security Top 10 2023`, `PCI DSS v4.0.1`).

## Access control & authentication
| Class | One-line | Anchor standard | Where to look | Seen by |
|-------|----------|-----------------|---------------|---------|
| Broken Access Control | Missing/incorrect authz on a resource or action | ASVS; API Top 10 (BOLA/BFLA) | Server-side authz checks on every privileged endpoint | Manual |
| Privilege Escalation | User gains rights beyond their role | ASVS; API Top 10 | Role/permission checks; admin-only paths; state transitions | Manual |
| Session Fixation | Session id not rotated after auth | ASVS (session mgmt) | Login handler - is the session regenerated on privilege change? | Manual |
| Weak Session IDs | Predictable/low-entropy session tokens | ASVS (session mgmt) | Token generation - RNG source, length, entropy | SAST+Manual |
| User Enumeration | Responses reveal whether an account exists | ASVS 5.0.0; Top 10:2025 | Login/reset/signup - do error messages or timing differ? | Manual |
| Password Mismanagement | Weak hashing, reversible storage, no policy | ASVS; see `reference/method/sensitive-data-at-rest.md` (reversible = wrong) | Password storage + verification; migrations/schema | SAST+Manual |
| Clickjacking | UI framed by an attacker to hijack clicks | ASVS 5.0.0; Top 10:2025 | `X-Frame-Options` / `frame-ancestors` CSP headers | SAST |
| Token / ID Validity Oracle | Different status, body, size or timing for malformed vs unknown vs expired vs valid tokens and object ids | ASVS 5.0.0 V6; API Top 10 2023 API2; CWE-204, CWE-208 | Token lookup and auth middleware error branches; 401/403/404 choice on object routes; `==` on secrets | Manual |
| Rate-limit Key and Coverage | No limit on SMS/email send, reset, OTP verify, search, export, GraphQL aliases; key from a spoofable header; in-memory store behind several instances | API Top 10 2023 API4, API6; CWE-307, CWE-799 | Limiter config (`keyGenerator`, `throttle`, store) against `routes.md` | Manual |
| Client-IP Header Trust | `X-Forwarded-For` first hop trusted for allow-lists, rate keys, audit logs or geo blocking | ASVS 5.0.0 V13; CWE-348, CWE-290 | `trust proxy`, `ProxyFix`, `TrustedProxies`, `RemoteIpValve`, IP allow-list code | SAST+Manual |
| Long-lived / Unrevocable Tokens | API tokens, PATs, remember-me or refresh tokens with no expiry or scope, stored in plaintext, not revoked on password change, role change or disable | ASVS 5.0.0 V7, V9; API Top 10 2023 API2; NHI Top 10 2025 NHI7; CWE-613 | Token table (`expires_at`, hash, `scopes`), issue/verify code, disable and password-change handlers | Manual |
| Spoofable Gateway Identity | Backend reads user / tenant from proxy headers (`X-User`, `X-Forwarded-User`) without verifying the peer; backend port also reachable directly | Top 10:2025 A07; CWE-290 | Header reads in middleware; compose / Kubernetes port exposure of the backend | Manual |
| Insecure Config Fallback | Auth, CSRF, TLS verification or tenant scope switched off by an env flag or when a variable is unset; literal default secret | Top 10:2025 A02, A10; CWE-1188, CWE-636 | `process.env.X or '...'` style defaults, `getenv(.., default)`, `if env != 'production'` around controls, overlays that weaken prod | SAST+Manual |
| Account Linking / Email Collision | Social or SSO login merged into an existing account by email without `email_verified`; IdP key not `iss` + `sub`; pre-hijack by early signup | ASVS 5.0.0 V10; Top 10:2025 A07; CWE-287 | OAuth callbacks, user lookup by email, "dangerous email linking" flags | Manual |
| MFA Bypass / Factor Management | A second login path (API, mobile, legacy, SSO) skips MFA; factors or recovery codes changed without re-auth; remember-device token not bound | ASVS 5.0.0 V6; NIST SP 800-63-4; PCI DSS v4.0.1 Req 8.4.2; CWE-308 | Every login route in `routes.md` against the MFA check; factor CRUD handlers | Manual |
| SAML Assertion Handling | Signature checked on another element than the one read; audience, recipient, expiry, `InResponseTo` unchecked | Top 10:2025 A07; ASVS 5.0.0 V6; CWE-347 | SAML library settings (`wantAssertionsSigned`, `strict`), custom assertion parsing | Manual |
| Scope-bypassing Data Access | Raw SQL, `unscoped()`, `withoutGlobalScopes()`, service-role / admin DB clients, jobs and exports that skip the tenant filter | API Top 10 2023 API1; ASVS 5.0.0 V8; CWE-639, CWE-863 | List every DB client and raw query; check the tenant predicate on each | Manual |
| Signed URLs and Share Links | Presigned URLs with long TTL or wildcard keys, issued without object authz, valid after ACL change; share links without expiry or revoke | API Top 10 2023 API1; CWE-639, CWE-613 | `getSignedUrl`, `generate_presigned_url`, `createSignedUrl`, share-token tables | Manual |
| Search Index Exposure | Admin or unscoped search key in the client; private fields indexed; no per-user filter; sort / filter on hidden fields as an oracle | API Top 10 2023 API3; CWE-200, CWE-203 | Indexer code, client bundle keys, search endpoint filters | Manual |
| Revocation Propagation | Disabled user, removed member or downgraded role keeps access through tokens, cached permissions, JWT claims, sockets, queued jobs | ASVS 5.0.0 V7, V8; CWE-613 | What the disable / remove-member handlers invalidate | Manual |
| Unreferenced Privileged Routes | Routes no client calls (role change, user create, impersonate, bulk) still reachable; "hidden" is not authz | API Top 10 2023 API5, API9; CWE-285 | Diff `routes.json` against the client's API calls (web, mobile, generated clients) | Manual |

## Injection & data flow
| Class | One-line | Anchor standard | Where to look | Seen by |
|-------|----------|-----------------|---------------|---------|
| SQL Injection | Untrusted input reaches a query unparameterized | ASVS; Top 10:2025 A05 | Data-access layer; string-built queries | SAST |
| Command Execution | Untrusted input reaches a shell/OS call | ASVS; Top 10:2025 A05 | `exec`/`system`/`spawn` call sites | SAST |
| Remote Code Execution | Attacker runs arbitrary code | ASVS 5.0.0; Top 10:2025 | Deserialization, template eval, dynamic `eval`, upload+include | SAST+Manual |
| Cross-Site Scripting (Reflected/DOM/Stored) | Untrusted data rendered as active markup/script | ASVS; Top 10:2025 A05 | Output encoding at every sink; `innerHTML`, template autoescaping | SAST+Manual |
| Cross-Site Script Inclusion (XSSI) | Sensitive JS/JSON pulled cross-origin via `<script>` | ASVS | JSON endpoints served as script; anti-XSSI prefixes | Manual |
| CSS Injection | Attacker-controlled CSS exfiltrates data / defaces | ASVS | User-controlled style content/attributes | Manual |
| Regex Injection (ReDoS) | Catastrophic backtracking from crafted input | ASVS; DoS | User input compiled into regex; expensive patterns | Manual |
| Mass Assignment | Request binds to fields it should not set | API Top 10 | Model binding / `update(params)` without allow-list | Manual |
| Prototype Pollution | `__proto__`/prototype chain mutated via input | ASVS 5.0.0; Top 10:2025 | Recursive merge/clone of untrusted objects | SAST+Manual |
| NoSQL Operator Injection | Request objects reach a query filter so `$ne`, `$gt`, `$regex`, `$where` change the query (login bypass, blind enumeration) | Top 10:2025 A05; CWE-943 | `find(req.body`, `{email: req.body.email}`, `$regex: req.`, `qs` bracket parsing, no sanitize / string cast | SAST+Manual |
| Export / Import Scope and CSV Formula | Export runs with service authority or crosses tenants; import skips authz; cells start with `= + - @` | API Top 10 2023 API1, API3; CWE-639, CWE-1236 | Export / report / backup jobs, CSV / XLSX writers, import endpoints | Manual |
| Queue / Event Consumer Trust | Consumer authorizes from ids in the message body; push endpoints (SNS, Pub/Sub, EventBridge) without signature or source check; side effects not idempotent | Top 10:2025 A08; CWE-345, CWE-290 | Consumer handlers, push webhook routes, dedupe keys | Manual |
| Decompression / Expansion Bombs | Body inflation, archive extraction or image decode without post-inflate size, entry or pixel caps | API Top 10 2023 API4; CWE-409 | `zlib`, `gunzip`, `ZipFile`, `unzipper`, `MAX_IMAGE_PIXELS`, `limitInputPixels` | SAST+Manual |
| Pre-auth Cost / Password Length | Expensive hashing or external calls before the rate gate; no max password length; bcrypt input over 72 bytes silently truncated | ASVS 5.0.0 V6; API Top 10 2023 API4; CWE-405 | Login / signup handlers, `bcrypt(id + password)` style inputs | Manual |
| XML External Entities (XXE) | External entity resolution in an XML parser | ASVS; Top 10:2025 A02 | XML parser config - is external entity resolution disabled? | SAST |
| XML Bombs | Entity-expansion DoS (billion laughs) | ASVS; DoS | XML parser entity-expansion limits | SAST+Manual |
| Directory Traversal | `../` reaches files outside the intended root | ASVS 5.0.0; Top 10:2025 | Path built from user input; file read/serve handlers | SAST |
| File Upload Vulnerabilities | Unrestricted type/size/location of uploads | ASVS 5.0.0; Top 10:2025 | Upload handler - type allow-list, storage path, execution | SAST+Manual |
| Open Redirects | Redirect target taken from unvalidated input | ASVS 5.0.0; Top 10:2025 | Redirect/`Location` built from a request param | SAST+Manual |
| Server-Side Request Forgery | Server fetches attacker-chosen URL (cloud metadata, internal services) | Top 10:2025 A01; API Top 10 2023 API7 | URL fetchers, webhooks, previews, PDF renderers | SAST+Manual |
| Fail-open error handling | Exception in a security check grants access | Top 10:2025 A10 | `catch`/`except` around verify/authz/payment returning success | Manual |
| Race conditions / double-spend | Concurrent requests bypass balance/limit checks | ASVS 5.0.0 V15; see `reference/standards/pci-dss.md` | Read-modify-write without locks/versions | Manual |

## Transport & network
| Class | One-line | Anchor standard | Where to look | Seen by |
|-------|----------|-----------------|---------------|---------|
| Unencrypted Communication | Sensitive traffic over plaintext | ASVS; PCI DSS v4.0.1 (transmission); CIS | Endpoints/services allowing HTTP; internal service calls | SAST+Manual |
| SSL Stripping | MITM downgrades HTTPS to HTTP | ASVS | HSTS header + preload; forced-TLS config | SAST+Manual |
| Downgrade Attacks | Forced fallback to weak protocol/cipher | ASVS; CIS | TLS version/cipher policy; server config/IaC | SAST+Manual |
| DNS Poisoning | Forged DNS answers redirect traffic | Infra/CIS | Resolver trust, DNSSEC, pinned endpoints | Manual |
| Host Header Poisoning | App trusts attacker-set `Host` for links/cache keys | ASVS | Absolute-URL/password-reset link building; cache keys | Manual |
| Subdomain Squatting | Dangling DNS to a decommissioned host is claimed | CIS; infra | DNS records pointing at deprovisioned resources | Manual |
| Shared-cache Leakage / Cache Deception | Authenticated responses cached by a CDN or proxy (no `private` / `no-store`), extension-based cache rules, unkeyed headers that change the response, cache keys without user or tenant | ASVS 5.0.0 V14; Top 10:2025 A02; CWE-524 | CDN / edge config in repo, `proxy_cache`, framework cache middleware, cache-key construction | Manual |
| Request Smuggling / Parse Disagreement | In-repo proxy forwards ambiguous `Transfer-Encoding` / `Content-Length`, HTTP/2 downgrade, custom HTTP parsing | ASVS 5.0.0 V4; CWE-444 | nginx / HAProxy / Envoy config in the repo, custom servers | Manual |

## Cross-origin & browser
| Class | One-line | Anchor standard | Where to look | Seen by |
|-------|----------|-----------------|---------------|---------|
| Cross-Origin Resource Sharing (CORS) | Over-permissive CORS exposes authed data | ASVS; API Top 10 | `Access-Control-Allow-Origin` - wildcards, reflected origin + credentials | SAST+Manual |
| Cross-Site Request Forgery (CSRF) | State-changing request forged from another site | ASVS 5.0.0; Top 10:2025 | Anti-CSRF tokens / SameSite cookies on mutating routes | Manual |
| Malvertising | Malicious third-party ad/script content | ASVS; Insecure Design | Third-party scripts/iframes; CSP `script-src` | Manual |
| Browser Messaging and Storage | `message` handlers without an exact `event.origin` check; `postMessage(.., '*')` with data; service worker caching authed responses; tokens kept after logout | ASVS 5.0.0 V3; CWE-346 | `addEventListener('message'`, `sw.js` / Workbox caching, logout handler | SAST+Manual |

## Supply chain & operations
| Class | One-line | Anchor standard | Where to look | Seen by |
|-------|----------|-----------------|---------------|---------|
| Toxic Dependencies | Known-vulnerable third-party packages | ASVS; Top 10:2025 A03 | Lockfiles - run SCA (Trivy/OSV, `reference/tooling/scanners.md`) | SAST |
| Slop Squatting | AI-hallucinated package name registered by an attacker | Top 10:2025 A03; AISVS 1.01; LLM Top 10 2026 LLM04 | New/unusual deps, esp. AI-suggested; verify each exists + is authentic | Manual |
| Native Code / FFI | Memory-safety bugs in C/C++ extensions, cgo, JNI, node-gyp addons, Rust `unsafe` in the repo | CWE Top 25 2025 (CWE-787, CWE-416, CWE-125) | `binding.gyp`, `*.c`, `ext_modules`, `import "C"`, `unsafe {` - state as a coverage gap unless a native-specific review ran | SAST+Manual |
| CI Cache / Artifact Poisoning | Jobs on untrusted triggers write caches or artifacts that privileged jobs restore or release; artifacts fetched by name, not digest | CICD-SEC-4, CICD-SEC-9; SLSA v1.2; CWE-494 | `actions/cache` keys shared across triggers, `download-artifact` in `workflow_run` | SAST+Manual |
| Denial of Service | Resource exhaustion takes the service down | ASVS; DoS | Unbounded loops/fan-out, missing rate limits, ReDoS, XML bombs | Manual |
| Logging and Monitoring | Missing/insufficient security logging | ASVS; Top 10:2025 A09 | Auth events, admin actions - logged? alerting? no secrets in logs | Manual |
| Information Leakage | Stack traces, verbose errors, metadata leak internals | ASVS 5.0.0; Top 10:2025 | Error handlers, debug flags, response headers, comments | SAST+Manual |
| Lax Security Settings | Insecure defaults / weak config | ASVS; CIS; Top 10:2025 A02 | Framework config, cloud/IaC defaults (run Checkov) | SAST |
| Insecure Design | Flaw in the design, not the implementation | ASVS; Top 10:2025 A06 | Trust boundaries, workflows, threat model gaps | Manual |
| Email Spoofing | Forged sender due to missing email auth | Infra/CIS | SPF / DKIM / DMARC records | Manual |

## Exposure, patch level and blast radius (start from `platform.md` and `intel.md`)
The initial-access and post-compromise classes behind most incident reports (national CERT alerts,
honeypot data): an unpatched runtime or product reached from the internet, a file or tool that should
never have been served, and a compromised server that can reach anything. Method:
`reference/method/threat-intel.md`.

| Class | One-line | Anchor standard | Where to look | Seen by |
|-------|----------|-----------------|---------------|---------|
| Runtime / Server Patch Level | Interpreter, server, datastore or base image pinned at a version with KEV / national-alert / critical CVEs, or behind the cycle's latest patch | Top 10:2025 A03; ASVS 5.0.0 V15; PCI DSS v4.0.1 Req 6.3.3; CWE-1395 | `intel.md` act-now / review rows; the pin in Dockerfile, compose, manifests, version files, CI | Script+Manual |
| End-of-life Runtime / Framework | Runtime, OS, datastore or framework cycle past vendor EOL, or a version range that still allows one | Top 10:2025 A03; PCI DSS v4.0.1 Req 6.3.3, Req 12.3.4; CWE-1104 | `intel.md` support column; managed runtimes (Lambda / Functions `runtime`) included | Script+Manual |
| Emergency Patch Readiness | A runtime fix cannot ship in hours: floating tags with no rebuild schedule, no base-image update automation, runtime from distro packages, unpinned digests | SSDF v1.1 RV.2; SLSA v1.2; CWE-1395 | `platform.md` signals `no-image-update-automation`, `unpinned-base-image`; CI rebuild triggers | Script+Manual |
| Web-root File Exposure | `.env`, `*.bak`, `*.sql`, archives, `.git/`, `phpinfo()`, `composer.json` inside a served directory; static serving rooted at the project root; directory listing | Top 10:2025 A02; ASVS 5.0.0 V13; CWE-538, CWE-527 | `platform.md` signals; docroot from nginx `root`, `public/`, `express.static`, `WORKDIR`; dotfile deny rules | Script+Manual |
| Management / Debug Plane Exposure | Tomcat manager / WAR deploy, JMX, Jolokia, actuator beyond health, Ignition, Telescope, Werkzeug or Rails debug consoles, admin paths without MFA | Top 10:2025 A02; API Top 10 2023 API9; CWE-306, CWE-489 | `tomcat-users.xml`, `management.endpoints`, `APP_DEBUG`, `debug=True`, Dockerfile `COPY *.war` | SAST+Manual |
| Exposed Admin / BI / Data Services | Metabase, Grafana, Kibana, Jupyter, phpMyAdmin, Adminer and similar, or Redis / Elasticsearch / Mongo / Postgres published without auth | Top 10:2025 A02; CIS Docker v1.9.0; Kubernetes Top 10 2025 K06; CWE-306 | `platform.md` signals `admin-tool-image`, `datastore-port-published`; Services of type LoadBalancer, Ingress hosts | Script+Manual |
| Upload-to-Execution Path | Uploads stored under the docroot with a script handler; `.htaccess` / `.user.ini` uploadable; app user can write code directories; writable root filesystem | Top 10:2025 A06; ASVS 5.0.0 V5; CWE-434, CWE-732 | Upload target vs docroot; nginx `location ~ \.php` scope; Dockerfile `USER` and `chown`; `read_only` | Manual |
| Build-context Leakage | `COPY . .` without a `.dockerignore` that drops `.env*`, `.git`, keys; packages that ship secrets or source maps | Top 10:2025 A02; CIS Docker v1.9.0; CWE-538 | Dockerfile `COPY` sources vs `.dockerignore`; `package.json` `files`, `.npmignore`, `MANIFEST.in` | Manual |
| Post-compromise Blast Radius | App tier with open egress (download a bot, join a DDoS, reach C2), root in the container, shell and download tools in the runtime image, one DB superuser shared by services, reused workload roles | Kubernetes Top 10 2025 K05, K08; NHI Top 10 2025 NHI9; CWE-250 | `platform.md` signals `sg-egress-any`, `k8s-no-networkpolicy`, `container-runs-as-root`, `download-tools-in-runtime-image`; DB grants; IAM role attachment | Script+Manual |
| Detection and Forensic Readiness | No trail of who read which records; admin, role-change, token-issue and export events not logged; access logs kept on-host only or for less than 12 months | Top 10:2025 A09; ASVS 5.0.0 V16; PCI DSS v4.0.1 Req 10.2.1, Req 10.5.1; CWE-778 | Logger calls in auth / admin / export handlers; log shipping; `retention_in_days`, bucket lifecycle | Manual |

## AI-specific (detail: `reference/standards/ai-llm-agentic.md`)
| Class | One-line | Anchor standard | Where to look | Seen by |
|-------|----------|-----------------|---------------|---------|
| Prompt Injection | Untrusted content overrides model instructions | AISVS 1.01; LLM Top 10 2026 LLM01; Agentic Top 10 2026 ASI01 | Prompt assembly - untrusted data mixed with instructions; tool-call gating | Manual |
| Data Extraction Attacks | Model coerced into leaking training/context data | AISVS 1.01; LLM Top 10 2026 | System-prompt/secret exposure; RAG context boundaries | Manual |
| Bias and Unreliability | Model output unfair or untrustworthy for the use | AISVS 1.01; LLM Top 10 2026 | Where model output drives decisions without a check | Manual |
| Excessive Agency / Tool Misuse | Agent tools broader than needed; no approval on destructive actions | LLM Top 10 2026 LLM03; Agentic 2026 ASI02/ASI03 | Tool registries, credentials given to agents | Manual |
| Improper Output Handling | Model output reaches HTML/eval/SQL/shell unencoded | LLM Top 10 2026 LLM10 | Render/exec of completions | SAST+Manual |
| MCP Tool Poisoning | Tool metadata carries hidden instructions / rug-pull | MCP Top 10 (beta) MCP03 | MCP server tool descriptions, `.mcp.json` | Manual |
| Agent Permission Over-grant | Committed agent allow-lists pre-approve write / publish / merge / exfil commands | Agentic 2026 ASI02/ASI03; LLM Top 10 2026 LLM03 | `.claude/settings.json` allow/deny, `defaultMode`, skill `allowed-tools` | Manual |
| Fail-open Agent Hooks | Guard hooks that exit non-blocking on error, miss command forms, or do not run on some OS | Top 10:2025 A10; Agentic 2026 ASI02 | `.claude/hooks/*`, hook exit codes, platform | Manual |
| Unvetted Agent Skills / MCP Servers | Vendored skills or MCP servers without provenance, pinning or script review | Agentic 2026 ASI04; MCP Top 10 (beta) MCP04/MCP09 | `.agents/skills`, `SKILL.md` scripts, `.mcp.json` launch commands | Manual |
| Committed Prompt Logs | Prompt history / transcripts with secrets, personal or customer data in the repo | LLM Top 10 2026 LLM02; CWE-532 | `prompt_history*`, transcripts, `.specstory/` (peek.py) | Manual |
| Agent Self-approval | Agents commit, approve, merge or release their own changes | AISVS 1.01 AC.8.1/AC.8.4; CICD-SEC-1 | git history, branch rules, agent allow-lists | Manual |

## Industry sectors
When detect lists `sectors` (or the user named one), walk the sector module's "Code-evidenced checks"
table (`medical` M01-M07, `finance` F01-F10 / C01-C06, `ecommerce` E01-E11, `public-sector` G01-G08,
`education` D01-D08, `iot-ot` T01-T11) the same way: covered / not-applicable / gap per row.

## Feeding the report
Every **gap** on this walk is a coverage statement in the audit report (section 2). Classes marked
**Manual** that you did NOT read for are not "clean" - they are unexamined; say so (a scanner's silence
on a Manual class is meaningless). For the storage class, defer to `reference/method/sensitive-data-at-rest.md`; for the
design-level Manual classes, the hunting method is in `reference/method/design-flaws.md`. Back to procedure:
`SKILL.md` Phase 4.
