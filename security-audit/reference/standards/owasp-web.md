# Module: owasp-web - OWASP Top 10:2025 + ASVS 5.0.0 + CWE Top 25 2025

Baseline for ANY application code. Versions per `reference/standards/index.md` (verified 2026-10-26).
Cite as `OWASP Top 10:2025 A0x` for the risk and `OWASP ASVS 5.0.0 V<ch>.<sec>.<req>` for the
verifiable requirement; add the CWE. Seen-by: **S** = SAST can catch, **M** = manual only,
**S+M** = scanners catch instances, design flaws need reading.

## Contents
- Part A - Top 10:2025 checks (A01-A10)
- Part B - ASVS 5.0.0 chapter router (V1-V17)
- Part C - CWE Top 25 2025 quick map
- Part D - Authentication specifics (NIST SP 800-63-4)
- Part E - IPA "How to Secure Your Web Site" (Japan) quick map

## Part A - OWASP Top 10:2025

### A01 Broken Access Control (now includes SSRF) - ASVS V8, V4; CWE-862/863/639/918/352
| Check | Where / grep hints | Seen |
|-------|-------------------|------|
| Every privileged route has a SERVER-side authz check (not UI hiding) | route tables, middleware chains, `@PreAuthorize`, `before_action`, `permission_classes`, `[Authorize]`, guards | M |
| Object ownership enforced (IDOR/BOLA): query scoped by current user/tenant | `findById(req.params.id)`, `Model.find(params[:id])`, `get_object_or_404(pk=` without owner filter | M |
| Tenant isolation in multi-tenant queries | `tenant_id`, `org_id`, row-level security, global query filters | M |
| Default-deny; new routes not public by omission | router registration vs auth middleware order | M |
| SSRF: server fetch of user-supplied URL is allow-listed; metadata IPs (169.254.169.254, fd00:ec2::254) blocked; redirects not followed blindly | `requests.get(url`, `fetch(`, `http.Get(`, `RestTemplate`, `HttpClient`, webhooks, image/URL preview, PDF renderers | S+M |
| CSRF on cookie-authenticated state-changing routes | `csrf`, `SameSite`, `csurf`, `protect_from_forgery`, `@csrf_exempt` | S+M |
| CORS not reflecting arbitrary origin with credentials | `Access-Control-Allow-Origin`, `cors({ origin: true, credentials: true })` | S+M |
| Path traversal on file read/serve | `path.join(base, req.`, `send_file(`, `../` | S |

### A02 Security Misconfiguration - ASVS V13, V3; CWE-16/611/1004
| Check | Where / grep hints | Seen |
|-------|-------------------|------|
| Debug off in prod; no stack traces to clients | `DEBUG = True`, `app.debug`, `NODE_ENV`, `display_errors`, `developer_exception_page` | S |
| Security headers: CSP, HSTS, X-Content-Type-Options, frame-ancestors | helmet, `SecurityMiddleware`, `secure_headers`, reverse-proxy config | S+M |
| Cookies: `Secure`, `HttpOnly`, `SameSite` | session config | S |
| XXE: external entities disabled | XML parser factories, `resolve_entities`, `DocumentBuilderFactory` | S |
| Default credentials / sample accounts / admin consoles exposed | seeds, fixtures, `admin/admin`, actuator, `/h2-console`, `/debug` | S+M |
| Management / debug planes not reachable: Tomcat manager and WAR deploy, JMX, Jolokia, actuator beyond `health`, Ignition, Telescope, Werkzeug / Rails consoles | `tomcat-users.xml`, `management.endpoints`, `APP_DEBUG`, `debug=True`; `platform.md` signals | S+M |
| Nothing sensitive served from the web root (`.env`, backups, dumps, `.git/`, `phpinfo()`); no directory listing; dotfiles denied | docroot config, `public/`; `platform.md` signals `webroot-sensitive-file`, `phpinfo-exposed`, `directory-listing` | S+M |
| Auth, CSRF, TLS verification or tenant scope never switched off by an env flag or an unset variable | `process.env.X` defaults, `if env != 'production'` around controls | M |
| Cloud/IaC defaults (see `reference/standards/cloud-iac.md`) | Terraform/CFN/K8s | S |

### A03 Software Supply Chain Failures - ASVS V15.2, V13; CWE-1104/829/494
Widened from 2021 "vulnerable components" to the whole chain. Detail in `reference/standards/supply-chain.md`.
| Check | Where | Seen |
|-------|-------|------|
| Known-vulnerable deps (reachable ones first) | lockfiles; Trivy/OSV output | S |
| Lockfile present and committed; versions pinned | `package-lock.json`, `poetry.lock`, `go.sum` | S |
| Dependency confusion / typo- or slop-squatting (AI-suggested names) | new/unusual deps, private-scope names resolvable publicly | M |
| CI actions pinned to commit SHA; no `pull_request_target` + checkout of PR head | `.github/workflows` (zizmor) | S |
| Remote scripts / CDN assets without integrity (`curl | sh`, `<script src>` without SRI) | Dockerfiles, HTML, install scripts | S+M |
| Runtime, server, datastore and base image at a supported, current patch level (lockfile SCA does not see them) | `platform.md` pins, `intel.md` (KEV, NVD, IPA / JPCERT/CC, EOL); `reference/method/threat-intel.md` | S+M |

### A04 Cryptographic Failures - ASVS V11, V12, V14; CWE-327/328/330/916/319
| Check | Where / grep hints | Seen |
|-------|-------------------|------|
| Passwords: Argon2id / scrypt / bcrypt / PBKDF2 with proper cost; never MD5/SHA-x alone, never reversible | `md5(`, `sha1(`, `createHash('sha256')` on passwords, `encrypt(password` | S+M |
| No ECB, no static IV/nonce, AEAD preferred (AES-GCM, ChaCha20-Poly1305) | `AES/ECB`, `Cipher.getInstance("AES")`, `iv = b'\x00'` | S |
| CSPRNG for tokens/IDs | `Math.random`, `random.random`, `rand()` for secrets | S |
| Keys not hard-coded; rotation possible; KMS/HSM used for data keys | `SECRET_KEY =`, `private_key`, `.pem` committed | S |
| TLS enforced for all external and internal sensitive traffic; cert validation not disabled | `verify=False`, `rejectUnauthorized: false`, `InsecureSkipVerify: true` | S |
| Sensitive data at rest encrypted / tokenized | `reference/method/sensitive-data-at-rest.md` | M |

### A05 Injection - ASVS V1, V2; CWE-89/78/79/94/77/917/1336
| Check | Where / grep hints | Seen |
|-------|-------------------|------|
| SQL/NoSQL parameterized; no string-built queries | `+ req.`, f-strings / `%` in `execute(`, `$where`, `raw(`, `Sequelize.literal`, `$queryRawUnsafe` | S |
| NoSQL filters typed: request objects cannot inject operators (`$ne`, `$gt`, `$regex`) into `find` / `findOne`; regex from input escaped | `find(req.body`, `{email: req.body.email}`, `sanitizeFilter`, `express-mongo-sanitize`, string casts (CWE-943) | S+M |
| OS command: no shell with user input | `exec(`, `child_process`, `os.system`, `subprocess(..., shell=True)`, `Runtime.exec` | S |
| XSS: contextual output encoding; no unsafe sinks | `innerHTML`, `dangerouslySetInnerHTML`, `v-html`, `|safe`, `html_safe`, `raw(`, `@Html.Raw` | S+M |
| Template injection / eval | `eval(`, `new Function(`, `render_template_string(`, `Velocity`, `vm.runIn` | S |
| LDAP / XPath / header / log injection | `ldap.search(` with concatenation, CRLF in headers, untrusted data in logs | S+M |
| Prompt injection for LLM features -> `reference/standards/ai-llm-agentic.md` | prompt assembly | M |

### A06 Insecure Design - ASVS V2 (business logic), V15; CWE-840/841/799
| Check | Where | Seen |
|-------|-------|------|
| Business-flow abuse: rate/volume limits on signup, OTP, coupons, checkout | flows in `reference/standards/owasp-api.md` API6 | M |
| State machines cannot be skipped (pay -> ship, verify -> activate) | workflow/status transitions | M |
| Trust boundaries explicit; webhooks verified (signature + timestamp + replay) | payment/provider callbacks | M |
| Money movement: atomic, idempotent, audited (`reference/standards/pci-dss.md` transaction integrity) | refunds, ledgers | M |

### A07 Authentication Failures - ASVS V6, V7, V9, V10; CWE-287/307/384/798/521
| Check | Where / grep hints | Seen |
|-------|-------------------|------|
| Brute-force / credential-stuffing protection (rate limit, lockout, CAPTCHA) on login, OTP, reset | login handlers | M |
| Session rotated on login/privilege change; invalidated on logout/password change | session regenerate calls | M |
| JWT: algorithm pinned (`alg: none` / HS-RS confusion rejected), `exp` checked, secret strong, not in localStorage when avoidable | `jwt.verify(`, `algorithms=`, `decode(` without verify | S+M |
| Password policy per NIST SP 800-63-4 (Part D) | signup/reset validation | M |
| MFA for admin and sensitive actions; recovery flows not weaker than login | admin auth, reset tokens (single-use, short TTL, hashed at rest) | M |
| OAuth/OIDC per OAuth 2.0 Security BCP (RFC 9700, 2025-01): PKCE for all clients, exact redirect URI match, `state`/`nonce`, no implicit / ROPC grants, sender-constrained or short-lived tokens, audience check | OAuth client/server config | M |
| JWT per JWT BCP (RFC 8725): explicit algorithm allow-list, `kid`/`jku`/`x5u` not trusted blindly, `typ` checked, separate keys per purpose | JWT libraries and verify calls | S+M |
| Passkeys / WebAuthn: RP ID and origin verified, challenge single-use and server-generated, user verification required for AAL2+, `signCount` / backup flags handled | WebAuthn server library config | M |
| User enumeration via messages or timing | login/reset/signup responses | M |

### A08 Software or Data Integrity Failures - ASVS V15, V5; CWE-502/345/494
| Check | Where / grep hints | Seen |
|-------|-------------------|------|
| No unsafe deserialization of untrusted data | `pickle.loads`, `yaml.load(` (not safe_load), `ObjectInputStream`, `unserialize(`, `BinaryFormatter`, `Marshal.load` | S |
| Signed/verified updates, artifacts, webhooks, cookies | signature verify calls; read the body of the verifier (dead-control check) | M |
| Mass assignment blocked | `Model.create(req.body)`, `update(params)`, `permit!`, `@ModelAttribute` on entities | S+M |
| Prototype pollution | deep-merge of untrusted objects, `__proto__` | S+M |

### A09 Security Logging and Alerting Failures - ASVS V16; CWE-778/117/532
| Check | Where | Seen |
|-------|-------|------|
| Auth events, authz failures, admin actions, payment events are logged with who/what/when | logger calls near those handlers | M |
| No secrets / tokens / PAN / passwords / full PII in logs | `logger.*(req.body)`, `console.log(user)` - `scripts/sensitive_sweep.py` surfaces `log` | S+M |
| Logs tamper-resistant / centralised; alerting exists for abuse signals | infra config | M |
| Forensic readiness: who read which records (actor, source IP, object id) for admin, export, role-change and token-issue events; access logs off-host and kept >= 12 months; 5xx / worker-crash alerts | logger calls in those handlers, log shipping, `retention_in_days` | M |

### A10 Mishandling of Exceptional Conditions (NEW in 2025) - ASVS V16, V2; CWE-754/755/390/248/636
| Check | Where / grep hints | Seen |
|-------|-------------------|------|
| Fail closed: an exception in an authz/verify/payment path denies, never allows | `try { verify } catch { return true / next() }`, `except: pass` around checks | M |
| Errors don't leak internals (stack, SQL, paths) | global error handlers | S+M |
| Resource cleanup on error (transactions rolled back, locks released, partial writes undone) | DB transactions, file handles | M |
| Unhandled promise rejections / panics crash or bypass logic | `.then(` without catch, goroutine panics, `unwrap()` on input | S+M |
| Timeouts and retries bounded on outbound calls | HTTP clients without timeout | S+M |

## Part B - ASVS 5.0.0 chapter router

Use ASVS to cite the *verifiable requirement* behind a Top 10 risk. Look up the exact requirement
number in the ASVS 5.0.0 document when writing the finding (https://github.com/OWASP/ASVS); if you
cannot confirm the sub-number, cite the chapter/section (`OWASP ASVS 5.0.0 V8.2`) rather than guess.

| Chapter | Topic | Typical defects to cite it for |
|---------|-------|-------------------------------|
| V1 | Encoding and Sanitization | injection, XSS, unsafe deserialization sinks |
| V2 | Validation and Business Logic | missing validation, business-flow abuse, anti-automation |
| V3 | Web Frontend Security | CSP, cookie flags, CORS, clickjacking, SRI, postMessage |
| V4 | API and Web Service | REST/GraphQL/WebSocket specifics, content types, HTTP method handling |
| V5 | File Handling | upload type/size, storage outside webroot, path traversal, zip slip |
| V6 | Authentication | password policy, brute force, MFA, credential recovery |
| V7 | Session Management | rotation, timeout, logout, token binding |
| V8 | Authorization | function/object/field-level authz, tenant isolation |
| V9 | Self-contained Tokens | JWT validation, alg pinning, claims (exp/aud/iss) |
| V10 | OAuth and OIDC | PKCE, redirect URI, state/nonce, token handling |
| V11 | Cryptography | algorithms, key management, randomness, hashing |
| V12 | Secure Communication | TLS everywhere, cert validation, HSTS |
| V13 | Configuration | secrets management, debug, defaults, dependency config |
| V14 | Data Protection | sensitive data classification, at-rest protection, caching, retention |
| V15 | Secure Coding and Architecture | dependency hygiene, dangerous functions, concurrency, mass assignment |
| V16 | Security Logging and Error Handling | security events, log injection, error handling, fail-closed |
| V17 | WebRTC | TURN/STUN, media encryption, signalling auth (only if WebRTC present) |

Levels: L1 = minimum for all apps; L2 = apps handling sensitive data (default target for audits);
L3 = high-assurance (payments core, health, critical infra). State the target level in the report.

## Part C - CWE Top 25 2025 quick map

Top 10 by rank: CWE-79 XSS, CWE-89 SQLi, CWE-352 CSRF, CWE-862 Missing Authorization, CWE-787 OOB
Write, CWE-22 Path Traversal, CWE-416 Use After Free, CWE-125 OOB Read, CWE-78 OS Command Injection,
CWE-94 Code Injection. Memory-safety CWEs (787/416/125) apply only to C/C++/unsafe Rust/native
modules - for those, Semgrep coverage is partial; state the gap or use language-specific tools.
Full list: https://cwe.mitre.org/top25/

## Part D - Authentication specifics (NIST SP 800-63-4, final 2025-07-31)

Cite when the client follows NIST or as the rationale for ASVS V6:
- Passwords: minimum 15 chars when single-factor (8 with MFA); allow at least 64; no composition
  rules; no periodic forced rotation; screen against breached/common lists.
- Phishing-resistant authenticators (WebAuthn/passkeys) required at AAL3, recommended for admins.
- Hard-coded credentials (CWE-798) map to Top 10:2025 **A07** (authentication), not A04.
- SMS OTP is a restricted authenticator - flag when it is the only second factor for privileged users.
Note: PCI DSS v4.0.1 Req 8.3.6 separately requires minimum 12 chars (numeric + alphabetic) for
in-scope systems - cite whichever governs; for payment systems cite both.

## Part E - IPA "How to Secure Your Web Site" (Japan) quick map
Japanese contracts and acceptance checks often require IPA's guide 安全なウェブサイトの作り方 (canonical
name `IPA How to Secure Your Web Site`, version per `reference/standards/index.md`). Cite it next to the
OWASP / ASVS citation when the client is Japanese or the report language is ja, with the chapter 1
item number: `IPA How to Secure Your Web Site 7th 1.1`. The guide gives 根本的解決 (fixes that remove the
cause) and 保険的対策 (mitigations); a finding whose code applies only a mitigation says so.

| Item | Vulnerability | Root fix the guide expects | Top 10:2025 | ASVS 5.0.0 | CWE |
|---|---|---|---|---|---|
| 1.1 | SQL injection | placeholders / bound parameters for every query | A05 | V1.2 | CWE-89 |
| 1.2 | OS command injection | no shell-invoking APIs; fixed arguments | A05 | V1.2 | CWE-78 |
| 1.3 | Unchecked path parameters / directory traversal | no file names from input; fixed directory; basename only | A01 | V5.3 | CWE-22 |
| 1.4 | Session management flaws | unpredictable ids, reissued at login, not in URLs, `Secure` cookies | A07 | V7.1, V7.2 | CWE-384 |
| 1.5 | Cross-site scripting | escape every output; quote attributes; restrict URL schemes; no script-generated markup from input | A05 | V1.2, V3.4 | CWE-79 |
| 1.6 | CSRF | secret token or re-authentication on state-changing requests; `SameSite` as a mitigation | A01 | V3.5 | CWE-352 |
| 1.7 | HTTP header injection | header APIs, no CR/LF from input | A05 | V4.2 | CWE-113 |
| 1.8 | Mail header injection | fixed headers, no CR/LF from input | A05 | V1.3 | CWE-93 |
| 1.9 | Clickjacking | `frame-ancestors` / `X-Frame-Options` | A02 | V3.4 | CWE-1021 |
| 1.10 | Buffer overflow | bounds-checked APIs, memory-safe languages | A05 | V1.4 | CWE-120 |
| 1.11 | Missing access control / authorisation | server-side authorisation on every resource | A01 | V8.2 | CWE-862, CWE-639 |
