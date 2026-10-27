# Module: owasp-api - OWASP API Security Top 10 2023

Apply to any HTTP/GraphQL/gRPC/WebSocket surface. Cite `OWASP API Security Top 10 2023 APIx` plus
the ASVS 5.0.0 chapter (V4 API, V8 Authorization, V2 Business Logic) and a CWE. Version per
`reference/standards/index.md`. Almost every row is **Manual** - API authz flaws are absences, not patterns.

## Method: build the endpoint inventory first
1. Enumerate routes from the router/controllers/OpenAPI spec (not from docs). For GraphQL: every
   query, mutation, subscription and resolver; for gRPC: every service method.
2. For each: auth required? role/permission check? object-ownership check? input schema? rate limit?
   Record as a table in your working notes - gaps in the table ARE the findings.
3. Compare the inventory with what the gateway/IaC exposes (API9): undocumented, old-version
   (`/v1/`), debug, or internal routes reachable from outside.

## Checks

| ID | Risk | What to verify | Where / grep hints |
|----|------|----------------|--------------------|
| API1 | Broken Object Level Authorization (BOLA/IDOR) | Every object lookup by client-supplied ID is scoped to the caller (owner/tenant) | `params.id`, `req.params`, `{id}` path vars -> `findById`, `get(pk=`, `find(params[:id])`; GraphQL `node(id:)` resolvers |
| API2 | Broken Authentication | Token validation complete (sig, alg, exp, aud, iss); no auth bypass routes; brute-force limits; API keys not in URLs | auth middleware, JWT verify, `/login`, `/token`, `apiKey=` query params |
| API3 | Broken Object Property Level Authorization | No mass assignment on write; no over-exposure on read (serializers return only allowed fields, e.g. no `password_hash`, `is_admin`, `ssn`) | `req.body` spread into models, `fields = '__all__'`, `toJSON` without allow-list, GraphQL types exposing internal fields |
| API4 | Unrestricted Resource Consumption | Pagination caps, request size limits, upload limits, rate limits, GraphQL depth/complexity limits, timeouts; cost-bearing calls (SMS, email, LLM tokens) throttled per user | `limit=` without max, `bodyParser` limits, `graphql-depth-limit`, LLM calls in request path |
| API5 | Broken Function Level Authorization | Admin/privileged functions check role server-side; HTTP method switching does not bypass (GET vs DELETE) | `/admin`, `/internal`, role decorators, route groups lacking middleware |
| API4+ | Rate-limit key and coverage | Every cost or abuse route has a limit (SMS / email send, reset, OTP verify, search, export, GraphQL aliases); the key is not a spoofable header (`X-Forwarded-For` without a trusted-proxy list); the store is shared across instances | `keyGenerator`, `trust proxy`, `throttle`, in-memory stores, `routes.md` vs limiter config |
| API6 | Unrestricted Access to Sensitive Business Flows | Flows that harm the business when automated (purchase, booking, referral, coupon, signup, OTP) have anti-automation | checkout, promo, invite, OTP endpoints |
| API7 | Server Side Request Forgery | User-influenced URLs fetched server-side are allow-listed; metadata endpoints and internal ranges blocked; DNS-rebinding considered | webhooks, URL import, image proxy, PDF/HTML render, OAuth `request_uri` |
| API8 | Security Misconfiguration | CORS, verbose errors, missing TLS, permissive HTTP methods, default GraphQL introspection/playground in prod | CORS config, error handlers, `introspection: true`, `playground` |
| API9 | Improper Inventory Management | Old API versions, staging hosts, debug endpoints retired or protected; OpenAPI matches reality | `/v1`, `/beta`, `/debug`, swagger in prod, IaC/gateway route lists |
| API10 | Unsafe Consumption of APIs | Third-party responses validated, timeouts set, TLS verified, redirects not followed blindly; data from partners treated as untrusted | outbound HTTP clients, webhook consumers, payment provider responses |

## Protocol-specific checks (cite with ASVS 5.0.0 V4)
| Surface | What to verify | Where |
|---------|----------------|-------|
| GraphQL | Field-level authz in resolvers (not only at the gateway); depth/complexity/cost limits; alias and batching abuse limited (brute force via 1000 aliased `login` mutations); introspection and playground off in prod; persisted queries for public clients | resolvers, `graphql-shield`, `depthLimit`, Apollo/Yoga config |
| WebSocket | `Origin` checked on upgrade (cross-site WebSocket hijacking); auth at connect AND authz per message/subscription; message size and rate limits | `ws`, `socket.io`, ActionCable, Channels consumers |
| gRPC | Server reflection off in prod; per-method auth interceptors; TLS (no `insecure` channels); message size limits; deadlines set | interceptors, `grpc.reflection`, channel credentials |
| Webhooks (inbound) | Signature verified on the raw body with constant-time compare, timestamp tolerance, replay/idempotency protection | provider callback handlers |

## Severity guidance
- BOLA/BFLA exposing other users' PII, payment or health data, or admin functions -> P0/P1 by data
  class (`reference/method/triage.md`).
- API4 without a cost amplifier -> usually P2; with paid downstream (SMS/LLM) -> P1.
- GraphQL introspection in prod alone -> Info/P2 unless it exposes hidden privileged operations.
