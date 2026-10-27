# What scanners cannot see - hunting design-level defects by reading

Scanners find patterns in the code that IS there. The most dangerous defects are about code that ISN'T
there, controls that only *appear* to work, or state split across two places that disagree. No pattern
match finds those. A human or agent finds them by **reading and forming hypotheses** (`SKILL.md`
Phase 1 and Phase 4). This file is the checklist of classes to hold in mind while reading.

## The structural reason scanners miss these

A scanner asserts "this bad pattern is present." It cannot assert "this necessary control is absent,"
because absence has no pattern to match. It cannot reason about intent, so a control that runs but does
nothing looks identical to one that works. And it sees one file at a time, so two components that are
each individually fine but contradict each other slip through.

## The defect classes

| Class | What it looks like | How to hunt it by reading |
|-------|--------------------|---------------------------|
| **Client-only authorization** | The server-side check does not exist to be found. The UI hides a button; the API endpoint behind it has no authz | Enumerate every privileged endpoint. For each, find the SERVER-side authz check. A missing one is invisible to SAST - the absence is the bug |
| **Dead security control** | A `validateSignature()` / `verifyToken()` / `checkPermission()` that always returns true / null / a no-op, called faithfully everywhere. The control is *believed* to work | Read the body of every security-critical function, not just its call sites. A control that cannot fail is the vulnerability. At least P1 (`reference/method/triage.md`) |
| **Two caches that disagree** | An in-memory cache and a shared cache (e.g. Redis), or a permission cache and the DB, that can hold different answers to the same question | Find every cache. Ask: what invalidates it, and can two layers return different values for one key? A stale authz cache is an access-control defect |
| **Sensitive data at rest** | Card / PII / PHI persisted unencrypted or reversibly - the defect is in the schema, not the logic | Full recipe in `reference/method/sensitive-data-at-rest.md`. Migrations first. This is Phase 2, mandatory for payment/PII/PHI repos |
| **Cross-repo secret sourcing** | A secret correctly read from an env var - that is itself populated from a credential committed in a DIFFERENT repo | Trace where env vars come from. A clean `process.env.X` read is not clean if `X` is set from a committed value in the infra/deploy repo. Scanners see one repo at a time |
| **Missing control at a trust boundary** | No rate limit, no input validation, no output encoding where untrusted data crosses in | Map the trust boundaries first (external input, third-party callbacks, inter-service calls). Check each boundary for the control that should guard it |
| **Logic / authorization-scope flaws** | User A can read user B's records by changing an ID; a workflow step can be skipped | Reason about object ownership and state machines. IDOR and broken-object-level-authorization are design flaws, not pattern hits (OWASP API Security Top 10) |
| **Hidden is not protected** | A route the UI never calls (role change, user create, impersonate, bulk export) still answers, because only the client knew not to call it | Diff `routes.json` against every client's API calls (web bundle, mobile app, generated clients). Each route no client calls needs its own server-side role check - read it |
| **The one unscoped query** | Tenant scoping done by a global scope / middleware, bypassed by raw SQL, `unscoped()`, a service-role client, a background job or an export | List every DB client and raw query; check the tenant predicate on each. Same for cache and storage keys built without user or tenant |
| **Trusted identity header** | The backend takes user / tenant from a header an auth proxy sets (`X-User`, `X-Forwarded-User`) and never checks the request came through the proxy | Find header reads in auth middleware; check whether the backend port is reachable directly (compose / Kubernetes ports) |
| **Weakest door to the same effect** | Role change, payout, export, delete or MFA reset reachable by several paths (UI, API, mobile, batch, import, admin tool) with different controls | For each sensitive effect, list every path that produces it and compare their controls; the weakest is the finding |
| **Revocation that does not reach every copy** | A disabled user or removed member keeps access through API tokens, cached permissions, JWT claims, sockets or queued jobs | Read what the disable / remove-member handlers invalidate, and list what they do not |

## How to hunt (method)

1. **Map trust boundaries first.** Where does untrusted data enter? External requests, webhooks and
   payment callbacks, message queues, inter-service calls, file/CSV imports. Draw the boundary before
   looking for the guard.
2. **For each privileged action, find the server-side control** - and read its body, not just its
   name. A control named `checkAccess` that returns `true` is worse than no control, because it buys
   false confidence.
3. **Follow the data, not the file.** Trace a payment provider's response, a user ID, a cached
   permission across files. Single-file scanners cannot; you can.
4. **Ask "what invalidates this?"** of every cache and every stored derived value. Disagreement between
   two sources of truth is a defect class scanners never see.
5. **Cross the repo boundary for secrets.** A clean env-var read can be sourced from a committed
   credential elsewhere. The audit is over the *system*, not one repo.

## Feeding triage

Design-level findings often have **no scanner behind them** - their `confirmed_by` is "manual review,"
and that is fully valid (`reference/method/triage.md`). Anchor them to a `file:line` and a requirement
(`reference/standards/index.md`) exactly like a scanner finding. A dead security control and a client-only authz gap
carry severity floors - do not let the absence of a scanner hit tempt you to under-rate them.
