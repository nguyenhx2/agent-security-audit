# Module: pci-dss - PCI DSS v4.0.1 requirements a code audit can evidence

Apply when the system touches cardholder data (CHD) or can affect its security (payment pages,
payment SDK integration, card-like columns). Cite `PCI DSS v4.0.1 Req X.Y.Z`. All future-dated
requirements are effective as of 2025-03-31 (best practice until then).
The storage recipe lives in `reference/method/sensitive-data-at-rest.md` - run it first.

## Contents
- Scope reduction - what to determine first
- Requirements evidenced from code / config / IaC
- Transaction integrity (money movement)
- What a static audit cannot evidence

## Scope reduction - determine first
1. **Does card data touch our servers?** Hosted fields / redirect / iframe (Stripe Elements, Adyen
   Drop-in, PAY.JP checkout) keep PAN off the server -> much smaller scope. Server-side PAN handling
   (raw card fields in API requests) -> full scope. Grep request DTOs and forms for card fields.
2. **What does the provider return and what do we persist?** Tokens/`last4`/brand/expiry are fine;
   PAN, CVV, track data are not (see sensitive-data-at-rest).
3. **Payment pages:** which pages load payment forms/iframes? Those pages are in scope for 6.4.3 and
   11.6.1 even when the iframe is the provider's.

## Requirements evidenced from code / config / IaC

| Req | Requirement (summary) | What to verify in source | Severity floor |
|-----|----------------------|--------------------------|----------------|
| 3.2.1 | Keep stored account data to a minimum; retention + secure deletion defined | Retention jobs / TTLs on payment tables; purge paths | P2 if none |
| **3.3.1** (3.3.1.1 track, 3.3.1.2 CVV/CVC, 3.3.1.3 PIN/PIN block) | **SAD not retained after authorization, even encrypted** - cite the sub-requirement for the data element | Columns, JSON blobs, logs, caches, queues, analytics holding CVV/track/PIN | **P0** |
| 3.3.2 / 3.3.3 | SAD stored before completion of authorization is encrypted; issuer exceptions narrow | Pre-auth queues/caches | P1 |
| **3.4.1** | PAN masked when displayed (max BIN + last 4) unless a documented role needs more | Admin UIs, receipts, emails, exports, API responses | P1 |
| 3.4.2 | Remote-access copy/relocation of PAN prevented except where authorized | Export/download features | P2 |
| **3.5.1** | **PAN unreadable wherever stored** (strong crypto with key mgmt, truncation, index tokens, keyed hashes) | Plaintext PAN columns, files, logs, backups; unkeyed hashes are weak (brute-forceable) | **P0** plaintext |
| 3.5.1.1 | Hashes of PAN must be keyed cryptographic hashes (HMAC) of the entire PAN | `sha256(pan)` without key -> finding | P1 |
| 3.6 / 3.7 | Key management: keys protected, least access, rotation, split knowledge where manual | Hard-coded keys, keys beside data, no rotation path, KMS usage | P1 |
| 4.2.1 | Strong cryptography for PAN over open/public networks; certs valid | `verify=False`, HTTP endpoints for payment calls, TLS < 1.2 | P1 |
| 6.2.4 | Software engineering techniques prevent common attacks (injection, XSS, access control, etc.) | Map to owasp-web findings on in-scope code | by finding |
| 6.3.2 | Inventory of bespoke and third-party software components (SBOM-like) | Lockfiles + SBOM generation in CI | P2 |
| 6.3.3 | **Critical** security patches installed within one month of release; others within a risk-based timeframe | Dependency findings on payment components | by finding |
| 6.4.1 / 6.4.2 | Public-facing web apps protected against attacks (6.4.2: automated technical solution, e.g. WAF, that detects and prevents) | WAF / bot-protection config in IaC or edge config in front of payment apps | P2 if absent for public payment apps |
| **6.4.3** | Payment-page scripts: authorized, integrity-assured (SRI/CSP hashes), inventoried with justification | `<script src>` on checkout pages without SRI; tag managers on payment pages; CSP absent | P1 |
| 8.2.x / 8.3.x | Unique IDs, no shared/generic accounts; MFA for CDE access; strong auth | Admin auth, service accounts, shared credentials in config | P1 |
| 8.4.2 | MFA for ALL access into the CDE (not only remote/admin) | Admin consoles and back-office apps that reach card data; SSO/MFA enforcement | P1 |
| 8.3.6 | Passwords >= 12 chars, numeric + alphabetic (where passwords are used) | Password validators | P2 |
| 8.6.2 | Passwords/passphrases for application and system accounts **that can be used for interactive login** not hard-coded in scripts/config/source (for API keys / tokens cite ASVS 5.0.0 V13 + CWE-798 instead) | Gitleaks hits on payment-related secrets | P0 if live provider secret |
| 10.2.x | Audit logs capture access to CHD, admin actions, auth events, log changes | Logging around payment operations | P2 |
| 10.3.x | Audit logs protected from modification | Log sinks, append-only tables | P2 |
| **11.6.1** | Change/tamper detection on payment pages' HTTP headers and script contents (weekly or per TRA) | CSP reporting, script-integrity monitoring, or provider-hosted page | P2 (P1 if scripts are first-party and unmonitored) |
| 12.3.3 | Cryptographic cipher suites/protocols inventoried and reviewed | TLS/cipher config in IaC | Info |

## Transaction integrity (money movement - no single PCI requirement; state the property)
Cite the property + ASVS 5.0.0 V2 (business logic) / V15 (concurrency) when a refund, payout,
wallet or ledger exists:
- **Atomicity:** balance change + ledger entry + provider call outcome in one transaction or a saga
  with compensation. Look for writes split across calls without rollback.
- **Idempotency:** every externally-triggered money operation (webhook, retry, double-click) carries an
  idempotency key enforced by a unique constraint. Look for webhook handlers without dedupe.
- **Race conditions:** read-modify-write of balances without row locks / optimistic versioning
  (`SELECT ... FOR UPDATE`, version columns). Double-spend via concurrent requests is P0/P1.
- **Immutable audit trail:** append-only ledger; no `UPDATE`/`DELETE` on ledger rows.
- **Webhook authenticity:** provider signature verified with the raw body, timestamp tolerance,
  replay protection. Read the verifier body - a no-op verifier is a dead control (P1 floor).

## What a static audit cannot evidence (state in Method-and-limitations)
Network segmentation (Req 1), physical security (9), ASV scans and pen tests (11.3/11.4), policies
and training (12), actual key ceremonies. A code audit supports, never replaces, a QSA assessment.
