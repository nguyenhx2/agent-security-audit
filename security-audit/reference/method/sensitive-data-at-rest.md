# Sensitive data at rest - the dimension everyone forgets

This is the reason this skill exists. A real project had a developer persisting customer payment-card
data straight into the database, unencrypted. Standard SAST never saw it. Every reviewer who read the
controllers and services walked straight past it - because **the defect lives in the schema, not in the
business logic**. Make this a first-class, mandatory phase of every audit that touches payments, PII,
or health data.

Back to the procedure: `SKILL.md` Phase 2. Severity overrides that reference this file:
`reference/method/triage.md`.

## The two PCI DSS classes (their remedies are opposite - teams conflate them)

PCI DSS current version: **v4.0.1** (a limited revision of v4.0; v3.2.1 is retired). Cite requirements
as `PCI DSS v4.0.1 Req X.Y.Z`, never a bare number - see `reference/standards/index.md` on version-scoped IDs.

| Class | Data | Rule | Remedy | The trap |
|-------|------|------|--------|----------|
| **NEVER-STORE** (SAD = sensitive authentication data) | Full magnetic-stripe / track data (track1, track2), card verification value (CVV / CVC / CVC2 / CID), PIN / PIN block | **Req 3.3.1**: MUST NOT be stored after authorization, **even if encrypted**. v4.0.1 has a narrow carve-out only for card *issuers* with a legitimate, documented business need | **Delete** the column; purge logs, caches, backups. Encryption does not redeem it | "We encrypted the CVV" is a **finding, not a mitigation**. This is the rule teams get wrong most, precisely because encrypting *feels* like diligence |
| **MUST-BE-UNREADABLE** | PAN (primary account number) | **Req 3.5.1**: rendered unreadable **wherever stored** - strong cryptography, truncation, tokenization, or (weakly) hashing. Storage needs a documented business justification | Tokenize / encrypt / truncate. Keep only if justified | A **hashed PAN is weak, not good**. Do not congratulate it - see below |

### Why a hashed PAN is weak, not good
The keyspace is small enough to brute-force. A 16-digit PAN with a known BIN (first 6-8 digits) and a
Luhn check constraint leaves far under 10^12 candidates - trivially enumerable offline. Say so in the
finding. A hashed PAN is a MUST-BE-UNREADABLE control that does not actually make the PAN unreadable;
treat it as a weak/insufficient control, never as a pass.

### Adjacent classes to sweep in the same pass
- Passwords stored **reversibly** - recoverable = wrong, regardless of algorithm (encryption is
  reversible; that is the point and the problem). Passwords must be salted-hashed one-way.
- Full PII persisted where a reference (token, foreign key) would do.
- Any of the above appearing in **logs**.
- **LLM / agent surfaces:** conversation and message tables, stored completions, vector stores
  (embeddings of personal data are personal data), eval datasets, fine-tune JSONL, feedback tables,
  tracing exports (LangSmith / Langfuse), and committed prompt / transcript logs
  (`prompt_history*`, `.specstory/`, `.claude/projects/*.jsonl`, Aider history) - in the working
  tree and in git history (`agent-config.md` lists both). View them only with `peek.py`, which masks
  secrets, e-mails, phone numbers and personal-data keys.
- **Committed data files** (`.sqlite`, `.db`, `.xlsx`, `.csv`, dumps, `.har`, `.eml`): the sweep lists
  them by name (`data_files_committed`); judge from the name and size, open only through peek.py.

## Run the sweep first (seconds, locations only)

See SKILL.md Phase 2 for the exact command (`--out <audit_dir>/work/<repo>/sweep.json`; add
`--extra-terms local_col_a,local_col_b` for project-specific column names). It walks migrations -> schema -> persistence calls -> logs -> client stores -> caches -> exports and
classifies hits (SAD never-store, PAN, reversible credentials, secrets at rest, national ID, contact
PII, health, biometric, JP/VN native-script terms). Digit runs are masked; Luhn-valid literals are
reported by location only. It always records what was searched, so a clean result is evidence.
**Hits are leads** - the steps below are how you confirm them by reading.

## Detection recipe - order matters (cheapest, highest-signal first)

1. **Migrations - all of them.** Column names are the evidence, and this is the single cheapest sweep
   available. Do not skip old migrations: a column dropped later still tells you what the design once
   persisted, and the data may survive in backups.
2. **Entity / model / schema definitions**, including JSON / JSONB columns. A JSON blob hides a card
   object that no column name reveals - so inspect what is *written into* it, not just its declared
   type. `metadata jsonb` tells you nothing; the code that builds the object does.
3. **What gets persisted from a payment provider's response.** `save(response)` is how card data lands
   in a table nobody designed for it: the gateway response body routinely carries more than the app
   needs. Trace the provider client's return value to every `.save()` / `INSERT` / `create()`.
4. **The spill surfaces** - where sensitive data leaks out of the primary store:
   logs, caches (in-memory and shared, e.g. Redis), analytics / event pipelines, CSV / Excel export
   paths, materialized views, database backups, and outbound payloads to third-party APIs.
5. **Client-side stores** - mobile preference files / keystores, browser `localStorage` /
   `sessionStorage` / IndexedDB.

## Grep vocabulary (case-insensitive; add local-language variants)

```
cvv  cvc  cvc2  cid  card_number  cardnumber  card_no  pan  credit_card  creditcard
track  track1  track2  pin_block  expiry  exp_month  exp_year  card_holder  cardholder
security_code
```

Run these over migrations and schema first, then over the model/serializer/logging code. Add the
project's local-language equivalents (e.g. translated column names). A hit is a lead, not a verdict -
confirm by reading what the column actually stores.

## Reporting rules (non-negotiable)

- **Never print a card number** - not a real one, not a test value, not truncated. Report the **column
  name** and **`file:line`**. The evidence is the location and the column, not the data.
- **A negative result is a real result.** Record "searched <files/globs> with <patterns> on
  <date>, found nothing" as an audit finding. A silent absence is not a result - a future reader
  cannot tell "checked and clean" from "never looked".
- Every audit report carries a **Sensitive data at rest** section whether or not anything was found -
  see `templates/audit-report.md.template`.

## Severity (see `reference/method/triage.md` for the full model)

- SAD (CVV/track/PIN) stored after authorization -> **P0, even if encrypted**.
- Plaintext PAN at rest -> **P0**.
- Hashed PAN -> weak control; severity by exposure and justification, never a pass.
- Reversibly-stored passwords -> P1 (P0 when the store is reachable by an attacker or the key sits beside it).

## Neutral illustration (structure only - no real data)

A payment table declares `card_number varchar` and `cvv varchar`, both written directly from a gateway
response in `{{path/to/payment.service}}:{{line}}`. Two findings, distinct classes:
- `cvv` column -> NEVER-STORE violation (PCI DSS v4.0.1 Req 3.3.1), P0. Remedy: drop column, purge
  logs/caches/backups. Do not accept "encrypt it".
- `card_number` column -> MUST-BE-UNREADABLE (PCI DSS v4.0.1 Req 3.5.1), P0 if plaintext. Remedy:
  tokenize or remove; justify any retention.
