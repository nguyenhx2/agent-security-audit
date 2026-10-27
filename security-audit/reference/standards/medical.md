# Module: medical - health and patient data (Japan medical-information guidelines, HIPAA pointers)

Applies when the system stores or processes patient, clinical, health-check, questionnaire, symptom,
medication or other health data (detect flag `health`). Health data is "special care-required personal
information" under the Japan APPI and sensitive personal data under GDPR / Vietnam PDPL; this module
adds the sector rules on top of `reference/standards/privacy.md`. Versions per
`reference/standards/index.md`.

## Contents
1. The guideline set ("3 ministries, 2 guidelines")
2. Code-evidenced checks M01-M07
3. Severity
4. Citation format
5. Outside Japan

## 1. The guideline set ("3 ministries, 2 guidelines")
Japan regulates medical information systems through two complementary guidelines, together called
3省2ガイドライン:

| Canonical name (cite this) | Japanese title | Issuer | Version | Applies to |
|---|---|---|---|---|
| `MHLW Medical Information Security Guidelines` | 医療情報システムの安全管理に関するガイドライン | Ministry of Health, Labour and Welfare | **7.0** | medical institutions and the systems they use. Five parts: 概説編, 経営管理編, 企画管理編, システム運用編, 保守委託機関編 (new in 7.0) |
| `MIC/METI Medical Service Provider Guidelines` | 医療情報を取り扱う情報システム・サービスの提供事業者における安全管理ガイドライン | Ministry of Internal Affairs and Communications + Ministry of Economy, Trade and Industry | **2.0** | vendors that build or operate systems handling medical information for institutions: SaaS, cloud, API providers, contract developers |

A vendor building a patient app or API for a clinic is bound by the MIC/METI guidelines directly and
must enable the institution to meet the MHLW guidelines, so findings usually cite both.
Neither guideline maps one-to-one to code: cite them for the obligation and pair each with the
verifiable control (`OWASP ASVS 5.0.0`, `OWASP API Security Top 10 2023`, `Japan APPI`).

## 2. Code-evidenced checks
| ID | Requirement | What to verify in code | Where / grep hints | Seen |
|---|---|---|---|---|
| M01 | Separation between institutions (multi-tenant) | Every query on patient-owned or facility-owned rows filters by the facility / tenant the caller is authorised for; no record reachable by a sequential or guessable id across facilities; linking a patient to a facility needs a second factor (facility approval, a one-time link code), not an id alone | facility / tenant id columns, joins, repository methods, link / invite endpoints, `routes.md` | M |
| M02 | Patient data only to that patient (BOLA) | The patient id comes from the verified session or token, never from a path, query or body parameter; update and delete on diaries, questionnaires and results check ownership | `get_current_patient`-style dependencies, path params named `patient_id`, admin vs patient routes | M |
| M03 | Authenticity, readability, preservation (真正性・見読性・保存性) | Who created and changed a clinical record and when is recorded and cannot be rewritten by the client; logical deletes keep history; scores and results are computed server-side, not accepted from the client | `created_by`, `updated_at`, soft-delete flags, history / audit tables, score calculation | M |
| M04 | Encryption in transit and at rest | TLS for every hop that carries health data; storage encryption on databases, object storage, backups; field-level encryption or tokenisation where the threat model needs it; no keys in code | DB / bucket IaC, ORM encrypted types, KMS config, connection strings | S+M |
| M05 | No health data in logs, errors or analytics | Logs, exception messages, SQL logs, APM traces and analytics events never carry names, birth dates, messaging-app user ids, questionnaire answers or diary text; error responses expose no internals | logger calls with request bodies or models, exception handlers, SQL echo settings, analytics `track(` payloads | S+M |
| M06 | Integrity with external systems | Notifications and calls to external medical systems happen after the database commit (or through an outbox), with timeouts and retries that cannot double-send or leave half-written state | transaction boundaries, `commit()` order, HTTP client timeouts, webhook senders | M |
| M07 | Access audit trail | Who viewed, changed or exported which patient's record, when and from where, is logged and protected; bulk reads and exports by staff or operators are detectable | access-log middleware, audit tables, export handlers, log retention (`reference/method/threat-intel.md` detection checks) | M |

Guideline items to cite (verified against the published texts on 2026-10-26; "-" = cite the part and
topic only, no single item covers it):

| Check | MHLW 7.0 システム運用編 | MIC/METI 2.0 |
|---|---|---|
| M01 | 14.2 access rights management | 5.1.5 risk treatment design; 別紙2 control items |
| M02 | 14.1.1 user identification and authentication; 14.2 | 5.1.5; 別紙2 |
| M03 | - (真正性・見読性・保存性 requirements) | 別紙2 |
| M04 | 13.3 encryption; 13.1-13.2 networks; 7.2 external access | 別紙2 |
| M05 | - | 別紙2 |
| M06 | - | 5.1.4 choosing the risk response |
| M07 | 17.1 review of audit trails (証跡) | 別紙2 |
| Backups | 12.2 backup | 別紙2 |

Also check the operator side the guidelines emphasise: least-privilege admin roles, MFA for remote
and administrative access, a maintenance-vendor access path that is logged and time-limited
(保守委託機関編), backups that ransomware cannot reach, and a documented incident contact.

## 3. Severity
- **P0:** any unauthenticated user, or any patient, can read or change another patient's or another
  facility's medical data (M01 / M02); health data in a publicly reachable store.
- **P1:** patient scoping relies on a client-supplied id behind authentication; health data
  routinely written to logs or third-party analytics; linking to a facility by id alone; no access
  audit trail for clinical records.
- **P2:** missing timeouts or commit ordering on external medical calls; inconsistent soft-delete or
  history handling; a development auth bypass that a configuration mistake could enable in production.

## 4. Citation format
Cite the item numbers in the table above; for anything else cite part + topic. Numbering changed
between versions, so never reuse an item number from 6.0 for 7.0.

```
standard: MHLW Medical Information Security Guidelines
standard_version: 7.0
requirement_id: システム運用編 14.2
also_maps_to: "MIC/METI Medical Service Provider Guidelines 2.0; OWASP API Security Top 10 2023 API1; Japan APPI Art. 23"
```
APPI articles used here: Art. 20(2) consent to acquire special care-required information, Art. 23
security control measures, Art. 26 breach reports to the PPC and the individual
(`reference/standards/privacy.md`).

## 5. Outside Japan
- US: HIPAA Security Rule (45 CFR 164.312 technical safeguards) for covered entities and business
  associates - `reference/standards/privacy.md`.
- EU / UK: GDPR Art. 9 special category data + Art. 32 security of processing.
- Vietnam: PDPL sensitive personal data (health).
The M01-M07 checks apply everywhere; only the citation changes.
