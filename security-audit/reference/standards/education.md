# Module: education - schools, universities, learning platforms, children's services

Applies when the code handles student, pupil, guardian, grade, attendance or learning data, or targets
children (detect sector `education`: students, guardians, grades, LTI, OneRoster, Classroom APIs).
Versions per `reference/standards/index.md`.

## 1. Which rules apply
| Canonical name | What it is | Version / date | Who it binds |
|---|---|---|---|
| `MEXT Education Information Security Guidelines` | 教育情報セキュリティポリシーに関するガイドライン (文部科学省) | revised 2025-03 | Japanese boards of education and schools; vendors of school-affairs (校務) and learning (学習) systems through procurement |
| `FERPA` | 20 U.S.C. 1232g; 34 CFR Part 99 | no rule change since 2011 | US schools receiving federal funds, and vendors acting as school officials |
| `COPPA` | 16 CFR Part 312, 2025 amendments | effective 2025-06-23, compliance from 2026-04-22 | online services directed to children under 13 in the US |
Also `Japan APPI` (students' and guardians' personal data; health records are special care-required).

## 2. Code-evidenced checks
| ID | Check | What to verify | Seen |
|---|---|---|---|
| D01 | Zero-trust access (MEXT cloud-first model) | SSO with MFA and conditional / risk-based access for teachers and administrators; access control replaces network separation | S+M |
| D02 | Role separation | teacher, student, guardian and administrator roles enforced server-side; a teacher sees only their classes; a guardian only their own children | M |
| D03 | Data classification carried into access rules | grades, health records and guidance records (重要性分類 I-II) more restricted than learning content; field-level authorisation | M |
| D04 | Encryption | student personal data encrypted at rest and in transit | S |
| D05 | Audit logs | access to grades, health and guidance records logged; FERPA record of disclosures | M |
| D06 | No student data to analytics or AI without a contract | analytics SDKs, LLM calls and ad tags receive no student PII; COPPA: no persistent identifiers to ad or analytics SDKs without parental consent | S+M |
| D07 | Children's consent and retention (COPPA) | verifiable parental consent before collection, separate consent for third-party disclosure, a written retention period enforced by a deletion job, neutral age gate | M |
| D08 | Directory-information opt-out (FERPA) | the opt-out flag is honoured in exports and APIs | M |

## 3. Severity
- **P0:** one student, guardian or teacher can read another class's or child's grades, health or guidance
  records; student data in a public store.
- **P1:** student PII sent to analytics, ad or AI services; no MFA for staff access to school-affairs data;
  COPPA consent missing for a child-directed service.
- **P2:** missing audit trail on grade or health access; retention not enforced.
