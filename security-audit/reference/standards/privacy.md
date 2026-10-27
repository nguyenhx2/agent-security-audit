# Module: privacy - data-protection and sector law, evidenced from code

Apply when the system stores personal, account, health, biometric, or children's data. Pick the
governing jurisdiction(s) in the scoping question (Phase 0) - never assume one. A code audit
evidences *technical* obligations only; legal basis, contracts, and DPIAs are out of static scope
(say so). Cite `<law> <article>` with the law's official identifier, e.g. `GDPR Art. 32`,
`Vietnam PDPL 91/2025/QH15 Art. <n>` - when unsure of the exact article, cite the obligation and the
law without an article number rather than guess.

## Contents
- Laws in force (verified 2026-10-26)
- Technical obligations to check in code
- Jurisdiction notes
- Severity guidance

## Laws in force (verified 2026-10-26)

| Jurisdiction | Instrument | Status / key dates |
|--------------|-----------|--------------------|
| EU / EEA | GDPR (Reg. 2016/679) | In force; Digital Omnibus amendments in legislative process (not law) |
| EU | NIS2 (Dir. 2022/2555) | Transposition mostly done; applies to essential/important entities |
| EU | DORA (Reg. 2022/2554) | Applies since 2025-01-17 to financial entities and ICT providers |
| EU | Cyber Resilience Act (Reg. 2024/2847) | Vulnerability/incident reporting (Art. 14) since 2026-09-11; full application 2027-12-11 - products with digital elements need SBOM + vuln handling |
| EU | AI Act (Reg. 2024/1689, amended 2026/1744) | GPAI duties since 2025-08-02; high-risk Annex III from 2027-12-02, Annex I from 2028-08-02 |
| UK | UK GDPR + DPA 2018 (as amended by DUAA 2025) | In force |
| Japan | APPI | 2026 amendment (Act No. 56 of 2026) promulgated 2026-07-17: penalty provisions from 2027-01-17, main reforms (administrative fines, children's and biometric data) by Cabinet Order no later than 2028-07-17 - cite current text, note pending changes |
| Vietnam | Personal Data Protection Law 91/2025/QH15 + Decree 356/2025/ND-CP | Effective 2026-01-01; replaces Decree 13/2023; fines up to 5% of prior-year revenue for cross-border transfer violations |
| Vietnam | Decree 330/2026/ND-CP (sanctions for cybersecurity and personal-data violations) | Effective 2026-08-19 (secondary source - verify before citing article numbers) |
| Vietnam (state / critical systems) | Decree 85/2016/ND-CP + Circular 12/2022/TT-BTTTT + TCVN 11930:2017 (information-system security levels) | In force per secondary sources; status after Cybersecurity Law 116/2025 UNVERIFIED - cite only for government / critical-infrastructure systems |
| Vietnam | Cybersecurity Law 116/2025/QH15 | Effective 2026-07-01 (replaces 2018 Cybersecurity Law + 2015 Network Information Security Law) - data localisation/log retention duties for covered services |
| US - California | CCPA/CPRA + CPPA regulations | Risk assessments from 2026-01-01; ADMT rules 2027-01-01; cybersecurity audit certifications phase in 2028-2030 by revenue |
| US - health | HIPAA Security Rule (45 CFR 164 Subpart C) | Current rule in force; 2025 overhaul still a proposed rule (final targeted 2027) - do not cite NPRM text as law |
| Other | PIPL (China), LGPD (Brazil), PDPA (Singapore/Thailand), PIPA (Korea), DPDP Act (India) | Identify per audit; verify status before citing |

## Technical obligations to check in code

| Obligation | What to verify | Where / grep hints |
|-----------|----------------|--------------------|
| Security of processing (GDPR Art. 32, APPI security control measures, PDPL protection measures, HIPAA 164.312) | Encryption at rest/in transit for personal data; access control; audit logs | `reference/method/sensitive-data-at-rest.md`, owasp-web A01/A04 |
| Data minimisation / purpose limitation | Only needed fields collected/stored; full records not copied where an ID would do; analytics payloads minimal | DTOs, analytics `track(` payloads, logs |
| Storage limitation / retention | TTLs, retention jobs, purge of soft-deleted rows, backups policy | `deleted_at` without purge, no retention job |
| Erasure / account deletion (GDPR Art. 17, CCPA delete, PDPL deletion right) | "Delete account" removes or anonymises PII across all tables, caches, search indexes, object storage, third parties (payment provider customer, CRM, analytics) | delete-account handler: follow every FK and side store |
| Access / portability (DSAR) | Export path exists and covers all stores; authz on export (only own data) | export endpoints |
| Consent | Tracking/analytics/marketing SDKs initialised only after consent; consent recorded with timestamp/version | SDK init order, cookie banners, mobile ATT |
| Special categories / sensitive data (health, biometric, children, national ID, APPI "special care-required", PDPL "sensitive personal data") | Extra protection (encryption, access logging, separate store); lawful basis flagged | `sensitive_sweep.py` classes health-PHI, biometric, national-id-PII |
| Cross-border transfer (PDPL, PIPL, APPI, GDPR Ch. V) | Where data is sent: third-party APIs, cloud regions, LLM providers; transfer recorded | outbound SDKs, region config, LLM calls with PII in prompts |
| Breach detection and notification support (GDPR 72h, PDPL 72h, APPI Art. 26 prompt + 30/60 days, CRA Art. 14 24h early warning) | Security event logging sufficient to detect and scope a breach | owasp-web A09 |
| Children's data | Age gating / parental consent paths where the product targets minors | signup flows |

## Jurisdiction notes
- **Vietnam PDPL:** sensitive personal data includes health, biometric, financial/bank account,
  location, criminal records, among others - treat stored bank/card data as sensitive even outside PCI.
- **Japan APPI** (articles as numbered since the 2022 enforcement; the 2026 amendment, Act No. 56 of
  2026, does not renumber them):
  - Art. 20(2): acquiring special care-required personal information (要配慮個人情報: medical history,
    health-check results, disability, race, creed, criminal record) needs the person's prior consent -
    check the consent step exists before such fields are stored.
  - Art. 23: security control measures (安全管理措置) - the article to cite for encryption, access
    control and logging of personal data. Art. 24-25: supervision of employees and contractors.
  - Art. 26: report leaks to the PPC and notify the person. Enforcement Rules Art. 8(1): prompt first
    report (the PPC general guideline 3-5-3-3 says "roughly 3-5 days" - cite the guideline for that
    figure, not the Rules); Art. 8(2): final report within 30 days, 60 days where an unauthorised
    purpose is suspected. In code: can a breach be detected and its scope (whose data) determined
    from the logs (`owasp-web.md` A09)?
  - Art. 27: third-party provision; Art. 28: transfer to a third party in a foreign country - LLM
    providers, analytics and overseas cloud regions receiving personal data.
  - Medical and health data: the sector guidelines in `reference/standards/medical.md` apply on top.
- **Japan My Number Act** (canonical name `Japan My Number Act`): the individual number may be held only
  for the purposes the Act permits (social security, tax, disaster response); flag any `my_number` /
  `kojin_bango` column, log line or API field outside an HR / payroll / tax system as a finding, and
  check that it is encrypted and access-logged where it is permitted.
- **Japan Telecommunications Business Act, external transmission rule** (外部送信規律, in force
  2023-06-16): sites and apps that send user information to third parties through tags or SDKs
  (analytics, ads, chat widgets) must publish or notify what is sent, to whom and why. In code: list
  third-party tags / SDKs and check a disclosure page or consent step references them.
- **HIPAA:** applies to covered entities and business associates; PHI at rest encryption is an
  "addressable" spec in the current rule, but its absence must be justified - treat as P1.

## Severity guidance
- Special-category or national-ID data stored plaintext and reachable -> P0/P1.
- Account deletion leaving PII live in primary stores -> P1; only in backups with a documented
  rotation -> P2.
- Missing consent gating for tracking SDKs -> P2 (P1 for children's products).
