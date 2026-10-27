# Standards baseline - versions, applicability, citation

Back to procedure: `SKILL.md` Phase 0. Per-module requirement detail lives in `standards/*.md`
(each linked from SKILL.md's module table).

## Contents
- Citation rule
- Baseline table (verified 2026-10-26)
- Which modules apply (derive from what the system IS)
- The coverage reflex - ask what is NOT in the table
- Re-verification procedure
- Old patterns (superseded versions)

## Citation rule

A finding cites `standard + version + requirement ID`, never a bare ID. IDs are version-scoped:
OWASP Top 10 `A03` meant *Injection* in 2021 and means *Software Supply Chain Failures* in 2025.
A bare "A03" is ambiguous today and wrong tomorrow.

Finding frontmatter splits this into `standard` (canonical name, below), `standard_version`, and
`requirement_id`; the validator warns on non-canonical names. Canonical names: OWASP Top 10, OWASP
ASVS, OWASP API Security Top 10, OWASP Top 10 for LLM Applications, OWASP Top 10 for Agentic
Applications, OWASP MCP Top 10, OWASP AISVS, OWASP MASVS, OWASP MASTG, OWASP Mobile Top 10, OWASP
Kubernetes Top 10, OWASP Non-Human Identities Top 10, OWASP Top 10 CI/CD Security Risks, PCI DSS, CIS AWS Foundations, CIS Azure
Foundations, CIS GCP Foundations, CIS Kubernetes, CIS Docker, SLSA, NIST SSDF SP 800-218, NIST SP
800-63-4, CWE, GDPR, UK GDPR, Japan APPI, Japan My Number Act, IPA How to Secure Your Web Site, MHLW Medical Information Security Guidelines, MIC/METI Medical Service Provider Guidelines, FISC Security Guidelines, Vietnam PDPL, Vietnam Cybersecurity Law, CCPA, HIPAA, EU CRA,
EU AI Act, NIS2, DORA. Unverified edition: `standard_version: 2022 (UNVERIFIED)`. CWE is never the
primary `standard` - it goes in `cwe:`; every `also_maps_to` entry carries a version.

Format: `OWASP ASVS 5.0.0 V8.2.1`, `OWASP Top 10:2025 A01`, `PCI DSS v4.0.1 Req 3.3.1`,
`OWASP API Security Top 10 2023 API1`, `OWASP Top 10 for Agentic Applications 2026 ASI02`, `OWASP Top 10 for LLM Applications 2026 LLM01`,
`CIS AWS Foundations v7.1.0 2.1.1`, `CWE-89`. Add a CWE whenever one fits - it is the most stable
cross-reference and what scanners emit.

## Baseline table

`verified: 2026-10-26` (web-verified against issuing bodies; every row re-checked on that date). This is the skill's shipped baseline.
**Phase 0 rule:** if today is more than 90 days past this date, re-verify the rows in scope before
citing (procedure below) and stamp the report with the new date. Within 90 days, cite as-is and
copy this date into the report. Anything not confirmable is cited with `(UNVERIFIED)`.

| Standard | Version | Released | Module file |
|----------|---------|----------|-------------|
| OWASP Top 10 (web) | **2025** (A01-A10 re-ordered; A03 Supply Chain, A10 Exceptional Conditions are new) | final: RC 2025-11-06, RC label removed 2025-12-24 (OWASP/Top10 repository) | `reference/standards/owasp-web.md` |
| OWASP ASVS | **5.0.0** (V1-V17) | 2025-05-30 | `reference/standards/owasp-web.md` |
| CWE Top 25 | **2025** | 2025-12 | `reference/standards/owasp-web.md` |
| OWASP API Security Top 10 | **2023** (no newer edition) | 2023 | `reference/standards/owasp-api.md` |
| PCI DSS | **v4.0.1** (future-dated reqs effective 2025-03-31; PCI SSC request for comments 2026-06/07 signals the next revision - re-check before citing) | 2024-06 | `reference/standards/pci-dss.md` |
| OWASP Top 10 for LLM Applications | **2026** (IDs renumbered vs 2025) | 2026-08-03 (announced 2026-09-01) | `reference/standards/ai-llm-agentic.md` |
| OWASP Top 10 for Agentic Applications | **2026** (ASI01-ASI10) | 2025-12-09 | `reference/standards/ai-llm-agentic.md` |
| OWASP MCP Top 10 | **beta** (living document; cite `(beta)`; official IDs are written `MCPxx:2025`) | 2025-2026 | `reference/standards/ai-llm-agentic.md` |
| OWASP AISVS | **1.01** (213 requirements, 12 chapters; Appendix C = AI-assisted secure coding, AC.8.x separation of duties) | 2026-10-16 (GitHub release, with 1.0) | `reference/standards/ai-llm-agentic.md` |
| OWASP MASVS / MASTG / MASWE | **2.1.0** / **2.0.0** / **1.0.0** | 2024-01-18 / 2026-06-30 / 2026-08-17 | `reference/standards/mobile.md` |
| OWASP Mobile Top 10 | **2024** | 2024 | `reference/standards/mobile.md` |
| CIS AWS / Azure / GCP Foundations | **v7.1.0** / **v6.0.0** / **v5.0.0** | 2026 | `reference/standards/cloud-iac.md` |
| CIS Kubernetes | **v2.1.0** (CIS-CAT lists 2.0.1); EKS/AKS/GKE **v2.0.0** | - | `reference/standards/cloud-iac.md` |
| CIS Docker | **v1.9.0** | - | `reference/standards/cloud-iac.md` |
| OWASP Kubernetes Top 10 | **2025** | 2025 | `reference/standards/cloud-iac.md` |
| OWASP Top 10 CI/CD Security Risks | single edition (CICD-SEC-1..10) | 2022-11 | `reference/standards/supply-chain.md` |
| SLSA | **v1.2** (adds Source Track) | 2025-11 | `reference/standards/supply-chain.md` |
| OWASP Non-Human Identities Top 10 | **2025** (NHI1-NHI10) | 2025 | `reference/standards/supply-chain.md` |
| NIST SSDF SP 800-218 | **v1.1** final (Rev 1 / v1.2 = initial public draft 2025-12-17, not final) | 2022-02 | `reference/standards/supply-chain.md` |
| NIST SP 800-63-4 | **final** (digital identity / authenticators) | 2025-07-31 | `reference/standards/owasp-web.md` |
| NIST SP 800-53 Rev 5 | **5.2.0** | 2025-08-27 | cite only if the client requires it |
| ISO/IEC 27001 | **2022 + Amd 1:2024** | 2024-02 | cite only if the client requires it |
| IPA How to Secure Your Web Site (安全なウェブサイトの作り方) | **7th** (revised 7th edition, 4th printing) | 2021-03-31 | `reference/standards/owasp-web.md` Part E |
| MHLW Medical Information Security Guidelines (医療情報システムの安全管理に関するガイドライン) | **7.0** (5 parts, 保守委託機関編 new) | 2026-06-29 (notice 産情発0629第1号) | `reference/standards/medical.md` |
| MIC/METI Medical Service Provider Guidelines (医療情報を取り扱う情報システム・サービスの提供事業者における安全管理ガイドライン) | **2.0** | 2025-03-28 | `reference/standards/medical.md` |
| FISC Security Guidelines (金融機関等コンピュータシステムの安全対策基準・解説書) | **14th** (令和8年3月版; parts 統制基準 / 実務基準 / 設備基準 / 監査基準) | 2026-03 (day from a secondary source; fisc.or.jp unreachable on 2026-10-26 - item numbers UNVERIFIED, cite the part) | `reference/standards/finance.md` |
| Japan APPI | current text (articles numbered since 2022); amendment Act No. 56 of 2026 promulgated 2026-07-17, penalties +6 months, rest by Cabinet Order (by 2028-07) | 2026-07-17 | `reference/standards/privacy.md` |
| Japan Credit Card Security Guidelines (クレジットカード・セキュリティガイドライン) | **6.1** (6.0 = substantive revision 2025-03-04) | 2026-03-11 | `reference/standards/ecommerce.md` |
| FSA Cybersecurity Guidelines (金融分野におけるサイバーセキュリティに関するガイドライン) | **2024** (technical amendment 2025-07-04) | 2024-10-04 | `reference/standards/finance.md` |
| Japan Government Unified Standards (政府機関等のサイバーセキュリティ対策のための統一基準群) | **令和7年度版** (guideline revisions 2025-09-05, 2026-06-12) | 2025-07-01 | `reference/standards/public-sector.md` |
| ISMAP / ISMAP-LIU | operating (control-standard revision drafted 2025-12, UNVERIFIED final) | - | `reference/standards/public-sector.md` |
| Japan Active Cyber Defense Act (サイバー対処能力強化法) | enacted 2025-05; asset notification and incident reporting from 2026-10-01 (secondary source) | 2025-05-16 | `reference/standards/public-sector.md` |
| MEXT Education Information Security Guidelines (教育情報セキュリティポリシーに関するガイドライン) | revised **2025-03** | 2025-03-25 | `reference/standards/education.md` |
| JC-STAR (IoT labelling, IPA) | ★1 since 2025-03-25; ★3 requirements 2026-06-12 | 2025-03-25 | `reference/standards/iot-ot.md` |
| Japan Telecommunications Business Act, external transmission rule (外部送信規律) | in force | 2023-06-16 | `reference/standards/privacy.md` |
| Japan My Number guideline (特定個人情報の適正な取扱いに関するガイドライン, 事業者編) | amended 令和7年6月 | 2025-06 | `reference/standards/privacy.md` |
| ETSI EN 303 645 | **V3.1.3** | 2024-09 | `reference/standards/iot-ot.md` |
| IEC 62443-3-3 / 4-1 / 4-2 | **Ed.1** (2013 / 2018 / 2019; Ed.2 of 4-1 and 4-2 expected late 2026 to 2027) | - | `reference/standards/iot-ot.md` |
| UN R155 / UN R156 | R155 original series + supplements; R156 01 series | mandatory for new vehicles (EU, Japan) since 2024-07 | `reference/standards/iot-ot.md` |
| FERPA / COPPA | 34 CFR 99 (2011) / 16 CFR 312 amended 2025, compliance 2026-04-22 | - | `reference/standards/education.md` |
| GLBA Safeguards Rule / NYDFS 23 NYCRR 500 | 2023 amendment (FTC notice since 2024-05-13) / final phase 2025-11-01 | - | `reference/standards/finance.md` |
| Vietnam Circular 09/2020/TT-NHNN + 50/2024/TT-NHNN | in force (50/2024 from 2025-01-01) | - | `reference/standards/finance.md` |
| Vietnam E-commerce Law 122/2025/QH15 + Decree 248/2026/ND-CP | in force | 2026-07-01 | `reference/standards/ecommerce.md` |
| Vietnam Decree 85/2016/ND-CP | listed as in force; parent law replaced 2026-07-01, no successor found (cite with caveat) | 2016 | `reference/standards/public-sector.md` |
| METI Cybersecurity Management Guidelines | **3.0** (SCS evaluation scheme ★3/★4 targeted around end of FY2026, not yet started) | 2023-03-24 | context only (organisational) |
| Privacy / sector law | jurisdiction-specific | see module | `reference/standards/privacy.md` |

## Which modules apply

`scripts/detect_stack.py` emits `standards_modules` from the repo fingerprint. Confirm with the user
in the scoping question; never silently drop a module the fingerprint selected.

| System has... | Module(s) mandatory |
|---------------|---------------------|
| Any application code | `owasp-web` (Top 10:2025 + ASVS 5.0.0 + CWE) |
| HTTP routes / API surface | + `owasp-api` |
| Card payments, a payment SDK, or card-like columns | + `pci-dss` + `reference/method/sensitive-data-at-rest.md` |
| Personal, account, health, or biometric data | + `privacy` (pick jurisdiction) |
| LLM calls, RAG, agents, MCP servers/clients | + `ai-llm-agentic` |
| Android / iOS / Flutter / React Native | + `mobile` |
| Terraform / CFN / CDK / K8s / Helm / Dockerfile | + `cloud-iac` |
| CI pipelines, lockfiles, build/release automation | + `supply-chain` |
| Money movement (refunds, ledgers, wallets, payouts) | transaction-integrity properties in `pci-dss` module (atomicity, idempotency, audit trail) |
| Industry sector (detect `sectors`, or the user says so) | + the sector module: `medical` (health / patient), `finance` (banking, payments operators, securities, crypto assets), `ecommerce` (shops, marketplaces), `public-sector` (government, local government, critical infrastructure), `education` (schools, learning platforms, children), `iot-ot` (devices, industrial control, vehicles) |
| Japanese client or report language ja | cite `IPA How to Secure Your Web Site` next to OWASP (`owasp-web` Part E); `Japan APPI` first in `privacy` |
| Supplier to a large Japanese company (user context, not code) | note the METI SCS evaluation scheme (★3 / ★4 around end of FY2026) and map its items to the baseline checks; not a separate module |

## The coverage reflex - ask what is NOT in the table

A defect class with no standard in scope is a class nobody looks at. Real misses from first passes
that lacked a row: unencrypted card data at rest (no PCI row); two divergent deploy pipelines and
long-lived CI credentials (no CICD-SEC/SLSA row); "delete my account" leaving PII live (no privacy
row); non-atomic refunds without idempotency keys (no transaction-integrity row).

Before Phase 1: list what the system *is* (takes payments? stores PII? deploys via pipeline? calls an
LLM? moves money? has a mobile client? an admin console?) and diff against the modules in scope.
Then cross-check with `reference/method/coverage-checklist.md` for classes that fall between standards.

## Re-verification procedure

1. For each in-scope standard: WebSearch `"<standard>" latest version`; confirm on the issuer's site
   (owasp.org, genai.owasp.org, pcisecuritystandards.org, cisecurity.org, csrc.nist.gov, slsa.dev,
   cwe.mitre.org, official law gazettes).
2. Record version + release date + source URL in the report's Method section.
3. Unconfirmable -> `(UNVERIFIED)`; do not cite specific IDs from it as authoritative.
4. If a version changed: update this table AND the module file, bump the skill's `z` version (`y` if a module is added or removed - see `CHANGELOG.md` Versioning rules), and
   add a CHANGELOG entry (see `CHANGELOG.md`).

## Old patterns

<details>
<summary>Superseded versions - recognise them in old reports, never cite them for new findings</summary>

- OWASP Top 10 **2021**: A01 Broken Access Control, A02 Cryptographic Failures, A03 Injection,
  A04 Insecure Design, A05 Security Misconfiguration, A06 Vulnerable and Outdated Components,
  A07 Identification and Authentication Failures, A08 Software and Data Integrity Failures,
  A09 Security Logging and Monitoring Failures, A10 SSRF. Mapping to 2025: 2021-A03 -> 2025-A05;
  2021-A02 -> 2025-A04; 2021-A05 -> 2025-A02; 2021-A06 -> 2025-A03 (widened); 2021-A10 SSRF -> 2025-A01.
- OWASP ASVS **4.0.3**: chapter numbers differ from 5.0.0 (e.g. 4.0.3 V4 = Access Control; 5.0.0 V8 =
  Authorization). Re-map, never copy IDs across.
- PCI DSS **v3.2.1**: retired 2024-03-31. v4.0 retired 2024-12-31 in favour of v4.0.1.
- CIS AWS Foundations v1.x-v6.x; SLSA v0.1 / v1.0 / v1.1.
- OWASP Top 10 for LLM Applications **2025** (LLM01 Prompt Injection, LLM02 Sensitive Information
  Disclosure, LLM03 Supply Chain, LLM04 Data and Model Poisoning, LLM05 Improper Output Handling, LLM06
  Excessive Agency, LLM07 System Prompt Leakage, LLM08 Vector and Embedding Weaknesses, LLM09
  Misinformation, LLM10 Unbounded Consumption) - superseded by 2026; IDs moved.
- OWASP AISVS 1.0 (superseded by 1.01).
- Vietnam Decree 13/2023/ND-CP: replaced by Decree 356/2025/ND-CP under PDPL 91/2025/QH15 (2026-01-01).
</details>
