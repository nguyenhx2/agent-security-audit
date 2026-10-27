# Module: public-sector - government and local-government systems, and their cloud vendors

Applies when the code serves a government body or a local government, or is a cloud service sold to
one (detect sector `government`: LGWAN, ISMAP, government cloud, JPKI / マイナポータル, `*.lg.jp`,
`gov.vn`), and to operators of critical infrastructure. Versions per `reference/standards/index.md`.

## 1. Which rules apply
| Canonical name | What it is | Version / date | Who it binds |
|---|---|---|---|
| `Japan Government Unified Standards` | 政府機関等のサイバーセキュリティ対策のための統一基準群 (統一規範 / 統一基準 / ガイドライン) | 令和7年度版 (2025-07-01); guideline revisions 2025-09-05 and 2026-06-12 (patch management designed into every system, IT-BCP) | central government bodies; contractors through procurement terms |
| `ISMAP` | 政府情報システムのためのセキュリティ評価制度 (ISMAP, ISMAP-LIU for low-impact SaaS) | operating; a revision of the control standard was in draft in 2025-12 (status unconfirmed) | cloud services sold to government |
| Japan active cyber defence act (サイバー対処能力強化法) | asset notification within 4 months and prompt incident reports (detailed report within 30 days) for designated critical-infrastructure operators | enacted 2025-05; reporting duties reported in force 2026-10-01 (secondary source) | 特別社会基盤事業者 (electricity, gas, water, transport, telecom, broadcasting, finance, card companies and others) |
| `Vietnam Decree 85/2016` + Circular 12/2022/TT-BTTTT | information-system security by level (5 levels) | still listed as in force; its parent law was replaced by Cybersecurity Law 116/2025 on 2026-07-01, no successor decree found - cite with that caveat | Vietnamese state and critical information systems |
| `Vietnam Cybersecurity Law` | Law 116/2025/QH15 | in force 2026-07-01 | services in Vietnam (data localisation and log retention for covered services) |

## 2. Code-evidenced checks
| ID | Check | What to verify | Seen |
|---|---|---|---|
| G01 | MFA for administrators and remote access | IdP / admin-console configuration, VPN / bastion settings in IaC | S+M |
| G02 | Patch management by design (2026-06 guideline revision) | automated dependency and base-image updates, EOL tracking (`intel.md`), a documented emergency patch path (`reference/method/threat-intel.md` patch readiness) | S+M |
| G03 | Approved cryptography | TLS settings and algorithms from the CRYPTREC list; no deprecated protocols | S |
| G04 | Logging | log collection, time synchronisation, retention and protection; for critical-infrastructure operators, enough to file a detailed incident report within 30 days | S+M |
| G05 | Web hygiene | no sensitive data in URLs, input validation, content-tampering protection on public sites | S+M |
| G06 | Cloud configuration | services and regions consistent with ISMAP-registered offerings; Japan-only regions where the contract requires them; customer-managed keys where required | S |
| G07 | Asset inventory | IaC tags or a CMDB export that can list product, model and version per server (the active cyber defence act asks operators to notify these) | S |
| G08 | Vietnam | security level of the system declared and its controls (Decree 85 / Circular 12) reflected in network segmentation, logging and access control; data localisation and log retention for services under Law 116/2025 | M |

## 3. Severity
- **P0:** citizen data (My Number, tax, social security) reachable without authorisation; admin consoles
  on the internet without MFA.
- **P1:** no patch automation or EOL tracking on an internet-facing government system; logs that cannot
  support a 30-day incident report; region or key settings that break the contract.
- **P2:** crypto or TLS settings outside the approved list on internal links.
