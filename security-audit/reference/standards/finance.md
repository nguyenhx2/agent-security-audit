# Module: finance - banking, payments operators, securities, crypto assets

Applies when the code moves or records money or financial positions (detect sectors `finance` /
`crypto`: bank accounts, transfers, ledgers, wallets, Zengin formats, open-banking APIs, crypto
libraries). Card data itself is `reference/standards/pci-dss.md`; this module adds the financial-sector
rules on top. Versions per `reference/standards/index.md`.

## Contents
1. Which rules apply
2. Code-evidenced checks F01-F10
3. Crypto-asset custody C01-C06
4. Severity
5. Citation notes

## 1. Which rules apply
| Canonical name | What it is | Version / date | Who it binds |
|---|---|---|---|
| `FISC Security Guidelines` | 金融機関等コンピュータシステムの安全対策基準・解説書 (FISC) | 14th, 2026-03 | Japanese banks, securities, insurers and their system vendors (de facto; referenced by FSA inspections). Parts: 統制基準 / 実務基準 / 設備基準 / 監査基準. The text is paid: cite edition + part, never quote it. 14th adds AI use and post-quantum cryptography readiness |
| `FSA Cybersecurity Guidelines` | 金融分野におけるサイバーセキュリティに関するガイドライン (FSA, 別紙18) | 2024-10-04, technical amendment 2025-07-04 | all FSA-supervised institutions. Items are 基本的な対応事項 (baseline) or 対応が望ましい事項 (desirable) |
| FSA 事務ガイドライン 16 + JVCEA rules | crypto-asset exchange custody and system governance | JVCEA system-governance rules in force 2026-07-01; crypto moves under the FIEA (amendment enacted 2026-07-15, in force within a year) | Japanese crypto-asset exchanges |
| `GLBA Safeguards Rule` | 16 CFR 314 (FTC) | 2023 amendment; FTC notice within 30 days for 500+ consumers since 2024-05-13 | US non-bank financial institutions |
| `NYDFS 23 NYCRR 500` | NY DFS cybersecurity regulation, second amendment | final phase 2025-11-01 (MFA for all users, asset inventory) | NY-licensed financial services |
| `Vietnam Circular 09/2020/TT-NHNN` + `Vietnam Circular 50/2024/TT-NHNN` | banking IT security; online-banking service security | 09/2020 in force (partly amended); 50/2024 from 2025-01-01 | Vietnamese banks and their apps |
Also: `PCI DSS` for card data, `Japan APPI` / My Number for customer data, DORA (EU) for EU entities.

## 2. Code-evidenced checks
| ID | Check | What to verify | FSA guideline item | Seen |
|---|---|---|---|---|
| F01 | Ledger integrity | balances change only through append-only journal entries; no direct `UPDATE balance` or `DELETE` on ledger tables; reconciliation job exists | 2.3.3 | M |
| F02 | Idempotency and atomicity | transfers, withdrawals and payouts take an idempotency key, run in one transaction with row locks or versioning, and cannot double-execute on retry | - | M |
| F03 | Privileged access and separation of duties | admin / operator actions need a second approver (maker-checker) for money movement and limit changes; no shared admin accounts; production data not reachable from developer roles | 2.3.1 | M |
| F04 | Authentication | MFA or risk-based authentication for customers by transaction value; MFA for all privileged and remote access; no default passwords; credentials embedded in APIs managed and rotated | 2.3.1 | S+M |
| F05 | Cryptography | data encrypted by classification with CRYPTREC-listed algorithms; keys in KMS / HSM; a crypto inventory or abstraction that allows algorithm migration (FISC 14th PQC readiness) instead of hard-coded RSA / ECDH everywhere | 2.3.3 | S+M |
| F06 | Logs | security and transaction logs tamper-protected (WORM, log-file validation), access-controlled, retained for the defined period | 2.3.4.2 | S+M |
| F07 | Backups | isolated, immutable, restore-tested backups (Object Lock, Backup Vault Lock, cross-account copies) | 2.3.3 | S |
| F08 | Vulnerability and asset management | SBOM generated in CI, dependency updates automated, EOL runtimes tracked (`intel.md`); SAST in CI | 2.2.1, 2.2.3, 2.3.4.3 | S |
| F09 | Network and environments | external / internal separation, least-permissive rules, dev and test separated from production, remote-access session timeout and logging | 2.3.4.4 | S+M |
| F10 | Mobile banking apps | root / jailbreak detection, certificate pinning, device binding, biometric or Smart-OTP for high-value transfers (Vietnam Circular 50/2024; also good practice elsewhere) | - | S+M |
Plus for open-banking / 電子決済等代行業 APIs: OAuth scopes per account, consent records, token binding, rate limits.

## 3. Crypto-asset custody (Japanese exchanges, and any custodial wallet)
| ID | Check | What to verify |
|---|---|---|
| C01 | Hot / cold separation | withdrawals sign only from a capped hot wallet; customer assets swept to offline cold storage; no code path that loads cold keys online |
| C02 | No single signer | multisig, MPC or threshold signing; no one service account or key that can sign alone; approval workflow before broadcast (single-person signing was a finding in the 2024 DMM Bitcoin case) |
| C03 | Key storage | private keys, seeds and xprv never in code, env files, CI variables or logs; HSM / KMS / custody-provider policy engine |
| C04 | Withdrawal controls | address allow-lists, velocity and amount limits, delay on large or new-address withdrawals, anomaly alerts, an emergency stop |
| C05 | Third-party wallet SDKs | pinned versions, webhook signature verification, scoped and IP-restricted API keys (a leak via an external wallet system was another 2024 finding) |
| C06 | Segregation | customer and house balances in separate ledgers with reconciliation |

## 4. Severity
- **P0:** a path that moves money or crypto without authorisation or approval; a signing key or seed
  reachable from code, config or CI; ledger rows editable through an API.
- **P1:** no idempotency on payouts or transfers; single-approver money movement; logs or backups an
  attacker who owns the app server can rewrite; MFA missing on privileged access.
- **P2:** missing SBOM / crypto inventory; dev and production not separated in IaC; rate limits
  missing on low-value endpoints.

## 5. Citation notes
FISC: `FISC Security Guidelines 14th 実務基準` (part level; item numbers unverified, the text is paid).
FSA: `FSA Cybersecurity Guidelines 2024 2.3.1` (item numbers from 別紙18). Pair each with the
verifiable control (`OWASP ASVS 5.0.0`, `PCI DSS v4.0.1`, CWE).
