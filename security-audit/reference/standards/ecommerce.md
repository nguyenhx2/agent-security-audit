# Module: ecommerce - online shops, marketplaces, card-accepting merchants

Applies when the code runs a shop or marketplace (detect sector `ecommerce`: carts, orders, shipping,
EC platforms, 3-D Secure, PSP checkout). Card data rules are `reference/standards/pci-dss.md`; this
module adds the merchant-side rules. Versions per `reference/standards/index.md`.

## 1. Which rules apply
| Canonical name | What it is | Version / date | Who it binds |
|---|---|---|---|
| `Japan Credit Card Security Guidelines` | クレジットカード・セキュリティガイドライン (クレジット取引セキュリティ対策協議会); METI treats it as the practical standard for the Installment Sales Act security duty | 6.1, 2026-03-11 (6.0 of 2025-03-04 holds the substantive changes) | every merchant in Japan that accepts cards, and its PSP / EC-platform vendors |
| `PCI DSS` | card data security | v4.0.1 | anyone storing, processing or transmitting card data |
| `Vietnam E-commerce Law` | Law 122/2025/QH15 + Decree 248/2026/ND-CP | in force 2026-07-01 | e-commerce sites and platforms in Vietnam |

## 2. Code-evidenced checks (Japan guideline 6.x unless noted)
| ID | Check | What to verify | Seen |
|---|---|---|---|
| E01 | Card non-retention (非保持化) | card numbers never stored, processed or passed through the merchant's servers: token, iframe, redirect or JavaScript-type PSP flow; no PAN column, PAN in logs, or server-side form field carrying a card number | S+M |
| E02 | Checkout page integrity | in JavaScript-type flows a skimmer defeats non-retention: CSP restricting script sources, SRI on third-party scripts, tamper detection on checkout pages, no admin-writable templates served on checkout | S+M |
| E03 | Admin panel protection (vulnerability measure 1) | admin reachable only from an IP allow-list or VPN, MFA on admin login, no default or shared accounts, non-default admin path; basic auth alone is not enough | S+M |
| E04 | No exposed data directories (measure 2) | no directory listing; `/upload`, `/backup`, `.git`, `.env`, `*.sql` not served; storage buckets private (`platform.md` signals) | S |
| E05 | Web application vulnerabilities (measure 3) | SQLi, XSS, OS command injection fixed; EC platform and plugins (EC-CUBE, WordPress / WooCommerce, Magento) patched - `intel.md`; SAST / DAST and dependency updates in CI | S+M |
| E06 | Anti-malware and tamper detection (measure 4) | server-side anti-malware / EDR and file-integrity monitoring of web roots in IaC or images | S |
| E07 | Card-testing countermeasures (measure 5) | rate limits on authorisation attempts per IP, device and card; CAPTCHA or bot detection on checkout; failed-authorisation limits | M |
| E08 | EMV 3-D Secure | 3DS2 enabled in the PSP integration for all EC transactions (required in principle since end of March 2025); not disabled or "attempt only" across the board | S+M |
| E09 | Login-fraud countermeasures (new in 6.0) | at member registration, login and attribute change, at least one of: MFA / 2-step, passkeys, attempt limits and lockout, device fingerprint / risk-based login, change-notification e-mails; absence at any of the three points is a finding | M |
| E10 | Upload handling | extension and content-type allow-lists, no execution in the upload directory, storage outside the web root (from the EC-site security checklist) | S+M |
| E11 | Vietnam: published operating rules, seller verification, buyer data protection, licensed payment intermediaries, MOIT notification badge | site footer / pages, seller onboarding flow, payment integrations | M |

## 3. Severity
- **P0:** card numbers on merchant servers or logs; a checkout page an attacker or admin template can
  inject script into without detection; admin panel on the internet without MFA holding customer data.
- **P1:** 3-D Secure disabled; no card-testing limits; no login-fraud control at one of the three points;
  unpatched EC platform with a KEV / alerted CVE.
- **P2:** missing tamper detection or file-integrity monitoring; weak upload restrictions without an
  execution path.

## 4. Detection hints
PSP SDKs (GMO-PG, SBPS, VeriTrans, Paygent, ZEUS, Stripe, PAY.JP, KOMOJU, Adyen, Braintree), EC
platforms, tables `orders` / `cart` / `payment`, routes `/checkout` `/cart` `/mypage` `/admin`, terms
`3ds`, `tds2`, `本人認証`.
