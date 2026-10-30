# Standards and industry sectors

**English** · [日本語](ja/standards-and-sectors.md)

Every finding cites a standard with its version. The skill picks which standards apply from what the code shows and from what you tell it, then the review lanes check the code against them.

![Coverage map. Technical domains: web and API (OWASP Top 10:2025, ASVS 5.0.0, API Security Top 10 2023, CWE Top 25 2025, IPA How to Secure Your Web Site); mobile (MASVS 2.1.0, MASTG 2.0.0, Mobile Top 10 2024); cloud and IaC (CIS benchmarks, OWASP Kubernetes Top 10 2025); CI/CD and supply chain (OWASP CI/CD Top 10, SLSA v1.2, SSDF v1.1, Non-Human Identities Top 10 2025); AI, LLM, agents and MCP (LLM Top 10 2026, Agentic Top 10 2026, MCP Top 10 beta, AISVS 1.01) and AI coding-agent configs; sensitive data at rest and payments (PCI DSS v4.0.1); privacy (GDPR, APPI, Vietnam PDPL, CCPA, HIPAA, EU CRA, EU AI Act). Industry sectors with Japanese, US, EU and Vietnamese rules: medical, finance and crypto assets, e-commerce, public sector, education, IoT, OT and vehicles.](../assets/coverage-map.svg)

## Standards modules

The reference material is split into <!--n:standards_modules-->14<!--/n--> standards modules. A lane reads only the modules in scope, and only the section it needs.

| Module | Main standards and versions | Applies when the system has |
|---|---|---|
| `owasp-web` | OWASP Top 10:2025, OWASP ASVS 5.0.0, CWE Top 25 2025, NIST SP 800-63-4, IPA How to Secure Your Web Site (7th edition) | Any application code |
| `owasp-api` | OWASP API Security Top 10 2023; GraphQL, WebSocket, gRPC and webhooks | HTTP routes or an API surface |
| `pci-dss` | PCI DSS v4.0.1, transaction integrity (atomicity, idempotency, audit trail) | Card payments, a payment SDK, card-like columns, or money movement |
| `privacy` | GDPR, Japan APPI (and the 2026 amendment), Japan My Number Act, Vietnam PDPL, EU CRA, EU AI Act, CCPA, HIPAA | Personal, account, health or biometric data |
| `ai-llm-agentic` | OWASP Top 10 for LLM Applications 2026, OWASP Top 10 for Agentic Applications 2026, OWASP MCP Top 10 (beta), OWASP AISVS 1.01 | LLM calls, RAG, agents, MCP servers or clients, AI coding-agent configuration |
| `mobile` | OWASP MASVS 2.1.0, OWASP MASTG 2.0.0, OWASP Mobile Top 10 2024 | Android, iOS, Flutter or React Native |
| `cloud-iac` | CIS AWS v7.1.0, Azure v6.0.0, GCP v5.0.0 Foundations, CIS Kubernetes v2.1.0, CIS Docker v1.9.0, OWASP Kubernetes Top 10 2025 | Terraform, CloudFormation, CDK, Kubernetes, Helm, Dockerfiles |
| `supply-chain` | OWASP Top 10 CI/CD Security Risks, SLSA v1.2, NIST SSDF SP 800-218 v1.1, OWASP Non-Human Identities Top 10 2025 | CI pipelines, lockfiles, build and release automation |
| `medical` | MHLW Medical Information Security Guidelines 7.0, MIC/METI Medical Service Provider Guidelines 2.0, HIPAA pointers | Sector: medical |
| `finance` | FISC Security Guidelines (14th), FSA Cybersecurity Guidelines, crypto-asset custody checks, GLBA Safeguards Rule, NYDFS 23 NYCRR 500, Vietnam Circulars 09/2020 and 50/2024 | Sector: finance or crypto |
| `ecommerce` | Japan Credit Card Security Guidelines 6.1, Vietnam E-commerce Law 122/2025 and Decree 248/2026 | Sector: e-commerce |
| `public-sector` | Japan Government Unified Standards, ISMAP, Japan Active Cyber Defense Act, Vietnam Decree 85/2016 and Cybersecurity Law 116/2025 | Sector: government |
| `education` | MEXT Education Information Security Guidelines, FERPA, COPPA | Sector: education |
| `iot-ot` | JC-STAR, ETSI EN 303 645, EU CRA, IEC 62443, UN R155 / R156 | Sector: IoT, OT or automotive |

The baseline was verified against the issuing bodies on the date in `SKILL.md` (`standards-verified`). When an audit runs more than 90 days after that date, the skill re-verifies the rows in scope before citing them and stamps the report with the new date; anything it cannot confirm is cited as `(UNVERIFIED)`. The full table, with release dates and superseded versions: [`standards/index.md`](https://github.com/nguyenhx2/agent-security-audit/blob/main/security-audit/reference/standards/index.md).

## The citation rule

A finding cites `standard + version + requirement ID`, never a bare ID. IDs are version-scoped: OWASP Top 10 `A03` meant Injection in 2021 and means Software Supply Chain Failures in 2025. A bare "A03" is ambiguous today and wrong tomorrow.

Examples of the format:

```text
OWASP Top 10:2025 A01
OWASP ASVS 5.0.0 V8.2.1
OWASP API Security Top 10 2023 API1
PCI DSS v4.0.1 Req 3.3.1
OWASP Top 10 for LLM Applications 2026 LLM01
OWASP Top 10 for Agentic Applications 2026 ASI02
CIS AWS Foundations v7.1.0 2.1.1
CWE-89
```

In a finding file this is split into three frontmatter fields: `standard` (a canonical name), `standard_version` and `requirement_id`. The validator accepts <!--n:standards-->59<!--/n--> canonical names and warns on any other, for example `OWASP Top 10`, `OWASP ASVS`, `PCI DSS`, `Japan APPI`, `IPA How to Secure Your Web Site`, `FISC Security Guidelines`. A CWE goes in the `cwe` field, never as the primary standard, and every `also_maps_to` entry carries a version. A feed (KEV, JVN) is never cited as the standard of a finding; the advisory URL goes in Evidence.

## Industry sectors

`detect_stack.py` reads <!--n:sectors-->9<!--/n--> sector signals from dependencies and from identifiers, Japanese romaji included (`karte`, `monshin`, `kanja`, `zengin`, `furikomi`), and maps them to six sector modules.

| Sector module | Signals | Japan | US, EU, global | Vietnam |
|---|---|---|---|---|
| Medical | medical | MHLW Medical Information Security Guidelines 7.0, MIC/METI Provider Guidelines 2.0 | HIPAA; GDPR Art. 9 | PDPL |
| Finance and crypto assets | finance, crypto | FISC Security Guidelines (14th), FSA Cybersecurity Guidelines; crypto-asset custody checks | GLBA Safeguards Rule, NYDFS 23 NYCRR 500 | Circulars 09/2020 and 50/2024 |
| E-commerce | ecommerce | Credit Card Security Guidelines 6.1 | PCI DSS v4.0.1 | E-commerce Law 122/2025, Decree 248/2026 |
| Public sector | government | Government Unified Standards, ISMAP, Active Cyber Defense Act | - | Decree 85/2016, Cybersecurity Law 116/2025 |
| Education | education | MEXT Education Information Security Guidelines | FERPA, COPPA | - |
| IoT, OT and vehicles | iot, ot, automotive | JC-STAR | ETSI EN 303 645, EU CRA, IEC 62443, UN R155 / R156 | - |

How a sector gets into scope:

- **Detected in the code.** Dependencies (FHIR and HL7, Zengin, wallet and chain libraries, EC platforms, LTI, MQTT and IoT SDKs, Modbus, OPC UA, CAN) or identifier keywords. Thresholds avoid known false positives: an Azure SDK full of `Sku` is not e-commerce, and card payments alone do not make a repository `finance`.
- **Stated by you.** "We are a bank" or "this is for a city office" adds the sector even when the code does not show it. In the Focus question, use Other to add one.
- A detected sector is named in the Focus question and also triggers the jurisdiction question.

The offline eval proves each sector is detected from realistic fixtures and that negatives report none ([eval/README.md](https://github.com/nguyenhx2/agent-security-audit/blob/main/eval/README.md)).

## Japanese standards

For a Japanese client, or when Japanese is a report language:

- `IPA How to Secure Your Web Site` (安全なウェブサイトの作り方) is cited next to OWASP.
- `Japan APPI` comes first among the privacy laws, with its article map: security control measures, breach reports and their deadlines, transfers abroad.
- Sector rules include the MHLW medical guidelines, the FISC Security Guidelines, the FSA Cybersecurity Guidelines, the Credit Card Security Guidelines, the Government Unified Standards, ISMAP, the Active Cyber Defense Act, the MEXT education guidelines and JC-STAR.
- In a Japanese report, the standards table shows Japanese standards by their Japanese names.
- For a supplier to a large Japanese company, the skill notes the METI SCS evaluation scheme (★3 / ★4) as context; it is not a separate module.

## The coverage reflex

A defect class with no standard in scope is a class nobody looks at. Before recon, the skill lists what the system is (takes payments? stores personal data? deploys through a pipeline? calls an LLM? moves money? has a mobile client or an admin console?) and compares that with the modules in scope. It then checks [`coverage-checklist.md`](https://github.com/nguyenhx2/agent-security-audit/blob/main/security-audit/reference/method/coverage-checklist.md) for classes that fall between standards. At Deep every checklist row is graded, at Standard the rows for in-scope modules; at Quick the classes not examined are listed as gaps.

## See also

- [Findings and reports](reports.md): how citations appear in findings
- [Your first audit](first-audit.md): the Focus and Jurisdiction questions
- [`standards/index.md`](https://github.com/nguyenhx2/agent-security-audit/blob/main/security-audit/reference/standards/index.md): versions, release dates, re-verification
