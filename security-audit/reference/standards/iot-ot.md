# Module: iot-ot - connected devices, industrial control, vehicles

Applies when the repo holds firmware, device or companion-app code, OT / ICS integrations, or vehicle
software (detect sectors `iot`, `ot`, `automotive`: MQTT, CoAP, BLE, OTA, RTOS / embedded Linux, Modbus,
OPC UA, BACnet, CAN, UDS, AUTOSAR). Versions per `reference/standards/index.md`.

## 1. Which rules apply
| Canonical name | What it is | Version / date | Who it binds |
|---|---|---|---|
| `JC-STAR` | IoT product security conformity assessment and labelling (IPA, Japan) | ★1 since 2025-03-25 (self-declaration); ★3 requirements for network equipment and cameras published 2026-06-12 (third-party evaluation) | IoT products sold in Japan; required for government and critical-infrastructure procurement at higher levels |
| `ETSI EN 303 645` | consumer IoT baseline (13 provisions) | V3.1.3, 2024-09 | consumer IoT; basis of JC-STAR ★1 and UK PSTI |
| `EU CRA` | Cyber Resilience Act, Regulation (EU) 2024/2847 | reporting of exploited vulnerabilities and severe incidents from 2026-09-11 (24 h / 72 h / final); full application 2027-12-11 | products with digital elements on the EU market |
| `IEC 62443` | industrial automation and control systems: 4-1 secure development lifecycle, 4-2 component requirements, 3-3 system requirements | 3-3 Ed.1 2013, 4-1 Ed.1 2018, 4-2 Ed.1 2019 (Ed.2 of 4-1 / 4-2 expected late 2026 to early 2027) | OT / ICS products and integrators |
| `UN R155` / `UN R156` | vehicle cybersecurity and software-update management systems (UNECE WP.29) | mandatory for new vehicles in the EU and Japan since 2024-07 | vehicle manufacturers and suppliers |

## 2. Code-evidenced checks
| ID | Check | What to verify | Maps to | Seen |
|---|---|---|---|---|
| T01 | No universal default password | unique per-device credentials or a forced change on first use | EN 303 645 5.1; JC-STAR ★1; IEC 62443 FR1 | S+M |
| T02 | Brute-force protection | attempt limits on local and remote login | JC-STAR ★1 | M |
| T03 | Signed, verified updates | firmware and OTA packages signed and verified before install; rollback / downgrade protection; secure boot | EN 303 645 5.3, 5.7; UN R156; IEC 62443 FR3 | S+M |
| T04 | No hard-coded secrets | no keys or passwords in firmware, app or build scripts; secrets in a secure element / HSM / TPM | EN 303 645 5.4 | S |
| T05 | Secure communication | TLS (or DTLS) with certificate validation not disabled; MQTT with auth and TLS; CAN / vehicle Ethernet message authentication (SecOC) where required | EN 303 645 5.5; IEC 62443 FR4 | S+M |
| T06 | Minimal attack surface | telnet, UART shells, ADB, debug ports and unused services disabled in production builds | EN 303 645 5.6; IEC 62443 FR7 | S+M |
| T07 | Vulnerability disclosure and support period | `SECURITY.md` / `security.txt`, a declared support period | EN 303 645 5.2; EU CRA Annex I | S |
| T08 | SBOM and no known exploitable vulnerabilities at release | SBOM generated in CI, SCA gate (`intel.md`, scanners) | EU CRA Annex I; IEC 62443-4-1 SVV | S |
| T09 | Data deletion | factory reset deletes user data; personal data protected | EN 303 645 5.8, 5.11 | M |
| T10 | Zones and conduits (OT) | OT protocols (Modbus, OPC UA, BACnet, S7) not exposed beyond their zone; OPC UA security mode not `None`; write commands authenticated | IEC 62443 FR5, FR1 | S+M |
| T11 | Secure development evidence (OT / automotive) | threat model, coding standard, SAST / fuzzing in CI, defect handling (IEC 62443-4-1; ISO/SAE 21434-aligned for vehicles) | IEC 62443-4-1 | S |

## 3. Severity
- **P0:** a default credential or unauthenticated write path that lets a network attacker control
  devices or industrial processes; unsigned firmware updates accepted over the network.
- **P1:** hard-coded secrets shared by all devices; debug interfaces enabled in production builds;
  certificate validation disabled; OPC UA security mode `None` on a reachable endpoint.
- **P2:** missing disclosure policy or SBOM; no rollback protection on an otherwise signed update.
