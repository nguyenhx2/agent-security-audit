# Notice

Copyright (c) 2026 Hoàng Xuân Nguyên (nguyenhx2, https://github.com/nguyenhx2)

This software is licensed under the GNU Affero General Public License, version 3 only
(`AGPL-3.0-only`). The full text is in [LICENSE.md](LICENSE.md).

In short: you may use it for any purpose, commercial included. If you distribute a modified
version, or let people use a modified version over a network, you must make the source of your
changes available under the same licence.

## Additional permission under GNU AGPL version 3, section 7

The output this software produces about a repository you run it on - findings, reports in any
format and language, work files, inventories and threat-intelligence summaries - is yours. You may
use, modify and distribute it under terms of your choice, without the obligations of the AGPL.

This permission does not extend to the software itself: the skill, its scripts, agents and
reference material, and the tooling in this repository, modified or not, remain under
AGPL-3.0-only.

## Credits

- **Cloudflare's `security-audit-skill`** (MIT licence) was the inspiration for several of the
  coverage classes this skill hunts for.
- **agent-harness-bootstrap** (https://github.com/nguyenhx2/agent-harness-bootstrap, same author,
  AGPL-3.0-only) provided the release tooling patterns and the skill linter vendored at
  `eval/vendor/skill-check.py`.

## Contributors

- **@mikemikimike** (https://github.com/mikemikimike): OpenAI v3 SDK detection patterns for the AI
  and agent inventory (pull request #6, in 1.15.1).

## Public advisory feeds

`scripts/threat_intel.py` reads public feeds that need no account. It sends only product names and
versions (and CVE IDs to EPSS), never repository names, paths, code or findings. Each feed is used
under its provider's published terms of use, and its content stays the provider's:

- CISA Known Exploited Vulnerabilities catalog (Cybersecurity and Infrastructure Security Agency, US)
- NVD CVE API 2.0 (National Institute of Standards and Technology, US). This product uses the NVD
  API but is not endorsed or certified by the NVD.
- EPSS (Forum of Incident Response and Security Teams, FIRST)
- endoflife.date
- IPA security alerts (Information-technology Promotion Agency, Japan)
- JPCERT/CC alerts (Japan Computer Emergency Response Team Coordination Center)
- JVN and JVN iPedia (operated by JPCERT/CC and IPA)

This repository redistributes no feed content. The test fixtures under `eval/fixtures/feeds/`
imitate the feed formats with invented entries.
