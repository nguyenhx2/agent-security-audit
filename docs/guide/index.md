# security-audit user guide

**English** · [日本語](ja/index.md)

`security-audit` is a read-only security audit skill for Claude Code. Point it at one or more repositories and it fingerprints the stack and the industry, runs pinned scanners, checks what you deploy against advisories published today, has models hunt the defects scanners cannot see, tries to refute every finding, and writes one validated set of findings and reports in Markdown, HTML and Excel, in English, Japanese or both.

It never edits, builds or runs the code it audits. All output goes to a folder beside the repository; you apply the fixes.

## Who it is for

- **Developers** who want a security review of their own repository before a release, or an answer to "are we affected by this CVE?".
- **Security engineers** who review web and API back ends, mobile apps, infrastructure as code, CI/CD pipelines and AI agents, and need findings that cite versioned standards and point at `file:line`.
- **Teams in regulated industries** (medical, finance and crypto assets, e-commerce, public sector, education, IoT, OT and vehicles) who need Japanese, US, EU or Vietnamese rules applied, not only OWASP.

It is not a tool for applying fixes, and not for reviewing only the current diff. For a diff review, use Claude Code's `security-review`.

## Two strengths

### Threat intelligence that is current at audit time

Lockfile scanners only answer "is a package I depend on vulnerable?". Many incidents start elsewhere: an interpreter or web server release, an exposed admin or BI tool, a file under the web root. On every audit, at every depth, `platform_inventory.py` reads what the repository actually deploys (base images, runtimes, servers, datastores, admin tools), and `threat_intel.py` matches it against <!--n:feeds-->8<!--/n--> public advisory feeds fetched at that moment: CISA KEV, NVD, FIRST EPSS, endoflife.date, IPA, JPCERT/CC, JVN and JVN iPedia. A new incident is covered without anyone naming it, and a feed that fails is a stated gap in the report, never a pass. See [Live threat intelligence](threat-intelligence.md).

### Scanners that update on a schedule, safely, never on their own

The <!--n:scanners-->8<!--/n--> pinned scanners run from images fixed by version and SHA-256 digest, so two audits of the same code agree and a re-scan judges a fix by the same rules that found the defect. New scanner versions arrive through a weekly workflow that waits 7 days after a release, proves the new version still finds a planted defect, and opens a pull request that a maintainer merges by hand. An audit never switches a scanner by itself. See [Scanners](scanners.md).

## Map of this guide

| Page | Read it to |
|---|---|
| [Install](install.md) | Install from the plugin marketplace or a release zip, verify it, and check your machine |
| [Your first audit](first-audit.md) | Start an audit, answer the scoping questions, pick a depth and find the output |
| [How an audit runs](how-it-works.md) | Follow phases 0 to 8: which script and which subagent does what |
| [Live threat intelligence](threat-intelligence.md) | Understand the advisory feeds, what is sent, and "are we affected by this alert?" |
| [Scanners](scanners.md) | See the pinned scanners, container and native modes, and how pins are updated |
| [Standards and industry sectors](standards-and-sectors.md) | See which standards apply, how sectors are detected, and how findings cite them |
| [Findings and reports](reports.md) | Read finding files and the Markdown, HTML and Excel reports, and the validator |
| [Models and cost](models.md) | See which model and effort run per depth, and measured cost and time |
| [Re-scan and fix verification](rescan.md) | Verify fixes with Phase 8 |
| [Security and privacy](security-and-privacy.md) | Know what the skill runs, sends, fetches and writes |
| [Troubleshooting and FAQ](troubleshooting.md) | Fix common failures |
| [Contributing](contributing.md) | Report issues and send pull requests |

## Quick start

```text
/plugin marketplace add nguyenhx2/agent-security-audit
/plugin install security-audit@agent-security-audit
```

Then, in Claude Code, from a folder outside the repository you want to audit:

```text
audit ../shop-api
```

The skill asks about depth, report language, focus and formats, then runs to the end. See [Your first audit](first-audit.md).

## See also

- [README](https://github.com/nguyenhx2/agent-security-audit/blob/main/README.md): overview, figures and screenshots
- [ARCHITECTURE](https://github.com/nguyenhx2/agent-security-audit/blob/main/docs/ARCHITECTURE.md): the design in one page
- [SKILL.md](https://github.com/nguyenhx2/agent-security-audit/blob/main/security-audit/SKILL.md): the full procedure the skill follows
