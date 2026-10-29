# Changelog

Repository releases of `agent-security-audit`, newest first. Each section is a short narrative of
what the release contains; the itemised change log of the skill itself lives in
[`security-audit/CHANGELOG.md`](security-audit/CHANGELOG.md) (and in Japanese in
[`editions/ja/security-audit/CHANGELOG.md`](editions/ja/security-audit/CHANGELOG.md)). The GitHub
release body is generated from the skill CHANGELOG by `scripts/release_notes.py`; see
[`docs/RELEASING.md`](docs/RELEASING.md).

## v1.15.1

A fix release of the `security-audit` skill, both editions. Five helper scripts gave the review
lanes a wrong or empty starting point on real repositories: a ja report citing the IPA guide failed
its own validation, apps on the OpenAI v3 SDK showed no AI components, a small shop was classed as
finance, the route map took an auth marker from a neighbouring Express route, and Cloudflare Worker
routes were not mapped. Each now has a self-test case (189 per edition). Details in
[`security-audit/CHANGELOG.md`](security-audit/CHANGELOG.md).

## v1.15.0

First public release of the repository. It ships the `security-audit` skill at 1.15.0 in two
editions with identical code: English (`security-audit-1.15.0.zip`, also the Claude Code plugin)
and Japanese (`security-audit-ja-1.15.0.zip`).

Highlights of the skill:

- **Read-only, evidence-anchored audits.** Every finding cites a file and line, a versioned
  standard and requirement ID, and survives an adversarial verification pass before it reaches the
  report. The audited code is never edited.
- **Live threat intelligence.** The runtimes, servers, datastores and base images a repository
  actually deploys (Dockerfile, compose, Kubernetes, serverless, version files) are matched against
  CISA KEV, NVD, FIRST EPSS, endoflife.date and the Japanese IPA, JPCERT/CC, JVN and JVN iPedia
  feeds. A feed that fails is a stated gap, never a silent pass, and feed text is treated as
  untrusted data.
- **Industry sectors.** Medical, finance, crypto, e-commerce, government, education, IoT, OT and
  automotive are detected from dependencies and identifiers, and each adds its own standards module
  with code-evidenced checks.
- **Japanese standards.** MHLW Medical Information Security Guidelines 7.0, MIC/METI guidelines,
  FISC, the Japan Credit Card Security Guidelines, Government Unified Standards and ISMAP, MEXT,
  JC-STAR, IPA "How to Secure Your Web Site" and an APPI article map, beside OWASP Top 10:2025,
  ASVS 5.0.0, API Top 10 2023, the LLM and Agentic Top 10 2026, MASVS, PCI DSS v4.0.1, CIS and SLSA.
- **Reports in Markdown, HTML and Excel, in English and Japanese**, from one canonical findings set;
  extra report languages are translated by a dedicated subagent that keeps every ID, path and
  standard name unchanged.
- **Model allocation per task.** Recon, lane review, verification and translation run as named
  subagents with their own model, effort and turn budgets, so the expensive model is spent where
  judgement is needed and not on mechanical work.

Repository additions around the skill: an offline eval suite that runs in CI without an API key
(`eval/run_eval.py`: selftest of both editions, edition parity, the skill linter, sector and
platform detection scored per class, threat intelligence against offline feed fixtures), a live
benchmark against pinned public fixtures (`benchmark/`, never run in CI), release tooling
(`scripts/`), and CI on Ubuntu, Windows and macOS with Python 3.9 and 3.13.
