# Live threat intelligence

**English** · [日本語](ja/threat-intelligence.md)

Lockfile scanners answer "is a package I depend on vulnerable?". Many incidents start elsewhere: an interpreter or server release (a PHP or OpenSSL emergency patch), an internet-facing product (a BI tool, an app-server console), a file that should never have been served. Every audit therefore checks what the repository **deploys** against advisories fetched at audit time, at every depth, without anyone having to name the incident.

![Live threat intelligence flow. The repos' version pins feed platform_inventory.py, which writes platform.json with each component's version, precision, context and exposure signals, without network. threat_intel.py matches it in the background against global feeds (CISA KEV, NVD, FIRST EPSS, endoflife.date) and Japanese feeds (IPA, JPCERT/CC, JVN, JVN iPedia), sending only product names and versions. A failed feed becomes a stated gap, never a pass. intel.json sorts components into act-now, review and update; the supply-chain-infra lane triages with severity floors; the report's section 2 lists versions, advisory ids, the feed date and gaps.](../assets/threat-intel-flow.svg)

## Step 1: platform_inventory.py

`platform_inventory.py` runs on every repository in seconds, with no network. It finds versions where lockfile scanners never look:

- Dockerfile `FROM` and `ARG` defaults, multi-stage builds included
- compose files, Kubernetes manifests and Helm charts
- version files such as `.tool-versions` and `.nvmrc`
- CI setup steps and serverless runtimes
- framework entries in lockfiles

For each component it records the version, the pin's `path:line`, and two attributes that decide what a match means:

| Attribute | Values | Why it matters |
|---|---|---|
| Precision | `exact` (x.y.z), `minor`, `major`, `floating` (`php:8.3-fpm`, `node:20`, `latest`), `range` (`^8.1`, `>=18`), `distro` (apt or apk package), `managed` (Lambda, App Engine, Functions) | An exact pin is evidence. A floating tag is whatever was built last. A distro package may carry a backport, so it needs a runtime check. A managed runtime is patched by the provider; only its cycle matters. A range is judged by its lowest allowed cycle. |
| Context | `deploy`, `build`, `ci`, `dev`, `declared` | `deploy` (final image stage, compose, manifests, serverless) is what runs. The others show intent, not production. |

It also records exposure and hardening signals (leads, not verdicts): `.env` or dumps under a web root, `phpinfo()`, directory listing, admin and BI tool images, published datastore ports, Spring actuator exposure, Tomcat manager roles, containers running as root, download tools in a runtime image, remote `ADD`, base images without a digest, no Kubernetes NetworkPolicy, security-group egress to anywhere, no automated base-image updates.

Output: `work/<repo>/platform.md` and `platform.json`.

## Step 2: threat_intel.py

One background command for all repositories matches the inventories against <!--n:feeds-->8<!--/n--> public feeds. It takes 10-90 seconds, longer without an NVD API key.

| Feed | Scope | What it answers | Caveat |
|---|---|---|---|
| CISA KEV catalog (GitHub mirror as fallback) | global | Exploited in the wild, used in ransomware | A US-centric selection |
| NVD CVE API 2.0 | global | Which CVEs affect this exact version (CPE + version) | CPE data can lag days to weeks behind a new CVE; rate-limited without a key |
| FIRST EPSS | global | Probability of exploitation in the next 30 days | Daily |
| endoflife.date | global | Support and security cycles, latest patch per cycle | Community-maintained; check the vendor page for a P0 or P1 decision |
| IPA security alerts | Japan | Emergency measures the national agency asks for (重要なセキュリティ情報) | Few items, high signal |
| JPCERT/CC alerts | Japan | 注意喚起, weekly reports, campaign alerts with indicators | |
| JVN | Japan | Coordinated vendor advisories (JVN#, JVNVU#), Japanese products | |
| JVN iPedia | Japan | The wider vulnerability database | Can be suspended; JVN and JPCERT/CC cover the gap |

Output: `work/intel.md` for the lanes and `work/intel.json` for the report and the validator. Each component gets a priority:

| Priority | Meaning |
|---|---|
| `act-now` | A KEV CVE, or a CVE a national alert asks to fix now, on the pinned version |
| `review` | End of life, an alert without a version match, critical CVEs |
| `update` | Behind the latest patch of its cycle |

### Severity floors

| Situation | Severity floor |
|---|---|
| Deployed exact version affected by a KEV CVE or a nationally alerted CVE, internet-reachable | P0 for pre-auth RCE or auth bypass, else P1 |
| Same, not internet-reachable (internal datastore, CI image) | P1 |
| Behind the cycle's latest patch with CVSS 9 or more, or EPSS 0.1 or more | P1 |
| Runtime, OS, datastore or framework past end of life in deploy context | P1 internet-facing, else P2 |
| Admin, BI or management tool or datastore reachable from outside without auth | P0 when it holds data or offers code execution, else P1 |
| Secret-bearing file committed under a served web root | P0 if it holds secrets or personal data, else P1 |

One finding per remediation: "upgrade PHP to the fixed version in the Dockerfile, rebuild and redeploy" lists every CVE it clears and every pin it must change. The remedy names the minimal fixed version and any interim mitigation the advisory gives, because a fixed Dockerfile is not a fixed server until it is rebuilt and redeployed.

The full rules: [`threat-intel.md`](https://github.com/nguyenhx2/agent-security-audit/blob/main/security-audit/reference/method/threat-intel.md).

## What is sent over the network

| Sent | To |
|---|---|
| An endoflife.date product id | endoflife.date |
| An NVD CPE string such as `cpe:2.3:a:php:php:8.3.30` | NVD |
| CVE ids | FIRST EPSS |
| Nothing (plain downloads) | CISA KEV, IPA, JPCERT/CC, JVN, JVN iPedia |

Never repository names, paths, code or findings. Only a fixed allowlist of hosts is contacted, and a redirect to any other host is refused. Feed text is untrusted data: titles are stripped of control, bidi and zero-width characters and truncated, links are kept only for the feed's own hosts, and nothing in a feed is followed or run.

## A failed feed is a stated gap

Each feed is optional. A feed that times out, answers with an error page or is suspended becomes a gap in `intel.md` and in the report's section 2, never a silent pass. `threat_intel.py` exits 0 even when feeds fail, so the audit continues. The report states the feed date, because advisories change daily and the report is true as of that date only.

The validator warns when a known-exploited or nationally alerted CVE, or an end-of-life deploy component, from `intel.json` appears in no finding and is not listed under Refuted with a reason.

## Cache and offline use

| Option | Effect |
|---|---|
| Default | Responses are cached under `~/.cache/security-audit/intel` with a time-to-live per feed. When a feed is down, a cached copy is reused and marked stale. |
| `--offline` | Cache only, no network. Missing feeds are gaps. Choose it when network access is not allowed; the skill states it as a gap in the report. |
| `--cache-dir DIR` | Use another cache folder. |
| `NVD_API_KEY` (environment) | Raises the NVD rate limit. No account is needed otherwise. |
| `--no-nvd`, `--max-nvd N` | Skip or cap the per-version NVD queries (slow without a key). |
| `--days N` | Window for national alerts and new KEV entries (default 60). |

To audit without any network access, say so when you start ("no network access"); the advisory step runs with `--offline`.

## "Are we affected by this alert?"

The same machinery answers a question about one advisory. Ask, for example:

```text
are we affected by CVE-2026-XXXXX?
/security-audit ../shop-api quick
注意喚起の影響確認
```

A Quick audit is usually enough. The platform inventory shows which version of the product each repository deploys and where it is pinned; the advisory match shows whether that version appears in KEV, NVD or a national alert. When a national alert names a product but NVD's CPE data does not yet confirm the version ("named in alerts, version match unconfirmed"), the lane reads the advisory's affected-version list and compares it with the pin; that comparison is the evidence. When only a `declared` or floating pin exists, the finding says the deployed version is unknown and names the runtime check that would decide it.

## Limits

- **Static.** The deployed version can differ from the repository (a hotfixed host, a PaaS image, a newer build of the same tag). A finding says which pin it is based on.
- **Feeds are selections.** NVD's CPE matching misses products it names differently and CVEs not yet analysed; KEV is a selection; national alerts cover what their agency published. A private fork or an unlisted vendor product is recorded as unmatched.

## See also

- [Scanners](scanners.md)
- [Security and privacy](security-and-privacy.md)
- [NOTICE](https://github.com/nguyenhx2/agent-security-audit/blob/main/NOTICE.md#public-advisory-feeds): feed providers and terms
