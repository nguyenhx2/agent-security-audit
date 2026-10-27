# Offline eval

**English** · [日本語](README.ja.md)

`run_eval.py` checks, on every push and without an API key, network or Docker, that the
deterministic parts the audit stands on still do what the skill says they do. The live benchmark
(real audits, real cost) is in [`benchmark/`](../benchmark/README.md).

```bash
python eval/run_eval.py                 # everything, about 2-4 minutes (the selftests dominate)
python eval/run_eval.py --no-selftest   # the fast parts only; results go to eval/results/tmp/
```

It prints one line per check and ends with `eval N/M`. Exit 0 only when every check passes. The
full run writes [`results/latest.json`](results/latest.json): per-part totals, precision and recall,
and every check with its outcome. The file has no timestamps or paths, so it changes only when a
result does. `scripts/check_numbers.py` reads it to verify the figures the README quotes.

## What each part proves

| Part | What runs | What it proves |
|---|---|---|
| gates | `tests/selftest.py` of both editions, `scripts/check_editions.py`, `vendor/skill-check.py --published` | Every script behaves as tested in both languages, with the same number of checks; the Japanese edition's code is identical to the English one once strings are masked; the skill passes the harness skill linter (frontmatter limits, triggers, references, trigger cases). |
| detect | `detect_stack.py` on [`fixtures/detect/`](fixtures/detect) | Each industry sector is detected from a dependency or from identifiers (including Japanese romaji such as `kanja`, `karte`, `monshin`) and selects its standards module. Negatives (an Azure SDK full of `Sku`, a marketing coupon, a plain API) report no sector. Scored as precision and recall per sector. |
| platform | `platform_inventory.py` on [`fixtures/platform/`](fixtures/platform) | Deployed versions are found where lockfile scanners cannot see them (a PHP version set through a Dockerfile `ARG`, compose images, a Lambda runtime in Terraform, `.nvmrc`), and exposure signals fire (root container, download tools in the runtime image, an admin tool, a published datastore port, `.env` and `phpinfo()` under the web root, `allow_url_include`). A hardened negative fires none of them. Scored per signal. |
| intel | `threat_intel.py --feeds-dir` on [`fixtures/feeds/`](fixtures/feeds) | A KEV entry plus a national alert on the exact deployed PHP version ranks it "act now", with EPSS; MySQL 5.7 is end of life; a version range is judged by its lowest cycle; a feed that answers with an HTML error page is a stated gap, never a pass; hostile feed text (a right-to-left override, an injected instruction, a foreign link) is sanitised; an offline run with an empty cache still exits 0 with every feed a gap. |

## Adding a case

Add a folder under `fixtures/detect/` or `fixtures/platform/` and an entry in
[`cases.json`](cases.json) that states what is **true** of the fixture: the sectors it belongs to,
the components it deploys, the signals that must and must not fire. Write the expectation first,
then run the eval. A failing case is a detector gap to fix in the skill, not a fixture to adjust
until it passes.

The fixtures are copied to a temporary folder before scanning, so the enclosing git repository
cannot change what the scripts see. The hostile characters in the IPA feed are not stored in the
repository: `{BIDI}` in `fixtures/feeds/ipa.rdf` is replaced at copy time.
