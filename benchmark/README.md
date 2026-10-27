# Live benchmark

`bench.py` runs real, headless Claude Code audits with the `security-audit` skill against public,
deliberately vulnerable repositories and measures what an audit costs and what it finds. It calls
the Claude API through the `claude` CLI, so it **costs money and never runs in CI**. The offline,
deterministic checks that do run on every push are in [`eval/`](../eval/README.md).

The results are in [`RESULTS.md`](RESULTS.md) ([日本語](RESULTS.ja.md)); the raw aggregate is
`results/results.json`.

## Method

- **Fixtures.** DVWA (PHP), NodeGoat (Node.js) and OWASP Juice Shop (TypeScript), pinned to the
  exact commits in [`fixtures.json`](fixtures.json). `bench.py run` refuses a fixture whose HEAD is
  not at its pin, so every published number is tied to one known source tree.
- **Ground truth.** Ten known vulnerability classes per fixture, each defined as a group of CWE IDs
  (`TRUTH` in `bench.py`), for example "SQL injection" = CWE-89, "IDOR / missing authz" = CWE-639,
  862, 863 or 285. A class counts as found when at least one finding's frontmatter cites a CWE in its
  group. Recall is classes found divided by ten. The classes are the projects' documented,
  intentional vulnerabilities, plus an "outdated / end-of-life runtime or image" class for DVWA and
  NodeGoat, which the threat-intelligence step is meant to catch. The same list is used for every
  skill version.
- **Runs.** Each skill version is installed side by side under its own name (for example `sa-v113`
  and `sa-v115`) and invoked with the same prompt, the same depth and the same per-run budget cap.
  Each run audits its own fresh copy of the fixture, so concurrent runs never share state. Several
  repetitions per fixture and version, because a model run is not deterministic: results are
  reported as mean, standard deviation, minimum and maximum.
- **Measured.** Cost in USD and turns (from the CLI's JSON output), wall-clock time, number of
  findings and their severity, recall against the ground truth, whether the findings pass the
  repository's own validator (`validate_findings.py` from this checkout, not an installed copy),
  and whether the threat-intelligence section and its inputs were produced.

What this does not measure: precision. A finding outside the ground-truth classes is not
necessarily a false positive (these projects have more bugs than their documentation lists), so
judging those takes a human read of each report.

## Reproduce

```bash
python benchmark/bench.py fetch          # clone the pinned fixtures into benchmark/fixtures/
python benchmark/bench.py run \
  --skill sa-v113=/path/to/security-audit-1.13.0 \
  --skill sa-v115=security-audit \
  --fixtures DVWA NodeGoat juice-shop --reps 2 --parallel 3 --depth quick --budget 10
python benchmark/bench.py report         # aggregate into benchmark/results/results.json
```

Requirements: `git`, Python 3.9+, and the `claude` CLI logged in. Runs write their audit folders to
`benchmark/runs/` (gitignored) and install the compared skill versions under `~/.claude/skills/`
for the duration of the run (`--keep-installed` keeps them). Runs are resumable: a run whose
`result.json` exists is not repeated, unless the CLI reported it as an error or gave no cost (an
interrupted run), which is never saved as a result and is run again.

`scripts/check_numbers.py` reads `results/results.json`, so the headline figures quoted in the
README are checked against it on every push.
