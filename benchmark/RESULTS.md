# Benchmark results

Live, headless Claude Code audits of three deliberately vulnerable projects, comparing security-audit
1.15.0 with 1.15.2. Method, ground truth and how to reproduce: [`README.md`](README.md). Raw data:
[`results/results.json`](results/results.json). The earlier 1.13.0 against 1.15.0 comparison is kept
below under [Earlier comparison](#earlier-comparison-1130-against-1150). [日本語](RESULTS.ja.md)

## Setup

- Fixtures pinned in [`fixtures.json`](fixtures.json): DVWA, NodeGoat, OWASP Juice Shop.
- Depth Quick, prompt `/<skill> <repo> quick --yes` plus "Report language: English. Formats:
  Markdown only.", the same per-run budget cap for both versions.
- Three runs per version and fixture, 18 runs, US$44.92 in total, all on 2026-10-30.
- Claude Code CLI 2.1.314 for every run, model `claude-opus-5-5` as the CLI's JSON output records.
  1.15.0 ran from a checkout of the `v1.15.0` tag, installed as `sa-v1150`; 1.15.2 from the release
  commit, installed as `sa-v1152`.
- Two audits ran at the same time on one Windows 11 machine, so wall-clock time includes contention.
  Cost, turns, findings and recall do not depend on it.

## Why this run

1.15.2 is a patch release: detection fixes from 1.15.1 (OpenAI SDK v3, the `shop` keyword, the
fetch-handler route parser, Express markers), newer scanner pins, the `--check-updates` option and a
ReDoS fix. None of it changes how the model hunts. The question is whether it made anything worse.

## Per project (mean of three runs)

| Project | Version | Recall (min-max) | Findings | Cost (USD) | Minutes | Turns | Validator pass | Intel section |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| DVWA | 1.15.0 | 100% (100-100) | 23.0 | 2.49 | 7.9 | 37 | 3/3 | 3/3 |
| DVWA | 1.15.2 | 100% (100-100) | 23.7 | 2.75 | 8.1 | 42 | 3/3 | 3/3 |
| NodeGoat | 1.15.0 | 100% (100-100) | 22.3 | 2.09 | 6.0 | 30 | 3/3 | 3/3 |
| NodeGoat | 1.15.2 | 100% (100-100) | 22.3 | 2.02 | 6.7 | 29 | 3/3 | 3/3 |
| Juice Shop | 1.15.0 | 97% (90-100) | 25.7 | 2.84 | 10.4 | 46 | 3/3 | 3/3 |
| Juice Shop | 1.15.2 | 90% (80-100) | 23.3 | 2.78 | 10.4 | 45 | 3/3 | 3/3 |

Median wall-clock time over all nine runs: 7.3 minutes (1.15.0), 7.7 minutes (1.15.2).

Classes not found in every run:

- 1.15.0: Juice Shop: XSS 2/3
- 1.15.2: Juice Shop: XSS 1/3, path traversal 2/3

## Every run

| Run | Cost (USD) | Minutes | Turns | Findings | Recall | EOL runtime found | Severity |
|---|---:|---:|---:|---:|---:|---|---|
| `sa-v1150_DVWA_1` | 2.45 | 7.3 | 34 | 26 | 100% | yes | P0 4, P1 11, P2 11 |
| `sa-v1150_DVWA_2` | 2.38 | 6.7 | 34 | 20 | 100% | yes | P0 5, P1 8, P2 7 |
| `sa-v1150_DVWA_3` | 2.65 | 9.6 | 42 | 23 | 100% | yes | Info 1, P0 7, P1 7, P2 8 |
| `sa-v1152_DVWA_1` | 2.48 | 7.7 | 40 | 22 | 100% | yes | P0 5, P1 8, P2 9 |
| `sa-v1152_DVWA_2` | 2.68 | 7.3 | 42 | 20 | 100% | yes | Info 5, P0 1, P1 6, P2 8 |
| `sa-v1152_DVWA_3` | 3.11 | 9.2 | 44 | 29 | 100% | yes | P0 6, P1 9, P2 14 |
| `sa-v1150_NodeGoat_1` | 1.99 | 5.7 | 27 | 23 | 100% | yes | P0 2, P1 10, P2 11 |
| `sa-v1150_NodeGoat_2` | 2.12 | 6.5 | 28 | 23 | 100% | yes | P0 2, P1 9, P2 12 |
| `sa-v1150_NodeGoat_3` | 2.16 | 5.9 | 34 | 21 | 100% | yes | Info 1, P0 2, P1 10, P2 8 |
| `sa-v1152_NodeGoat_1` | 1.92 | 6.3 | 28 | 25 | 100% | yes | P0 2, P1 10, P2 13 |
| `sa-v1152_NodeGoat_2` | 2.15 | 7.5 | 32 | 21 | 100% | yes | P0 2, P1 9, P2 10 |
| `sa-v1152_NodeGoat_3` | 1.98 | 6.4 | 28 | 21 | 100% | yes | P0 3, P1 8, P2 10 |
| `sa-v1150_juice-shop_1` | 2.57 | 8.7 | 39 | 30 | 100% | - | Info 1, P0 7, P1 17, P2 5 |
| `sa-v1150_juice-shop_2` | 2.91 | 9.6 | 49 | 19 | 90% | - | P0 4, P1 12, P2 3 |
| `sa-v1150_juice-shop_3` | 3.02 | 13.0 | 51 | 28 | 100% | - | Info 1, P0 7, P1 15, P2 5 |
| `sa-v1152_juice-shop_1` | 2.56 | 9.2 | 44 | 20 | 80% | - | P0 6, P1 10, P2 4 |
| `sa-v1152_juice-shop_2` | 2.87 | 11.1 | 48 | 20 | 90% | - | P0 3, P1 14, P2 3 |
| `sa-v1152_juice-shop_3` | 2.92 | 11.1 | 44 | 30 | 100% | - | P0 5, P1 20, P2 5 |

## What changed and what did not

- **Recall.** The same on DVWA and NodeGoat (100% in all twelve runs). On Juice Shop 1.15.2 missed
  three class-runs against one: XSS twice and path traversal once, all in the first two runs; the
  third run found all ten. XSS on Juice Shop was already the weakest class for 1.15.0 (1/3 in the
  earlier comparison, 2/3 here), and nothing in 1.15.2 touches the review lanes, so this reads as
  run-to-run variance rather than a regression. Three runs per cell cannot rule that out.
- **End-of-life runtime and threat intelligence.** Found in all six DVWA and NodeGoat audits for both
  versions; every report of both versions has the "Platform versions and threat intelligence" section.
- **Cost.** US$2.52 against US$2.47 per audit (+2%), within the spread of either version. 1.15.2 spent
  more on DVWA, mostly one US$3.11 run, and less on NodeGoat and Juice Shop.
- **Time.** About eight minutes per audit for both; medians 7.3 and 7.7 minutes.
- **Not measured.** Precision: these projects have more bugs than their documentation lists, so a
  finding outside the ten classes needs a human read before it can be called a false positive.

## Notes on this run

- **A scoring bug, fixed before the numbers above.** `sa-v1152_DVWA_3` first scored 0 findings. The
  model had copied the project into a helper folder named `snapshot-<date>_<time>` inside the output
  directory and audited that copy; `bench.py` took the last folder by name, which was the snapshot,
  not the audit. `bench.py` now only reads audit folders named by timestamp, and re-scoring gave 29
  findings, 100% recall, a passing validator and the intelligence section. Because that copy had no
  git history, the secret-history scan of that run was limited.
- **Feeds in that same run.** The CISA KEV list came from a 79-hour-old cache and JVN iPedia did not
  answer; the report says both, as the skill requires.

## Earlier comparison: 1.13.0 against 1.15.0

Run on 2026-10-26 (1.13.0, CLI 2.1.310) and 2026-10-27 (1.15.0, CLI 2.1.311), same fixtures, prompt,
depth and budget, three runs per cell, 18 runs, US$41.71. Raw data:
[`results/results-1.13-vs-1.15.json`](results/results-1.13-vs-1.15.json).

| Project | Version | Recall (min-max) | Findings | Cost (USD) | Minutes | Turns | Validator pass | Intel section |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| DVWA | 1.13.0 | 87% (80-100) | 21.3 | 2.71 | 13.6 | 30 | 3/3 | 0/3 |
| DVWA | 1.15.0 | 97% (90-100) | 19.7 | 2.34 | 6.8 | 40 | 3/3 | 3/3 |
| NodeGoat | 1.13.0 | 100% (100-100) | 23.0 | 2.00 | 9.3 | 19 | 3/3 | 0/3 |
| NodeGoat | 1.15.0 | 100% (100-100) | 23.7 | 1.89 | 6.0 | 28 | 3/3 | 3/3 |
| Juice Shop | 1.13.0 | 77% (70-90) | 17.0 | 2.10 | 9.2 | 29 | 3/3 | 0/3 |
| Juice Shop | 1.15.0 | 93% (90-100) | 23.7 | 2.87 | 9.7 | 37 | 3/3 | 3/3 |

Overall recall 88% against 97%, end-of-life runtime found in 4/6 against 6/6 DVWA and NodeGoat
audits, threat-intelligence section in 0/9 against 9/9, cost US$2.27 against US$2.36 per audit.
Mean time favoured 1.15.0 by 30%, but two slow 1.13.0 runs (26 and 18 minutes, while three audits
shared the machine) carry most of that; the medians were 8.2 and 6.9 minutes.

Classes not found in every run:

- 1.13.0: DVWA: CSRF 2/3, brute force / weak login 2/3, outdated / EOL runtime or image 1/3; Juice Shop: XSS 0/3, NoSQL injection 2/3, XXE 2/3, path traversal 2/3, SSRF 2/3
- 1.15.0: DVWA: brute force / weak login 2/3; Juice Shop: XSS 1/3

## History of this benchmark

Reported so the numbers above can be judged with what happened before them.

1. **Release candidate (2026-10-26).** A first 1.15.0 build ran on the same fixtures. Of its nine
   runs, eight finished and one (DVWA, run 3) stopped after four minutes and US$1.56 without writing
   any finding: the model paused to ask a question that nobody in a headless run could answer. That
   led to the SKILL.md rule "Finish the run" (go through to the report without pausing once Phase 0
   is answered) in the final 1.15.0. The release-candidate runs are not mixed into the tables above.
2. **Interrupted runs.** Several batches were stopped before they finished (low memory, a manual
   stop, and on 2026-10-30 a first attempt that compared 1.15.1 before 1.15.2 existed). Runs cut off
   that way returned no result or an aborted result; they were deleted and run again, and none of
   them is in the tables. `bench.py` refuses to save such a run as a result, so a resumed benchmark
   repeats it instead of counting a zero.
3. **Audit folder selection (2026-10-30).** See "Notes on this run" above.
