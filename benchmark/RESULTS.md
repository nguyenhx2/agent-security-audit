# Benchmark results

Live, headless Claude Code audits of three deliberately vulnerable projects, comparing security-audit
1.13.0 with 1.15.0. Method, ground truth and how to reproduce: [`README.md`](README.md). Raw data:
[`results/results.json`](results/results.json). [日本語](RESULTS.ja.md)

## Setup

- Fixtures pinned in [`fixtures.json`](fixtures.json): DVWA, NodeGoat, OWASP Juice Shop.
- Depth Quick, prompt `/<skill> <repo> quick --yes` plus "Report language: English. Formats:
  Markdown only.", the same per-run budget cap for both versions.
- Three runs per version and fixture, 18 runs, US$41.71 in total.
- Claude Code CLI 2.1.310 for the 1.13.0 runs (2026-10-26), 2.1.311 for the 1.15.0 runs
  (2026-10-27). The CLI updated itself between the two days; both used the same model,
  `claude-opus-5-5`, as the CLI's JSON output records.
- Up to three audits ran at the same time on one Windows 11 machine, so wall-clock time includes
  contention. Cost, turns, findings and recall do not depend on it.

## Per project (mean of three runs)

| Project | Version | Recall (min-max) | Findings | Cost (USD) | Minutes | Turns | Validator pass | Intel section |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| DVWA | 1.13.0 | 87% (80-100) | 21.3 | 2.71 | 13.6 | 30 | 3/3 | 0/3 |
| DVWA | 1.15.0 | 97% (90-100) | 19.7 | 2.34 | 6.8 | 40 | 3/3 | 3/3 |
| NodeGoat | 1.13.0 | 100% (100-100) | 23.0 | 2.00 | 9.3 | 19 | 3/3 | 0/3 |
| NodeGoat | 1.15.0 | 100% (100-100) | 23.7 | 1.89 | 6.0 | 28 | 3/3 | 3/3 |
| Juice Shop | 1.13.0 | 77% (70-90) | 17.0 | 2.10 | 9.2 | 29 | 3/3 | 0/3 |
| Juice Shop | 1.15.0 | 93% (90-100) | 23.7 | 2.87 | 9.7 | 37 | 3/3 | 3/3 |

Median wall-clock time over all nine runs: 8.2 minutes (1.13.0), 6.9 minutes (1.15.0).

Classes not found in every run:

- 1.13.0: DVWA: CSRF 2/3, brute force / weak login 2/3, outdated / EOL runtime or image 1/3; Juice Shop: XSS 0/3, NoSQL injection 2/3, XXE 2/3, path traversal 2/3, SSRF 2/3
- 1.15.0: DVWA: brute force / weak login 2/3; Juice Shop: XSS 1/3

## Every run

| Run | Cost (USD) | Minutes | Turns | Findings | Recall | EOL runtime found | Severity |
|---|---:|---:|---:|---:|---:|---|---|
| `sa-v113_DVWA_1` | 2.93 | 26.0 | 10 | 16 | 80% | no | P0 5, P1 6, P2 5 |
| `sa-v113_DVWA_2` | 2.48 | 6.8 | 40 | 23 | 80% | no | P0 7, P1 7, P2 9 |
| `sa-v113_DVWA_3` | 2.71 | 8.2 | 39 | 25 | 100% | yes | P0 6, P1 11, P2 8 |
| `sa-v115_DVWA_1` | 2.46 | 6.5 | 45 | 17 | 90% | yes | P0 5, P1 5, P2 7 |
| `sa-v115_DVWA_2` | 1.90 | 6.9 | 33 | 19 | 100% | yes | Info 1, P0 6, P1 7, P2 5 |
| `sa-v115_DVWA_3` | 2.66 | 7.0 | 41 | 23 | 100% | yes | Info 2, P0 4, P1 8, P2 9 |
| `sa-v113_NodeGoat_1` | 2.54 | 18.4 | 11 | 27 | 100% | yes | P0 2, P1 11, P2 14 |
| `sa-v113_NodeGoat_2` | 1.70 | 5.0 | 22 | 20 | 100% | yes | P0 2, P1 8, P2 10 |
| `sa-v113_NodeGoat_3` | 1.76 | 4.6 | 24 | 22 | 100% | yes | P0 2, P1 10, P2 10 |
| `sa-v115_NodeGoat_1` | 1.79 | 6.6 | 28 | 28 | 100% | yes | Info 1, P0 2, P1 9, P2 16 |
| `sa-v115_NodeGoat_2` | 1.81 | 5.2 | 29 | 21 | 100% | yes | Info 1, P0 2, P1 8, P2 10 |
| `sa-v115_NodeGoat_3` | 2.06 | 6.1 | 28 | 22 | 100% | yes | Info 2, P0 2, P1 9, P2 9 |
| `sa-v113_juice-shop_1` | 2.70 | 10.3 | 42 | 26 | 90% | - | P0 4, P1 15, P2 7 |
| `sa-v113_juice-shop_2` | 1.97 | 10.3 | 11 | 12 | 70% | - | P0 4, P1 7, P2 1 |
| `sa-v113_juice-shop_3` | 1.63 | 7.0 | 33 | 13 | 70% | - | P0 4, P1 7, P2 2 |
| `sa-v115_juice-shop_1` | 2.65 | 10.4 | 46 | 25 | 90% | - | Info 1, P0 4, P1 16, P2 4 |
| `sa-v115_juice-shop_2` | 2.88 | 9.8 | 12 | 18 | 100% | - | P0 4, P1 11, P2 3 |
| `sa-v115_juice-shop_3` | 3.07 | 9.1 | 53 | 28 | 90% | - | P0 6, P1 15, P2 7 |

## What changed and what did not

- **Recall.** 1.15.0 found more of the documented classes on DVWA and Juice Shop; NodeGoat was
  already at 100% for both. On DVWA most of the gain is the end-of-life runtime class (3/3 runs against
  1/3), which the new platform inventory and threat-intelligence steps exist to catch; on Juice Shop
  it is spread over several injection and SSRF classes.
- **Threat intelligence.** Every 1.15.0 report has the "Platform versions and threat intelligence"
  section; 1.13.0 has no such step.
- **Cost.** About the same per audit (+4% on the mean). 1.15.0 spends more on Juice Shop, the largest
  project, and less on DVWA and NodeGoat.
- **Time.** The mean favours 1.15.0 by 30%, but two slow 1.13.0 runs (26 and 18 minutes, the first
  runs while three audits shared the machine) carry most of that. The medians differ by about a
  minute.
- **Not measured.** Precision: these projects have more bugs than their documentation lists, so a
  finding outside the ten classes needs a human read before it can be called a false positive.

## History of this benchmark

Reported so the numbers above can be judged with what happened before them.

1. **Release candidate (2026-10-26).** A first 1.15.0 build ran on the same fixtures. Of its nine
   runs, eight finished and one (DVWA, run 3) stopped after four minutes and US$1.56 without writing
   any finding: the model paused to ask a question that nobody in a headless run could answer. That
   led to the SKILL.md rule "Finish the run" (go through to the report without pausing once Phase 0
   is answered) in the final 1.15.0. The release-candidate runs are not mixed into the table above.
2. **Interrupted runs.** Twice a batch of runs was stopped before it finished (low memory, then a
   manual stop). Runs cut off that way returned no result or an aborted result; they were deleted and
   run again, and none of them is in the table. `bench.py` now refuses to save such a run as a
   result, so a resumed benchmark repeats it instead of counting a zero.
