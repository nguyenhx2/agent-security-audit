# Contributing

Thanks for looking at this repository. The skill audits other people's code and reports what it
finds, so the bar is "does it still find what it claims, and only that", not "does it run". The
checks below answer that automatically, so nobody has to remember it by hand.

## Dev setup

Everything runs on the Python standard library, **Python 3.9 or newer** (`py -3` on Windows,
`python3` elsewhere). Optional extras:

- `openpyxl` (`python -m pip install openpyxl`): the Excel report, and the selftest checks for it.
  CI installs it; without it the selftest runs one check fewer.
- Node (`npx`): `scripts/check_mermaid.py` renders diagrams with `@mermaid-js/mermaid-cli`. Without
  it the static checks still run locally; CI always renders.
- Pillow is needed only to regenerate the plugin icon (`scripts/make_icons.py`).

## Layout

| Path | What it is |
|---|---|
| `security-audit/` | The skill, English edition. **The master**: every change starts here. |
| `editions/ja/security-audit/` | The same skill with Japanese prose. Same code, same behaviour. |
| `eval/` | Offline eval suite, runs in CI with no API key ([`eval/README.md`](eval/README.md)). |
| `benchmark/` | Live benchmark against pinned public fixtures; costs money, never in CI. |
| `scripts/` | Release and documentation gates. |

## The gates

Run from the repository root. All must exit 0 before a pull request:

```bash
python security-audit/tests/selftest.py               # the English edition behaves as tested
python editions/ja/security-audit/tests/selftest.py   # and so does the Japanese one
python eval/run_eval.py                               # gates, detection, platform, threat intel
python scripts/check_editions.py                      # the editions are the same code
python scripts/validate_release.py                    # versions, CHANGELOGs, style, skill linter
python scripts/build_plugins.py --check               # plugin manifests match the skill
python scripts/check_numbers.py                       # figures in the docs match reality
python scripts/check_mermaid.py                       # every diagram renders
python scripts/check_svg.py                           # every figure is self-contained
```

CI runs the selftests on Ubuntu, Windows and macOS with Python 3.9 and 3.13, and everything else on
Ubuntu ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)).

## Change the English edition, then mirror it

1. Make the change in `security-audit/`.
2. Make the same change in `editions/ja/security-audit/`. Code is copied byte for byte apart from
   comments, docstrings, help text and console messages, which are translated. Machine-read output
   (JSON keys, finding headings the validator reads, report section names the selftest checks)
   follows whatever the English edition does for the Japanese report language.
3. `scripts/check_editions.py` compares the two: Python files must have an identical syntax tree
   once every string is masked, the file trees must match (only the English edition carries
   `README.ja.md` and the plugin files), and versions, agent frontmatter and eval ids must agree.

## CHANGELOG and versions

The versioning rules are at the top of
[`security-audit/CHANGELOG.md`](security-audit/CHANGELOG.md): versions are `1.y.z`, `y` for a
capability users notice, `z` for fixes, refinements and data updates. A release moves the version in
both editions together. [`docs/RELEASING.md`](docs/RELEASING.md) has the procedure.

## Eval cases

A new detector or a fixed false positive gets an eval case: a small fixture under `eval/fixtures/`
and an entry in `eval/cases.json` stating what is **true** of the fixture. Write the expectation
first. A failing case is a gap to fix in the skill, never a fixture to adjust until it passes. Then
run `python eval/run_eval.py` and commit the updated `eval/results/latest.json`; CI fails when the
committed result differs from its own run.

## House style

- **No em-dashes.** Plain hyphens only, everywhere: docs, code, commit messages, release notes.
  `validate_release.py` fails on one.
- **LF line endings** in every text file. `.gitattributes` enforces it on checkout;
  `validate_release.py` fails on a CRLF file.
- **No invented numbers.** A figure in a README is computed by `scripts/check_numbers.py` or quoted
  from a result file it reads. Use a badge label or an inline marker it knows
  (`<!--n:sectors-->9<!--/n-->`) so the figure is checked on every push.
- `README.ja.md` mirrors `README.md`: same sections, same order, Japanese prose.
