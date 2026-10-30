# Contributing

**English** · [日本語](ja/contributing.md)

Issues and pull requests are welcome. The bar is "does it still find what it claims, and only that", and automated gates answer it. The full guide is [CONTRIBUTING.md](https://github.com/nguyenhx2/agent-security-audit/blob/main/CONTRIBUTING.md).

## Report an issue

- **A bug, a false positive, a missed defect class, a wrong standard citation:** open an issue on [GitHub](https://github.com/nguyenhx2/agent-security-audit/issues). Include the skill version (the `VERSION` file in the installed skill), your OS, the depth, and what you expected. Describe audited code with a minimal, made-up example; never paste real secrets, personal data or private code.
- **A vulnerability in the skill itself** (a hostile repository or feed that makes a script run code, write outside its folder, leak a secret or reach the network when it should not): do not open a public issue. Use private vulnerability reporting, as described in [SECURITY.md](https://github.com/nguyenhx2/agent-security-audit/blob/main/SECURITY.md).

Vulnerabilities in the repositories you audit belong to their owners, and issues in the third-party scanners or feeds belong upstream.

## Pull request flow

1. Make the change in the English edition, `security-audit/`, the master.
2. Mirror it in the Japanese edition, `editions/ja/security-audit/`: code byte for byte, with comments, docstrings, help text and console messages translated.
3. A new detector or a fixed false positive gets an eval case: a small fixture under `eval/fixtures/` and an entry in `eval/cases.json` that states what is true of the fixture. Write the expectation first.
4. Run the gates from the repository root; all must exit 0:

   ```bash
   python security-audit/tests/selftest.py
   python editions/ja/security-audit/tests/selftest.py
   python eval/run_eval.py
   python scripts/check_editions.py
   python scripts/validate_release.py
   python scripts/build_plugins.py --check
   python scripts/check_numbers.py
   python scripts/check_mermaid.py
   python scripts/check_svg.py
   ```

5. Open the pull request. CI runs the self-tests on Ubuntu, Windows and macOS with Python 3.9 and 3.13, and everything else on Ubuntu.

House style: no em-dashes (plain hyphens only), LF line endings, and no invented numbers: a figure in the docs is checked by `scripts/check_numbers.py`. Scanner pins are not bumped by hand; the weekly `update-pins` workflow proposes them ([Scanners](scanners.md#the-weekly-update-pins-workflow)).

## Support the project

If this skill saves you time, you can support it through GitHub Sponsors (Sponsor button on the repository).

## See also

- [CONTRIBUTING.md](https://github.com/nguyenhx2/agent-security-audit/blob/main/CONTRIBUTING.md)
- [Releasing](https://github.com/nguyenhx2/agent-security-audit/blob/main/docs/RELEASING.md)
- [eval/README.md](https://github.com/nguyenhx2/agent-security-audit/blob/main/eval/README.md): the offline eval
