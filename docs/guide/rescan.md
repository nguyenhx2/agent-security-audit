# Re-scan and fix verification

**English** · [日本語](ja/rescan.md)

The auditor never patches. You fix the findings, then ask the skill to verify the fixes. That is Phase 8; it runs only on request.

## When to run it

After you have applied fixes to the audited repositories, ask in the same audit context, for example:

```text
re-scan to verify the fixes
I fixed FIND-SHOPAPI-001 to 004, please verify
```

Phase 8 needs the audit's `work/` folder, which the default cleanup keeps. If the audit was run with `--purge-work`, the scanner pins and source findings are gone, and a re-scan is a new audit.

## What it does

1. **Re-runs the scanners with the same images.** Per repository, `run_scanners.py` writes into `work/<repo>/rescan-<new ts>/`, with every scanner pinned to the exact `image:tag@sha256` recorded in the first run's `scanners.json` (`--pin tool=...`). Then `normalize_findings.py` runs on that folder.
2. **Re-reads every manual finding.** Each `path:line` anchor is opened again in the current code.
3. **Updates the status at the source.** `status` and `verified` are changed in `work/findings.json` (and in each `findings_<L>.json` for other languages). Edits made by hand in `findings/<lang>/*.md` would be overwritten by the next rebuild, so the JSON is the place.
4. **Rebuilds every report set.** Per language: `new_finding.py --force` (translated sets with `--source`), `build_report.py --force --fill`, `validate_findings.py`, and the chosen HTML and Excel renders.

## When a finding closes

A finding closes only when both are true:

- it **no longer reproduces**: the scanner no longer reports it, or the re-read shows the defect is gone; and
- the **catching rule still exists**: the rule that found it is still emitted by the same scanner image, so the silence is not ruleset drift.

A finding never closes on assertion ("we fixed it"). `accepted-risk` and `false-positive` are set only with your recorded decision and reason.

```text
open -> (you fix) -> re-scan with the same image digests (+ re-read for manual findings)
     -> reproduces?  yes -> stays open
                     no  -> catching rule still present? -> closed
```

## Why the same digests matter

If the re-scan used a newer scanner, a finding could disappear because a rule changed, not because the code was fixed. Pinning by digest makes the re-scan run exactly the same scanner build as the first scan. Rule packs and vulnerability databases, however, update independently of image tags.

Some data still moves:

- **Offline mode** (`--offline`) keeps the Trivy and zizmor databases fixed but skips OSV-Scanner. Re-run OSV-Scanner online for OSV and `MAL-*` findings.
- **Semgrep's `p/default`** rule pack is fetched even offline, so it is not frozen. The skill checks that a closed finding's rule id is still emitted.

## What changes in the reports

The rebuilt reports carry the new statuses and `verified` dates, and the Excel Summary's status chart and counts follow. The rebuilt workbook replaces the previous one at the same path, so keep a copy first if your team typed into its Owner, Due date or Notes columns, and carry those entries over. The re-scan output stays beside the first run under `work/<repo>/rescan-<ts>/`.

## See also

- [Scanners](scanners.md#why-pins-are-digests)
- [Findings and reports](reports.md)
- [`triage.md`](https://github.com/nguyenhx2/agent-security-audit/blob/main/security-audit/reference/method/triage.md#separation-of-duties-and-lifecycle): the finding lifecycle
