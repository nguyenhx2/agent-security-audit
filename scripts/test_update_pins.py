#!/usr/bin/env python3
"""Offline tests for scripts/update_pins.py: no network, the real repo is never written.

Each test copies a frozen snapshot of the files update_pins.py manages (both editions + both READMEs,
scripts/fixtures/update_pins_tree/*.fixture) into a temporary root and drives the script with --offline-fixture scripts/fixtures/update_pins.json and
--today 2026-10-30, so the cooldown cutoff is 2026-10-23. Covered: highest stable tag wins, rc /
floating / arch-suffixed / other-style tags are ignored, a too-new release (by registry or GitHub
date) waits, never a downgrade, a failed lookup exits 2, a non-index tag is refused, --write moves
every location in both editions and is idempotent, and the two editions' scripts still differ only
in strings and comments (the check_editions.py rule).

    py -3 scripts/test_update_pins.py
"""
from __future__ import annotations

import json
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
for _s in (sys.stdout, sys.stderr):
    if hasattr(_s, "reconfigure"):
        _s.reconfigure(encoding="utf-8", errors="replace")

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent
SCRIPT = HERE / "update_pins.py"
FIXTURE = HERE / "fixtures" / "update_pins.json"
# a frozen copy of the managed files with the pins the fixture was written against, so the tests
# keep passing after the real pins move (refresh both together, never one alone)
TREE = HERE / "fixtures" / "update_pins_tree"
EN, JA = "security-audit", "editions/ja/security-audit"
COPY = [f"{ed}/{rel}" for ed in (EN, JA) for rel in (
    "SKILL.md", "scripts/run_scanners.py", "scripts/env_check.py",
    "reference/tooling/scanners.md", "reference/tooling/platforms.md")] + ["README.md", "README.ja.md"]
TODAY = "2026-10-30"
WRITABLE = ["gitleaks", "semgrep", "trivy", "osv-scanner", "checkov", "zizmor"]  # no failing lookups

sys.path.insert(0, str(HERE))
import check_editions  # noqa: E402
import update_pins  # noqa: E402


def run(root: pathlib.Path, *args: str):
    p = subprocess.run([sys.executable, "-B", str(SCRIPT), "--root", str(root), "--offline-fixture", str(FIXTURE),
                        "--today", TODAY, *args], capture_output=True, text=True, encoding="utf-8")
    return p.returncode, p.stdout + p.stderr


class TempRoot(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self._tmp.name)
        for rel in COPY:
            (self.root / rel).parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(TREE / (rel + ".fixture"), self.root / rel)

    def tearDown(self):
        self._tmp.cleanup()

    def read(self, rel: str) -> str:
        return (self.root / rel).read_text(encoding="utf-8")

    def check_json(self, *args: str):
        out = self.root / "out.json"
        rc, log = run(self.root, "--check", "--json", str(out), *args)
        return rc, json.loads(out.read_text(encoding="utf-8")), log


class Selection(TempRoot):
    def test_full_check(self):
        rc, data, log = self.check_json()
        self.assertEqual(rc, 2, log)  # hadolint and mobsfscan lookups fail
        ups = {u["tool"]: u for u in data["updates"]}
        self.assertEqual(sorted(ups), ["gitleaks", "osv-scanner", "semgrep", "zizmor"])
        # highest stable eligible: 1.184.0 is too new, 1.185.0-rc1 / arm64 / develop ignored
        self.assertEqual(ups["semgrep"]["new_tag"], "1.183.0")
        self.assertEqual(ups["semgrep"]["released"], "2026-10-15")
        # tag style kept: 9.2.0 (no v) and v9.1.0-rc.1 ignored
        self.assertEqual(ups["gitleaks"]["new_tag"], "v9.0.0")
        self.assertEqual(ups["zizmor"]["new_tag"], "1.32.0")  # v1.40.0 is the other style
        self.assertEqual(ups["osv-scanner"]["new_digest"], "sha256:" + "4" * 64)
        # untrusted html_url replaced by a constructed GitHub URL
        self.assertEqual(ups["gitleaks"]["notes_url"], "https://github.com/gitleaks/gitleaks/releases/tag/v9.0.0")
        self.assertEqual(ups["semgrep"]["notes_url"], "https://github.com/semgrep/semgrep/releases/tag/v1.183.0")
        cur = {c["tool"]: c for c in data["current"]}
        # trivy 0.77.0: registry date is old enough but the GitHub release is newer -> still cooling
        self.assertEqual(cur["trivy"]["status"], "cooldown")
        # checkov: the registry only lists older tags -> current, never a downgrade
        self.assertEqual(cur["checkov"]["status"], "current")
        self.assertEqual(cur["checkov"]["tag"], "3.3.29")
        errs = {e["tool"]: e["error"] for e in data["errors"]}
        self.assertEqual(sorted(errs), ["hadolint", "mobsfscan"])
        self.assertIn("503", errs["hadolint"])
        self.assertIn("multi-arch index", errs["mobsfscan"])
        self.assertNotIn("hadolint", cur)
        self.assertEqual(data["checked"], TODAY)
        self.assertEqual(data["cooldown_days"], 7)
        for k in ("tool", "image", "old_tag", "new_tag", "old_digest", "new_digest", "released", "notes_url"):
            self.assertIn(k, data["updates"][0])

    def test_exit_codes(self):
        self.assertEqual(run(self.root, "--check", "--tool", "semgrep")[0], 10)
        self.assertEqual(run(self.root, "--check", "--tool", "checkov", "trivy")[0], 0)
        self.assertEqual(run(self.root, "--check", "--tool", "hadolint")[0], 2)
        self.assertEqual(run(self.root, "--check", "--tool", "semgrep", "hadolint")[0], 2)

    def test_cooldown_option(self):
        rc, data, log = self.check_json("--tool", "semgrep", "trivy", "--cooldown-days", "0")
        self.assertEqual(rc, 10, log)
        ups = {u["tool"]: u["new_tag"] for u in data["updates"]}
        self.assertEqual(ups, {"semgrep": "1.184.0", "trivy": "0.77.0"})
        rc, data, _ = self.check_json("--tool", "semgrep", "--cooldown-days", "30")
        self.assertEqual((rc, data["updates"]), (0, []))  # 1.182.0 is 20 days old

    def test_never_downgrade_unit(self):
        self.assertEqual(update_pins.stable_tags(["1.2.3", "v1.3.0", "1.10.0", "1.11.0-rc1", "latest",
                                                  "1.9.9-amd64", "sha-1234567", "2.0", "1.2.3.4"], ""),
                         ["1.10.0", "1.2.3"])
        self.assertEqual(update_pins.stable_tags(["v1.2.3", "1.3.0"], "v"), ["v1.2.3"])
        self.assertIsNone(update_pins.parse_date("1970-01-01T00:00:00Z"))
        self.assertIsNone(update_pins.parse_date("not a date"))
        self.assertEqual(str(update_pins.parse_date("2026-10-02T00:00:00+09:00")), "2026-10-01 15:00:00+00:00")
        self.assertEqual(update_pins.clean("a\x1b[31mb\nc"), "a [31mb c")


class Write(TempRoot):
    def snapshot(self):
        return {rel: (self.root / rel).read_bytes() for rel in COPY}

    def test_write_every_location_and_idempotent(self):
        before = self.snapshot()
        pr = self.root / "pr.md"
        rc, log = run(self.root, "--write", "--tool", *WRITABLE, "--pr-body", str(pr), "--json", str(self.root / "w.json"))
        self.assertEqual(rc, 10, log)
        for ed in (EN, JA):
            rs = self.read(f"{ed}/scripts/run_scanners.py")
            self.assertIn('"ghcr.io/gitleaks/gitleaks:v9.0.0@sha256:' + "1" * 64 + '"', rs)
            self.assertIn('"semgrep/semgrep:1.183.0@sha256:' + "2" * 64 + '"', rs)
            self.assertIn('"ghcr.io/google/osv-scanner:v2.8.0@sha256:' + "4" * 64 + '"', rs)
            self.assertIn('"ghcr.io/zizmorcore/zizmor:1.32.0@sha256:' + "5" * 64 + '"', rs)
            self.assertIn("aquasec/trivy:0.76.1@sha256:790fd66d", rs)  # cooling: untouched
            self.assertIn("bridgecrew/checkov:3.3.29@sha256:3cc125b5", rs)
            self.assertIn(f'PINS_VERIFIED = "{TODAY}"', rs)
            env = self.read(f"{ed}/scripts/env_check.py")
            for s in ("github.com/zricethezav/gitleaks/v9@v9.0.0", "semgrep==1.183.0",
                      "github.com/google/osv-scanner/v2/cmd/osv-scanner@v2.8.0", "zizmor==1.32.0",
                      "cargo install zizmor --version 1.32.0", "checkov==3.3.29"):
                self.assertIn(s, env, f"{ed} env_check.py: {s}")
            plat = self.read(f"{ed}/reference/tooling/platforms.md")
            self.assertEqual(plat.count("semgrep==1.183.0"), 2)
            for s in ("gitleaks/v9@v9.0.0", "osv-scanner@v2.8.0", "zizmor==1.32.0"):
                self.assertIn(s, plat)
            sc = self.read(f"{ed}/reference/tooling/scanners.md")
            for s in ("ghcr.io/gitleaks/gitleaks:v9.0.0`", "semgrep/semgrep:1.183.0`",
                      "ghcr.io/google/osv-scanner:v2.8.0`", "ghcr.io/zizmorcore/zizmor:1.32.0`", "aquasec/trivy:0.76.1`"):
                self.assertIn(s, sc)
            skill = self.read(f"{ed}/SKILL.md")
            self.assertIn(f'scanner-pins-verified: "{TODAY}"', skill)
            self.assertIn('standards-verified: "2026-10-26"', skill)  # not ours to move
            for rel in (f"{ed}/scripts/run_scanners.py", f"{ed}/scripts/env_check.py",
                        f"{ed}/reference/tooling/scanners.md", f"{ed}/reference/tooling/platforms.md"):
                text = self.read(rel)
                for old in ("8.30.1", "1.181.0", "2.7.0", "1.31.1"):
                    self.assertNotRegex(text, r"(?<![\w.])v?" + re.escape(old) + r"(?![\w.])", f"{rel} still has {old}")
        self.assertIn(f"scanner pins verified {TODAY}", self.read(f"{EN}/SKILL.md"))
        self.assertIn(f"スキャナのピン検証日 {TODAY}", self.read(f"{JA}/SKILL.md"))
        self.assertIn(f"(pins verified {TODAY})", self.read(f"{EN}/reference/tooling/scanners.md"))
        self.assertIn(f"ピン留めは {TODAY} に検証", self.read(f"{JA}/reference/tooling/scanners.md"))
        for rel, date_s in (("README.md", f"(last: {TODAY})"), ("README.ja.md", f"（最新の検証日：{TODAY}）")):
            text = self.read(rel)
            self.assertIn(date_s, text)
            for s in ("| Semgrep 1.183.0 |", "| Gitleaks 9.0.0 |", "| OSV-Scanner 2.8.0 |", "| zizmor 1.32.0 |",
                      "| Trivy 0.76.1 |", "| Checkov 3.3.29 |"):
                self.assertIn(s, text, f"{rel}: {s}")
        # only the managed text changed; line endings untouched; no em-dash introduced
        after = self.snapshot()
        for rel in COPY:
            self.assertEqual(before[rel].count(b"\r\n"), after[rel].count(b"\r\n"), rel)
            self.assertEqual(before[rel].count("\u2014".encode()), after[rel].count("\u2014".encode()), rel)
        # editions still differ only in strings and comments
        for rel in ("scripts/run_scanners.py", "scripts/env_check.py"):
            self.assertEqual(check_editions.norm(self.read(f"{EN}/{rel}")), check_editions.norm(self.read(f"{JA}/{rel}")), rel)
        self.assertEqual(update_pins.read_pins(self.root)["semgrep"].split("@")[0], "semgrep/semgrep:1.183.0")
        body = pr.read_text(encoding="utf-8")
        self.assertNotIn("\u2014", body)
        self.assertIn("human must review", body)
        self.assertIn("https://github.com/semgrep/semgrep/releases/tag/v1.183.0", body)
        self.assertIn("スキャナのピンを 2026-10-30 に更新", body)
        self.assertIn("semgrep 1.181.0 -> 1.183.0", body)
        self.assertIn("Cooldown: 7 days", body)
        self.assertNotRegex(json.dumps(json.loads(self.read("w.json"))["stale_mentions"]), r"\w")  # nothing missed

        # second run: nothing to do, byte-identical files
        snap = self.snapshot()
        rc, log = run(self.root, "--write", "--tool", *WRITABLE)
        self.assertEqual(rc, 0, log)
        self.assertEqual(snap, self.snapshot())

    def test_write_with_failed_lookup(self):
        rc, log = run(self.root, "--write", "--tool", "semgrep", "hadolint")
        self.assertEqual(rc, 2, log)  # the failure wins the exit code, the good update is still written
        self.assertIn("semgrep/semgrep:1.183.0@", self.read(f"{EN}/scripts/run_scanners.py"))
        self.assertIn("hadolint/hadolint:v2.15.1@", self.read(f"{EN}/scripts/run_scanners.py"))

    def test_write_refuses_partial_plan(self):
        rel = f"{JA}/scripts/run_scanners.py"
        text = self.read(rel).replace("81474464c1f0", "000000000000")  # JA pin drifted: IMAGES differ
        (self.root / rel).write_bytes(text.encode("utf-8"))
        before = self.snapshot()
        rc, log = run(self.root, "--write", "--tool", "semgrep")
        self.assertNotEqual(rc, 10, log)
        self.assertEqual(before, self.snapshot())


if __name__ == "__main__":
    unittest.main(verbosity=2)
