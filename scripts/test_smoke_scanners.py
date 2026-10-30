#!/usr/bin/env python3
"""Offline unit tests for scripts/smoke_scanners.py - no container engine, no network.

The scanners themselves only run in CI (docker on ubuntu-latest). What can be proven here: the
--pins-json to --pin mapping, the fixture build (suffixes, .github, fake tokens, git history), and
the pass / fail logic against canned scanner output shaped like each scanner's real SARIF, as
run_scanners.py writes it into raw/. One test drives main() end to end with the runner replaced by
a stub that writes those canned files, so the real normalize_findings.py reads them too.

Usage:
  python scripts/test_smoke_scanners.py [-v]
"""
from __future__ import annotations

import sys

sys.dont_write_bytecode = True
for _s in (sys.stdout, sys.stderr):
    if hasattr(_s, "reconfigure"):
        _s.reconfigure(encoding="utf-8", errors="replace")

import copy
import json
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path, PurePosixPath

sys.path.insert(0, str(Path(__file__).resolve().parent))
import smoke_scanners as smoke  # noqa: E402

IMAGES = smoke.runner_literal("IMAGES")
OUTPUTS = smoke.runner_literal("EXPECTED")
EXPECT = json.loads(smoke.EXPECT.read_text(encoding="utf-8"))
D1 = "sha256:" + "1" * 64
D2 = "sha256:" + "a" * 64


# ------------------------------------------------------------------ canned scanner output

def sarif(driver: str, rules: list, results: list) -> dict:
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": driver, "rules": rules}}, "results": results}]}


def result(rule_id, uri, msg="", **extra) -> dict:
    r = {"ruleId": rule_id, "level": "error", "message": {"text": msg or rule_id},
         "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri},
                                             "region": {"startLine": 3, "startColumn": 1}}}]}
    r.update(extra)
    return r


def canned() -> dict:
    """raw/ relative path -> SARIF document, one realistic hit per planted defect."""
    gl_rules = [{"id": "github-pat", "shortDescription": {"text": "Uncovered a GitHub Personal Access Token, "
                                                                  "potentially leading to unauthorized repository access."}}]
    gl_fp = {"commitSha": "3f1c0de0a1b2c3d4e5f60718293a4b5c6d7e8f90", "author": "smoke fixture",
             "email": "smoke-fixture@example.invalid", "date": "2020-01-01T00:00:00Z"}
    trivy_rules = [
        {"id": "CVE-2021-23337", "name": "LanguageSpecificPackageVulnerability",
         "shortDescription": {"text": "nodejs-lodash: command injection via template"},
         "help": {"text": "Vulnerability CVE-2021-23337\nSeverity: HIGH\nPackage: lodash\nFixed Version: 4.17.21"},
         "properties": {"tags": ["vulnerability", "security", "HIGH"], "security-severity": "7.2"}},
        {"id": "DS002", "name": "Misconfiguration", "shortDescription": {"text": "Image user should not be 'root'"},
         "properties": {"tags": ["misconfiguration", "security", "HIGH"]}},
    ]
    return {
        "gitleaks-git.sarif": sarif("gitleaks", gl_rules, [
            result("github-pat", "legacy/deploy.env", "github-pat has detected secret for file legacy/deploy.env.",
                   partialFingerprints=gl_fp),
            result("github-pat", "config/settings.ini", "github-pat has detected secret for file config/settings.ini.",
                   partialFingerprints=gl_fp)]),
        "gitleaks-dir.sarif": sarif("gitleaks", gl_rules, [
            result("github-pat", "config/settings.ini", "github-pat has detected secret for file config/settings.ini.")]),
        "semgrep.sarif": sarif("Semgrep OSS", [
            {"id": "python.lang.security.audit.subprocess-shell-true.subprocess-shell-true",
             "name": "python.lang.security.audit.subprocess-shell-true.subprocess-shell-true",
             "shortDescription": {"text": "Semgrep Finding: python.lang.security.audit.subprocess-shell-true"},
             "properties": {"tags": ["CWE-78: Improper Neutralization of Special Elements used in an OS Command"]}}],
            [result("python.lang.security.audit.subprocess-shell-true.subprocess-shell-true", "app/views.py",
                    "Found 'subprocess' function 'check_output' with 'shell=True'.")]),
        "trivy.sarif": sarif("Trivy", trivy_rules, [
            result("CVE-2021-23337", "web/package-lock.json",
                   "Package: lodash\nInstalled Version: 4.17.4\nVulnerability CVE-2021-23337\nSeverity: HIGH\n"
                   "Fixed Version: 4.17.21\nLink: [CVE-2021-23337](https://avd.aquasec.com/nvd/cve-2021-23337)",
                   ruleIndex=0),
            result("DS002", "Dockerfile", "Artifact: Dockerfile\nType: dockerfile\nVulnerability DS002\n"
                                          "Severity: HIGH\nMessage: Last USER command in Dockerfile should not be 'root'",
                   ruleIndex=1)]),
        "osv-scanner.sarif": sarif("osv-scanner", [
            {"id": "GHSA-35jh-r3h4-6jhm", "shortDescription": {"text": "GHSA-35jh-r3h4-6jhm: Command Injection in lodash"},
             "deprecatedIds": ["CVE-2021-23337"], "help": {"text": "lodash 4.17.4 -> 4.17.21", "markdown": ""}}],
            [result("GHSA-35jh-r3h4-6jhm", "file:///src/web/package-lock.json",
                    "Package 'lodash@4.17.4' is vulnerable to 'GHSA-35jh-r3h4-6jhm' (also known as 'CVE-2021-23337').")]),
        "checkov/results_sarif.sarif": sarif("checkov", [
            {"id": "CKV_AWS_24", "name": "Ensure no security groups allow ingress from 0.0.0.0:0 to port 22",
             "shortDescription": {"text": "Ensure no security groups allow ingress from 0.0.0.0:0 to port 22"}}],
            [result("CKV_AWS_24", "infra/main.tf",
                    "Ensure no security groups allow ingress from 0.0.0.0:0 to port 22")]),
        "hadolint.sarif": {"version": "2.1.0", "runs": [
            {"tool": {"driver": {"name": "Hadolint", "fullName": "Haskell Dockerfile Linter"}},
             "results": [result("DL3007", "/src/Dockerfile", "Using latest is prone to errors if the image will "
                                                             "ever update. Pin the version explicitly to a release tag")]}]},
        "zizmor.sarif": sarif("zizmor", [{"id": "zizmor/dangerous-triggers",
                                          "shortDescription": {"text": "use of fundamentally insecure workflow trigger"}}],
                              [result("zizmor/dangerous-triggers", ".github/workflows/pr-target.yml",
                                      "use of fundamentally insecure workflow trigger")]),
        "mobsfscan.sarif": sarif("mobsfscan", [{"id": "android_logging",
                                                "shortDescription": {"text": "The App logs information."}}],
                                 [result("android_logging",
                                         "android/app/src/main/java/com/acme/smoke/MainActivity.java",
                                         "The App logs information. Please ensure that sensitive information is never logged.")]),
    }


OK_EXIT = {"gitleaks": {"exit_code": 0, "exit_code_dir": 0}, "semgrep": {"exit_code": 0}, "trivy": {"exit_code": 0},
           "osv-scanner": {"exit_code": 1}, "checkov": {"exit_code": 0}, "hadolint": {},
           "zizmor": {"exit_code": 14}, "mobsfscan": {"exit_code": 1}}


def manifest(images=None) -> dict:
    images = images or IMAGES
    tools = []
    for t in IMAGES:
        rec = {"tool": t, "mode": "docker", "status": "ok", "image": images[t],
               "digest": images[t].split(":")[0] + "@" + images[t].split("@")[-1],
               "outputs": [o for o in OUTPUTS[t]], "stderr_tail": "", "seconds": 1.0}
        rec.update(OK_EXIT[t])
        tools.append(rec)
    return {"mode": "docker", "mount_file_count": 12, "tools": tools}


def write_raw(raw: Path, docs: dict) -> None:
    for rel, doc in docs.items():
        p = raw / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(doc if isinstance(doc, str) else json.dumps(doc), encoding="utf-8")
    (raw / "semgrep.json").write_text(json.dumps({"results": [], "errors": []}), encoding="utf-8")


# ------------------------------------------------------------------ tests

class Pins(unittest.TestCase):
    def test_update_pins_format_maps_to_pin_args(self):
        data = {"checked": "2026-10-30", "updates": [
            {"tool": "trivy", "image": "aquasec/trivy", "old_tag": "0.76.1", "new_tag": "0.77.0",
             "old_digest": "sha256:" + "0" * 64, "new_digest": D1},
            {"tool": "gitleaks", "image": "ghcr.io/gitleaks/gitleaks", "new_tag": "v8.31.0", "new_digest": D2}]}
        pins = smoke.pins_from_updates(data, set(IMAGES))
        self.assertEqual(pins, {"trivy": f"aquasec/trivy:0.77.0@{D1}",
                                "gitleaks": f"ghcr.io/gitleaks/gitleaks:v8.31.0@{D2}"})
        self.assertEqual(smoke.pin_args(pins), ["--pin", f"gitleaks=ghcr.io/gitleaks/gitleaks:v8.31.0@{D2}",
                                                "--pin", f"trivy=aquasec/trivy:0.77.0@{D1}"])

    def test_pin_passes_run_scanners_own_check(self):
        # run_scanners.py refuses ':latest' and untagged pins; every mapped ref must get through.
        ref = smoke.pins_from_updates([{"tool": "zizmor", "image": "ghcr.io/zizmorcore/zizmor",
                                        "new_tag": "1.32.0", "new_digest": D1}], set(IMAGES))["zizmor"]
        self.assertFalse(ref.endswith(":latest"))
        self.assertTrue(":" in ref.split("/")[-1] and "@sha256:" in ref)

    def test_bare_list_and_digest_without_prefix(self):
        pins = smoke.pins_from_updates([{"tool": "semgrep", "image": "semgrep/semgrep", "new_tag": "1.190.0",
                                         "new_digest": "b" * 64}], set(IMAGES))
        self.assertEqual(pins["semgrep"], "semgrep/semgrep:1.190.0@sha256:" + "b" * 64)

    def test_empty_updates_means_current_pins(self):
        self.assertEqual(smoke.pins_from_updates({"updates": []}, set(IMAGES)), {})
        self.assertEqual(smoke.pin_args({}), [])

    def test_rejected(self):
        good = {"tool": "trivy", "image": "aquasec/trivy", "new_tag": "0.77.0", "new_digest": D1}
        bad = [
            {**good, "tool": "nmap"},
            {**good, "new_tag": "latest"},
            {**good, "new_tag": ""},
            {**good, "new_tag": "0.77.0; rm -rf /"},
            {**good, "new_digest": "sha256:xyz"},
            {**good, "new_digest": None},
            {**good, "image": "aquasec/trivy:0.77.0"},
            {**good, "image": "aquasec/trivy@" + D1},
            {**good, "image": "Aquasec/Trivy"},
            {**good, "image": "--entrypoint=sh"},
        ]
        for u in bad:
            with self.subTest(u=u), self.assertRaises(smoke.PinError):
                smoke.pins_from_updates({"updates": [u]}, set(IMAGES))
        with self.assertRaises(smoke.PinError):
            smoke.pins_from_updates({"updates": [good, {**good, "new_digest": D2}]}, set(IMAGES))
        with self.assertRaises(smoke.PinError):
            smoke.pins_from_updates({"nope": 1}, set(IMAGES))
        with self.assertRaises(smoke.PinError):
            smoke.pins_from_updates({"updates": ["trivy"]}, set(IMAGES))


class Fixture(unittest.TestCase):
    def test_fake_token_shape(self):
        t = smoke.fake_token("tree")
        self.assertRegex(t, r"^ghp_[0-9A-Za-z]{36}$")
        self.assertEqual(t, smoke.fake_token("tree"))
        self.assertNotEqual(t, smoke.fake_token("history"))

    def test_dest_mapping(self):
        self.assertEqual(smoke.fixture_dest(PurePosixPath("_github/workflows/a.yml.fixture")).as_posix(),
                         ".github/workflows/a.yml")
        self.assertEqual(smoke.fixture_dest(PurePosixPath("Dockerfile.fixture")).as_posix(), "Dockerfile")
        with self.assertRaises(ValueError):
            smoke.fixture_dest(PurePosixPath("app/views.py"))

    def test_tree_is_inert_in_this_repository(self):
        # Every file carries the suffix (CodeQL / Dependabot never see .py, .yml, lockfiles), and no
        # committed file holds a token: only placeholders.
        for p in smoke.TREE.rglob("*"):
            if p.is_file():
                self.assertTrue(p.name.endswith(smoke.FIXTURE_SUFFIX), p)
                raw = p.read_bytes()
                self.assertNotIn(b"\r\n", raw, p)
                self.assertNotIn(chr(0x2014).encode(), raw, p)
                self.assertIsNone(re.search(rb"gh[pousr]_[0-9A-Za-z]{30,}", raw), p)

    def test_expect_covers_every_pinned_scanner(self):
        self.assertEqual(set(EXPECT["tools"]), set(IMAGES))
        for tool, spec in EXPECT["tools"].items():
            self.assertTrue(spec["checks"], tool)
            for c in spec["checks"]:
                self.assertIn(c["output"], OUTPUTS[tool], f"{tool}: {c['output']} is not a run_scanners output")
                self.assertTrue(c["any_of"], tool)

    def test_build_tree(self):
        d = Path(tempfile.mkdtemp())
        try:
            written = smoke.build_fixture(d / "repo", d, EXPECT["history_only"], git=False)
            for want in (".github/workflows/pr-target.yml", "Dockerfile", "requirements.txt", "web/package-lock.json",
                         "infra/main.tf", "app/views.py", "config/settings.ini", "legacy/deploy.env",
                         "android/app/src/main/AndroidManifest.xml"):
                self.assertIn(want, written)
            ini = (d / "repo" / "config" / "settings.ini").read_text(encoding="utf-8")
            self.assertIn(smoke.fake_token("tree"), ini)
            for p in (d / "repo").rglob("*"):
                if p.is_file():
                    self.assertNotIn(b"@@FAKE_", p.read_bytes(), p)
                    self.assertNotIn(b"\r\n", p.read_bytes(), p)
            json.loads((d / "repo" / "web" / "package-lock.json").read_text(encoding="utf-8"))
        finally:
            smoke.rmtree(d)

    def test_history_only_must_exist(self):
        d = Path(tempfile.mkdtemp())
        try:
            with self.assertRaises(RuntimeError):
                smoke.build_fixture(d / "repo", d, ["nope/missing.env"], git=False)
        finally:
            smoke.rmtree(d)

    @unittest.skipUnless(shutil.which("git"), "git not on PATH")
    def test_git_history(self):
        d = Path(tempfile.mkdtemp())
        try:
            repo = d / "repo"
            smoke.build_fixture(repo, d, EXPECT["history_only"])
            env = smoke.git_env(d)
            log = subprocess.run(["git", "log", "--all", "--name-status", "--format=%s"], cwd=repo, env=env,
                                 capture_output=True, text=True, check=True).stdout
            self.assertIn("A\tlegacy/deploy.env", log)
            self.assertIn("D\tlegacy/deploy.env", log)
            self.assertFalse((repo / "legacy" / "deploy.env").exists())
            self.assertTrue((repo / "config" / "settings.ini").exists())
            status = subprocess.run(["git", "status", "--porcelain"], cwd=repo, env=env,
                                    capture_output=True, text=True, check=True).stdout
            self.assertEqual(status.strip(), "")
            shown = subprocess.run(["git", "show", "HEAD~1:legacy/deploy.env"], cwd=repo, env=env,
                                   capture_output=True, text=True, check=True).stdout
            self.assertIn(smoke.fake_token("history"), shown)
        finally:
            smoke.rmtree(d)


class Evaluate(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.raw = self.dir / "raw"
        self.docs = canned()

    def tearDown(self):
        smoke.rmtree(self.dir)

    def rows(self, man=None, tools=None, expect=None):
        write_raw(self.raw, self.docs)
        return smoke.evaluate(man or manifest(), self.raw, expect or EXPECT, tools or list(IMAGES), IMAGES, OUTPUTS)

    def row(self, tool, **kw):
        return next(r for r in self.rows(**kw) if r["tool"] == tool)

    def test_all_pass(self):
        rows = self.rows()
        for r in rows:
            self.assertTrue(r["ok"], r)
            self.assertTrue(r["ran"] and r["expected_found"], r)
        self.assertEqual(smoke.overall_exit(rows, []), smoke.EXIT_PASS)
        self.assertEqual(self.row("osv-scanner")["matched"], ["GHSA-35jh-r3h4-6jhm"])
        self.assertIn("DS002", self.row("trivy")["matched"])

    def test_missed_defect_fails(self):
        self.docs["zizmor.sarif"]["runs"][0]["results"] = []
        r = self.row("zizmor")
        self.assertTrue(r["ran"])
        self.assertFalse(r["expected_found"] or r["ok"])
        self.assertIn("dangerous-triggers", r["detail"])
        self.assertEqual(smoke.overall_exit([r], []), smoke.EXIT_FAIL)

    def test_renamed_rule_fails_until_expect_is_updated(self):
        res = self.docs["hadolint.sarif"]["runs"][0]["results"][0]
        res["ruleId"] = "DL9999"
        res["message"]["text"] = "something else"
        self.assertFalse(self.row("hadolint")["ok"])
        expect = copy.deepcopy(EXPECT)
        expect["tools"]["hadolint"]["checks"][0]["any_of"].append("DL9999")
        self.assertTrue(self.row("hadolint", expect=expect)["ok"])

    def test_history_secret_must_come_from_history_scan(self):
        # Working-tree hit only: the history pass found nothing at legacy/ -> gitleaks git mode broke.
        self.docs["gitleaks-git.sarif"]["runs"][0]["results"] = \
            [r for r in self.docs["gitleaks-git.sarif"]["runs"][0]["results"]
             if "legacy" not in r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]]
        r = self.row("gitleaks")
        self.assertFalse(r["ok"])
        self.assertIn("legacy/deploy.env", r["detail"])

    def test_both_trivy_checks_required(self):
        self.docs["trivy.sarif"]["runs"][0]["results"] = self.docs["trivy.sarif"]["runs"][0]["results"][:1]
        r = self.row("trivy")
        self.assertFalse(r["ok"])
        self.assertIn("DS001", r["detail"])

    def test_cve_only_in_osv_aliases(self):
        doc = self.docs["osv-scanner.sarif"]
        doc["runs"][0]["tool"]["driver"]["rules"][0].update(id="PYSEC-2099-1", shortDescription={"text": "x"})
        res = doc["runs"][0]["results"][0]
        res["ruleId"] = "PYSEC-2099-1"
        res["message"]["text"] = "Package 'requests@2.19.1' is vulnerable"
        # matched through rule.deprecatedIds (CVE-2021-23337), the alias list osv-scanner emits
        self.assertTrue(self.row("osv-scanner")["ok"])

    def test_rule_by_index_only(self):
        res = self.docs["trivy.sarif"]["runs"][0]["results"][0]
        del res["ruleId"]
        res["message"]["text"] = "Package: lodash"
        r = self.row("trivy")
        self.assertTrue(r["ok"], r)
        self.assertIn("CVE-2021-23337", r["matched"])

    def test_unparseable_and_missing_output(self):
        self.docs["mobsfscan.sarif"] = "{not json"
        r = self.row("mobsfscan")
        self.assertFalse(r["ok"])
        self.assertIn("not valid JSON", r["detail"])
        self.docs["mobsfscan.sarif"] = {"version": "2.1.0"}
        self.assertIn("not SARIF", self.row("mobsfscan")["detail"])
        del self.docs["mobsfscan.sarif"]
        (self.raw / "mobsfscan.sarif").unlink()  # written by the previous call
        self.assertIn("missing", self.row("mobsfscan")["detail"])

    def test_hostile_shapes_do_not_crash(self):
        self.docs["checkov/results_sarif.sarif"] = {"runs": [None, {"tool": "x", "results": [None, 7, {"ruleId": 5,
                                                    "locations": "nope", "message": []}]}]}
        r = self.row("checkov")
        self.assertFalse(r["ok"])

    def test_empty_hadolint_merge_fails(self):
        # run_scanners merges per-Dockerfile output; a crashing hadolint still leaves this shell (status ok).
        self.docs["hadolint.sarif"] = {"version": "2.1.0", "runs": []}
        r = self.row("hadolint")
        self.assertTrue(r["ran"])
        self.assertFalse(r["ok"])

    def test_crash_exit_code_fails_even_with_findings(self):
        man = manifest()
        rec = next(t for t in man["tools"] if t["tool"] == "semgrep")
        rec.update(exit_code=2, stderr_tail="semgrep: fatal error: rule parse")
        r = self.row("semgrep", man=man)
        self.assertTrue(r["expected_found"])
        self.assertFalse(r["ok"])
        self.assertIn("exit_code 2", r["detail"])
        man = manifest()
        next(t for t in man["tools"] if t["tool"] == "gitleaks")["exit_code_dir"] = 1
        self.assertIn("exit_code_dir 1", self.row("gitleaks", man=man)["detail"])

    def test_not_ran(self):
        man = manifest()
        next(t for t in man["tools"] if t["tool"] == "checkov").update(status="failed", reason="pull failed: manifest unknown")
        r = self.row("checkov", man=man)
        self.assertFalse(r["ran"] or r["ok"])
        self.assertIn("pull failed", r["detail"])
        man["tools"] = [t for t in man["tools"] if t["tool"] != "zizmor"]
        self.assertIn("did not report", self.row("zizmor", man=man)["detail"])
        r = self.row("trivy", man={"fatal": "mount verification failed: /src resolved to 0 files", "tools": []})
        self.assertIn("mount verification failed", r["detail"])

    def test_subset_and_no_spec(self):
        rows = self.rows(tools=["trivy"])
        self.assertEqual([r["tool"] for r in rows], ["trivy"])
        expect = copy.deepcopy(EXPECT)
        del expect["tools"]["trivy"]
        self.assertIn("no expectations", self.row("trivy", expect=expect)["detail"])
        self.assertEqual(smoke.overall_exit([], []), smoke.EXIT_FAIL)

    def test_table_and_short_ref(self):
        self.assertEqual(smoke.short_ref(f"aquasec/trivy:0.77.0@{D2}"), "aquasec/trivy:0.77.0@sha256:aaaaaaaaaaaa")
        out = smoke.table(self.rows())
        self.assertIn("gitleaks", out)
        self.assertIn("found", out)


class MainEndToEnd(unittest.TestCase):
    """main() with the engine probe and the runner stubbed; the fixture build, git and the real
    normalize_findings.py run for real."""

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self._detect, self._invoke = smoke.detect_engine, smoke.invoke
        self.seen = []

    def tearDown(self):
        smoke.detect_engine, smoke.invoke = self._detect, self._invoke
        smoke.rmtree(self.dir)

    def fake_runner(self, docs, images=None):
        real_invoke = self._invoke

        def run(cmd, timeout):
            if Path(cmd[2]).name != "run_scanners.py":
                return real_invoke(cmd, timeout)  # normalize_findings.py: the real one
            self.seen.append(cmd)
            repo, out = Path(cmd[3]), Path(cmd[cmd.index("--out") + 1])
            self.assertTrue((repo / ".git").is_dir())
            self.assertTrue((repo / ".github" / "workflows" / "pr-target.yml").is_file())
            pins = dict(cmd[i + 1].split("=", 1) for i, c in enumerate(cmd) if c == "--pin")
            tools = cmd[cmd.index("--tools") + 1].split(",")
            write_raw(out / "raw", docs)
            man = manifest({**IMAGES, **pins, **(images or {})})
            man["tools"] = [t for t in man["tools"] if t["tool"] in tools]
            (out / "scanners.json").write_text(json.dumps(man), encoding="utf-8")
            return 0, "mode=docker ok=[...]", ""
        return run

    @unittest.skipUnless(shutil.which("git"), "git not on PATH")
    def test_pass_with_candidate_pins(self):
        pins_file = self.dir / "pins.json"
        pins_file.write_text(json.dumps({"updates": [
            {"tool": "trivy", "image": "aquasec/trivy", "old_tag": "0.76.1", "new_tag": "0.77.0", "new_digest": D1},
            {"tool": "mobsfscan", "image": "opensecurity/mobsfscan", "new_tag": "1.0.2", "new_digest": D2}]}),
            encoding="utf-8")
        smoke.detect_engine = lambda: {"daemon_ok": True, "engine": "docker"}
        smoke.invoke = self.fake_runner(canned())
        out = self.dir / "smoke.json"
        rc = smoke.main(["--pins-json", str(pins_file), "--json", str(out), "--tool", "trivy,zizmor",
                         "--tool", "gitleaks"])
        self.assertEqual(rc, 0)
        cmd = self.seen[0]
        self.assertIn("--mode", cmd)
        self.assertEqual(cmd[cmd.index("--mode") + 1], "container")
        self.assertIn(f"trivy=aquasec/trivy:0.77.0@{D1}", cmd)
        self.assertFalse(any(c.startswith("mobsfscan=") for c in cmd))  # not requested -> not pinned
        rep = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(rep["result"], "pass")
        self.assertEqual(rep["pins_ignored"], ["mobsfscan"])
        self.assertEqual([r["tool"] for r in rep["tools"]], ["trivy", "zizmor", "gitleaks"])
        trivy = rep["tools"][0]
        self.assertTrue(trivy["candidate"])
        self.assertEqual(trivy["image"], f"aquasec/trivy:0.77.0@{D1}")
        self.assertEqual(rep["normalize"]["exit_code"], 0)
        self.assertGreaterEqual(rep["normalize"]["planted_candidates"]["trivy"], 1)

    @unittest.skipUnless(shutil.which("git"), "git not on PATH")
    def test_fail_on_miss_and_wrong_image(self):
        docs = canned()
        docs["zizmor.sarif"]["runs"][0]["results"] = []
        pins_file = self.dir / "pins.json"
        pins_file.write_text(json.dumps({"updates": [
            {"tool": "trivy", "image": "aquasec/trivy", "new_tag": "0.77.0", "new_digest": D1}]}), encoding="utf-8")
        smoke.detect_engine = lambda: {"daemon_ok": True, "engine": "docker"}
        smoke.invoke = self.fake_runner(docs, images={"trivy": IMAGES["trivy"]})  # runner ignored the pin
        out = self.dir / "smoke.json"
        rc = smoke.main(["--pins-json", str(pins_file), "--json", str(out), "--tool", "trivy", "--tool", "zizmor"])
        self.assertEqual(rc, 1)
        rep = json.loads(out.read_text(encoding="utf-8"))
        by = {r["tool"]: r for r in rep["tools"]}
        self.assertFalse(by["zizmor"]["ok"])
        self.assertFalse(by["trivy"]["ok"])
        self.assertIn("not the candidate", by["trivy"]["detail"])

    def test_no_engine_exit_2(self):
        smoke.detect_engine = lambda: {"daemon_ok": False, "installed": ["docker"]}
        smoke.invoke = lambda cmd, timeout: self.fail("runner must not start without an engine")
        out = self.dir / "smoke.json"
        self.assertEqual(smoke.main(["--json", str(out)]), smoke.EXIT_NO_ENGINE)
        rep = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(rep["result"], "no-engine")
        self.assertEqual(rep["exit_code"], 2)

    def test_bad_pins_file_exit_1(self):
        p = self.dir / "pins.json"
        p.write_text(json.dumps({"updates": [{"tool": "trivy", "image": "aquasec/trivy", "new_tag": "latest",
                                              "new_digest": D1}]}), encoding="utf-8")
        smoke.detect_engine = lambda: self.fail("pins are validated before anything runs")
        self.assertEqual(smoke.main(["--pins-json", str(p)]), smoke.EXIT_FAIL)
        p.write_text("{oops", encoding="utf-8")
        self.assertEqual(smoke.main(["--pins-json", str(p)]), smoke.EXIT_FAIL)

    def test_unknown_tool_is_usage_error(self):
        with self.assertRaises(SystemExit) as cm:
            smoke.main(["--tool", "nmap"])
        self.assertEqual(cm.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
