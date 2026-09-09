"""End-to-end regression tests over the exports in tests/fixtures.

Each test runs the real scripts on a small synthetic `get-web-acl` export and asserts on the
artifacts they write. Standard library only, no network, nothing outside a temp dir.

    python3 -m unittest discover -s tests -v
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SCRIPTS = os.path.join(ROOT, "skills", "ddos-guardian", "scripts")
FIXTURES = os.path.join(HERE, "fixtures")
ASSESS = os.path.join(SCRIPTS, "waf-assess.py")
REPORT = os.path.join(SCRIPTS, "waf-report.py")


def run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, *args], capture_output=True, text=True)


def assess(fixture: str, out: str) -> subprocess.CompletedProcess:
    return run(ASSESS, os.path.join(FIXTURES, fixture), out)


def result_block(stdout: str) -> dict:
    block = stdout.split("---RESULT---", 1)[-1]
    return dict(re.findall(r"^([A-Z_]+):\s*(.*)$", block, re.M))


def issue_titles(out: str) -> list[str]:
    with open(os.path.join(out, "scripted-findings.md"), encoding="utf-8") as fh:
        return re.findall(r"^## Issue \d+ \((\w+)\): (.*)$", fh.read(), re.M)


class AssessFixtures(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="ddos-guardian-test-")

    def test_antiddos_count_override_without_configs_does_not_crash(self):
        """A rule group with no ManagedRuleGroupConfigs normalises `config` to None."""
        out = os.path.join(self.tmp, "amr")
        proc = assess("amr-count-no-configs.json", out)
        self.assertEqual(proc.returncode, 0, proc.stderr[-2000:])
        self.assertNotIn("Traceback", proc.stderr)
        res = result_block(proc.stdout)
        self.assertEqual(res.get("STATUS"), "OK")
        titles = [t for _, t in issue_titles(out)]
        self.assertTrue(any("ChallengeAllDuringEvent" in t for t in titles), titles)

    def test_firewall_manager_rule_groups_are_assessed(self):
        """Pre/post-process Firewall Manager groups evaluate in the same priority space."""
        out = os.path.join(self.tmp, "fms")
        proc = assess("fms-pre-post-groups.json", out)
        self.assertEqual(proc.returncode, 0, proc.stderr[-2000:])
        with open(os.path.join(out, "waf-summary.json"), encoding="utf-8") as fh:
            summary = json.load(fh)
        names = [r["name"] for r in summary["rules"]]
        self.assertEqual(names, ["PREFMManaged-AntiDDoS", "PREFMManaged-CRS", "rate-blanket",
                                 "ShieldMitigationRuleGroup_111122223333_abc_x"])
        self.assertIs(summary["web_acl"]["managed_by_fms"], True)
        self.assertIs(summary["web_acl"]["shield_advanced"], True)
        titles = [t for _, t in issue_titles(out)]
        self.assertFalse(any(t.startswith("Missing CRS") for t in titles), titles)
        self.assertTrue(any("AWSManagedRulesCommonRuleSet is overridden to Count" in t
                            for t in titles), titles)

    def test_unanchored_exempt_uri_regex_is_reported(self):
        """The regex lives under ClientSideActionConfig.Challenge.ExemptUriRegularExpressions."""
        out = os.path.join(self.tmp, "exempt")
        proc = assess("amr-exempt-regex-unanchored.json", out)
        self.assertEqual(proc.returncode, 0, proc.stderr[-2000:])
        with open(os.path.join(out, "pre-checks.json"), encoding="utf-8") as fh:
            pre = json.load(fh)
        flags = pre.get("flags", pre).get("exempt_regex_branches")
        self.assertTrue(flags, "exempt_regex_branches flag is empty")
        patterns = {b["pattern"]: b for b in flags[0]["branches"]}
        self.assertFalse(patterns["\\/api\\/"]["anchored_start"])
        self.assertTrue(patterns["^\\/health$"]["anchored_start"])
        titles = [t for _, t in issue_titles(out)]
        self.assertTrue(any("exempt URI regex is unanchored" in t for t in titles), titles)


class ReportFixtures(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="ddos-guardian-test-")

    def test_quotes_in_urls_cannot_break_out_of_href(self):
        out = os.path.join(self.tmp, "fms")
        proc = assess("fms-pre-post-groups.json", out)
        self.assertEqual(proc.returncode, 0, proc.stderr[-2000:])
        with open(os.path.join(FIXTURES, "xss-summary.md"), encoding="utf-8") as fh:
            summary = fh.read()
        with open(os.path.join(out, "scripted-findings.md"), encoding="utf-8") as fh:
            findings = fh.read()
        with open(os.path.join(out, "findings.md"), "w", encoding="utf-8") as fh:
            fh.write(summary + findings)
        html_path = os.path.join(out, "report.html")
        proc = run(REPORT, out, "--out", html_path)
        self.assertEqual(proc.returncode, 0, proc.stderr[-2000:])
        with open(html_path, encoding="utf-8") as fh:
            html = fh.read()
        # Every href value must be a clean quoted string with no second attribute inside it.
        for href in re.findall(r'href="([^"]*)"', html):
            self.assertNotIn("onmouseover", href)
        self.assertNotRegex(html, r'href="[^"]*"onmouseover=')
        self.assertNotIn("<a href=\"https://x.example/a\"onmouseover", html)
        # The legitimate part of the link still renders as a link.
        self.assertIn('<a href="https://x.example/a"', html)

    def test_query_strings_in_urls_still_link(self):
        sys.path.insert(0, SCRIPTS)
        import importlib.util
        spec = importlib.util.spec_from_file_location("waf_report", REPORT)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        out = mod._inline("see [d](https://a.example/x?a=1&b=2) and https://b.example/p?q=1&r=2 end")
        self.assertIn('<a href="https://a.example/x?a=1&amp;b=2"', out)
        self.assertIn('<a href="https://b.example/p?q=1&amp;r=2"', out)


if __name__ == "__main__":
    unittest.main()
