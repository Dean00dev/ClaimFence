from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from claimfence.baseline import apply_baseline, write_baseline
from claimfence.config import Config, load_config
from claimfence.models import Severity
from claimfence.reporters import (
    github_output_report,
    github_report,
    github_summary,
    json_report,
    sarif_report,
)
from claimfence.scanner import scan_file, scan_paths


FIXTURES = Path(__file__).parent / "fixtures"


class ScannerTests(unittest.TestCase):
    def test_unbounded_claims_are_flagged(self) -> None:
        findings, _ = scan_file(FIXTURES / "unbounded.md", Config())
        rules = {finding.rule_id for finding in findings}
        self.assertTrue({"CF001", "CF002", "CF003", "CF101", "CF102"}.issubset(rules))

    def test_bounded_claim_is_accepted(self) -> None:
        findings, _ = scan_file(FIXTURES / "bounded.md", Config())
        self.assertEqual([], findings)

    def test_negated_claims_are_not_findings(self) -> None:
        findings, _ = scan_file(FIXTURES / "negated.md", Config())
        self.assertEqual([], findings)

    def test_epistemically_negated_claim_is_not_a_finding(self) -> None:
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
            path = Path(directory) / "README.md"
            path.write_text(
                "# Boundary\n\nThis tool cannot determine whether it is safe to wait.\n",
                encoding="utf-8",
            )
            findings, _ = scan_file(path, Config())
        self.assertEqual([], findings)

    def test_missing_path_is_an_error(self) -> None:
        with self.assertRaises(FileNotFoundError):
            scan_paths([Path("this-path-must-not-exist")], Config())

    def test_fenced_code_is_ignored(self) -> None:
        findings, _ = scan_file(FIXTURES / "code.md", Config())
        self.assertEqual([], findings)

    def test_multiline_html_comment_is_ignored(self) -> None:
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
            path = Path(directory) / "README.md"
            path.write_text(
                "# Demo\n\n<!--\nThis is unbreakable and guarantees security.\n-->\nVisible prose.\n",
                encoding="utf-8",
            )
            findings, _ = scan_file(path, Config())
        self.assertEqual([], findings)

    def test_reasoned_inline_suppression(self) -> None:
        findings, suppressed = scan_file(FIXTURES / "suppressed.md", Config())
        self.assertEqual([], findings)
        self.assertEqual(1, suppressed)

    def test_suppression_without_reason_is_ignored(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "README.md"
            path.write_text(
                "# Demo\n\n<!-- claimfence-disable-next-line CF002 -->\nThis is secure.\n",
                encoding="utf-8",
            )
            findings, suppressed = scan_file(path, Config())
        self.assertGreater(len(findings), 0)
        self.assertEqual(0, suppressed)

    def test_discovery_respects_excludes(self) -> None:
        config = Config(exclude=["fixtures/**"])
        result = scan_paths([Path(__file__).parent], config)
        self.assertEqual(0, result.files_scanned)

    def test_baseline_filters_only_known_fingerprints(self) -> None:
        result = scan_paths([FIXTURES / "unbounded.md"], Config())
        original = len(result.findings)
        with tempfile.TemporaryDirectory() as directory:
            baseline = Path(directory) / "baseline.json"
            write_baseline(result, baseline)
            apply_baseline(result, baseline)
        self.assertEqual([], result.findings)
        self.assertEqual(original, result.baselined)

    def test_fingerprint_distinguishes_same_filename_in_different_directories(self) -> None:
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
            root = Path(directory)
            first = root / "a" / "README.md"
            second = root / "b" / "README.md"
            first.parent.mkdir()
            second.parent.mkdir()
            claim = "# Demo\n\nThis is production-ready.\n"
            first.write_text(claim, encoding="utf-8")
            second.write_text(claim, encoding="utf-8")
            first_findings, _ = scan_file(first, Config())
            second_findings, _ = scan_file(second, Config())
        first_cf002 = next(f for f in first_findings if f.rule_id == "CF002")
        second_cf002 = next(f for f in second_findings if f.rule_id == "CF002")
        self.assertNotEqual(first_cf002.fingerprint, second_cf002.fingerprint)

    def test_reporters_produce_machine_readable_output(self) -> None:
        result = scan_paths([FIXTURES / "unbounded.md"], Config())
        parsed_json = json.loads(json_report(result))
        parsed_sarif = json.loads(sarif_report(result, Path.cwd()))
        annotations = github_report(result, Path.cwd())
        summary = github_summary(result, Path.cwd(), Severity.WARNING)
        outputs = github_output_report(result, Severity.WARNING)
        self.assertEqual("ClaimFence", parsed_json["tool"]["name"])
        self.assertEqual("0.2.0", parsed_json["tool"]["version"])
        self.assertEqual("2.1.0", parsed_sarif["version"])
        self.assertEqual("0.2.0", parsed_sarif["runs"][0]["tool"]["driver"]["version"])
        self.assertIn("::error", annotations)
        self.assertIn("### Findings by rule", summary)
        self.assertIn("outcome=failed", outputs)

    def test_configuration_validation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "claimfence.toml"
            path.write_text('[claimfence]\nfail_on = "error"\ncontext_lines = 4\n', encoding="utf-8")
            config = load_config(path)
        self.assertEqual(Severity.ERROR, config.fail_on)
        self.assertEqual(4, config.context_lines)


if __name__ == "__main__":
    unittest.main()
