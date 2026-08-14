from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from contextlib import redirect_stdout
from io import StringIO

from claimfence.cli import main


FIXTURES = Path(__file__).parent / "fixtures"


class CliTests(unittest.TestCase):
    def test_warning_threshold_fails(self) -> None:
        with redirect_stdout(StringIO()):
            code = main([str(FIXTURES / "unbounded.md"), "--no-color"])
        self.assertEqual(1, code)

    def test_error_threshold_ignores_warning_only_document(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "README.md"
            path.write_text("# Demo\n\nThis is production-ready.\n", encoding="utf-8")
            with redirect_stdout(StringIO()):
                code = main([str(path), "--fail-on", "error", "--no-color"])
        self.assertEqual(0, code)

    def test_json_output_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report.json"
            code = main([
                str(FIXTURES / "unbounded.md"),
                "--format", "json",
                "--output", str(output),
                "--fail-on", "none",
            ])
            payload = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(0, code)
        self.assertGreater(len(payload["findings"]), 0)

    def test_version(self) -> None:
        with self.assertRaises(SystemExit) as raised:
            with patch("sys.stdout"):
                main(["--version"])
        self.assertEqual(0, raised.exception.code)

    def test_github_summary_and_outputs_are_written_before_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            summary = Path(directory) / "summary.md"
            outputs = Path(directory) / "outputs.txt"
            with redirect_stdout(StringIO()):
                code = main([
                    str(FIXTURES / "unbounded.md"),
                    "--format", "github",
                    "--github-summary", str(summary),
                    "--github-output", str(outputs),
                ])
            summary_text = summary.read_text(encoding="utf-8")
            output_values = dict(
                line.split("=", 1)
                for line in outputs.read_text(encoding="utf-8").splitlines()
            )
        self.assertEqual(1, code)
        self.assertIn("## ClaimFence scan", summary_text)
        self.assertIn("**Failed**", summary_text)
        self.assertEqual("failed", output_values["outcome"])
        self.assertGreater(int(output_values["findings-count"]), 0)

    def test_report_only_outcome_passes_with_findings(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            outputs = Path(directory) / "outputs.txt"
            with redirect_stdout(StringIO()):
                code = main([
                    str(FIXTURES / "unbounded.md"),
                    "--fail-on", "none",
                    "--github-output", str(outputs),
                    "--no-color",
                ])
            values = dict(
                line.split("=", 1)
                for line in outputs.read_text(encoding="utf-8").splitlines()
            )
        self.assertEqual(0, code)
        self.assertEqual("passed", values["outcome"])


if __name__ == "__main__":
    unittest.main()
