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


if __name__ == "__main__":
    unittest.main()
