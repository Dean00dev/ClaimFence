from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
from io import StringIO
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from claimfence.cli import main
from claimfence.config import Config
from claimfence.drift import (
    compare_ledgers,
    drift_fails,
    drift_github_output,
    drift_github_summary,
    drift_json_report,
    drift_text_report,
    load_ledger,
    validate_ledger,
)
from claimfence.reporters import ledger_payload
from claimfence.scanner import scan_paths


class DriftTests(unittest.TestCase):
    def test_rewrap_and_unrelated_block_insertion_are_drift_stable(self) -> None:
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
            root = Path(directory)
            readme, _ = self._project(root)
            previous = self._ledger(root, readme)
            readme.write_text(
                "# Demo\n\nAn unrelated introduction.\n\n"
                "Under version 1, the gateway is\nproduction-ready.\n\n"
                "Inspect [the receipt](docs/receipt.md).\n\n"
                "## Limitations\n\nOther configurations are out of scope.\n",
                encoding="utf-8",
            )
            current = self._ledger(root, readme)

        drift = compare_ledgers(previous, current)
        self.assertEqual(0, drift["summary"]["events"])
        self.assertEqual(1, drift["summary"]["stable_claims"])
        self.assertFalse(drift_fails(drift, "any"))

    def test_v04_ledger_can_seed_v05_comparison(self) -> None:
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
            root = Path(directory)
            readme, _ = self._project(root)
            current = self._ledger(root, readme)
        previous = deepcopy(current)
        previous["tool"]["version"] = "0.4.0"
        previous["$schema"] = previous["$schema"].replace("v0.5.0", "v0.4.0")

        drift = compare_ledgers(previous, current)
        self.assertEqual(0, drift["summary"]["events"])
        self.assertEqual("0.4.0", drift["previous"]["tool_version"])
        self.assertEqual("0.5.0", drift["current"]["tool_version"])

    def test_changed_evidence_bytes_require_review(self) -> None:
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
            root = Path(directory)
            readme, receipt = self._project(root)
            previous = self._ledger(root, readme)
            receipt.write_text("measured evidence v2\n", encoding="utf-8")
            current = self._ledger(root, readme)

        first = compare_ledgers(previous, current)
        second = compare_ledgers(previous, current)
        evidence = [event for event in first["events"] if event["kind"] == "evidence-changed"]
        self.assertEqual(1, len(evidence))
        self.assertTrue(evidence[0]["review_required"])
        self.assertNotEqual(
            evidence[0]["before"][0]["sha256"],
            evidence[0]["after"][0]["sha256"],
        )
        self.assertEqual(drift_json_report(first), drift_json_report(second))
        self.assertTrue(drift_fails(first, "review"))
        self.assertTrue(drift_fails(first, "any"))
        self.assertFalse(drift_fails(first, "none"))

    def test_equivalent_local_link_spelling_is_drift_stable(self) -> None:
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
            root = Path(directory)
            readme, _ = self._project(root)
            previous = self._ledger(root, readme)
            readme.write_text(
                "# Demo\n\nUnder version 1, the gateway is production-ready.\n\n"
                "Inspect [the receipt](./docs/receipt.md).\n\n"
                "## Limitations\n\nOther configurations are out of scope.\n",
                encoding="utf-8",
            )
            current = self._ledger(root, readme)

        drift = compare_ledgers(previous, current)
        self.assertEqual(0, drift["summary"]["events"])

    def test_present_evidence_becoming_missing_requires_review(self) -> None:
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
            root = Path(directory)
            readme, receipt = self._project(root)
            previous = self._ledger(root, readme)
            receipt.unlink()
            current = self._ledger(root, readme)

        drift = compare_ledgers(previous, current)
        changed = [
            event for event in drift["events"] if event["kind"] == "evidence-changed"
        ]
        self.assertEqual(1, len(changed))
        self.assertEqual("present", changed[0]["before"][0]["status"])
        self.assertEqual("missing", changed[0]["after"][0]["status"])
        self.assertTrue(changed[0]["review_required"])

    def test_new_linked_claim_is_change_without_review_classification(self) -> None:
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
            root = Path(directory)
            readme = root / "README.md"
            readme.write_text("# Demo\n", encoding="utf-8")
            previous = self._ledger(root, readme)
            readme, _ = self._project(root)
            current = self._ledger(root, readme)

        drift = compare_ledgers(previous, current)
        self.assertEqual(1, drift["summary"]["events"])
        self.assertEqual("claim-added", drift["events"][0]["kind"])
        self.assertFalse(drift["events"][0]["review_required"])
        self.assertFalse(drift_fails(drift, "review"))
        self.assertTrue(drift_fails(drift, "any"))

    def test_lost_evidence_and_linked_status_require_review(self) -> None:
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
            root = Path(directory)
            readme, _ = self._project(root)
            previous = self._ledger(root, readme)
            readme.write_text(
                "# Demo\n\nUnder version 1, the gateway is production-ready.\n\n"
                "## Limitations\n\nOther configurations are out of scope.\n",
                encoding="utf-8",
            )
            current = self._ledger(root, readme)

        drift = compare_ledgers(previous, current)
        kinds = {event["kind"] for event in drift["events"]}
        self.assertIn("evidence-removed", kinds)
        self.assertTrue(any(event["review_required"] for event in drift["events"]))
        status = [
            event
            for event in drift["events"]
            if event.get("field") == "status"
        ]
        self.assertEqual([("linked", "review")], [(e["before"], e["after"]) for e in status])

    def test_ledger_validation_rejects_duplicate_claim_ids(self) -> None:
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
            root = Path(directory)
            readme, _ = self._project(root)
            ledger = self._ledger(root, readme)
        duplicate = deepcopy(ledger)
        duplicate["claims"].append(deepcopy(duplicate["claims"][0]))
        duplicate["summary"]["claims_detected"] = 2
        with self.assertRaisesRegex(ValueError, "duplicate claim id"):
            validate_ledger(duplicate)

    def test_ledger_validation_rejects_malformed_evidence_digest(self) -> None:
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
            root = Path(directory)
            readme, _ = self._project(root)
            ledger = self._ledger(root, readme)
        malformed = deepcopy(ledger)
        local = next(
            anchor
            for anchor in malformed["claims"][0]["evidence"]
            if anchor["kind"] == "local-file"
        )
        local["sha256"] = "not-a-digest"
        with self.assertRaisesRegex(ValueError, "must be a SHA-256 digest"):
            validate_ledger(malformed)

    def test_ledger_loader_bounds_untrusted_input(self) -> None:
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
            path = Path(directory) / "oversized.json"
            path.write_text("{}", encoding="utf-8")
            with patch("claimfence.drift.MAX_LEDGER_BYTES", 1):
                with self.assertRaisesRegex(ValueError, "exceeds the .* limit"):
                    load_ledger(path)

    def test_ledger_loader_rejects_excessive_nesting_cleanly(self) -> None:
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
            path = Path(directory) / "nested.json"
            path.write_text("{}", encoding="utf-8")
            with patch("claimfence.drift.json.loads", side_effect=RecursionError):
                with self.assertRaisesRegex(ValueError, "nested too deeply"):
                    load_ledger(path)

    def test_drift_schema_and_github_receipts_are_explicit(self) -> None:
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
            root = Path(directory)
            readme, receipt = self._project(root)
            previous = self._ledger(root, readme)
            receipt.write_text("changed\n", encoding="utf-8")
            current = self._ledger(root, readme)
            schema = json.loads(
                (Path(__file__).parents[1] / "schema" / "evidence-drift-v1.schema.json")
                .read_text(encoding="utf-8")
            )
        drift = compare_ledgers(previous, current)
        self.assertEqual(schema["$id"], drift["$schema"])
        self.assertIn("## ClaimFence evidence drift", drift_github_summary(drift))
        outputs = dict(
            line.split("=", 1) for line in drift_github_output(drift, "review").splitlines()
        )
        self.assertEqual("true", outputs["drift-configured"])
        self.assertEqual("failed", outputs["drift-outcome"])
        self.assertEqual(
            "not-configured",
            dict(
                line.split("=", 1)
                for line in drift_github_output(None, "none").splitlines()
            )["drift-outcome"],
        )

    def test_github_drift_summary_escapes_ledger_paths(self) -> None:
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
            root = Path(directory)
            readme, _ = self._project(root)
            previous = self._ledger(root, readme)
        previous["claims"][0]["path"] = "`</code>\n## injected"
        current = deepcopy(previous)
        current["claims"] = []
        current["summary"]["claims_detected"] = 0
        drift = compare_ledgers(previous, current)
        summary = drift_github_summary(drift)
        self.assertNotIn("\n## injected", summary)
        self.assertIn("&lt;/code&gt;", summary)

    def test_text_drift_report_flattens_control_characters(self) -> None:
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
            root = Path(directory)
            readme, _ = self._project(root)
            previous = self._ledger(root, readme)
        previous["claims"][0]["path"] = "before\n\x1b[31mafter"
        current = deepcopy(previous)
        current["claims"] = []
        current["summary"]["claims_detected"] = 0
        report = drift_text_report(compare_ledgers(previous, current))
        self.assertNotIn("\x1b", report)
        self.assertNotIn("\nafter", report)

    def test_cli_writes_drift_receipt_and_enforces_review_gate(self) -> None:
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
            root = Path(directory)
            _, receipt = self._project(root)
            previous = root / "previous-ledger.json"
            drift_output = root / "drift.json"
            github_output = root / "github-output.txt"
            github_summary = root / "github-summary.md"
            with redirect_stdout(StringIO()):
                initial = main(
                    [
                        "README.md",
                        "--root",
                        str(root),
                        "--fail-on",
                        "none",
                        "--ledger-output",
                        str(previous),
                    ]
                )
            receipt.write_text("changed evidence\n", encoding="utf-8")
            with redirect_stdout(StringIO()):
                compared = main(
                    [
                        "README.md",
                        "--root",
                        str(root),
                        "--fail-on",
                        "none",
                        "--compare-ledger",
                        str(previous),
                        "--drift-output",
                        str(drift_output),
                        "--fail-on-drift",
                        "review",
                        "--github-output",
                        str(github_output),
                        "--github-summary",
                        str(github_summary),
                    ]
                )
            payload = json.loads(drift_output.read_text(encoding="utf-8"))
            outputs = dict(
                line.split("=", 1)
                for line in github_output.read_text(encoding="utf-8").splitlines()
            )
            summary_text = github_summary.read_text(encoding="utf-8")
        self.assertEqual(0, initial)
        self.assertEqual(1, compared)
        self.assertEqual(1, payload["summary"]["claims_requiring_review"])
        self.assertEqual("failed", outputs["drift-outcome"])
        self.assertIn("ClaimFence evidence drift", summary_text)

    def test_cli_rejects_orphaned_drift_options(self) -> None:
        with self.assertRaises(SystemExit) as raised:
            with redirect_stderr(StringIO()), redirect_stdout(StringIO()):
                main([".", "--drift-output", "drift.json"])
        self.assertEqual(2, raised.exception.code)

    def test_cli_refuses_to_overwrite_comparison_ledger(self) -> None:
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
            root = Path(directory)
            self._project(root)
            previous = root / "previous.json"
            with redirect_stdout(StringIO()):
                self.assertEqual(
                    0,
                    main(
                        [
                            "README.md",
                            "--root",
                            str(root),
                            "--fail-on",
                            "none",
                            "--ledger-output",
                            str(previous),
                        ]
                    ),
                )
            before = previous.read_bytes()
            with self.assertRaises(SystemExit) as raised:
                with redirect_stderr(StringIO()), redirect_stdout(StringIO()):
                    main(
                        [
                            "README.md",
                            "--root",
                            str(root),
                            "--fail-on",
                            "none",
                            "--compare-ledger",
                            str(previous),
                            "--ledger-output",
                            str(previous),
                        ]
                    )
            self.assertEqual(before, previous.read_bytes())
        self.assertEqual(2, raised.exception.code)

    @staticmethod
    def _project(root: Path) -> tuple[Path, Path]:
        (root / "docs").mkdir(exist_ok=True)
        receipt = root / "docs" / "receipt.md"
        receipt.write_text("measured evidence v1\n", encoding="utf-8")
        readme = root / "README.md"
        readme.write_text(
            "# Demo\n\nUnder version 1, the gateway is production-ready.\n\n"
            "Inspect [the receipt](docs/receipt.md).\n\n"
            "## Limitations\n\nOther configurations are out of scope.\n",
            encoding="utf-8",
        )
        return readme, receipt

    @staticmethod
    def _ledger(root: Path, readme: Path) -> dict[str, object]:
        result = scan_paths([readme], Config(), root)
        return ledger_payload(result, root)


if __name__ == "__main__":
    unittest.main()
