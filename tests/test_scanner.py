from __future__ import annotations

import json
import hashlib
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
    html_report,
    json_report,
    ledger_report,
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

    def test_verification_word_inside_a_disclaimer_is_not_a_finding(self) -> None:
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
            root = Path(directory)
            path = root / "README.md"
            path.write_text(
                "# Boundary\n\nLinked is not a synonym for verified.\n",
                encoding="utf-8",
            )
            findings, _ = scan_file(path, Config(), root)
        self.assertEqual([], findings)

    def test_soft_wrapped_epistemic_negation_is_not_a_finding(self) -> None:
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
            root = Path(directory)
            path = root / "README.md"
            path.write_text(
                "# Boundary\n\n"
                "> This tool cannot determine\n"
                "> whether it is safe to wait.\n",
                encoding="utf-8",
            )
            findings, _ = scan_file(path, Config(), root)
        self.assertEqual([], findings)

    def test_rewrapping_preserves_rules_claims_and_fingerprints(self) -> None:
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
            root = Path(directory)
            path = root / "README.md"
            path.write_text(
                "# Demo\n\n## Verification\n\n"
                "This production-ready gateway prevents all attacks.\n\n"
                "## Limitations\n\nUntested inputs are out of scope.\n",
                encoding="utf-8",
            )
            first, _ = scan_file(path, Config(), root)
            path.write_text(
                "# Demo\n\n## Verification\n\n"
                "This production-ready gateway\nprevents all attacks.\n\n"
                "## Limitations\n\nUntested inputs are out of scope.\n",
                encoding="utf-8",
            )
            second, _ = scan_file(path, Config(), root)

        first_contract = [
            (finding.rule_id, finding.severity, finding.claim, finding.fingerprint)
            for finding in first
        ]
        second_contract = [
            (finding.rule_id, finding.severity, finding.claim, finding.fingerprint)
            for finding in second
        ]
        self.assertEqual(first_contract, second_contract)
        universal = next(finding for finding in second if finding.rule_id == "CF003")
        self.assertEqual((6, 10), (universal.line, universal.column))

    def test_claim_identifier_survives_rewrap_and_unrelated_block_insertion(self) -> None:
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
            root = Path(directory)
            path = root / "README.md"
            path.write_text(
                "# Demo\n\n## Verification\n\n"
                "This production-ready gateway prevents all attacks.\n\n"
                "## Limitations\n\nUntested inputs are out of scope.\n",
                encoding="utf-8",
            )
            first = scan_paths([path], Config(), root)
            path.write_text(
                "# Demo\n\nAn unrelated introductory paragraph.\n\n"
                "## Verification\n\nThis production-ready gateway\n"
                "prevents all attacks.\n\n"
                "## Limitations\n\nUntested inputs are out of scope.\n",
                encoding="utf-8",
            )
            second = scan_paths([path], Config(), root)

        self.assertEqual(1, len(first.claims))
        self.assertEqual(1, len(second.claims))
        self.assertEqual(first.claims[0].claim_id, second.claims[0].claim_id)

    def test_duplicate_claim_text_receives_distinct_identifiers(self) -> None:
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
            root = Path(directory)
            path = root / "README.md"
            path.write_text(
                "# Demo\n\nThis gateway is production-ready.\n\n"
                "## Another deployment\n\nThis gateway is production-ready.\n",
                encoding="utf-8",
            )
            result = scan_paths([path], Config(), root)

        self.assertEqual(2, len(result.claims))
        self.assertEqual(2, len({claim.claim_id for claim in result.claims}))

    def test_universal_negative_is_an_assurance_finding(self) -> None:
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
            root = Path(directory)
            path = root / "README.md"
            path.write_text(
                "# Demo\n\n## Verification\n\n"
                "The browser never receives a model-provider API key.\n\n"
                "## Limitations\n\nThis does not cover modified deployments.\n",
                encoding="utf-8",
            )
            findings, _ = scan_file(path, Config(), root)
        self.assertIn("CF003", {finding.rule_id for finding in findings})

    def test_epistemic_boundary_suppresses_nested_universal_negative(self) -> None:
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
            root = Path(directory)
            path = root / "README.md"
            path.write_text(
                "# Boundary\n\n"
                "This review does not establish that the browser never receives an API key.\n",
                encoding="utf-8",
            )
            findings, _ = scan_file(path, Config(), root)
        self.assertEqual([], findings)

    def test_policy_intent_is_not_treated_as_measured_protection(self) -> None:
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
            root = Path(directory)
            path = root / "SECURITY.md"
            path.write_text(
                "# Supported version\n\n"
                "Pre-1.0 changes may break compatibility when needed to protect users.\n",
                encoding="utf-8",
            )
            findings, _ = scan_file(path, Config(), root)
        self.assertEqual([], findings)

    def test_logical_blocks_are_not_mistaken_for_blocking_behavior(self) -> None:
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
            root = Path(directory)
            path = root / "README.md"
            path.write_text(
                "# Parser\n\nThe parser joins source-mapped logical blocks.\n",
                encoding="utf-8",
            )
            findings, _ = scan_file(path, Config(), root)
        self.assertEqual([], findings)

    def test_blocks_with_a_security_object_remains_assurance_language(self) -> None:
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
            root = Path(directory)
            path = root / "README.md"
            path.write_text(
                "# Demo\n\n## Verification\n\nThe gateway blocks attacks.\n\n"
                "## Limitations\n\nOther inputs are out of scope.\n",
                encoding="utf-8",
            )
            findings, _ = scan_file(path, Config(), root)
        self.assertIn("CF002", {finding.rule_id for finding in findings})

    def test_evidence_words_without_an_anchor_do_not_satisfy_a_claim(self) -> None:
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
            root = Path(directory)
            path = root / "README.md"
            path.write_text(
                "# Demo\n\n## Verification\n\n"
                "Under version 1, the gateway is secure. See the campaign report.\n\n"
                "## Limitations\n\nOther configurations are out of scope.\n",
                encoding="utf-8",
            )
            findings, _ = scan_file(path, Config(), root)
        self.assertIn("CF002", {finding.rule_id for finding in findings})

    def test_missing_local_evidence_references_are_findings(self) -> None:
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
            root = Path(directory)
            path = root / "README.md"
            path.write_text(
                "# Demo\n\n## Verification\n\n"
                "Under version 1, the gateway is secure. Reproduce with "
                "`pytest tests/missing.py`; inspect [the report](reports/missing.md).\n\n"
                "## Limitations\n\nOther configurations are out of scope.\n",
                encoding="utf-8",
            )
            findings, _ = scan_file(path, Config(), root)
        broken = [finding for finding in findings if finding.rule_id == "CF005"]
        self.assertEqual(2, len(broken))
        self.assertEqual(
            {"tests/missing.py", "reports/missing.md"},
            {finding.claim for finding in broken},
        )

    def test_inline_filename_example_is_not_treated_as_evidence(self) -> None:
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
            root = Path(directory)
            path = root / "README.md"
            path.write_text(
                "# Demo\n\n## Tests\n\n"
                "The tool protects Windows. A fixture may contain `NUL.txt` as data.\n\n"
                "## Limitations\n\nOther platforms are out of scope.\n",
                encoding="utf-8",
            )
            findings, _ = scan_file(path, Config(), root)
        rules = {finding.rule_id for finding in findings}
        self.assertIn("CF002", rules)
        self.assertNotIn("CF005", rules)

    def test_claim_ledger_maps_and_hashes_local_evidence(self) -> None:
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
            root = Path(directory)
            (root / "docs").mkdir()
            (root / "tests").mkdir()
            receipt = root / "docs" / "receipt.md"
            receipt.write_text("measured evidence\n", encoding="utf-8")
            test_file = root / "tests" / "check.py"
            test_file.write_text("assert True\n", encoding="utf-8")
            readme = root / "README.md"
            readme.write_text(
                "# Demo\n\n## Verification\n\n"
                "Under version 1, the gateway is secure. Reproduce with "
                "`pytest tests/check.py`; inspect [the receipt](docs/receipt.md).\n\n"
                "## Limitations\n\nOther configurations are out of scope.\n",
                encoding="utf-8",
            )
            result = scan_paths([readme], Config(), root)
            payload = json.loads(ledger_report(result, root))
            schema = json.loads(
                (Path(__file__).parents[1] / "schema" / "claim-ledger-v1.schema.json")
                .read_text(encoding="utf-8")
            )

        self.assertEqual("https://json-schema.org/draft/2020-12/schema", schema["$schema"])
        self.assertEqual(schema["$id"], payload["$schema"])
        self.assertEqual(1, payload["summary"]["claims_detected"])
        claim = payload["claims"][0]
        self.assertEqual("linked", claim["status"])
        self.assertEqual(["CF002"], claim["rules"])
        local = {
            anchor["repository_path"]: anchor
            for anchor in claim["evidence"]
            if anchor["kind"] == "local-file"
        }
        self.assertEqual(
            hashlib.sha256(b"measured evidence\n").hexdigest(),
            local["docs/receipt.md"]["sha256"],
        )
        self.assertEqual(
            hashlib.sha256(b"assert True\n").hexdigest(),
            local["tests/check.py"]["sha256"],
        )
        self.assertIn("command", {anchor["kind"] for anchor in claim["evidence"]})

    def test_evidence_map_is_deterministic_and_escapes_document_html(self) -> None:
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
            root = Path(directory)
            path = root / "README.md"
            path.write_text(
                "# Demo\n\n## Verification\n\n"
                "<script>alert('x')</script> This is production-ready.\n\n"
                "## Limitations\n\nOther configurations are out of scope.\n",
                encoding="utf-8",
            )
            result = scan_paths([path], Config(), root)
            first = html_report(result, root)
            second = html_report(result, root)

        self.assertEqual(first, second)
        self.assertNotIn("<script>alert('x')</script>", first)
        self.assertIn("&lt;script&gt;alert(&#x27;x&#x27;)&lt;/script&gt;", first)
        self.assertIn("data-status=\"review\"", first)

    def test_existing_empty_reference_satisfies_integrity_only(self) -> None:
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
            root = Path(directory)
            (root / "docs").mkdir()
            (root / "reports").mkdir()
            (root / "tests").mkdir()
            (root / "reports" / "receipt.md").touch()
            (root / "tests" / "check.py").touch()
            path = root / "docs" / "README.md"
            path.write_text(
                "# Demo\n\n## Verification\n\n"
                "Under version 1, the gateway is secure. Reproduce with "
                "`pytest tests/check.py`; inspect [the receipt](../reports/receipt.md).\n\n"
                "## Limitations\n\nOther configurations are out of scope.\n",
                encoding="utf-8",
            )
            findings, _ = scan_file(path, Config(), root)
        self.assertEqual([], findings)

    def test_external_evidence_link_is_not_resolved_locally(self) -> None:
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
            root = Path(directory)
            path = root / "README.md"
            path.write_text(
                "# Demo\n\n## Verification\n\n"
                "Under version 1, the gateway is secure; inspect "
                "[the CI run](https://example.com/runs/1).\n\n"
                "## Limitations\n\nOther configurations are out of scope.\n",
                encoding="utf-8",
            )
            findings, _ = scan_file(path, Config(), root)
        self.assertEqual([], findings)

    def test_local_evidence_reference_cannot_escape_root(self) -> None:
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
            root = Path(directory)
            (root / "docs").mkdir()
            path = root / "docs" / "README.md"
            path.write_text(
                "# Demo\n\n## Verification\n\n"
                "Under version 1, the gateway is secure; inspect "
                "[the receipt](../../outside.md).\n\n"
                "## Limitations\n\nOther configurations are out of scope.\n",
                encoding="utf-8",
            )
            findings, _ = scan_file(path, Config(), root)
        escaped = [finding for finding in findings if finding.rule_id == "CF005"]
        self.assertEqual(1, len(escaped))
        self.assertIn("escapes", escaped[0].message)

    def test_reasoned_suppression_applies_to_a_wrapped_logical_block(self) -> None:
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
            root = Path(directory)
            path = root / "README.md"
            path.write_text(
                "# Demo\n\n## Verification\n\n"
                "<!-- claimfence-disable-next-line CF002: literal product status -->\n"
                "The gateway is\nproduction-ready.\n\n"
                "## Limitations\n\nOther configurations are out of scope.\n",
                encoding="utf-8",
            )
            findings, suppressed = scan_file(path, Config(), root)
        self.assertEqual([], findings)
        self.assertEqual(1, suppressed)

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

    def test_ledger_preserves_suppression_reason(self) -> None:
        result = scan_paths([FIXTURES / "suppressed.md"], Config(), Path.cwd())
        claim = result.claims[0]
        self.assertEqual("suppressed", claim.status)
        self.assertEqual(("term is the literal upstream product name",), claim.suppression_reasons)

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
        self.assertEqual("0.4.0", parsed_json["tool"]["version"])
        self.assertEqual("2.1.0", parsed_sarif["version"])
        self.assertEqual("0.4.0", parsed_sarif["runs"][0]["tool"]["driver"]["version"])
        self.assertIn("::error", annotations)
        self.assertIn("### Findings by rule", summary)
        self.assertIn("outcome=failed", outputs)
        self.assertIn("claims-count=", outputs)
        self.assertIn("review-claims-count=", outputs)
        self.assertIn("evidence-anchors-count=", outputs)

    def test_configuration_validation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "claimfence.toml"
            path.write_text('[claimfence]\nfail_on = "error"\ncontext_lines = 4\n', encoding="utf-8")
            config = load_config(path)
        self.assertEqual(Severity.ERROR, config.fail_on)
        self.assertEqual(4, config.context_lines)

    def test_context_blocks_configuration(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "claimfence.toml"
            path.write_text('[claimfence]\ncontext_blocks = 2\n', encoding="utf-8")
            config = load_config(path)
        self.assertEqual(2, config.context_blocks)
        self.assertEqual(2, config.context_radius())


if __name__ == "__main__":
    unittest.main()
