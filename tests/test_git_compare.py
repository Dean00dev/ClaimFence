from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from claimfence.cli import main
from claimfence.config import Config
from claimfence.git_compare import scan_git_ref


class GitComparisonTests(unittest.TestCase):
    def test_compare_ref_detects_changed_evidence_and_records_exact_commit(self) -> None:
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
            root = self._repository(Path(directory))
            base_commit = self._commit(root, "base")
            (root / "docs" / "receipt.md").write_text(
                "measured evidence v2\n", encoding="utf-8"
            )
            drift = root / "drift.json"
            summary = root / "summary.md"
            outputs = root / "outputs.txt"

            with redirect_stdout(StringIO()):
                code = main(
                    [
                        "README.md",
                        "--root",
                        str(root),
                        "--fail-on",
                        "none",
                        "--compare-ref",
                        base_commit,
                        "--drift-output",
                        str(drift),
                        "--github-summary",
                        str(summary),
                        "--github-output",
                        str(outputs),
                    ]
                )

            payload = json.loads(drift.read_text(encoding="utf-8"))
            values = dict(
                line.split("=", 1)
                for line in outputs.read_text(encoding="utf-8").splitlines()
            )
            summary_text = summary.read_text(encoding="utf-8")

        self.assertEqual(0, code)
        self.assertEqual(
            {
                "mode": "git-ref",
                "base_commit": base_commit,
                "policy_source": "current-worktree",
            },
            payload["comparison"],
        )
        self.assertEqual(1, payload["summary"]["events"])
        self.assertEqual("evidence-changed", payload["events"][0]["kind"])
        self.assertEqual(base_commit, values["drift-base-commit"])
        self.assertIn(base_commit, summary_text)

    def test_compare_ref_is_deterministic_and_does_not_change_head(self) -> None:
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
            root = self._repository(Path(directory))
            base_commit = self._commit(root, "base")
            before_head = self._git(root, "rev-parse", "HEAD")

            first = scan_git_ref(root, [root / "README.md"], Config(), "HEAD")
            second = scan_git_ref(root, [root / "README.md"], Config(), base_commit)
            after_head = self._git(root, "rev-parse", "HEAD")

        self.assertEqual(base_commit, first.commit)
        self.assertEqual(first.ledger, second.ledger)
        self.assertEqual(before_head, after_head)

    def test_ambient_git_repository_override_cannot_redirect_comparison(self) -> None:
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
            parent = Path(directory)
            (parent / "intended").mkdir()
            (parent / "other").mkdir()
            root = self._repository(parent / "intended")
            other = self._repository(parent / "other")
            expected = self._commit(root, "intended")
            self._commit(other, "other")

            with patch.dict("os.environ", {"GIT_DIR": str(other / ".git")}):
                scanned = scan_git_ref(root, [root / "README.md"], Config(), "HEAD")

        self.assertEqual(expected, scanned.commit)

    def test_new_markdown_path_becomes_claim_added_instead_of_invalid_input(self) -> None:
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
            root = Path(directory)
            self._git(root, "init", "-q")
            (root / "README.md").write_text("# Demo\n", encoding="utf-8")
            base_commit = self._commit(root, "empty documentation")
            new = root / "new.md"
            new.write_text(
                "<!-- claimfence-id: demo/new -->\n\n"
                "Under version 1, this gateway is production-ready.\n\n"
                "Inspect [the receipt](README.md).\n\n"
                "## Limitations\n\nOther configurations are out of scope.\n",
                encoding="utf-8",
            )
            drift = root / "drift.json"
            with redirect_stdout(StringIO()):
                code = main(
                    [
                        "new.md",
                        "--root",
                        str(root),
                        "--fail-on",
                        "none",
                        "--compare-ref",
                        base_commit,
                        "--drift-output",
                        str(drift),
                    ]
                )
            payload = json.loads(drift.read_text(encoding="utf-8"))

        self.assertEqual(0, code)
        self.assertEqual(["claim-added"], [event["kind"] for event in payload["events"]])

    def test_compare_ref_and_compare_ledger_are_mutually_exclusive(self) -> None:
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
            root = self._repository(Path(directory))
            ledger = root / "ledger.json"
            ledger.write_text("{}", encoding="utf-8")
            with self.assertRaises(SystemExit) as raised:
                with redirect_stderr(StringIO()), redirect_stdout(StringIO()):
                    main(
                        [
                            "README.md",
                            "--root",
                            str(root),
                            "--compare-ref",
                            "HEAD",
                            "--compare-ledger",
                            str(ledger),
                        ]
                    )

        self.assertEqual(2, raised.exception.code)

    def test_compare_ref_rejects_option_like_or_missing_revision(self) -> None:
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
            root = self._repository(Path(directory))
            self._commit(root, "base")
            for ref in ("--help", "refs/heads/does-not-exist"):
                with self.subTest(ref=ref):
                    with self.assertRaises(SystemExit) as raised:
                        with redirect_stderr(StringIO()), redirect_stdout(StringIO()):
                            main(
                                [
                                    "README.md",
                                    "--root",
                                    str(root),
                                    "--compare-ref",
                                    ref,
                                ]
                            )
                    self.assertEqual(2, raised.exception.code)

    @staticmethod
    def _repository(root: Path) -> Path:
        GitComparisonTests._git(root, "init", "-q")
        (root / "docs").mkdir()
        (root / "docs" / "receipt.md").write_text(
            "measured evidence v1\n", encoding="utf-8"
        )
        (root / "README.md").write_text(
            "# Demo\n\n"
            "<!-- claimfence-id: gateway/readiness -->\n\n"
            "Under version 1, the gateway is production-ready.\n\n"
            "Inspect [the receipt](docs/receipt.md).\n\n"
            "## Limitations\n\nOther configurations are out of scope.\n",
            encoding="utf-8",
        )
        return root

    @staticmethod
    def _commit(root: Path, message: str) -> str:
        GitComparisonTests._git(root, "add", ".")
        GitComparisonTests._git(
            root,
            "-c",
            "user.name=ClaimFence Tests",
            "-c",
            "user.email=claimfence@example.invalid",
            "commit",
            "-q",
            "-m",
            message,
        )
        return GitComparisonTests._git(root, "rev-parse", "HEAD")

    @staticmethod
    def _git(root: Path, *arguments: str) -> str:
        completed = subprocess.run(
            ["git", "-C", str(root), *arguments],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        return completed.stdout.strip()


if __name__ == "__main__":
    unittest.main()
