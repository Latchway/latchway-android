#!/usr/bin/env python3
"""Offline tests for the single-maintainer Android release request verifier."""

from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).with_name("verify-maintainer-release.py")
SPEC = importlib.util.spec_from_file_location("verify_maintainer_release", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
COMMIT = "a" * 40


class MaintainerReleaseVerifierTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name, "latchway-android")
        (self.root / "latchway-core/src/main/kotlin/dev/latchway/core").mkdir(
            parents=True
        )
        (self.root / "contract.lock").write_text(
            "\n".join(
                (
                    "contract_version: 1.0.0",
                    "wire_protocol: 2",
                    "core_release: v1.0.0",
                    f"core_commit: {'b' * 40}",
                    f'bundle_sha256: "{'c' * 64}"',
                    "minimum_server_version: 1.0.0",
                    "maximum_tested_server_version: 1.0.x",
                    "",
                )
            ),
            encoding="utf-8",
        )
        (
            self.root
            / "latchway-core/src/main/kotlin/dev/latchway/core/LatchwayApi.kt"
        ).write_text(
            'public const val LATCHWAY_SDK_VERSION: String = "1.0.0"\n'
            'public const val LATCHWAY_CONTRACT_VERSION: String = "1.0.0"\n',
            encoding="utf-8",
        )
        (self.root / "CHANGELOG.md").write_text(
            "# Changelog\n\n## [1.0.0] - 2026-09-01\n",
            encoding="utf-8",
        )
        self.output = self.root / "intent.json"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def arguments(self, **overrides: str) -> argparse.Namespace:
        values: dict[str, object] = {
            "repository_name": "Latchway/latchway-android",
            "profile": "single_maintainer_v1",
            "release_commit": COMMIT,
            "release_version": "1.0.0",
            "workflow_commit": COMMIT,
            "workflow_ref": "refs/heads/main",
            "run_id": "123",
            "run_attempt": "1",
            "confirmation": "publish-v1.0.0-with-deferred-assurance",
            "intent_output": self.output,
            "github_output": None,
        }
        values.update(overrides)
        return argparse.Namespace(**values)

    def verify(self, **overrides: str) -> dict[str, str]:
        def git(*arguments: str) -> str:
            if arguments[:2] == ("rev-parse", "--verify"):
                return COMMIT
            if arguments[:2] == ("status", "--porcelain=v1"):
                return ""
            raise AssertionError(arguments)

        with patch.object(MODULE, "ROOT", self.root), patch.object(
            MODULE, "git", side_effect=git
        ):
            return MODULE.verify(self.arguments(**overrides))

    def test_accepts_exact_main_request_and_emits_honest_intent(self) -> None:
        outputs = self.verify()
        value = json.loads(self.output.read_text(encoding="utf-8"))
        self.assertEqual(outputs["version"], "1.0.0")
        self.assertEqual(outputs["core_commit"], "b" * 40)
        self.assertEqual(value["profile"], "single_maintainer_v1")
        self.assertFalse(value["publication_ready"])
        self.assertFalse(value["release_qualified"])
        self.assertFalse(value["requires_independent_human_review"])
        self.assertIn("independent_human_review", value["deferred_evidence"])
        self.assertIn("cloud_deployments", value["deferred_evidence"])
        self.assertFalse(any(item.startswith("cloud_deployments.") for item in value["deferred_evidence"]))
        self.assertEqual(value["global_profile_required_evidence"], [])
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o600)

    def test_rejects_every_dispatch_identity_mismatch(self) -> None:
        cases = (
            {"repository_name": "someone/latchway-android"},
            {"profile": "strict_full"},
            {"release_version": "1.0.1"},
            {"workflow_commit": "d" * 40},
            {"workflow_ref": "refs/heads/release"},
            {"confirmation": "yes"},
            {"release_commit": "A" * 40, "workflow_commit": "A" * 40},
        )
        for values in cases:
            with self.subTest(values=values), self.assertRaisesRegex(
                MODULE.Rejected, "maintainer_release_dispatch_invalid"
            ):
                self.verify(**values)

    def test_rejects_checked_out_commit_mismatch_and_dirty_tree(self) -> None:
        with patch.object(MODULE, "ROOT", self.root), patch.object(
            MODULE, "git", return_value="d" * 40
        ), self.assertRaisesRegex(MODULE.Rejected, "commit_mismatch"):
            MODULE.verify(self.arguments())

        def dirty(*arguments: str) -> str:
            return COMMIT if arguments[0] == "rev-parse" else "?? secret.txt"

        with patch.object(MODULE, "ROOT", self.root), patch.object(
            MODULE, "git", side_effect=dirty
        ), self.assertRaisesRegex(MODULE.Rejected, "worktree_dirty"):
            MODULE.verify(self.arguments())

    def test_rejects_invalid_contract_duplicate_and_symlink(self) -> None:
        lock = self.root / "contract.lock"
        original = lock.read_text(encoding="utf-8")
        lock.write_text(original + "wire_protocol: 2\n", encoding="utf-8")
        with self.assertRaisesRegex(MODULE.Rejected, "contract_lock_invalid"):
            self.verify()
        lock.unlink()
        lock.symlink_to(self.root / "CHANGELOG.md")
        with self.assertRaisesRegex(MODULE.Rejected, "contract_lock_invalid"):
            self.verify()

    def test_rejects_runtime_or_changelog_version_drift(self) -> None:
        runtime = (
            self.root
            / "latchway-core/src/main/kotlin/dev/latchway/core/LatchwayApi.kt"
        )
        runtime.write_text(
            runtime.read_text(encoding="utf-8").replace("1.0.0", "1.0.1", 1),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(MODULE.Rejected, "local_version_invalid"):
            self.verify()
        runtime.write_text(
            'public const val LATCHWAY_SDK_VERSION: String = "1.0.0"\n'
            'public const val LATCHWAY_CONTRACT_VERSION: String = "1.0.0"\n',
            encoding="utf-8",
        )
        (self.root / "CHANGELOG.md").write_text("# Changelog\n", encoding="utf-8")
        with self.assertRaisesRegex(MODULE.Rejected, "changelog_invalid"):
            self.verify()

    def test_rejects_unsafe_run_identity_or_intent_destination(self) -> None:
        for values in ({"run_id": "0"}, {"run_attempt": "01"}, {"run_id": str(2**53)}):
            with self.subTest(values=values), self.assertRaisesRegex(
                MODULE.Rejected, "run_identity_invalid"
            ):
                self.verify(**values)
        destination = self.root / "destination"
        destination.mkdir()
        with self.assertRaisesRegex(MODULE.Rejected, "intent_output_invalid"):
            self.verify(intent_output=destination)


if __name__ == "__main__":
    unittest.main()
