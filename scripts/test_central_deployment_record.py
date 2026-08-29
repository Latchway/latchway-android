#!/usr/bin/env python3
"""Tests for immutable Central upload intent, deployment, and status records."""

from __future__ import annotations

import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/central-deployment-record.py"
COMMIT = "a" * 40
DEPLOYMENT_ID = "28570f16-da32-4c14-bd2e-c1acc0782365"
MODULES = (
    "latchway-core", "latchway-okhttp", "latchway-play-integrity",
    "latchway-firebase-auth", "latchway-bom",
)


class CentralDeploymentRecordTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.repository = self.root / "repository"
        artifact = self.repository / "dev/latchway/latchway-core/1.0.0/latchway-core-1.0.0.pom"
        artifact.parent.mkdir(parents=True)
        artifact.write_text("reviewed bytes\n", encoding="utf-8")
        self.archive = self.root / "repository.zip"
        self.archive.write_bytes(b"deterministic archive")
        self.public_key = self.root / "public-key.asc"
        self.public_key.write_bytes(b"reviewed key")
        self.intent = self.root / "maven-central-upload-intent.json"
        self.record = self.root / "maven-central-deployment.json"
        self.status = self.root / "portal-status.json"
        self.evidence = self.root / "maven-central-deployment-status.json"
        self.execute(
            "create-intent",
            "--repository", str(self.repository),
            "--archive", str(self.archive),
            "--public-key", str(self.public_key),
            "--source-commit", COMMIT,
            "--tag", "v1.0.0",
            "--version", "1.0.0",
            "--namespace", "dev.latchway",
            "--publishing-type", "automatic",
            "--output", str(self.intent),
            expected=0,
        )
        self.execute(
            "create-record",
            "--intent", str(self.intent),
            "--deployment-id", DEPLOYMENT_ID,
            "--output", str(self.record),
            expected=0,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def execute(self, *arguments: str, expected: int | None = None) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            ["python3", str(SCRIPT), *arguments],
            cwd=ROOT,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if expected is not None:
            self.assertEqual(result.returncode, expected, result.stderr)
        return result

    def portal_status(self, state: str = "PUBLISHED") -> dict[str, object]:
        intent = json.loads(self.intent.read_text(encoding="utf-8"))
        return {
            "deploymentId": DEPLOYMENT_ID,
            "deploymentName": intent["deployment_name"],
            "deploymentState": state,
            "purls": intent["expected_purls"] if state in {"VALIDATED", "PUBLISHING", "PUBLISHED"} else [],
        }

    def validate_status(self, value: dict[str, object]) -> subprocess.CompletedProcess[str]:
        self.status.write_text(json.dumps(value), encoding="utf-8")
        return self.execute(
            "validate-status",
            "--intent", str(self.intent),
            "--record", str(self.record),
            "--status", str(self.status),
            "--output", str(self.evidence),
        )

    def test_records_exact_source_artifact_key_and_deployment_bindings(self) -> None:
        intent = json.loads(self.intent.read_text(encoding="utf-8"))
        record = json.loads(self.record.read_text(encoding="utf-8"))
        self.assertEqual(intent["source_commit"], COMMIT)
        self.assertEqual(intent["reviewed_repository_archive_sha256"], hashlib.sha256(self.archive.read_bytes()).hexdigest())
        self.assertEqual(record["intent_sha256"], hashlib.sha256(self.intent.read_bytes()).hexdigest())
        self.assertEqual(record["deployment_id"], DEPLOYMENT_ID)
        self.execute(
            "validate-inputs",
            "--intent", str(self.intent),
            "--repository", str(self.repository),
            "--archive", str(self.archive),
            "--public-key", str(self.public_key),
            expected=0,
        )

    def test_rejects_release_input_changed_after_intent_was_recorded(self) -> None:
        artifact = next(self.repository.rglob("*.pom"))
        artifact.write_text("changed bytes\n", encoding="utf-8")
        result = self.execute(
            "validate-inputs",
            "--intent", str(self.intent),
            "--repository", str(self.repository),
            "--archive", str(self.archive),
            "--public-key", str(self.public_key),
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not match", result.stderr)

    def test_accepts_exact_final_status_and_emits_stable_hash_bound_evidence(self) -> None:
        result = self.validate_status(self.portal_status())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "PUBLISHED")
        evidence = json.loads(self.evidence.read_text(encoding="utf-8"))
        self.assertEqual(evidence["deployment_id"], DEPLOYMENT_ID)
        self.assertEqual(evidence["record_sha256"], hashlib.sha256(self.record.read_bytes()).hexdigest())

    def test_rejects_wrong_id_name_unknown_state_and_unexpected_purl(self) -> None:
        mutations = []
        wrong_id = self.portal_status()
        wrong_id["deploymentId"] = "38570f16-da32-4c14-bd2e-c1acc0782365"
        mutations.append(wrong_id)
        wrong_name = self.portal_status()
        wrong_name["deploymentName"] = "unrelated-release"
        mutations.append(wrong_name)
        wrong_state = self.portal_status()
        wrong_state["deploymentState"] = "MAGIC_SUCCESS"
        mutations.append(wrong_state)
        wrong_purl = self.portal_status()
        wrong_purl["purls"] = ["pkg:maven/attacker/other@1.0.0"]
        mutations.append(wrong_purl)
        for value in mutations:
            with self.subTest(value=value):
                self.evidence.unlink(missing_ok=True)
                result = self.validate_status(value)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(self.evidence.exists())

    def test_immutable_record_cannot_be_rebound_or_overwritten(self) -> None:
        result = self.execute(
            "create-record",
            "--intent", str(self.intent),
            "--deployment-id", "38570f16-da32-4c14-bd2e-c1acc0782365",
            "--output", str(self.record),
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("existing immutable state differs", result.stderr)

        value = json.loads(self.record.read_text(encoding="utf-8"))
        value["source_commit"] = "b" * 40
        self.record.write_text(json.dumps(value), encoding="utf-8")
        result = self.execute(
            "validate-record", "--intent", str(self.intent), "--record", str(self.record),
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not match", result.stderr)


if __name__ == "__main__":
    unittest.main()
