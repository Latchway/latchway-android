#!/usr/bin/env python3
"""Adversarial tests for immutable Central deployment state and artifact closure."""

from __future__ import annotations

import hashlib
import json
import subprocess
import tempfile
import unittest
import warnings
import zipfile
from pathlib import Path

from test_central_fixture import create_release_inputs, write_zip


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/central-deployment-record.py"
COMMIT = "a" * 40
DEPLOYMENT_ID = "28570f16-da32-4c14-bd2e-c1acc0782365"


class CentralDeploymentRecordTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.repository, self.archive, self.portal_bundle, self.public_key = create_release_inputs(self.root)
        self.intent = self.root / "maven-central-upload-intent.json"
        self.record = self.root / "maven-central-deployment.json"
        self.raw_status = self.root / "portal-status.json"
        self.status = self.root / "maven-central-deployment-status.json"
        self.create_intent()
        self.execute(
            "create-record", "--intent", str(self.intent), "--deployment-id", DEPLOYMENT_ID,
            "--output", str(self.record), expected=0,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def execute(self, *arguments: str, expected: int | None = None) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            ["python3", str(SCRIPT), *arguments], cwd=ROOT, check=False,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        if expected is not None:
            self.assertEqual(result.returncode, expected, result.stderr)
        return result

    def create_intent(self) -> None:
        self.execute(
            "create-intent", "--repository", str(self.repository), "--archive", str(self.archive),
            "--portal-bundle", str(self.portal_bundle), "--public-key", str(self.public_key),
            "--source-commit", COMMIT, "--tag", "v1.0.0", "--version", "1.0.0",
            "--namespace", "dev.latchway", "--publishing-type", "user_managed",
            "--output", str(self.intent), expected=0,
        )

    def portal_status(self, state: str = "PUBLISHED") -> dict[str, object]:
        intent = json.loads(self.intent.read_text(encoding="utf-8"))
        return {
            "deploymentId": DEPLOYMENT_ID,
            "deploymentName": intent["deployment_name"],
            "deploymentState": state,
            "purls": intent["expected_purls"] if state in {"VALIDATED", "PUBLISHING", "PUBLISHED"} else [],
        }

    def normalize_status(self, value: dict[str, object]) -> subprocess.CompletedProcess[str]:
        self.raw_status.write_text(json.dumps(value), encoding="utf-8")
        return self.execute(
            "validate-status", "--intent", str(self.intent), "--record", str(self.record),
            "--status", str(self.raw_status), "--output", str(self.status),
        )

    def test_records_exact_repository_archive_portal_bundle_key_and_source(self) -> None:
        intent = json.loads(self.intent.read_text(encoding="utf-8"))
        record = json.loads(self.record.read_text(encoding="utf-8"))
        self.assertEqual(intent["reviewed_repository_file_count"], 120)
        self.assertEqual(intent["reviewed_portal_bundle_file_count"], 144)
        self.assertEqual(intent["reviewed_portal_bundle_sha256"], hashlib.sha256(self.portal_bundle.read_bytes()).hexdigest())
        self.assertTrue(intent["deployment_name"].endswith(intent["reviewed_portal_bundle_sha256"]))
        self.assertEqual(record["record_kind"], "portal_deployment")
        self.assertEqual(record["reviewed_portal_bundle_sha256"], intent["reviewed_portal_bundle_sha256"])
        self.execute(
            "validate-inputs", "--intent", str(self.intent), "--repository", str(self.repository),
            "--archive", str(self.archive), "--portal-bundle", str(self.portal_bundle),
            "--public-key", str(self.public_key), expected=0,
        )

    def test_rejects_missing_extra_or_invalid_checksum_repository_files(self) -> None:
        mutations = []
        checksum = next(self.repository.rglob("*.sha256"))
        checksum.write_text("0" * 64, encoding="ascii")
        mutations.append("checksum")
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                result = self.execute(
                    "validate-inputs", "--intent", str(self.intent), "--repository", str(self.repository),
                    "--archive", str(self.archive), "--portal-bundle", str(self.portal_bundle),
                    "--public-key", str(self.public_key),
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("checksum does not match", result.stderr)

        self.repository, self.archive, self.portal_bundle, self.public_key = create_release_inputs(self.root / "fresh")
        (self.repository / "dev/latchway/foreign.txt").write_text("extra", encoding="utf-8")
        result = self.execute(
            "create-intent", "--repository", str(self.repository), "--archive", str(self.archive),
            "--portal-bundle", str(self.portal_bundle), "--public-key", str(self.public_key),
            "--source-commit", COMMIT, "--tag", "v1.0.0", "--version", "1.0.0",
            "--publishing-type", "user_managed", "--output", str(self.root / "extra-intent.json"),
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("exact closed artifact set", result.stderr)

    def test_rejects_archive_byte_substitution_duplicate_and_portal_extra(self) -> None:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(self.archive, "a") as archive:
                name = archive.namelist()[0]
                archive.writestr(name, b"substituted")
        result = self.execute(
            "validate-inputs", "--intent", str(self.intent), "--repository", str(self.repository),
            "--archive", str(self.archive), "--portal-bundle", str(self.portal_bundle),
            "--public-key", str(self.public_key),
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("duplicate", result.stderr)

        write_zip(self.archive, self.repository, signed=False)
        with zipfile.ZipFile(self.portal_bundle, "a") as portal:
            portal.writestr("dev/latchway/unreviewed.bin", b"extra")
        result = self.execute(
            "validate-inputs", "--intent", str(self.intent), "--repository", str(self.repository),
            "--archive", str(self.archive), "--portal-bundle", str(self.portal_bundle),
            "--public-key", str(self.public_key),
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("exact closed artifact set", result.stderr)

    def test_accepts_exact_final_portal_status_and_rejects_wrong_bindings(self) -> None:
        result = self.normalize_status(self.portal_status())
        self.assertEqual(result.returncode, 0, result.stderr)
        evidence = json.loads(self.status.read_text(encoding="utf-8"))
        self.assertEqual(evidence["record_kind"], "portal_deployment")
        self.assertEqual(evidence["deployment_state"], "PUBLISHED")
        self.execute(
            "validate-complete", "--intent", str(self.intent), "--record", str(self.record),
            "--status", str(self.status), "--public-manifest-sha256", "f" * 64, expected=0,
        )
        for field, value in (
            ("deploymentId", "38570f16-da32-4c14-bd2e-c1acc0782365"),
            ("deploymentName", "unrelated"),
            ("deploymentState", "MAGIC_SUCCESS"),
        ):
            mutated = self.portal_status()
            mutated[field] = value
            self.status.unlink(missing_ok=True)
            self.assertNotEqual(self.normalize_status(mutated).returncode, 0)

    def test_selects_only_one_exact_deterministic_portal_deployment(self) -> None:
        name = json.loads(self.intent.read_text(encoding="utf-8"))["deployment_name"]
        listing = self.root / "listing.json"
        listing.write_text(json.dumps({"deployments": [
            {"deploymentId": DEPLOYMENT_ID, "deploymentName": name},
            {"deploymentId": "38570f16-da32-4c14-bd2e-c1acc0782365", "deploymentName": "other"},
        ], "page": 0, "pageSize": 100, "pageCount": 1, "totalResultCount": 2}), encoding="utf-8")
        result = self.execute("select-deployment", "--intent", str(self.intent), "--listing", str(listing), expected=0)
        self.assertEqual(result.stdout.strip(), DEPLOYMENT_ID)
        listing.write_text(json.dumps({"deployments": [
            {"deploymentId": DEPLOYMENT_ID, "deploymentName": name},
            {"deploymentId": "38570f16-da32-4c14-bd2e-c1acc0782365", "deploymentName": name},
        ], "page": 0, "pageSize": 100, "pageCount": 1, "totalResultCount": 2}), encoding="utf-8")
        result = self.execute("select-deployment", "--intent", str(self.intent), "--listing", str(listing))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("multiple deployments", result.stderr)

    def test_public_coordinate_adoption_is_complete_and_manifest_bound(self) -> None:
        self.record.unlink()
        evidence = self.root / "public.json"
        evidence.write_text(json.dumps({
            "schema_version": 2, "registry": "maven_central", "namespace": "dev.latchway",
            "version": "1.0.0", "public_manifest_sha256": "c" * 64,
        }), encoding="utf-8")
        self.execute(
            "create-adoption-record", "--intent", str(self.intent), "--public-evidence", str(evidence),
            "--output", str(self.record), expected=0,
        )
        self.execute(
            "create-adoption-status", "--intent", str(self.intent), "--record", str(self.record),
            "--public-evidence", str(evidence), "--output", str(self.status), expected=0,
        )
        self.execute(
            "validate-complete", "--intent", str(self.intent), "--record", str(self.record),
            "--status", str(self.status), "--public-manifest-sha256", "c" * 64, expected=0,
        )
        result = self.execute(
            "validate-complete", "--intent", str(self.intent), "--record", str(self.record),
            "--status", str(self.status), "--public-manifest-sha256", "d" * 64,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("current public manifest", result.stderr)

    def test_immutable_record_cannot_be_rebound_or_overwritten(self) -> None:
        result = self.execute(
            "create-record", "--intent", str(self.intent),
            "--deployment-id", "38570f16-da32-4c14-bd2e-c1acc0782365", "--output", str(self.record),
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("existing immutable state differs", result.stderr)


if __name__ == "__main__":
    unittest.main()
