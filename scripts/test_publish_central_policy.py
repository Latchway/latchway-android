#!/usr/bin/env python3
"""Offline tests for resumable, single-upload Maven Central publication."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/publish-central.sh"
RECORD_HELPER = ROOT / "scripts/central-deployment-record.py"
COMMIT = "0" * 40
DEPLOYMENT_ID = "28570f16-da32-4c14-bd2e-c1acc0782365"


class CentralPublicationPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.scripts = self.root / "scripts"
        self.scripts.mkdir()
        shutil.copy2(SCRIPT, self.scripts / SCRIPT.name)
        shutil.copy2(RECORD_HELPER, self.scripts / RECORD_HELPER.name)
        self.release = self.root / "build/release"
        repository = self.release / "repository"
        artifact = repository / "dev/latchway/latchway-core/1.0.0/latchway-core-1.0.0.pom"
        artifact.parent.mkdir(parents=True)
        artifact.write_text("reviewed\n", encoding="utf-8")
        self.archive = self.release / "latchway-android-1.0.0-maven-repository.zip"
        self.archive.write_bytes(b"archive")
        self.public_key = self.release / "latchway-maven-signing-public-key.asc"
        self.public_key.write_bytes(b"public key")
        self.intent = self.release / "maven-central-upload-intent.json"
        self.record = self.release / "maven-central-deployment.json"
        self.status_evidence = self.release / "maven-central-deployment-status.json"
        subprocess.run(
            [
                "python3", str(self.scripts / RECORD_HELPER.name), "create-intent",
                "--repository", str(repository), "--archive", str(self.archive),
                "--public-key", str(self.public_key), "--source-commit", COMMIT,
                "--tag", "v1.0.0", "--version", "1.0.0", "--namespace", "dev.latchway",
                "--publishing-type", "automatic", "--output", str(self.intent),
            ],
            check=True,
        )
        intent_value = json.loads(self.intent.read_text(encoding="utf-8"))
        self.portal_status = self.root / "portal-status.json"
        self.portal_status.write_text(json.dumps({
            "deploymentId": DEPLOYMENT_ID,
            "deploymentName": intent_value["deployment_name"],
            "deploymentState": "PUBLISHED",
            "purls": intent_value["expected_purls"],
        }), encoding="utf-8")
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.verify_log = self.root / "verify.log"
        self.upload_log = self.root / "upload.log"
        self.status_log = self.root / "status.log"
        self.bundle_log = self.root / "bundle.log"
        self.write_executable("git", """#!/bin/bash
set -euo pipefail
case "$*" in
  *"status --porcelain") exit 0 ;;
  *"rev-parse HEAD") printf '%040d\n' 0 ;;
  *"rev-list -n 1 v1.0.0") printf '%040d\n' 0 ;;
  *) echo "unexpected git command: $*" >&2; exit 2 ;;
esac
""")
        self.write_executable("curl", """#!/bin/bash
set -euo pipefail
output=
url=${!#}
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output) output=$2; shift 2 ;;
    *) shift ;;
  esac
done
case "$url" in
  */api/v1/publisher/upload\\?*)
    printf 'upload\n' >>"$FAKE_UPLOAD_LOG"
    printf '%s\n' "$FAKE_DEPLOYMENT_ID" >"$output"
    printf '201'
    ;;
  */api/v1/publisher/status\\?id=*)
    printf 'status\n' >>"$FAKE_STATUS_LOG"
    cp "$FAKE_PORTAL_STATUS" "$output"
    printf '200'
    ;;
  *) printf '%s' "$FAKE_CENTRAL_STATUS" ;;
esac
""")
        self.write_executable_at(self.scripts / "verify-central-release.sh", """#!/bin/bash
set -euo pipefail
test "$1" = 1.0.0
test "$LATCHWAY_CENTRAL_EXPECTED_REPOSITORY" = "$FAKE_EXPECTED_REPOSITORY"
printf 'verified\n' >>"$FAKE_VERIFY_LOG"
""")
        self.write_executable_at(self.scripts / "build-central-portal-bundle.sh", """#!/bin/bash
set -euo pipefail
test "$1" = 1.0.0
printf 'bundle\n' >"$2"
printf 'built\n' >>"$FAKE_BUNDLE_LOG"
""")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_executable(self, name: str, source: str) -> None:
        self.write_executable_at(self.bin / name, source)

    @staticmethod
    def write_executable_at(path: Path, source: str) -> None:
        path.write_text(source, encoding="utf-8")
        path.chmod(0o755)

    def create_record(self) -> None:
        subprocess.run(
            [
                "python3", str(self.scripts / RECORD_HELPER.name), "create-record",
                "--intent", str(self.intent), "--deployment-id", DEPLOYMENT_ID,
                "--output", str(self.record),
            ],
            check=True,
        )

    def invoke(
        self,
        central_status: str,
        *,
        allow_upload: bool = False,
        credentials: bool = False,
        stop_after_record: bool = False,
    ) -> subprocess.CompletedProcess[str]:
        environment = {
            **os.environ,
            "PATH": f"{self.bin}:/usr/bin:/bin",
            "LATCHWAY_RELEASE_VERSION": "1.0.0",
            "LATCHWAY_CENTRAL_PUBLISHING_TYPE": "automatic",
            "LATCHWAY_CENTRAL_UPLOAD_INTENT": str(self.intent),
            "LATCHWAY_CENTRAL_DEPLOYMENT_RECORD": str(self.record),
            "LATCHWAY_CENTRAL_DEPLOYMENT_STATUS": str(self.status_evidence),
            "LATCHWAY_CENTRAL_SIGNING_PUBLIC_KEY": str(self.public_key),
            "LATCHWAY_CENTRAL_ALLOW_NEW_UPLOAD": str(allow_upload).lower(),
            "LATCHWAY_CENTRAL_STOP_AFTER_RECORD": str(stop_after_record).lower(),
            "LATCHWAY_CENTRAL_SKIP_LOCAL_GATES": "true",
            "LATCHWAY_CENTRAL_STATUS_ATTEMPTS": "1",
            "LATCHWAY_CENTRAL_STATUS_DELAY_SECONDS": "1",
            "FAKE_CENTRAL_STATUS": central_status,
            "FAKE_DEPLOYMENT_ID": DEPLOYMENT_ID,
            "FAKE_PORTAL_STATUS": str(self.portal_status),
            "FAKE_EXPECTED_REPOSITORY": str(self.release / "repository"),
            "FAKE_VERIFY_LOG": str(self.verify_log),
            "FAKE_UPLOAD_LOG": str(self.upload_log),
            "FAKE_STATUS_LOG": str(self.status_log),
            "FAKE_BUNDLE_LOG": str(self.bundle_log),
            "LATCHWAY_ALLOW_UNTAGGED_RELEASE_FOR_STAGING": "false",
        }
        for name in (
            "LATCHWAY_MAVEN_CENTRAL_USERNAME", "LATCHWAY_MAVEN_CENTRAL_PASSWORD",
            "LATCHWAY_SIGNING_KEY", "LATCHWAY_SIGNING_PASSWORD",
        ):
            environment.pop(name, None)
        if credentials:
            environment.update({
                "LATCHWAY_MAVEN_CENTRAL_USERNAME": "token-user",
                "LATCHWAY_MAVEN_CENTRAL_PASSWORD": "token-password",
                "LATCHWAY_SIGNING_KEY": "test-private-key",
                "LATCHWAY_SIGNING_PASSWORD": "test-passphrase",
            })
        return subprocess.run(
            ["/bin/bash", str(self.scripts / SCRIPT.name)],
            cwd=self.root,
            env=environment,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    def test_existing_coordinates_are_verified_without_credentials_or_upload(self) -> None:
        result = self.invoke("200")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.verify_log.read_text(encoding="utf-8"), "verified\n")
        self.assertFalse(self.upload_log.exists())

    def test_existing_intent_without_deployment_id_fails_closed(self) -> None:
        result = self.invoke("404", credentials=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("refusing a second upload", result.stderr)
        self.assertFalse(self.upload_log.exists())

    def test_new_upload_requires_explicit_single_use_authorization_and_records_id(self) -> None:
        result = self.invoke("404", allow_upload=True, credentials=True, stop_after_record=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.upload_log.read_text(encoding="utf-8"), "upload\n")
        self.assertEqual(self.bundle_log.read_text(encoding="utf-8"), "built\n")
        record = json.loads(self.record.read_text(encoding="utf-8"))
        self.assertEqual(record["deployment_id"], DEPLOYMENT_ID)
        self.assertFalse(self.status_log.exists())

    def test_stop_after_record_resume_is_read_only_and_does_not_require_credentials(self) -> None:
        self.create_record()
        result = self.invoke("404", stop_after_record=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(DEPLOYMENT_ID, result.stdout)
        self.assertFalse(self.upload_log.exists())
        self.assertFalse(self.status_log.exists())

    def test_rerun_queries_recorded_deployment_and_never_uploads_again(self) -> None:
        self.create_record()
        result = self.invoke("404", allow_upload=True, credentials=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("PUBLISHED", result.stdout)
        self.assertFalse(self.upload_log.exists())
        self.assertFalse(self.bundle_log.exists())
        evidence = json.loads(self.status_evidence.read_text(encoding="utf-8"))
        self.assertEqual(evidence["deployment_id"], DEPLOYMENT_ID)

    def test_wrong_portal_deployment_status_fails_closed_without_upload(self) -> None:
        self.create_record()
        value = json.loads(self.portal_status.read_text(encoding="utf-8"))
        value["deploymentId"] = "38570f16-da32-4c14-bd2e-c1acc0782365"
        self.portal_status.write_text(json.dumps(value), encoding="utf-8")
        result = self.invoke("404", credentials=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("deployment ID mismatch", result.stderr)
        self.assertFalse(self.upload_log.exists())

    def test_unknown_registry_state_never_uploads(self) -> None:
        result = self.invoke("503", allow_upload=True, credentials=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("HTTP 503", result.stderr)
        self.assertFalse(self.upload_log.exists())


if __name__ == "__main__":
    unittest.main()
