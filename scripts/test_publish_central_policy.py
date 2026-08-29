#!/usr/bin/env python3
"""End-to-end tests for recoverable, least-privilege Central publication."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from test_central_fixture import create_release_inputs


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
        self.repository, self.archive, self.portal_bundle, self.public_key = create_release_inputs(self.release)
        self.intent = self.release / "maven-central-upload-intent.json"
        self.record = self.release / "maven-central-deployment.json"
        self.status_evidence = self.release / "maven-central-deployment-status.json"
        subprocess.run([
            "python3", str(self.scripts / RECORD_HELPER.name), "create-intent",
            "--repository", str(self.repository), "--archive", str(self.archive),
            "--portal-bundle", str(self.portal_bundle), "--public-key", str(self.public_key),
            "--source-commit", COMMIT, "--tag", "v1.0.0", "--version", "1.0.0",
            "--namespace", "dev.latchway", "--publishing-type", "user_managed",
            "--output", str(self.intent),
        ], check=True)
        intent_value = json.loads(self.intent.read_text(encoding="utf-8"))
        self.deployment_name = intent_value["deployment_name"]
        self.portal_status = self.root / "portal-status.json"
        self.portal_status.write_text(json.dumps({
            "deploymentId": DEPLOYMENT_ID,
            "deploymentName": self.deployment_name,
            "deploymentState": "PUBLISHED",
            "purls": intent_value["expected_purls"],
        }), encoding="utf-8")
        self.empty_listing = self.root / "empty-listing.json"
        self.match_listing = self.root / "match-listing.json"
        self.empty_listing.write_text(json.dumps({
            "deployments": [], "page": 0, "pageSize": 100, "pageCount": 0, "totalResultCount": 0,
        }), encoding="utf-8")
        self.match_listing.write_text(json.dumps({
            "deployments": [{"deploymentId": DEPLOYMENT_ID, "deploymentName": self.deployment_name}],
            "page": 0, "pageSize": 100, "pageCount": 1, "totalResultCount": 1,
        }), encoding="utf-8")
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.upload_log = self.root / "upload.log"
        self.list_log = self.root / "list.log"
        self.status_log = self.root / "status.log"
        self.publish_log = self.root / "publish.log"
        self.secret_leak_log = self.root / "secret-leak.log"
        self.write_executable("git", """#!/bin/bash
set -euo pipefail
if [[ -n "${LATCHWAY_MAVEN_CENTRAL_USERNAME:-}${LATCHWAY_MAVEN_CENTRAL_PASSWORD:-}" ]]; then
  printf 'git inherited Portal credentials\n' >>"$FAKE_SECRET_LEAK_LOG"
  exit 9
fi
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
  */api/v1/publisher/deployments)
    printf 'list\n' >>"$FAKE_LIST_LOG"
    count=$(wc -l <"$FAKE_LIST_LOG" | tr -d ' ')
    if (( count >= FAKE_LIST_MATCH_AT )); then cp "$FAKE_MATCH_LISTING" "$output"; else cp "$FAKE_EMPTY_LISTING" "$output"; fi
    printf '200'
    ;;
  */api/v1/publisher/upload\\?*)
    printf 'upload\n' >>"$FAKE_UPLOAD_LOG"
    if [[ "$FAKE_UPLOAD_OUTCOME" == transport-failure ]]; then exit 28; fi
    printf '%s\n' "$FAKE_DEPLOYMENT_ID" >"$output"
    printf '201'
    ;;
  */api/v1/publisher/status\\?id=*)
    printf 'status\n' >>"$FAKE_STATUS_LOG"
    count=$(wc -l <"$FAKE_STATUS_LOG" | tr -d ' ')
    if [[ "$FAKE_STATUS_FIRST_VALIDATED" == true && "$count" == 1 ]]; then
      sed 's/"PUBLISHED"/"VALIDATED"/' "$FAKE_PORTAL_STATUS" >"$output"
    else
      cp "$FAKE_PORTAL_STATUS" "$output"
    fi
    printf '200'
    ;;
  */api/v1/publisher/deployment/*)
    printf 'publish\n' >>"$FAKE_PUBLISH_LOG"
    : >"$output"
    printf '204'
    ;;
  *)
    if [[ -n "${LATCHWAY_MAVEN_CENTRAL_USERNAME:-}${LATCHWAY_MAVEN_CENTRAL_PASSWORD:-}" ]]; then
      printf 'public curl inherited Portal credentials\n' >>"$FAKE_SECRET_LEAK_LOG"
      exit 9
    fi
    printf '%s' "$FAKE_CENTRAL_STATUS"
    ;;
esac
""")
        self.write_executable_at(self.scripts / "verify-central-release.sh", """#!/bin/bash
set -euo pipefail
test "$1" = 1.0.0
test "$LATCHWAY_CENTRAL_EXPECTED_REPOSITORY" = "$FAKE_EXPECTED_REPOSITORY"
printf '{"schema_version":2,"registry":"maven_central","namespace":"dev.latchway","version":"1.0.0","public_manifest_sha256":"%064d"}\n' 0
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
        subprocess.run([
            "python3", str(self.scripts / RECORD_HELPER.name), "create-record",
            "--intent", str(self.intent), "--deployment-id", DEPLOYMENT_ID,
            "--output", str(self.record),
        ], check=True)

    def invoke(
        self,
        central_status: str = "404",
        *,
        credentials: bool = False,
        intent_fresh: bool = False,
        stop_after_record: bool = False,
        publish_after_validation: bool = False,
        list_match_at: int = 999,
        upload_outcome: str = "success",
        status_first_validated: bool = False,
        signing_secrets: bool = False,
    ) -> subprocess.CompletedProcess[str]:
        environment = {
            **os.environ,
            "PATH": f"{self.bin}:/usr/bin:/bin",
            "LATCHWAY_RELEASE_VERSION": "1.0.0",
            "LATCHWAY_CENTRAL_PUBLISHING_TYPE": "user_managed",
            "LATCHWAY_CENTRAL_UPLOAD_INTENT": str(self.intent),
            "LATCHWAY_CENTRAL_DEPLOYMENT_RECORD": str(self.record),
            "LATCHWAY_CENTRAL_DEPLOYMENT_STATUS": str(self.status_evidence),
            "LATCHWAY_CENTRAL_PORTAL_BUNDLE": str(self.portal_bundle),
            "LATCHWAY_CENTRAL_SIGNING_PUBLIC_KEY": str(self.public_key),
            "LATCHWAY_CENTRAL_INTENT_FRESH": str(intent_fresh).lower(),
            "LATCHWAY_CENTRAL_STOP_AFTER_RECORD": str(stop_after_record).lower(),
            "LATCHWAY_CENTRAL_PUBLISH_AFTER_VALIDATION": str(publish_after_validation).lower(),
            "LATCHWAY_CENTRAL_SKIP_LOCAL_GATES": "true",
            "LATCHWAY_CENTRAL_STATUS_ATTEMPTS": "2",
            "LATCHWAY_CENTRAL_STATUS_DELAY_SECONDS": "1",
            "LATCHWAY_CENTRAL_ADOPTION_ATTEMPTS": "1",
            "LATCHWAY_CENTRAL_ADOPTION_DELAY_SECONDS": "1",
            "FAKE_CENTRAL_STATUS": central_status,
            "FAKE_DEPLOYMENT_ID": DEPLOYMENT_ID,
            "FAKE_PORTAL_STATUS": str(self.portal_status),
            "FAKE_EXPECTED_REPOSITORY": str(self.repository),
            "FAKE_EMPTY_LISTING": str(self.empty_listing),
            "FAKE_MATCH_LISTING": str(self.match_listing),
            "FAKE_LIST_MATCH_AT": str(list_match_at),
            "FAKE_UPLOAD_OUTCOME": upload_outcome,
            "FAKE_STATUS_FIRST_VALIDATED": str(status_first_validated).lower(),
            "FAKE_UPLOAD_LOG": str(self.upload_log),
            "FAKE_LIST_LOG": str(self.list_log),
            "FAKE_STATUS_LOG": str(self.status_log),
            "FAKE_PUBLISH_LOG": str(self.publish_log),
            "FAKE_SECRET_LEAK_LOG": str(self.secret_leak_log),
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
            })
        if signing_secrets:
            environment.update({"LATCHWAY_SIGNING_KEY": "private", "LATCHWAY_SIGNING_PASSWORD": "pass"})
        return subprocess.run(
            ["/bin/bash", str(self.scripts / SCRIPT.name)], cwd=self.root, env=environment,
            check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )

    def test_public_coordinates_create_complete_manifest_bound_adoption(self) -> None:
        result = self.invoke("200")
        self.assertEqual(result.returncode, 0, result.stderr)
        record = json.loads(self.record.read_text(encoding="utf-8"))
        status = json.loads(self.status_evidence.read_text(encoding="utf-8"))
        self.assertEqual(record["record_kind"], "public_registry_adoption")
        self.assertEqual(status["deployment_state"], "PUBLISHED")
        self.assertEqual(record["public_manifest_sha256"], "0" * 64)
        self.assertFalse(self.upload_log.exists())
        self.status_evidence.unlink()
        resumed = self.invoke("200")
        self.assertEqual(resumed.returncode, 0, resumed.stderr)
        self.assertTrue(self.status_evidence.is_file())

    def test_pre_post_and_successful_post_crash_windows_are_recoverable(self) -> None:
        # Fresh/pre-POST path: authoritative listing is empty, so upload once.
        result = self.invoke(credentials=True, intent_fresh=True, stop_after_record=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.upload_log.read_text(encoding="utf-8"), "upload\n")
        self.assertEqual(json.loads(self.record.read_text())["deployment_id"], DEPLOYMENT_ID)

        # A rerun after POST but before record durability adopts the exact name.
        self.record.unlink()
        self.upload_log.unlink()
        self.list_log.unlink()
        result = self.invoke(credentials=True, stop_after_record=True, list_match_at=1)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Adopted exact existing", result.stdout)
        self.assertFalse(self.upload_log.exists())

        # An ambiguous transport result is reconciled, never blindly retried.
        self.record.unlink()
        self.list_log.unlink()
        result = self.invoke(
            credentials=True, intent_fresh=True, stop_after_record=True,
            list_match_at=2, upload_outcome="transport-failure",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.upload_log.read_text(encoding="utf-8"), "upload\n")

    def test_record_is_durable_before_explicit_publish_and_reruns_never_upload(self) -> None:
        self.create_record()
        result = self.invoke(
            credentials=True, publish_after_validation=True, status_first_validated=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.publish_log.read_text(encoding="utf-8"), "publish\n")
        self.assertEqual(self.status_log.read_text(encoding="utf-8"), "status\nstatus\n")
        self.assertFalse(self.upload_log.exists())
        self.assertEqual(json.loads(self.status_evidence.read_text())["deployment_state"], "PUBLISHED")

    def test_portal_credentials_are_removed_before_unrelated_subprocesses(self) -> None:
        result = self.invoke(credentials=True, intent_fresh=True, stop_after_record=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.secret_leak_log.exists())

    def test_signing_material_is_rejected_by_network_publisher(self) -> None:
        result = self.invoke(credentials=True, signing_secrets=True)
        self.assertEqual(result.returncode, 64)
        self.assertIn("must not be exposed", result.stderr)
        self.assertFalse(self.upload_log.exists())

    def test_unknown_registry_state_and_ambiguous_duplicate_listing_fail_closed(self) -> None:
        result = self.invoke("503", credentials=True, intent_fresh=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("HTTP 503", result.stderr)
        self.assertFalse(self.upload_log.exists())

        duplicate = json.loads(self.match_listing.read_text())
        duplicate["deployments"].append({
            "deploymentId": "38570f16-da32-4c14-bd2e-c1acc0782365",
            "deploymentName": self.deployment_name,
        })
        duplicate["totalResultCount"] = 2
        self.match_listing.write_text(json.dumps(duplicate))
        result = self.invoke(credentials=True, list_match_at=1)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("multiple deployments", result.stderr)
        self.assertFalse(self.upload_log.exists())


if __name__ == "__main__":
    unittest.main()
