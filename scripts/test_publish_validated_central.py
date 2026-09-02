#!/usr/bin/env python3
"""Offline tests for the exact Maven Central publication transition."""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from test_central_fixture import create_release_inputs


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/publish-validated-central.sh"
RECORD_HELPER = ROOT / "scripts/central-deployment-record.py"
COMMIT = "0" * 40
DEPLOYMENT_ID = "28570f16-da32-4c14-bd2e-c1acc0782365"


class ValidatedCentralPublicationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.scripts = self.root / "scripts"
        self.scripts.mkdir()
        shutil.copy2(SCRIPT, self.scripts / SCRIPT.name)
        shutil.copy2(RECORD_HELPER, self.scripts / RECORD_HELPER.name)
        release = self.root / "release"
        repository, archive, portal, public_key = create_release_inputs(release)
        self.intent = release / "intent.json"
        self.record = release / "record.json"
        self.status = release / "status.json"
        subprocess.run(
            [
                "python3",
                str(self.scripts / RECORD_HELPER.name),
                "create-intent",
                "--repository",
                str(repository),
                "--archive",
                str(archive),
                "--portal-bundle",
                str(portal),
                "--public-key",
                str(public_key),
                "--source-commit",
                COMMIT,
                "--tag",
                "v1.0.0",
                "--version",
                "1.0.0",
                "--namespace",
                "dev.latchway",
                "--publishing-type",
                "user_managed",
                "--output",
                str(self.intent),
            ],
            check=True,
        )
        subprocess.run(
            [
                "python3",
                str(self.scripts / RECORD_HELPER.name),
                "create-record",
                "--intent",
                str(self.intent),
                "--deployment-id",
                DEPLOYMENT_ID,
                "--output",
                str(self.record),
            ],
            check=True,
        )
        intent = json.loads(self.intent.read_text(encoding="utf-8"))
        self.validated = self.root / "validated.json"
        self.published = self.root / "published.json"
        base = {
            "deploymentId": DEPLOYMENT_ID,
            "deploymentName": intent["deployment_name"],
            "purls": intent["expected_purls"],
        }
        self.validated.write_text(
            json.dumps({**base, "deploymentState": "VALIDATED"}), encoding="utf-8"
        )
        self.published.write_text(
            json.dumps({**base, "deploymentState": "PUBLISHED"}), encoding="utf-8"
        )
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.status_log = self.root / "status.log"
        self.publish_log = self.root / "publish.log"
        curl = self.bin / "curl"
        curl.write_text(
            """#!/bin/bash
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
  */status\\?id=*)
    printf 'status\n' >>"$FAKE_STATUS_LOG"
    count=$(wc -l <"$FAKE_STATUS_LOG" | tr -d ' ')
    if [[ "$FAKE_STATUS_MODE" == wrong ]]; then
      sed 's#pkg:maven/dev.latchway/latchway-core@1.0.0#pkg:maven/evil/core@1.0.0#' "$FAKE_VALIDATED" >"$output"
    elif [[ "$FAKE_STATUS_MODE" == stuck || "$count" == 1 ]]; then
      cp "$FAKE_VALIDATED" "$output"
    else
      cp "$FAKE_PUBLISHED" "$output"
    fi
    printf '200'
    ;;
  */deployment/*)
    printf 'publish\n' >>"$FAKE_PUBLISH_LOG"
    : >"$output"
    if [[ "$FAKE_PUBLISH_OUTCOME" == transport ]]; then exit 28; fi
    printf '%s' "$FAKE_PUBLISH_CODE"
    ;;
  *) echo "unexpected URL $url" >&2; exit 2 ;;
esac
""",
            encoding="utf-8",
        )
        curl.chmod(0o755)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def invoke(
        self,
        *,
        credentials: bool = True,
        status_mode: str = "normal",
        publish_outcome: str = "success",
        publish_code: str = "204",
        signing_secrets: bool = False,
    ) -> subprocess.CompletedProcess[str]:
        environment = {
            **os.environ,
            "PATH": f"{self.bin}:/usr/bin:/bin",
            "LATCHWAY_CENTRAL_UPLOAD_INTENT": str(self.intent),
            "LATCHWAY_CENTRAL_DEPLOYMENT_RECORD": str(self.record),
            "LATCHWAY_CENTRAL_DEPLOYMENT_STATUS": str(self.status),
            "LATCHWAY_CENTRAL_PUBLISH_ATTEMPTS": "2",
            "LATCHWAY_CENTRAL_PUBLISH_DELAY_SECONDS": "1",
            "LATCHWAY_CENTRAL_PORTAL_API_BASE_URL": "https://central.test/api/v1/publisher",
            "FAKE_VALIDATED": str(self.validated),
            "FAKE_PUBLISHED": str(self.published),
            "FAKE_STATUS_LOG": str(self.status_log),
            "FAKE_PUBLISH_LOG": str(self.publish_log),
            "FAKE_STATUS_MODE": status_mode,
            "FAKE_PUBLISH_OUTCOME": publish_outcome,
            "FAKE_PUBLISH_CODE": publish_code,
        }
        for name in (
            "LATCHWAY_MAVEN_CENTRAL_USERNAME",
            "LATCHWAY_MAVEN_CENTRAL_PASSWORD",
            "LATCHWAY_SIGNING_KEY",
            "LATCHWAY_SIGNING_PASSWORD",
        ):
            environment.pop(name, None)
        if credentials:
            environment.update(
                {
                    "LATCHWAY_MAVEN_CENTRAL_USERNAME": "publisher",
                    "LATCHWAY_MAVEN_CENTRAL_PASSWORD": "password",
                }
            )
        if signing_secrets:
            environment.update(
                {
                    "LATCHWAY_SIGNING_KEY": "private",
                    "LATCHWAY_SIGNING_PASSWORD": "password",
                }
            )
        return subprocess.run(
            ["/bin/bash", str(self.scripts / SCRIPT.name)],
            cwd=self.root,
            env=environment,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    def test_publishes_only_exact_validated_deployment_and_persists_status(self) -> None:
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.publish_log.read_text(encoding="utf-8"), "publish\n")
        self.assertEqual(
            json.loads(self.status.read_text(encoding="utf-8"))["deployment_state"],
            "PUBLISHED",
        )

    def test_existing_complete_status_is_read_only_success(self) -> None:
        raw = json.loads(self.published.read_text(encoding="utf-8"))
        subprocess.run(
            [
                "python3",
                str(self.scripts / RECORD_HELPER.name),
                "validate-status",
                "--intent",
                str(self.intent),
                "--record",
                str(self.record),
                "--status",
                str(self.published),
                "--output",
                str(self.status),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
        )
        self.assertEqual(raw["deploymentState"], "PUBLISHED")
        result = self.invoke(credentials=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.status_log.exists())
        self.assertFalse(self.publish_log.exists())

    def test_complete_public_registry_adoption_needs_no_portal_credentials(self) -> None:
        self.record.unlink()
        evidence = self.root / "public-evidence.json"
        evidence.write_text(
            json.dumps(
                {
                    "schema_version": 2,
                    "registry": "maven_central",
                    "namespace": "dev.latchway",
                    "version": "1.0.0",
                    "public_manifest_sha256": "d" * 64,
                }
            ),
            encoding="utf-8",
        )
        subprocess.run(
            [
                "python3",
                str(self.scripts / RECORD_HELPER.name),
                "create-adoption-record",
                "--intent",
                str(self.intent),
                "--public-evidence",
                str(evidence),
                "--output",
                str(self.record),
            ],
            check=True,
        )
        subprocess.run(
            [
                "python3",
                str(self.scripts / RECORD_HELPER.name),
                "create-adoption-status",
                "--intent",
                str(self.intent),
                "--record",
                str(self.record),
                "--public-evidence",
                str(evidence),
                "--output",
                str(self.status),
            ],
            check=True,
        )
        result = self.invoke(credentials=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.status_log.exists())
        self.assertFalse(self.publish_log.exists())

    def test_rejects_wrong_purls_before_publication_request(self) -> None:
        result = self.invoke(status_mode="wrong")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unexpected or duplicate PURLs", result.stderr)
        self.assertFalse(self.publish_log.exists())

    def test_ambiguous_publish_is_not_retried_in_same_invocation(self) -> None:
        result = self.invoke(status_mode="stuck", publish_outcome="transport")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("outcome remains unresolved", result.stderr)
        self.assertEqual(self.publish_log.read_text(encoding="utf-8"), "publish\n")
        self.assertFalse(self.status.exists())

    def test_rejects_definite_http_error_and_missing_credentials(self) -> None:
        rejected = self.invoke(publish_code="409")
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("returned HTTP 409", rejected.stderr)
        self.status_log.unlink()
        self.publish_log.unlink()
        missing = self.invoke(credentials=False)
        self.assertEqual(missing.returncode, 64)
        self.assertIn("credentials are required", missing.stderr)
        self.assertFalse(self.status_log.exists())
        self.assertFalse(self.publish_log.exists())

    def test_rejects_private_signing_material_before_network_access(self) -> None:
        result = self.invoke(signing_secrets=True)
        self.assertEqual(result.returncode, 64)
        self.assertIn("Private signing material", result.stderr)
        self.assertFalse(self.status_log.exists())
        self.assertFalse(self.publish_log.exists())


if __name__ == "__main__":
    unittest.main()
