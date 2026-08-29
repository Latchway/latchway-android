#!/usr/bin/env python3
"""Offline tests for exact Maven Central release verification."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from test_central_fixture import write_zip


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/verify-central-release.sh"
MODULES = (
    "latchway-core",
    "latchway-okhttp",
    "latchway-play-integrity",
    "latchway-firebase-auth",
    "latchway-bom",
)


class CentralVerificationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.remote = self.root / "remote"
        self.expected = self.root / "expected"
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.fingerprint = "A" * 40
        self.write_executable("curl", """#!/bin/bash
set -euo pipefail
output=
head_only=false
url=${!#}
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output) output=$2; shift 2 ;;
    --head) head_only=true; shift ;;
    *) shift ;;
  esac
done
relative=${url#https://central.test/}
source="$FAKE_CENTRAL_ROOT/$relative"
[[ -f "$source" ]] || exit 22
if [[ "$head_only" == true ]]; then
  exit 0
fi
cp "$source" "$output"
""")
        self.write_executable("gpg", """#!/bin/bash
set -euo pipefail
if [[ " $* " == *" --with-colons "* ]]; then
  printf 'fpr:::::::::AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:\n'
elif [[ " $* " == *" --status-fd "* ]]; then
  if [[ -n "${FAKE_GPG_STATUS_FILE:-}" ]]; then
    /bin/cat "$FAKE_GPG_STATUS_FILE"
  else
    printf '%s\n' \
      '[GNUPG:] NEWSIG' \
      '[GNUPG:] KEY_CONSIDERED AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA 0' \
      '[GNUPG:] SIG_ID abcdefghijklmnopqrstuvwx 1787961600 2026-08-29' \
      '[GNUPG:] GOODSIG AAAAAAAAAAAAAAAA Latchway Release' \
      '[GNUPG:] VALIDSIG AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA 2026-08-29 1787961600 0 4 0 1 10 00' \
      '[GNUPG:] TRUST_UNDEFINED 0 pgp'
  fi
fi
""")
        self.public_key = self.root / "public-key.asc"
        self.public_key.write_text("reviewed public key\n", encoding="utf-8")
        for module in MODULES:
            extensions = ["pom", "module", "sources.jar", "javadoc.jar"]
            if module != "latchway-bom":
                extensions.append("aar")
            for extension in extensions:
                name = f"{module}-1.0.0-{extension}"
                if extension in {"pom", "module", "aar"}:
                    name = f"{module}-1.0.0.{extension}"
                payload = (
                    f"<project><tag>v1.0.0</tag><artifact>{module}</artifact></project>\n".encode()
                    if extension == "pom"
                    else f"immutable {module} {extension}\n".encode()
                )
                relative = Path("dev/latchway", module, "1.0.0", name)
                self.write_artifact(self.remote / relative, payload)
                expected = self.expected / relative
                expected.parent.mkdir(parents=True, exist_ok=True)
                expected.write_bytes(payload)
                for algorithm in ("md5", "sha1", "sha256", "sha512"):
                    expected.with_name(f"{expected.name}.{algorithm}").write_bytes(
                        (self.remote / relative).with_name(f"{name}.{algorithm}").read_bytes()
                    )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_executable(self, name: str, source: str) -> None:
        path = self.bin / name
        path.write_text(source, encoding="utf-8")
        path.chmod(0o755)

    @staticmethod
    def write_artifact(path: Path, payload: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        for algorithm in ("md5", "sha1", "sha256", "sha512"):
            path.with_name(f"{path.name}.{algorithm}").write_text(
                hashlib.new(algorithm, payload).hexdigest(), encoding="utf-8"
            )
        path.with_name(f"{path.name}.asc").write_text("-----BEGIN PGP SIGNATURE-----\ntest\n", encoding="utf-8")

    def invoke(
        self,
        *,
        expected: bool = True,
        gpg_status: str | None = None,
        extra_environment: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        environment = {
            **os.environ,
            "PATH": f"{self.bin}:/usr/bin:/bin",
            "FAKE_CENTRAL_ROOT": str(self.remote),
            "LATCHWAY_MAVEN_CENTRAL_BASE_URL": "https://central.test/dev/latchway",
            "LATCHWAY_CENTRAL_VERIFY_ATTEMPTS": "1",
            "LATCHWAY_CENTRAL_VERIFY_DELAY_SECONDS": "1",
        }
        environment.pop("LATCHWAY_CENTRAL_EXPECTED_REPOSITORY", None)
        if expected:
            environment["LATCHWAY_CENTRAL_EXPECTED_REPOSITORY"] = str(self.expected)
            environment["LATCHWAY_CENTRAL_SIGNING_FINGERPRINT"] = self.fingerprint
            environment["LATCHWAY_CENTRAL_SIGNING_PUBLIC_KEY"] = str(self.public_key)
        if gpg_status is not None:
            status_file = self.root / "gpg-status"
            status_file.write_text(gpg_status, encoding="utf-8")
            environment["FAKE_GPG_STATUS_FILE"] = str(status_file)
        environment.update(extra_environment or {})
        return subprocess.run(
            ["/bin/bash", str(SCRIPT), "1.0.0"],
            cwd=ROOT,
            env=environment,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    def test_exact_public_repository_matches_reviewed_bytes(self) -> None:
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('"primary_artifacts_byte_identical": true', result.stdout)
        evidence = json.loads(result.stdout)
        self.assertEqual(evidence["schema_version"], 2)
        self.assertRegex(evidence["public_manifest_sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(len(evidence["public_manifest"]), 144)
        self.assertEqual(evidence["files"][0]["gpg_status"]["primary_fingerprint"], self.fingerprint)
        self.assertEqual(len(evidence["files"][0]["checksums"]), 4)
        self.assertIn("signature_armored", evidence["files"][0])

    def test_signing_subkey_is_accepted_only_through_validsig_primary_field(self) -> None:
        subkey = "B" * 40
        status = "\n".join((
            "[GNUPG:] NEWSIG",
            f"[GNUPG:] KEY_CONSIDERED {self.fingerprint} 0",
            "[GNUPG:] SIG_ID abcdefghijklmnopqrstuvwx 1787961600 2026-08-29",
            f"[GNUPG:] GOODSIG {subkey[-16:]} Latchway Signing Subkey",
            (
                f"[GNUPG:] VALIDSIG {subkey} 2026-08-29 1787961600 0 4 0 1 10 00 "
                f"{self.fingerprint}"
            ),
            "[GNUPG:] TRUST_UNDEFINED 0 pgp",
            "",
        ))
        result = self.invoke(gpg_status=status)
        self.assertEqual(result.returncode, 0, result.stderr)
        evidence = json.loads(result.stdout)
        self.assertEqual(evidence["files"][0]["gpg_status"]["signing_fingerprint"], subkey)

    def test_revoked_expired_and_unknown_gpg_statuses_are_rejected(self) -> None:
        baseline = "\n".join((
            "[GNUPG:] NEWSIG",
            f"[GNUPG:] KEY_CONSIDERED {self.fingerprint} 0",
            "[GNUPG:] SIG_ID abcdefghijklmnopqrstuvwx 1787961600 2026-08-29",
            f"[GNUPG:] GOODSIG {self.fingerprint[-16:]} Latchway Release",
            (
                f"[GNUPG:] VALIDSIG {self.fingerprint} "
                "2026-08-29 1787961600 0 4 0 1 10 00"
            ),
            "[GNUPG:] TRUST_UNDEFINED 0 pgp",
        ))
        for invalid in ("REVKEYSIG rejected", "EXPKEYSIG expired", "EXPSIG expired", "FUTURE_OK nope"):
            with self.subTest(invalid=invalid):
                result = self.invoke(gpg_status=f"{baseline}\n[GNUPG:] {invalid}\n")
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("signature status is invalid", result.stderr)

    def test_self_consistent_but_different_public_artifact_is_rejected(self) -> None:
        path = self.remote / "dev/latchway/latchway-core/1.0.0/latchway-core-1.0.0.aar"
        self.write_artifact(path, b"different but internally checksummed bytes\n")
        result = self.invoke()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("differs from the reviewed release byte-for-byte", result.stderr)

    def test_independent_consumer_mode_remains_available(self) -> None:
        path = self.remote / "dev/latchway/latchway-core/1.0.0/latchway-core-1.0.0.aar"
        self.write_artifact(path, b"different but internally checksummed bytes\n")
        result = self.invoke(expected=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('"signature_files_present": true', result.stdout)

    def test_invalid_public_checksum_is_rejected_before_byte_comparison(self) -> None:
        checksum = self.remote / "dev/latchway/latchway-core/1.0.0/latchway-core-1.0.0.aar.sha256"
        checksum.write_text("0" * 64, encoding="utf-8")
        result = self.invoke()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("checksum mismatch", result.stderr)

    def test_release_proof_hash_binds_exact_intent_record_and_published_status(self) -> None:
        helper = ROOT / "scripts/central-deployment-record.py"
        archive = self.root / "release.zip"
        portal_bundle = self.root / "portal.zip"
        write_zip(archive, self.expected, signed=False)
        write_zip(portal_bundle, self.expected, signed=True)
        intent = self.root / "maven-central-upload-intent.json"
        record = self.root / "maven-central-deployment.json"
        raw_status = self.root / "raw-status.json"
        status = self.root / "maven-central-deployment-status.json"
        subprocess.run([
            "python3", str(helper), "create-intent",
            "--repository", str(self.expected), "--archive", str(archive),
            "--portal-bundle", str(portal_bundle),
            "--public-key", str(self.public_key), "--source-commit", "a" * 40,
            "--tag", "v1.0.0", "--version", "1.0.0", "--namespace", "dev.latchway",
            "--publishing-type", "user_managed", "--output", str(intent),
        ], check=True)
        deployment_id = "28570f16-da32-4c14-bd2e-c1acc0782365"
        subprocess.run([
            "python3", str(helper), "create-record", "--intent", str(intent),
            "--deployment-id", deployment_id, "--output", str(record),
        ], check=True)
        intent_value = json.loads(intent.read_text(encoding="utf-8"))
        raw_status.write_text(json.dumps({
            "deploymentId": deployment_id,
            "deploymentName": intent_value["deployment_name"],
            "deploymentState": "PUBLISHED",
            "purls": intent_value["expected_purls"],
        }), encoding="utf-8")
        subprocess.run([
            "python3", str(helper), "validate-status", "--intent", str(intent),
            "--record", str(record), "--status", str(raw_status), "--output", str(status),
        ], check=True, stdout=subprocess.DEVNULL)
        environment = {
            "LATCHWAY_CENTRAL_UPLOAD_INTENT": str(intent),
            "LATCHWAY_CENTRAL_DEPLOYMENT_RECORD": str(record),
            "LATCHWAY_CENTRAL_DEPLOYMENT_STATUS": str(status),
            "LATCHWAY_CENTRAL_REQUIRE_DEPLOYMENT_EVIDENCE": "true",
        }
        result = self.invoke(extra_environment=environment)
        self.assertEqual(result.returncode, 0, result.stderr)
        evidence = json.loads(result.stdout)
        self.assertEqual(
            evidence["deployment"]["intent_sha256"],
            hashlib.sha256(intent.read_bytes()).hexdigest(),
        )

        status_value = json.loads(status.read_text(encoding="utf-8"))
        status_value["deployment_state"] = "VALIDATED"
        status.write_text(json.dumps(status_value), encoding="utf-8")
        rejected = self.invoke(extra_environment=environment)
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("not complete and PUBLISHED", rejected.stderr)


if __name__ == "__main__":
    unittest.main()
