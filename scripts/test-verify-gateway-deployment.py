#!/usr/bin/env python3

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest
from typing import Any


ROOT = pathlib.Path(__file__).resolve().parents[1]
VERIFIER = ROOT / "scripts" / "verify-gateway-deployment.py"
SCHEMA = "latchway.gateway-deployment-statement.v1"
AUDIENCE = "latchway-physical-evidence"
ORIGIN = "https://gateway.example.test/latchway"
KEY_ID = "release-key-2026"
ENVIRONMENT = "production"
CORE_COMMIT = "1" * 40
CONTRACT_VERSION = "1.2.3"
CONTRACT_BUNDLE = "2" * 64
IMAGE_DIGEST = "sha256:" + "3" * 64
CONFIGURATION = "4" * 64
CERTIFICATE = "5" * 64


def canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def timestamp(value: dt.datetime) -> str:
    return value.astimezone(dt.timezone.utc).isoformat(timespec="seconds").replace(
        "+00:00", "Z"
    )


def ios_client() -> dict[str, Any]:
    return {
        "platform": "react_native_ios_app_attest",
        "application_identifier": "dev.latchway.example",
        "app_version": "1.2.3",
        "build_number": "42",
        "team_id": "AB12CD34EF",
        "signing_certificate_sha256": CERTIFICATE,
        "app_attest_environment": "production",
        "provider": "app_attest",
        "minimum_trust_level": "device_verified",
        "require_request_hash": True,
        "require_play_recognized": False,
        "require_licensed": False,
        "allow_testing": False,
        "allow_debug": False,
    }


def android_client() -> dict[str, Any]:
    return {
        "platform": "react_native_android_play_integrity",
        "application_identifier": "dev.latchway.example",
        "app_version": "1.2.3",
        "build_number": "42",
        "signing_certificate_sha256": CERTIFICATE,
        "cloud_project_number": "123456789012",
        "installer_package": "com.android.vending",
        "play_track": "internal",
        "provider": "play_integrity",
        "minimum_trust_level": "strong_device_verified",
        "require_request_hash": True,
        "require_play_recognized": True,
        "require_licensed": True,
        "allow_testing": False,
        "allow_debug": False,
    }


def statement(clients: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    return {
        "schema_version": SCHEMA,
        "audience": AUDIENCE,
        "key_id": KEY_ID,
        "deployment_id": "deployment-2026-08-29-001",
        "gateway_origin": ORIGIN,
        "environment": ENVIRONMENT,
        "issued_at": timestamp(now - dt.timedelta(minutes=1)),
        "expires_at": timestamp(now + dt.timedelta(hours=1)),
        "core_commit": CORE_COMMIT,
        "contract_version": CONTRACT_VERSION,
        "contract_bundle_sha256": CONTRACT_BUNDLE,
        "gateway_image_digest": IMAGE_DIGEST,
        "gateway_configuration_sha256": CONFIGURATION,
        "clients": clients if clients is not None else [ios_client()],
    }


class GatewayDeploymentVerifierTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.openssl = shutil.which("openssl")
        if cls.openssl is None:
            raise unittest.SkipTest("openssl is unavailable")
        cls.temporary = tempfile.TemporaryDirectory(prefix="latchway-deployment-test-")
        cls.root = pathlib.Path(cls.temporary.name)
        cls.private_key = cls.root / "private-key.pem"
        cls.public_key = cls.root / "public-key.pem"
        subprocess.run(
            [
                cls.openssl,
                "ecparam",
                "-name",
                "prime256v1",
                "-genkey",
                "-noout",
                "-out",
                str(cls.private_key),
            ],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            [
                cls.openssl,
                "pkey",
                "-in",
                str(cls.private_key),
                "-pubout",
                "-out",
                str(cls.public_key),
            ],
            check=True,
            capture_output=True,
        )
        der = subprocess.run(
            [
                cls.openssl,
                "pkey",
                "-pubin",
                "-in",
                str(cls.public_key),
                "-outform",
                "DER",
            ],
            check=True,
            capture_output=True,
        ).stdout
        cls.public_key_pin = hashlib.sha256(der).hexdigest()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temporary.cleanup()

    def setUp(self) -> None:
        self.case = pathlib.Path(tempfile.mkdtemp(prefix="case-", dir=self.root))

    def sign(self, payload: bytes, key: pathlib.Path | None = None) -> pathlib.Path:
        source = self.case / "signed-payload"
        signature = self.case / "statement.sig"
        source.write_bytes(payload)
        subprocess.run(
            [
                self.openssl,
                "dgst",
                "-sha256",
                "-sign",
                str(key or self.private_key),
                "-out",
                str(signature),
                str(source),
            ],
            check=True,
            capture_output=True,
        )
        return signature

    def arguments(
        self,
        statement_path: pathlib.Path,
        signature_path: pathlib.Path,
        client_policy_path: pathlib.Path,
        *,
        public_key: pathlib.Path | None = None,
        public_key_pin: str | None = None,
        gateway_origin: str = ORIGIN,
        gateway_configuration: str = CONFIGURATION,
    ) -> list[str]:
        return [
            sys.executable,
            str(VERIFIER),
            "--statement",
            str(statement_path),
            "--signature",
            str(signature_path),
            "--public-key",
            str(public_key or self.public_key),
            "--public-key-sha256",
            public_key_pin or self.public_key_pin,
            "--client-policy",
            str(client_policy_path),
            "--key-id",
            KEY_ID,
            "--gateway-origin",
            gateway_origin,
            "--environment",
            ENVIRONMENT,
            "--core-commit",
            CORE_COMMIT,
            "--contract-version",
            CONTRACT_VERSION,
            "--contract-bundle-sha256",
            CONTRACT_BUNDLE,
            "--gateway-image-digest",
            IMAGE_DIGEST,
            "--gateway-configuration-sha256",
            gateway_configuration,
        ]

    def invoke(
        self,
        value: dict[str, Any],
        *,
        client: dict[str, Any] | None = None,
        payload: bytes | None = None,
        public_key_pin: str | None = None,
        gateway_origin: str = ORIGIN,
        gateway_configuration: str = CONFIGURATION,
    ) -> subprocess.CompletedProcess[str]:
        statement_payload = payload if payload is not None else canonical(value)
        statement_path = self.case / "statement.json"
        statement_path.write_bytes(statement_payload)
        signature_path = self.sign(statement_payload)
        client_policy_path = self.case / "client-policy.json"
        client_policy_path.write_bytes(canonical(client or ios_client()))
        return subprocess.run(
            self.arguments(
                statement_path,
                signature_path,
                client_policy_path,
                public_key_pin=public_key_pin,
                gateway_origin=gateway_origin,
                gateway_configuration=gateway_configuration,
            ),
            check=False,
            capture_output=True,
            text=True,
        )

    def assert_rejected(self, result: subprocess.CompletedProcess[str]) -> None:
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("gateway deployment statement rejected:", result.stderr)

    def test_valid_ios_and_android_statements_verify(self) -> None:
        current = statement()
        ios_result = self.invoke(current)
        self.assertEqual(ios_result.returncode, 0, ios_result.stderr)
        summary = json.loads(ios_result.stdout)
        self.assertTrue(summary["valid"])
        self.assertEqual(summary["statement_sha256"], hashlib.sha256(canonical(current)).hexdigest())

        android = android_client()
        android_result = self.invoke(
            statement([ios_client(), android]),
            client=android,
        )
        self.assertEqual(android_result.returncode, 0, android_result.stderr)

    def test_valid_signature_over_noncanonical_or_unknown_json_is_rejected(self) -> None:
        current = statement()
        noncanonical = json.dumps(current, indent=2, sort_keys=True).encode("utf-8")
        self.assert_rejected(self.invoke(current, payload=noncanonical))

        current["unexpected"] = True
        self.assert_rejected(self.invoke(current))

    def test_wrong_key_pin_and_invalid_signature_are_rejected(self) -> None:
        self.assert_rejected(self.invoke(statement(), public_key_pin="0" * 64))

        current = statement()
        payload = canonical(current)
        statement_path = self.case / "statement-invalid-signature.json"
        statement_path.write_bytes(payload)
        signature_path = self.case / "invalid.sig"
        signature_path.write_bytes(b"\x30\x00")
        client_path = self.case / "client.json"
        client_path.write_bytes(canonical(ios_client()))
        result = subprocess.run(
            self.arguments(statement_path, signature_path, client_path),
            check=False,
            capture_output=True,
            text=True,
        )
        self.assert_rejected(result)

    def test_statement_lifetime_and_clock_skew_are_bounded(self) -> None:
        now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
        too_long = statement()
        too_long["issued_at"] = timestamp(now - dt.timedelta(minutes=1))
        too_long["expires_at"] = timestamp(now + dt.timedelta(hours=24))
        self.assert_rejected(self.invoke(too_long))

        future = statement()
        future["issued_at"] = timestamp(now + dt.timedelta(minutes=6))
        future["expires_at"] = timestamp(now + dt.timedelta(hours=1))
        self.assert_rejected(self.invoke(future))

    def test_redirect_style_origin_and_coordinate_mismatch_are_rejected(self) -> None:
        redirected = statement()
        redirected["gateway_origin"] = "https://gateway.example.test/a/../latchway"
        self.assert_rejected(
            self.invoke(
                redirected,
                gateway_origin="https://gateway.example.test/a/../latchway",
            )
        )
        self.assert_rejected(
            self.invoke(statement(), gateway_configuration="6" * 64)
        )

    def test_current_client_policy_must_match_exactly(self) -> None:
        different = ios_client()
        different["app_version"] = "9.9.9"
        self.assert_rejected(self.invoke(statement(), client=different))

        permissive = ios_client()
        permissive["allow_debug"] = True
        self.assert_rejected(self.invoke(statement([permissive]), client=permissive))

    def test_symlink_and_oversized_statement_are_rejected(self) -> None:
        current = canonical(statement())
        target = self.case / "real-statement.json"
        target.write_bytes(current)
        link = self.case / "statement-link.json"
        os.symlink(target, link)
        signature_path = self.sign(current)
        client_path = self.case / "client-link-test.json"
        client_path.write_bytes(canonical(ios_client()))
        result = subprocess.run(
            self.arguments(link, signature_path, client_path),
            check=False,
            capture_output=True,
            text=True,
        )
        self.assert_rejected(result)

        oversized = self.case / "oversized.json"
        oversized.write_bytes(b"x" * (32 * 1024 + 1))
        result = subprocess.run(
            self.arguments(oversized, signature_path, client_path),
            check=False,
            capture_output=True,
            text=True,
        )
        self.assert_rejected(result)

    def test_non_p256_key_is_rejected(self) -> None:
        private_key = self.case / "p384-private.pem"
        public_key = self.case / "p384-public.pem"
        subprocess.run(
            [
                self.openssl,
                "ecparam",
                "-name",
                "secp384r1",
                "-genkey",
                "-noout",
                "-out",
                str(private_key),
            ],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            [
                self.openssl,
                "pkey",
                "-in",
                str(private_key),
                "-pubout",
                "-out",
                str(public_key),
            ],
            check=True,
            capture_output=True,
        )
        der = subprocess.run(
            [
                self.openssl,
                "pkey",
                "-pubin",
                "-in",
                str(public_key),
                "-outform",
                "DER",
            ],
            check=True,
            capture_output=True,
        ).stdout
        payload = canonical(statement())
        statement_path = self.case / "p384-statement.json"
        statement_path.write_bytes(payload)
        signature_path = self.sign(payload, key=private_key)
        client_path = self.case / "p384-client.json"
        client_path.write_bytes(canonical(ios_client()))
        result = subprocess.run(
            self.arguments(
                statement_path,
                signature_path,
                client_path,
                public_key=public_key,
                public_key_pin=hashlib.sha256(der).hexdigest(),
            ),
            check=False,
            capture_output=True,
            text=True,
        )
        self.assert_rejected(result)


if __name__ == "__main__":
    unittest.main()
