#!/usr/bin/env python3

from __future__ import annotations

import copy
import datetime as dt
import importlib.util
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest


SCRIPT = pathlib.Path(__file__).with_name("device-evidence.py")
SCHEMA_PATH = SCRIPT.parent.parent / "Conformance" / "physical-device-evidence.schema.json"
SPEC = importlib.util.spec_from_file_location("device_evidence", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
device_evidence = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(device_evidence)


def now(offset_seconds: int = 0) -> str:
    value = dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=offset_seconds)
    return value.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def profile() -> dict:
    expected = {
        "application_identifier": "dev.latchway.conformance",
        "app_version": "1.0.0",
        "build_number": "42",
        "signing_certificate_sha256": "1" * 64,
        "cloud_project_number": "123456789012",
        "installer_package": "com.android.vending",
        "play_track": "internal",
        "require_licensed": "true",
        "source_commit": "2" * 40,
        "core_commit": "7" * 40,
        "contract_bundle_sha256": "3" * 64,
        "gateway_image_digest": "sha256:" + "4" * 64,
        "gateway_configuration_sha256": "5" * 64,
        "gateway_origin": "https://gateway.example.com",
        "gateway_environment": "production",
        "gateway_deployment_key_id": "gateway-key-1",
        "gateway_deployment_statement_sha256": "a" * 64,
        "gateway_deployment_public_key_sha256": "c" * 64,
        "error_mapping_feature": "missing_feature",
    }
    return {
        "schema_version": device_evidence.PROFILE_VERSION,
        "platform": "android_play_integrity",
        "repository": "Latchway/latchway-android",
        "source": {
            "commit": expected["source_commit"],
            "core_commit": expected["core_commit"],
            "worktree_clean": True,
            "sdk_version": "0.1.0",
            "contract_version": "0.5.1",
            "contract_bundle_sha256": expected["contract_bundle_sha256"],
            "gateway_image_digest": expected["gateway_image_digest"],
            "gateway_configuration_sha256": expected["gateway_configuration_sha256"],
            "gateway_origin": expected["gateway_origin"],
            "gateway_deployment_key_id": expected["gateway_deployment_key_id"],
            "gateway_deployment_statement_sha256": expected["gateway_deployment_statement_sha256"],
            "gateway_deployment_public_key_sha256": expected["gateway_deployment_public_key_sha256"],
        },
        "toolchain": {
            "runner_os": "Linux",
            "runner_arch": "x86_64",
            "compiler": "Kotlin 2.3.10",
            "build_tool": "Gradle 9.5.0",
            "collector_version": "1",
        },
        "expected_pins": expected,
        "application_binary_sha256": "6" * 64,
        "device_inventory_sha256": "8" * 64,
    }


def observation() -> dict:
    expected = profile()["expected_pins"]
    tests = []
    for name in sorted(device_evidence.PLATFORM_POLICY["android_play_integrity"]["tests"]):
        entry = {"id": name, "status": "passed", "duration_ms": 1}
        if name == "dpop_replay_rejected":
            entry.update(http_status=401, error_code="dpop_replayed", request_id="request-replay-1234")
        elif name == "tampered_dpop_rejected":
            entry.update(http_status=401, error_code="dpop_invalid", request_id="request-tamper-1234")
        elif name == "canonical_error_mapping":
            entry.update(http_status=404, error_code="feature_not_found", request_id="request-mapping-1234", mapped_error_type="kotlin_latchway_exception")
        elif name == "installation_revocation":
            entry.update(http_status=403, error_code="installation_revoked", request_id="request-revoked-1234")
        elif name == "protocol_version_rejection":
            entry.update(http_status=426, error_code="protocol_version_unsupported", request_id="request-protocol-1234", protocol_version_sent=0)
        elif name == "session_refresh_rotation":
            entry.update(
                credential_before_sha256="a" * 64,
                credential_after_sha256="b" * 64,
                installation_before_sha256="c" * 64,
                installation_after_sha256="c" * 64,
            )
        tests.append(entry)
    return {
        "schema_version": device_evidence.OBSERVATION_VERSION,
        "platform": "android_play_integrity",
        "run": {
            "id": "test-run-12345678",
            "mode": "release",
            "started_at": now(-2),
            "completed_at": now(-1),
        },
        "gateway_version": "1.0.0",
        "application": {
            "identifier": expected["application_identifier"],
            "version": expected["app_version"],
            "build": expected["build_number"],
            "build_mode": "release",
            "distribution": "play_internal",
            "debuggable": False,
            "signing_certificate_sha256": expected["signing_certificate_sha256"],
            "cloud_project_number": expected["cloud_project_number"],
            "installer_package": expected["installer_package"],
            "play_track": expected["play_track"],
        },
        "device": {
            "physical": True,
            "simulator": False,
            "emulator": False,
            "testing": False,
            "debugger_attached": False,
            "model": "Google Pixel 10",
            "os_name": "Android",
            "os_version": "17",
            "os_build": "BP2A.260101.001",
            "security_level": "strongbox",
        },
        "provider": {
            "name": "play_integrity",
            "environment": "production",
            "trust_level": "strong_device_verified",
            "request_hash_bound": True,
            "app_recognition": "PLAY_RECOGNIZED",
            "account_licensing": "LICENSED",
        },
        "observed_pins": copy.deepcopy(expected),
        "tests": tests,
        "redaction": {
            "identity_token_recorded": False,
            "session_token_recorded": False,
            "refresh_token_recorded": False,
            "dpop_proof_recorded": False,
            "attestation_evidence_recorded": False,
            "private_key_recorded": False,
            "provider_credential_recorded": False,
        },
    }


class DeviceEvidenceTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))

    def evidence(self) -> tuple[dict, dict]:
        current_profile = profile()
        result = device_evidence.build_evidence(observation(), current_profile, self.schema)
        return result, current_profile

    def test_valid_release_evidence_passes(self) -> None:
        evidence, current_profile = self.evidence()
        self.assertTrue(evidence["release_eligible"])
        self.assertEqual(device_evidence.verify(evidence, current_profile, self.schema), [])

    def test_json_loader_rejects_ambiguous_nonfinite_and_symlinked_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            duplicate = root / "duplicate.json"
            nonfinite = root / "nonfinite.json"
            target = root / "target.json"
            link = root / "link.json"
            duplicate.write_text('{"platform":"ios","platform":"android"}', encoding="utf-8")
            nonfinite.write_text('{"duration_ms":NaN}', encoding="utf-8")
            target.write_text('{"valid":true}', encoding="utf-8")
            link.symlink_to(target)

            with self.assertRaisesRegex(ValueError, "duplicate JSON object member"):
                device_evidence.load_json(duplicate)
            with self.assertRaisesRegex(ValueError, "non-finite JSON number"):
                device_evidence.load_json(nonfinite)
            with self.assertRaisesRegex(ValueError, "missing JSON file"):
                device_evidence.load_json(link)

    def test_schema_rejects_unexpected_field(self) -> None:
        evidence, _ = self.evidence()
        evidence["raw_evidence"] = "forbidden"
        self.assertTrue(device_evidence.schema_errors(evidence, self.schema))

    def test_simulator_and_debug_build_fail_closed(self) -> None:
        current = observation()
        current["device"]["physical"] = False
        current["device"]["simulator"] = True
        current["application"]["debuggable"] = True
        result = device_evidence.build_evidence(current, profile(), self.schema)
        self.assertFalse(result["release_eligible"])

    def test_testing_attestation_fails_closed(self) -> None:
        current = observation()
        current["device"]["testing"] = True
        current["provider"]["trust_level"] = "debug"
        result = device_evidence.build_evidence(current, profile(), self.schema)
        self.assertFalse(result["release_eligible"])

    def test_pin_mismatch_fails_closed(self) -> None:
        current = observation()
        current["observed_pins"]["signing_certificate_sha256"] = "9" * 64
        result = device_evidence.build_evidence(current, profile(), self.schema)
        self.assertFalse(result["release_eligible"])

    def test_non_play_and_unlicensed_evidence_fail_closed(self) -> None:
        current = observation()
        current["application"]["installer_package"] = "com.android.shell"
        current["provider"]["account_licensing"] = "UNLICENSED"
        result = device_evidence.build_evidence(current, profile(), self.schema)
        self.assertFalse(result["release_eligible"])

    def test_negative_cases_require_exact_protocol_results(self) -> None:
        current = observation()
        replay = next(item for item in current["tests"] if item["id"] == "dpop_replay_rejected")
        replay["error_code"] = "dpop_invalid"
        result = device_evidence.build_evidence(current, profile(), self.schema)
        self.assertFalse(result["release_eligible"])

    def test_refresh_error_mapping_revocation_and_protocol_require_concrete_results(self) -> None:
        cases = (
            ("canonical_error_mapping", "mapped_error_type", "swift_latchway_problem"),
            ("session_refresh_rotation", "credential_after_sha256", "a" * 64),
            ("installation_revocation", "error_code", "session_revoked"),
            ("protocol_version_rejection", "protocol_version_sent", 1),
        )
        for test_id, field, value in cases:
            with self.subTest(test_id=test_id, field=field):
                current = observation()
                record = next(item for item in current["tests"] if item["id"] == test_id)
                record[field] = value
                result = device_evidence.build_evidence(current, profile(), self.schema)
                self.assertFalse(result["release_eligible"])

    def test_secret_shaped_values_are_rejected(self) -> None:
        current = observation()
        current["gateway_version"] = "DPoP abcdefghijklmnopqrstuvwxyz0123456789"
        self.assertTrue(device_evidence.secret_scan(current))

    def test_cli_writes_json_junit_and_validation_summary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            profile_path = root / "profile.json"
            observation_path = root / "observation.json"
            evidence_path = root / "evidence.json"
            junit_path = root / "junit.xml"
            summary_path = root / "summary.json"
            profile_path.write_text(json.dumps(profile()), encoding="utf-8")
            observation_path.write_text(json.dumps(observation()), encoding="utf-8")
            completed = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "finalize",
                    "--schema", str(SCHEMA_PATH),
                    "--profile", str(profile_path),
                    "--observation", str(observation_path),
                    "--evidence", str(evidence_path),
                    "--junit", str(junit_path),
                    "--summary", str(summary_path),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertTrue(json.loads(summary_path.read_text())["valid"])
            self.assertIn("testsuite", junit_path.read_text())


if __name__ == "__main__":
    unittest.main()
