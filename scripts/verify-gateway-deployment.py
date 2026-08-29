#!/usr/bin/env python3

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import hmac
import json
import os
import pathlib
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import urllib.parse
from typing import Any


SCHEMA_VERSION = "latchway.gateway-deployment-statement.v1"
AUDIENCE = "latchway-physical-evidence"
MAX_STATEMENT_BYTES = 32 * 1024
MAX_CLIENT_POLICY_BYTES = 8 * 1024
MAX_PUBLIC_KEY_BYTES = 8 * 1024
MAX_SIGNATURE_BYTES = 256
MAX_VALIDITY = dt.timedelta(hours=24)
CLOCK_SKEW = dt.timedelta(minutes=5)

TOP_LEVEL_FIELDS = {
    "schema_version",
    "audience",
    "key_id",
    "deployment_id",
    "gateway_origin",
    "environment",
    "issued_at",
    "expires_at",
    "core_commit",
    "contract_version",
    "contract_bundle_sha256",
    "gateway_image_digest",
    "gateway_configuration_sha256",
    "clients",
}

IOS_CLIENT_FIELDS = {
    "platform",
    "application_identifier",
    "app_version",
    "build_number",
    "team_id",
    "signing_certificate_sha256",
    "app_attest_environment",
    "provider",
    "minimum_trust_level",
    "require_request_hash",
    "require_play_recognized",
    "require_licensed",
    "allow_testing",
    "allow_debug",
}

ANDROID_CLIENT_FIELDS = {
    "platform",
    "application_identifier",
    "app_version",
    "build_number",
    "signing_certificate_sha256",
    "cloud_project_number",
    "installer_package",
    "play_track",
    "provider",
    "minimum_trust_level",
    "require_request_hash",
    "require_play_recognized",
    "require_licensed",
    "allow_testing",
    "allow_debug",
}

IOS_PLATFORMS = {"ios_app_attest", "react_native_ios_app_attest"}
ANDROID_PLATFORMS = {"android_play_integrity", "react_native_android_play_integrity"}
TRUST_LEVELS = {"device_verified", "strong_device_verified"}
PLAY_TRACKS = {"internal", "closed", "open", "production"}

COMMIT = re.compile(r"[0-9a-f]{40}")
SHA256 = re.compile(r"[0-9a-f]{64}")
OCI_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
SEMVER = re.compile(
    r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
)
IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{2,254}")
BOUNDED_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
ENVIRONMENT = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
TEAM_ID = re.compile(r"[A-Z0-9]{10}")
CLOUD_PROJECT = re.compile(r"[1-9][0-9]{0,18}")
RFC3339_UTC = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,6})?Z"
)

# DER SubjectPublicKeyInfo prefix for id-ecPublicKey using prime256v1/P-256
# followed by an uncompressed 65-byte EC point. The complete SPKI is 91 bytes.
P256_SPKI_PREFIX = bytes.fromhex(
    "3059301306072a8648ce3d020106082a8648ce3d03010703420004"
)


class Rejected(Exception):
    pass


def canonical_json(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError) as error:
        raise Rejected("json_not_canonicalizable") from error


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise Rejected("json_duplicate_key")
        value[key] = item
    return value


def reject_nonfinite(_: str) -> None:
    raise Rejected("json_nonfinite_number")


def load_canonical_json(data: bytes, label: str) -> Any:
    try:
        text = data.decode("utf-8")
        value = json.loads(
            text,
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=reject_nonfinite,
        )
    except Rejected:
        raise
    except (UnicodeError, ValueError, RecursionError) as error:
        raise Rejected(f"{label}_json_invalid") from error
    if canonical_json(value) != data:
        raise Rejected(f"{label}_not_canonical")
    return value


def read_regular_file(path: pathlib.Path, maximum: int, label: str) -> bytes:
    try:
        initial = os.lstat(path)
    except OSError as error:
        raise Rejected(f"{label}_file_unsafe") from error
    if stat.S_ISLNK(initial.st_mode) or not stat.S_ISREG(initial.st_mode):
        raise Rejected(f"{label}_file_unsafe")
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise Rejected(f"{label}_file_unsafe") from error
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or (info.st_dev, info.st_ino) != (initial.st_dev, initial.st_ino)
            or info.st_size < 1
            or info.st_size > maximum
        ):
            raise Rejected(f"{label}_file_unsafe")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(65536, maximum + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > maximum:
                raise Rejected(f"{label}_file_oversize")
        return b"".join(chunks)
    except OSError as error:
        raise Rejected(f"{label}_file_unreadable") from error
    finally:
        os.close(descriptor)


def bounded_text(value: Any, maximum: int = 128) -> bool:
    return (
        isinstance(value, str)
        and 1 <= len(value) <= maximum
        and all(ord(character) >= 0x20 and character != "\x7f" for character in value)
    )


def canonical_origin(value: Any) -> str:
    if not isinstance(value, str) or not value.isascii() or not value or value.strip() != value:
        raise Rejected("gateway_origin_invalid")
    try:
        parsed = urllib.parse.urlsplit(value)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as error:
        raise Rejected("gateway_origin_invalid") from error
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise Rejected("gateway_origin_invalid")
    if hostname != hostname.lower() or len(hostname) > 253 or ":" in hostname:
        raise Rejected("gateway_origin_invalid")
    labels = hostname.split(".")
    if any(
        not label
        or len(label) > 63
        or re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label) is None
        for label in labels
    ):
        raise Rejected("gateway_origin_invalid")
    if port is not None and not 1 <= port <= 65535:
        raise Rejected("gateway_origin_invalid")
    path = parsed.path
    if path:
        if (
            path.endswith("/")
            or "%" in path
            or "\\" in path
            or re.fullmatch(r"/(?:[A-Za-z0-9_~.-]+)(?:/[A-Za-z0-9_~.-]+)*", path) is None
            or any(segment in {".", ".."} for segment in path.split("/"))
        ):
            raise Rejected("gateway_origin_invalid")
    canonical_port = "" if port in (None, 443) else f":{port}"
    result = f"https://{hostname}{canonical_port}{path}"
    if result != value:
        raise Rejected("gateway_origin_not_canonical")
    return result


def parse_timestamp(value: Any, label: str) -> dt.datetime:
    if not isinstance(value, str) or RFC3339_UTC.fullmatch(value) is None:
        raise Rejected(f"{label}_invalid")
    try:
        parsed = dt.datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise Rejected(f"{label}_invalid") from error
    if parsed.tzinfo != dt.timezone.utc:
        raise Rejected(f"{label}_invalid")
    return parsed


def validate_client(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise Rejected("client_invalid")
    platform = value.get("platform")
    if platform in IOS_PLATFORMS:
        if set(value) != IOS_CLIENT_FIELDS:
            raise Rejected("client_fields_invalid")
        if value.get("provider") != "app_attest":
            raise Rejected("client_provider_invalid")
        if value.get("app_attest_environment") != "production":
            raise Rejected("client_app_attest_environment_invalid")
        team_id = value.get("team_id")
        if not isinstance(team_id, str) or TEAM_ID.fullmatch(team_id) is None:
            raise Rejected("client_team_id_invalid")
        if value.get("require_play_recognized") is not False or value.get("require_licensed") is not False:
            raise Rejected("client_play_policy_invalid")
    elif platform in ANDROID_PLATFORMS:
        if set(value) != ANDROID_CLIENT_FIELDS:
            raise Rejected("client_fields_invalid")
        if value.get("provider") != "play_integrity":
            raise Rejected("client_provider_invalid")
        cloud_project = value.get("cloud_project_number")
        if not isinstance(cloud_project, str) or CLOUD_PROJECT.fullmatch(cloud_project) is None:
            raise Rejected("client_cloud_project_invalid")
        if value.get("installer_package") != "com.android.vending":
            raise Rejected("client_installer_invalid")
        if value.get("play_track") not in PLAY_TRACKS:
            raise Rejected("client_play_track_invalid")
        if value.get("require_play_recognized") is not True or value.get("require_licensed") is not True:
            raise Rejected("client_play_policy_invalid")
    else:
        raise Rejected("client_platform_invalid")

    application_identifier = value.get("application_identifier")
    if not isinstance(application_identifier, str) or IDENTIFIER.fullmatch(application_identifier) is None:
        raise Rejected("client_application_identifier_invalid")
    if not bounded_text(value.get("app_version"), 64) or not bounded_text(value.get("build_number"), 64):
        raise Rejected("client_version_invalid")
    signing_certificate = value.get("signing_certificate_sha256")
    if not isinstance(signing_certificate, str) or SHA256.fullmatch(signing_certificate) is None:
        raise Rejected("client_signing_certificate_invalid")
    if value.get("minimum_trust_level") not in TRUST_LEVELS:
        raise Rejected("client_trust_policy_invalid")
    if value.get("require_request_hash") is not True:
        raise Rejected("client_request_hash_policy_invalid")
    if value.get("allow_testing") is not False or value.get("allow_debug") is not False:
        raise Rejected("client_release_policy_invalid")
    return value


def validate_expected_arguments(arguments: argparse.Namespace) -> dict[str, str]:
    if BOUNDED_ID.fullmatch(arguments.key_id) is None:
        raise Rejected("expected_key_id_invalid")
    if ENVIRONMENT.fullmatch(arguments.environment) is None:
        raise Rejected("expected_environment_invalid")
    if COMMIT.fullmatch(arguments.core_commit) is None:
        raise Rejected("expected_core_commit_invalid")
    if len(arguments.contract_version) > 64 or SEMVER.fullmatch(arguments.contract_version) is None:
        raise Rejected("expected_contract_version_invalid")
    if SHA256.fullmatch(arguments.contract_bundle_sha256) is None:
        raise Rejected("expected_contract_bundle_invalid")
    if OCI_DIGEST.fullmatch(arguments.gateway_image_digest) is None:
        raise Rejected("expected_gateway_image_invalid")
    if SHA256.fullmatch(arguments.gateway_configuration_sha256) is None:
        raise Rejected("expected_gateway_configuration_invalid")
    if SHA256.fullmatch(arguments.public_key_sha256) is None:
        raise Rejected("expected_public_key_pin_invalid")
    return {
        "key_id": arguments.key_id,
        "gateway_origin": canonical_origin(arguments.gateway_origin),
        "environment": arguments.environment,
        "core_commit": arguments.core_commit,
        "contract_version": arguments.contract_version,
        "contract_bundle_sha256": arguments.contract_bundle_sha256,
        "gateway_image_digest": arguments.gateway_image_digest,
        "gateway_configuration_sha256": arguments.gateway_configuration_sha256,
    }


def validate_statement(
    value: Any,
    expected: dict[str, str],
    expected_client: dict[str, Any],
    now: dt.datetime,
) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != TOP_LEVEL_FIELDS:
        raise Rejected("statement_fields_invalid")
    if value.get("schema_version") != SCHEMA_VERSION:
        raise Rejected("statement_schema_invalid")
    if value.get("audience") != AUDIENCE:
        raise Rejected("statement_audience_invalid")
    deployment_id = value.get("deployment_id")
    if not isinstance(deployment_id, str) or BOUNDED_ID.fullmatch(deployment_id) is None:
        raise Rejected("statement_deployment_id_invalid")
    if BOUNDED_ID.fullmatch(str(value.get("key_id", ""))) is None:
        raise Rejected("statement_key_id_invalid")
    if ENVIRONMENT.fullmatch(str(value.get("environment", ""))) is None:
        raise Rejected("statement_environment_invalid")
    if COMMIT.fullmatch(str(value.get("core_commit", ""))) is None:
        raise Rejected("statement_core_commit_invalid")
    if len(str(value.get("contract_version", ""))) > 64 or SEMVER.fullmatch(str(value.get("contract_version", ""))) is None:
        raise Rejected("statement_contract_version_invalid")
    if SHA256.fullmatch(str(value.get("contract_bundle_sha256", ""))) is None:
        raise Rejected("statement_contract_bundle_invalid")
    if OCI_DIGEST.fullmatch(str(value.get("gateway_image_digest", ""))) is None:
        raise Rejected("statement_gateway_image_invalid")
    if SHA256.fullmatch(str(value.get("gateway_configuration_sha256", ""))) is None:
        raise Rejected("statement_gateway_configuration_invalid")

    origin = canonical_origin(value.get("gateway_origin"))
    for name, expected_value in expected.items():
        actual = origin if name == "gateway_origin" else value.get(name)
        if not isinstance(actual, str) or not hmac.compare_digest(actual, expected_value):
            raise Rejected(f"statement_{name}_mismatch")

    issued_at = parse_timestamp(value.get("issued_at"), "statement_issued_at")
    expires_at = parse_timestamp(value.get("expires_at"), "statement_expires_at")
    if expires_at <= issued_at or expires_at - issued_at > MAX_VALIDITY:
        raise Rejected("statement_validity_window_invalid")
    if issued_at > now + CLOCK_SKEW:
        raise Rejected("statement_not_yet_valid")
    if expires_at <= now - CLOCK_SKEW:
        raise Rejected("statement_expired")

    clients = value.get("clients")
    if not isinstance(clients, list) or not 1 <= len(clients) <= 64:
        raise Rejected("statement_clients_invalid")
    validated_clients = [validate_client(client) for client in clients]
    identities: set[tuple[str, str]] = set()
    encodings: set[bytes] = set()
    for client in validated_clients:
        identity = (client["platform"], client["application_identifier"])
        encoding = canonical_json(client)
        if identity in identities or encoding in encodings:
            raise Rejected("statement_client_duplicate")
        identities.add(identity)
        encodings.add(encoding)
    if sum(client == expected_client for client in validated_clients) != 1:
        raise Rejected("statement_current_client_mismatch")
    return value


def openssl_binary() -> str:
    executable = shutil.which("openssl")
    if executable is None or not pathlib.Path(executable).is_file():
        raise Rejected("openssl_unavailable")
    return executable


def run_openssl(executable: str, arguments: list[str]) -> subprocess.CompletedProcess[bytes]:
    environment = {
        "PATH": os.defpath,
        "LANG": "C",
        "LC_ALL": "C",
        "OPENSSL_CONF": os.devnull,
    }
    try:
        return subprocess.run(
            [executable, *arguments],
            check=False,
            capture_output=True,
            env=environment,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise Rejected("openssl_failed") from error


def verify_signature(
    statement: bytes,
    signature: bytes,
    public_key: bytes,
    expected_public_key_sha256: str,
) -> None:
    executable = openssl_binary()
    with tempfile.TemporaryDirectory(prefix="latchway-deployment-verify-") as directory:
        root = pathlib.Path(directory)
        statement_path = root / "statement.json"
        signature_path = root / "statement.sig"
        key_path = root / "public-key.pem"
        statement_path.write_bytes(statement)
        signature_path.write_bytes(signature)
        key_path.write_bytes(public_key)
        for path in (statement_path, signature_path, key_path):
            path.chmod(0o600)

        converted = run_openssl(
            executable,
            ["pkey", "-pubin", "-in", str(key_path), "-outform", "DER"],
        )
        der = converted.stdout
        if (
            converted.returncode != 0
            or len(der) != 91
            or not der.startswith(P256_SPKI_PREFIX)
        ):
            raise Rejected("public_key_not_p256")
        actual_pin = hashlib.sha256(der).hexdigest()
        if not hmac.compare_digest(actual_pin, expected_public_key_sha256):
            raise Rejected("public_key_pin_mismatch")

        verified = run_openssl(
            executable,
            [
                "dgst",
                "-sha256",
                "-verify",
                str(key_path),
                "-signature",
                str(signature_path),
                str(statement_path),
            ],
        )
        if verified.returncode != 0:
            raise Rejected("statement_signature_invalid")


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description="Verify a signed Latchway gateway deployment statement.",
    )
    result.add_argument("--statement", type=pathlib.Path, required=True)
    result.add_argument("--signature", type=pathlib.Path, required=True)
    result.add_argument("--public-key", type=pathlib.Path, required=True)
    result.add_argument("--public-key-sha256", required=True)
    result.add_argument("--client-policy", type=pathlib.Path, required=True)
    result.add_argument("--key-id", required=True)
    result.add_argument("--gateway-origin", required=True)
    result.add_argument("--environment", required=True)
    result.add_argument("--core-commit", required=True)
    result.add_argument("--contract-version", required=True)
    result.add_argument("--contract-bundle-sha256", required=True)
    result.add_argument("--gateway-image-digest", required=True)
    result.add_argument("--gateway-configuration-sha256", required=True)
    return result


def main() -> int:
    arguments = parser().parse_args()
    try:
        expected = validate_expected_arguments(arguments)
        statement_bytes = read_regular_file(
            arguments.statement, MAX_STATEMENT_BYTES, "statement"
        )
        signature = read_regular_file(
            arguments.signature, MAX_SIGNATURE_BYTES, "signature"
        )
        public_key = read_regular_file(
            arguments.public_key, MAX_PUBLIC_KEY_BYTES, "public_key"
        )
        client_policy_bytes = read_regular_file(
            arguments.client_policy, MAX_CLIENT_POLICY_BYTES, "client_policy"
        )
        statement = load_canonical_json(statement_bytes, "statement")
        expected_client = validate_client(
            load_canonical_json(client_policy_bytes, "client_policy")
        )
        verify_signature(
            statement_bytes,
            signature,
            public_key,
            arguments.public_key_sha256,
        )
        validated = validate_statement(
            statement,
            expected,
            expected_client,
            dt.datetime.now(dt.timezone.utc),
        )
        summary = {
            "deployment_id": validated["deployment_id"],
            "expires_at": validated["expires_at"],
            "key_id": validated["key_id"],
            "statement_sha256": hashlib.sha256(statement_bytes).hexdigest(),
            "valid": True,
        }
        sys.stdout.buffer.write(canonical_json(summary) + b"\n")
        return 0
    except Rejected as error:
        print(f"gateway deployment statement rejected: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
