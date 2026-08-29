#!/usr/bin/env python3
"""Create and validate immutable Maven Central deployment state records."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import tempfile
from pathlib import Path
from typing import Any


VERSION = re.compile(r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
NAMESPACE = re.compile(r"^[A-Za-z0-9]+(?:[._-][A-Za-z0-9]+)*$")
UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", re.I)
SHA256 = re.compile(r"^[0-9a-f]{64}$")
INTENT_SCHEMA = "latchway.maven-central-upload-intent.v1"
RECORD_SCHEMA = "latchway.maven-central-deployment.v1"
STATUS_SCHEMA = "latchway.maven-central-deployment-status.v1"
MAXIMUM_JSON_BYTES = 2 * 1024 * 1024
MODULES = (
    "latchway-core",
    "latchway-okhttp",
    "latchway-play-integrity",
    "latchway-firebase-auth",
    "latchway-bom",
)
STATES = {"PENDING", "VALIDATING", "VALIDATED", "PUBLISHING", "PUBLISHED", "FAILED"}


class Rejected(RuntimeError):
    """State is missing, ambiguous, or not bound to this release."""


def canonical_bytes(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def regular_file(path: Path, *, maximum: int | None = None) -> os.stat_result:
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or path.is_symlink() or metadata.st_size <= 0:
        raise Rejected(f"expected a non-empty regular file: {path}")
    if maximum is not None and metadata.st_size > maximum:
        raise Rejected(f"file exceeds the reviewed size bound: {path}")
    return metadata


def load_json(path: Path) -> dict[str, Any]:
    regular_file(path, maximum=MAXIMUM_JSON_BYTES)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise Rejected(f"invalid JSON: {path}") from error
    if not isinstance(value, dict):
        raise Rejected(f"expected a JSON object: {path}")
    return value


def write_no_clobber(path: Path, value: dict[str, Any]) -> None:
    payload = canonical_bytes(value)
    if path.exists():
        regular_file(path, maximum=MAXIMUM_JSON_BYTES)
        if path.read_bytes() != payload:
            raise Rejected(f"existing immutable state differs: {path}")
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temporary, 0o600)
        os.link(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def expected_purls(namespace: str, version: str) -> list[str]:
    return [f"pkg:maven/{namespace}/{module}@{version}" for module in MODULES]


def repository_manifest(repository: Path) -> tuple[str, int]:
    if not repository.is_dir() or repository.is_symlink():
        raise Rejected("reviewed repository is missing or unsafe")
    rows: list[dict[str, Any]] = []
    for path in sorted(repository.rglob("*")):
        if path.is_dir() and not path.is_symlink():
            continue
        regular_file(path)
        relative = path.relative_to(repository).as_posix()
        if not relative.startswith("dev/latchway/"):
            raise Rejected(f"reviewed repository contains an unexpected path: {relative}")
        rows.append({"path": relative, "bytes": path.stat().st_size, "sha256": sha256_file(path)})
    if not rows:
        raise Rejected("reviewed repository is empty")
    return sha256_bytes(canonical_bytes(rows)), len(rows)


def create_intent(arguments: argparse.Namespace) -> dict[str, Any]:
    version = arguments.version
    source_commit = arguments.source_commit
    tag = arguments.tag
    namespace = arguments.namespace
    if VERSION.fullmatch(version) is None or tag != f"v{version}":
        raise Rejected("release version and tag are invalid")
    if COMMIT.fullmatch(source_commit) is None:
        raise Rejected("source commit is invalid")
    if NAMESPACE.fullmatch(namespace) is None:
        raise Rejected("namespace is invalid")
    regular_file(arguments.archive)
    regular_file(arguments.public_key, maximum=1024 * 1024)
    manifest_sha256, manifest_files = repository_manifest(arguments.repository)
    archive_sha256 = sha256_file(arguments.archive)
    deployment_name = f"latchway-android-v{version}-{source_commit[:12]}-{archive_sha256[:12]}"
    return {
        "schema": INTENT_SCHEMA,
        "repository": "Latchway/latchway-android",
        "source_commit": source_commit,
        "release_tag": tag,
        "version": version,
        "namespace": namespace,
        "deployment_name": deployment_name,
        "publishing_type": arguments.publishing_type,
        "reviewed_repository_archive_sha256": archive_sha256,
        "reviewed_repository_manifest_sha256": manifest_sha256,
        "reviewed_repository_file_count": manifest_files,
        "reviewed_public_key_sha256": sha256_file(arguments.public_key),
        "expected_purls": expected_purls(namespace, version),
        "authorization": "single_upload_only",
    }


def validate_intent(value: dict[str, Any]) -> dict[str, Any]:
    expected_keys = {
        "schema", "repository", "source_commit", "release_tag", "version", "namespace",
        "deployment_name", "publishing_type", "reviewed_repository_archive_sha256",
        "reviewed_repository_manifest_sha256", "reviewed_repository_file_count",
        "reviewed_public_key_sha256", "expected_purls", "authorization",
    }
    if set(value) != expected_keys or value.get("schema") != INTENT_SCHEMA:
        raise Rejected("upload intent schema is invalid")
    version = value.get("version")
    if not isinstance(version, str) or VERSION.fullmatch(version) is None:
        raise Rejected("upload intent version is invalid")
    if value.get("release_tag") != f"v{version}":
        raise Rejected("upload intent tag is invalid")
    if value.get("repository") != "Latchway/latchway-android":
        raise Rejected("upload intent repository is invalid")
    commit = value.get("source_commit")
    namespace = value.get("namespace")
    if not isinstance(commit, str) or COMMIT.fullmatch(commit) is None:
        raise Rejected("upload intent source commit is invalid")
    if not isinstance(namespace, str) or NAMESPACE.fullmatch(namespace) is None:
        raise Rejected("upload intent namespace is invalid")
    name = value.get("deployment_name")
    if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", name):
        raise Rejected("upload intent deployment name is invalid")
    if value.get("publishing_type") not in {"automatic", "user_managed"}:
        raise Rejected("upload intent publishing type is invalid")
    for field in (
        "reviewed_repository_archive_sha256",
        "reviewed_repository_manifest_sha256",
        "reviewed_public_key_sha256",
    ):
        item = value.get(field)
        if not isinstance(item, str) or SHA256.fullmatch(item) is None:
            raise Rejected(f"upload intent {field} is invalid")
    count = value.get("reviewed_repository_file_count")
    if not isinstance(count, int) or isinstance(count, bool) or not 1 <= count <= 10000:
        raise Rejected("upload intent repository file count is invalid")
    if value.get("expected_purls") != expected_purls(namespace, version):
        raise Rejected("upload intent PURLs are invalid")
    if value.get("authorization") != "single_upload_only":
        raise Rejected("upload intent authorization is invalid")
    return value


def validate_intent_inputs(
    intent_path: Path,
    repository: Path,
    archive: Path,
    public_key: Path,
) -> None:
    intent = validate_intent(load_json(intent_path))
    regular_file(archive)
    regular_file(public_key, maximum=1024 * 1024)
    manifest_sha256, manifest_files = repository_manifest(repository)
    expected = {
        "reviewed_repository_archive_sha256": sha256_file(archive),
        "reviewed_repository_manifest_sha256": manifest_sha256,
        "reviewed_repository_file_count": manifest_files,
        "reviewed_public_key_sha256": sha256_file(public_key),
    }
    for field, value in expected.items():
        if intent.get(field) != value:
            raise Rejected(f"upload intent {field} does not match the supplied release input")


def create_record(intent_path: Path, deployment_id: str) -> dict[str, Any]:
    intent = validate_intent(load_json(intent_path))
    if UUID.fullmatch(deployment_id) is None:
        raise Rejected("Portal deployment ID is not a UUID")
    return {
        "schema": RECORD_SCHEMA,
        "intent_sha256": sha256_file(intent_path),
        "deployment_id": deployment_id.lower(),
        "deployment_name": intent["deployment_name"],
        "publishing_type": intent["publishing_type"],
        "namespace": intent["namespace"],
        "version": intent["version"],
        "source_commit": intent["source_commit"],
        "expected_purls": intent["expected_purls"],
    }


def validate_record(intent_path: Path, record_path: Path) -> dict[str, Any]:
    intent = validate_intent(load_json(intent_path))
    record = load_json(record_path)
    expected_keys = {
        "schema", "intent_sha256", "deployment_id", "deployment_name", "publishing_type",
        "namespace", "version", "source_commit", "expected_purls",
    }
    if set(record) != expected_keys or record.get("schema") != RECORD_SCHEMA:
        raise Rejected("deployment record schema is invalid")
    deployment_id = record.get("deployment_id")
    if not isinstance(deployment_id, str) or UUID.fullmatch(deployment_id) is None:
        raise Rejected("deployment record ID is invalid")
    expected = {
        "intent_sha256": sha256_file(intent_path),
        "deployment_name": intent["deployment_name"],
        "publishing_type": intent["publishing_type"],
        "namespace": intent["namespace"],
        "version": intent["version"],
        "source_commit": intent["source_commit"],
        "expected_purls": intent["expected_purls"],
    }
    for field, value in expected.items():
        if record.get(field) != value:
            raise Rejected(f"deployment record {field} does not match the upload intent")
    return record


def validate_status(intent_path: Path, record_path: Path, status_path: Path) -> dict[str, Any]:
    intent = validate_intent(load_json(intent_path))
    record = validate_record(intent_path, record_path)
    raw = load_json(status_path)
    deployment_id = raw.get("deploymentId")
    deployment_name = raw.get("deploymentName")
    state = raw.get("deploymentState")
    purls = raw.get("purls", [])
    if deployment_id != record["deployment_id"]:
        raise Rejected("Portal status deployment ID mismatch")
    if deployment_name != intent["deployment_name"]:
        raise Rejected("Portal status deployment name mismatch")
    if state not in STATES:
        raise Rejected("Portal returned an unknown deployment state")
    if not isinstance(purls, list) or any(not isinstance(item, str) for item in purls):
        raise Rejected("Portal status PURLs are invalid")
    if len(purls) != len(set(purls)) or not set(purls).issubset(set(intent["expected_purls"])):
        raise Rejected("Portal status contains unexpected or duplicate PURLs")
    if state in {"VALIDATED", "PUBLISHING", "PUBLISHED"} and sorted(purls) != sorted(intent["expected_purls"]):
        raise Rejected("Portal final deployment does not contain every exact coordinate")
    result: dict[str, Any] = {
        "schema": STATUS_SCHEMA,
        "intent_sha256": sha256_file(intent_path),
        "record_sha256": sha256_file(record_path),
        "deployment_id": record["deployment_id"],
        "deployment_name": intent["deployment_name"],
        "deployment_state": state,
        "purls": sorted(purls),
    }
    if state == "FAILED":
        errors = raw.get("errors")
        if errors is None:
            raise Rejected("failed Portal deployment omitted error details")
        encoded_errors = canonical_bytes(errors)
        if len(encoded_errors) > MAXIMUM_JSON_BYTES:
            raise Rejected("Portal deployment errors exceed the evidence bound")
        result["errors_sha256"] = sha256_bytes(encoded_errors)
    return result


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    intent = commands.add_parser("create-intent")
    intent.add_argument("--repository", type=Path, required=True)
    intent.add_argument("--archive", type=Path, required=True)
    intent.add_argument("--public-key", type=Path, required=True)
    intent.add_argument("--source-commit", required=True)
    intent.add_argument("--tag", required=True)
    intent.add_argument("--version", required=True)
    intent.add_argument("--namespace", default="dev.latchway")
    intent.add_argument("--publishing-type", choices=("automatic", "user_managed"), required=True)
    intent.add_argument("--output", type=Path, required=True)

    record = commands.add_parser("create-record")
    record.add_argument("--intent", type=Path, required=True)
    record.add_argument("--deployment-id", required=True)
    record.add_argument("--output", type=Path, required=True)

    validate_intent_parser = commands.add_parser("validate-intent")
    validate_intent_parser.add_argument("--intent", type=Path, required=True)
    validate_intent_parser.add_argument(
        "--field",
        choices=("deployment_name", "publishing_type", "namespace", "version", "source_commit"),
    )

    validate_inputs_parser = commands.add_parser("validate-inputs")
    validate_inputs_parser.add_argument("--intent", type=Path, required=True)
    validate_inputs_parser.add_argument("--repository", type=Path, required=True)
    validate_inputs_parser.add_argument("--archive", type=Path, required=True)
    validate_inputs_parser.add_argument("--public-key", type=Path, required=True)

    validate_record_parser = commands.add_parser("validate-record")
    validate_record_parser.add_argument("--intent", type=Path, required=True)
    validate_record_parser.add_argument("--record", type=Path, required=True)
    validate_record_parser.add_argument(
        "--field",
        choices=("deployment_id", "deployment_name", "publishing_type", "namespace", "version", "source_commit"),
    )

    status = commands.add_parser("validate-status")
    status.add_argument("--intent", type=Path, required=True)
    status.add_argument("--record", type=Path, required=True)
    status.add_argument("--status", type=Path, required=True)
    status.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    try:
        if arguments.command == "create-intent":
            write_no_clobber(arguments.output, create_intent(arguments))
        elif arguments.command == "create-record":
            write_no_clobber(arguments.output, create_record(arguments.intent, arguments.deployment_id))
        elif arguments.command == "validate-intent":
            intent = validate_intent(load_json(arguments.intent))
            print(intent[arguments.field] if arguments.field else json.dumps(intent, sort_keys=True))
        elif arguments.command == "validate-inputs":
            validate_intent_inputs(
                arguments.intent,
                arguments.repository,
                arguments.archive,
                arguments.public_key,
            )
        elif arguments.command == "validate-record":
            record = validate_record(arguments.intent, arguments.record)
            print(record[arguments.field] if arguments.field else json.dumps(record, sort_keys=True))
        elif arguments.command == "validate-status":
            result = validate_status(arguments.intent, arguments.record, arguments.status)
            write_no_clobber(arguments.output, result)
            print(result["deployment_state"])
        else:  # pragma: no cover - argparse makes this unreachable.
            raise Rejected("unknown command")
    except (OSError, Rejected) as error:
        print(f"Central deployment evidence rejected: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
