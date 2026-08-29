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
import zipfile
from pathlib import Path
from typing import Any, BinaryIO


VERSION = re.compile(r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
NAMESPACE = re.compile(r"^[A-Za-z0-9]+(?:[._-][A-Za-z0-9]+)*$")
UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", re.I)
SHA256 = re.compile(r"^[0-9a-f]{64}$")
INTENT_SCHEMA = "latchway.maven-central-upload-intent.v2"
RECORD_SCHEMA = "latchway.maven-central-deployment.v2"
STATUS_SCHEMA = "latchway.maven-central-deployment-status.v2"
MAXIMUM_JSON_BYTES = 2 * 1024 * 1024
MAXIMUM_ARCHIVE_BYTES = 2 * 1024 * 1024 * 1024
MAXIMUM_SIGNATURE_BYTES = 64 * 1024
MODULES = (
    "latchway-core",
    "latchway-okhttp",
    "latchway-play-integrity",
    "latchway-firebase-auth",
    "latchway-bom",
)
STATES = {"PENDING", "VALIDATING", "VALIDATED", "PUBLISHING", "PUBLISHED", "FAILED"}
CHECKSUM_ALGORITHMS = ("md5", "sha1", "sha256", "sha512")


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


def digest_stream(source: BinaryIO, algorithm: str = "sha256") -> str:
    digest = hashlib.new(algorithm)
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


def primary_repository_paths(version: str) -> list[str]:
    paths: list[str] = []
    for module in MODULES:
        extensions = ["pom", "module", "sources.jar", "javadoc.jar"]
        if module != "latchway-bom":
            extensions.append("aar")
        prefix = f"dev/latchway/{module}/{version}/{module}-{version}"
        for extension in extensions:
            separator = "." if extension in {"pom", "module", "aar"} else "-"
            paths.append(f"{prefix}{separator}{extension}")
    return sorted(paths)


def expected_repository_paths(version: str) -> list[str]:
    primaries = primary_repository_paths(version)
    return sorted(primaries + [f"{path}.{algorithm}" for path in primaries for algorithm in CHECKSUM_ALGORITHMS])


def repository_manifest(repository: Path, version: str) -> tuple[str, int]:
    if not repository.is_dir() or repository.is_symlink():
        raise Rejected("reviewed repository is missing or unsafe")
    expected = expected_repository_paths(version)
    observed: list[str] = []
    for path in sorted(repository.rglob("*")):
        if path.is_dir() and not path.is_symlink():
            continue
        regular_file(path)
        observed.append(path.relative_to(repository).as_posix())
    if observed != expected:
        missing = sorted(set(expected) - set(observed))
        extra = sorted(set(observed) - set(expected))
        raise Rejected(f"reviewed repository is not the exact closed artifact set (missing={missing}, extra={extra})")

    for primary in primary_repository_paths(version):
        payload = repository / primary
        for algorithm in CHECKSUM_ALGORITHMS:
            checksum = repository / f"{primary}.{algorithm}"
            try:
                observed_digest = checksum.read_text(encoding="ascii")
            except UnicodeDecodeError as error:
                raise Rejected(f"reviewed checksum is not ASCII: {checksum}") from error
            with payload.open("rb") as source:
                expected_digest = digest_stream(source, algorithm)
            if observed_digest != expected_digest:
                raise Rejected(f"reviewed checksum does not match its exact artifact: {checksum}")

    rows = [
        {"path": relative, "bytes": (repository / relative).stat().st_size, "sha256": sha256_file(repository / relative)}
        for relative in expected
    ]
    return sha256_bytes(canonical_bytes(rows)), len(rows)


def validate_zip_entry(info: zipfile.ZipInfo) -> None:
    if info.is_dir() or info.flag_bits & 0x1:
        raise Rejected(f"archive contains a directory or encrypted entry: {info.filename}")
    if info.filename.startswith("/") or "\\" in info.filename or any(part in {"", ".", ".."} for part in info.filename.split("/")):
        raise Rejected(f"archive contains an unsafe path: {info.filename}")
    mode = (info.external_attr >> 16) & 0xFFFF
    if mode and not stat.S_ISREG(mode):
        raise Rejected(f"archive contains a non-regular entry: {info.filename}")


def validate_archive(archive: Path, repository: Path, version: str, *, signed: bool) -> int:
    regular_file(archive, maximum=MAXIMUM_ARCHIVE_BYTES)
    repository_paths = expected_repository_paths(version)
    expected = set(repository_paths)
    if signed:
        expected.update(f"{path}.asc" for path in primary_repository_paths(version))
    try:
        with zipfile.ZipFile(archive) as source:
            infos = source.infolist()
            names = [info.filename for info in infos]
            if len(names) != len(set(names)):
                raise Rejected("archive contains duplicate entries")
            if set(names) != expected:
                missing = sorted(expected - set(names))
                extra = sorted(set(names) - expected)
                raise Rejected(f"archive is not the exact closed artifact set (missing={missing}, extra={extra})")
            total = 0
            for info in infos:
                validate_zip_entry(info)
                total += info.file_size
                if total > MAXIMUM_ARCHIVE_BYTES:
                    raise Rejected("archive uncompressed contents exceed the reviewed size bound")
                with source.open(info) as archived:
                    archived_sha256 = digest_stream(archived)
                if info.filename.endswith(".asc"):
                    if not 0 < info.file_size <= MAXIMUM_SIGNATURE_BYTES:
                        raise Rejected(f"archive signature has an invalid size: {info.filename}")
                    continue
                local = repository / info.filename
                if info.file_size != local.stat().st_size or archived_sha256 != sha256_file(local):
                    raise Rejected(f"archive entry differs from the reviewed repository: {info.filename}")
    except zipfile.BadZipFile as error:
        raise Rejected(f"invalid ZIP archive: {archive}") from error
    return len(expected)


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
    regular_file(arguments.public_key, maximum=1024 * 1024)
    manifest_sha256, manifest_files = repository_manifest(arguments.repository, version)
    archive_files = validate_archive(arguments.archive, arguments.repository, version, signed=False)
    portal_files = validate_archive(arguments.portal_bundle, arguments.repository, version, signed=True)
    if archive_files != manifest_files:
        raise Rejected("reviewed repository archive does not contain the exact repository")
    portal_sha256 = sha256_file(arguments.portal_bundle)
    deployment_name = f"latchway-android-v{version}-{source_commit[:12]}-{portal_sha256}"
    return {
        "schema": INTENT_SCHEMA,
        "repository": "Latchway/latchway-android",
        "source_commit": source_commit,
        "release_tag": tag,
        "version": version,
        "namespace": namespace,
        "deployment_name": deployment_name,
        "publishing_type": arguments.publishing_type,
        "reviewed_repository_archive_sha256": sha256_file(arguments.archive),
        "reviewed_repository_manifest_sha256": manifest_sha256,
        "reviewed_repository_file_count": manifest_files,
        "reviewed_portal_bundle_sha256": portal_sha256,
        "reviewed_portal_bundle_file_count": portal_files,
        "reviewed_public_key_sha256": sha256_file(arguments.public_key),
        "expected_purls": expected_purls(namespace, version),
        "authorization": "recoverable_exact_upload",
    }


def validate_intent(value: dict[str, Any]) -> dict[str, Any]:
    expected_keys = {
        "schema", "repository", "source_commit", "release_tag", "version", "namespace",
        "deployment_name", "publishing_type", "reviewed_repository_archive_sha256",
        "reviewed_repository_manifest_sha256", "reviewed_repository_file_count",
        "reviewed_portal_bundle_sha256", "reviewed_portal_bundle_file_count",
        "reviewed_public_key_sha256", "expected_purls", "authorization",
    }
    if set(value) != expected_keys or value.get("schema") != INTENT_SCHEMA:
        raise Rejected("upload intent schema is invalid")
    version = value.get("version")
    if not isinstance(version, str) or VERSION.fullmatch(version) is None:
        raise Rejected("upload intent version is invalid")
    if value.get("release_tag") != f"v{version}" or value.get("repository") != "Latchway/latchway-android":
        raise Rejected("upload intent release identity is invalid")
    commit = value.get("source_commit")
    namespace = value.get("namespace")
    if not isinstance(commit, str) or COMMIT.fullmatch(commit) is None:
        raise Rejected("upload intent source commit is invalid")
    if not isinstance(namespace, str) or NAMESPACE.fullmatch(namespace) is None:
        raise Rejected("upload intent namespace is invalid")
    portal_sha256 = value.get("reviewed_portal_bundle_sha256")
    name = value.get("deployment_name")
    expected_name = f"latchway-android-v{version}-{commit[:12]}-{portal_sha256}"
    if not isinstance(name, str) or name != expected_name or len(name) > 128:
        raise Rejected("upload intent deployment name is invalid")
    if value.get("publishing_type") != "user_managed":
        raise Rejected("upload intent must use recoverable user-managed publication")
    for field in (
        "reviewed_repository_archive_sha256", "reviewed_repository_manifest_sha256",
        "reviewed_portal_bundle_sha256", "reviewed_public_key_sha256",
    ):
        item = value.get(field)
        if not isinstance(item, str) or SHA256.fullmatch(item) is None:
            raise Rejected(f"upload intent {field} is invalid")
    if value.get("reviewed_repository_file_count") != len(expected_repository_paths(version)):
        raise Rejected("upload intent repository file count is invalid")
    expected_portal_count = len(expected_repository_paths(version)) + len(primary_repository_paths(version))
    if value.get("reviewed_portal_bundle_file_count") != expected_portal_count:
        raise Rejected("upload intent Portal bundle file count is invalid")
    if value.get("expected_purls") != expected_purls(namespace, version):
        raise Rejected("upload intent PURLs are invalid")
    if value.get("authorization") != "recoverable_exact_upload":
        raise Rejected("upload intent authorization is invalid")
    return value


def validate_intent_inputs(intent_path: Path, repository: Path, archive: Path, portal_bundle: Path, public_key: Path) -> None:
    intent = validate_intent(load_json(intent_path))
    version = intent["version"]
    regular_file(public_key, maximum=1024 * 1024)
    manifest_sha256, manifest_files = repository_manifest(repository, version)
    archive_files = validate_archive(archive, repository, version, signed=False)
    portal_files = validate_archive(portal_bundle, repository, version, signed=True)
    expected = {
        "reviewed_repository_archive_sha256": sha256_file(archive),
        "reviewed_repository_manifest_sha256": manifest_sha256,
        "reviewed_repository_file_count": manifest_files,
        "reviewed_portal_bundle_sha256": sha256_file(portal_bundle),
        "reviewed_portal_bundle_file_count": portal_files,
        "reviewed_public_key_sha256": sha256_file(public_key),
    }
    if archive_files != manifest_files:
        raise Rejected("reviewed archive is not equivalent to the reviewed repository")
    for field, value in expected.items():
        if intent.get(field) != value:
            raise Rejected(f"upload intent {field} does not match the supplied release input")


def record_common(intent_path: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    intent = validate_intent(load_json(intent_path))
    return intent, {
        "schema": RECORD_SCHEMA,
        "intent_sha256": sha256_file(intent_path),
        "deployment_name": intent["deployment_name"],
        "publishing_type": intent["publishing_type"],
        "namespace": intent["namespace"],
        "version": intent["version"],
        "source_commit": intent["source_commit"],
        "expected_purls": intent["expected_purls"],
        "reviewed_portal_bundle_sha256": intent["reviewed_portal_bundle_sha256"],
    }


def create_record(intent_path: Path, deployment_id: str) -> dict[str, Any]:
    _, result = record_common(intent_path)
    if UUID.fullmatch(deployment_id) is None:
        raise Rejected("Portal deployment ID is not a UUID")
    result.update({"record_kind": "portal_deployment", "deployment_id": deployment_id.lower(), "public_manifest_sha256": None})
    return result


def public_manifest_from_evidence(path: Path, version: str) -> str:
    evidence = load_json(path)
    if evidence.get("schema_version") != 2 or evidence.get("registry") != "maven_central":
        raise Rejected("public registry evidence schema is invalid")
    if evidence.get("namespace") != "dev.latchway" or evidence.get("version") != version:
        raise Rejected("public registry evidence coordinates are invalid")
    digest = evidence.get("public_manifest_sha256")
    if not isinstance(digest, str) or SHA256.fullmatch(digest) is None:
        raise Rejected("public registry evidence manifest is invalid")
    return digest


def create_adoption_record(intent_path: Path, evidence_path: Path) -> dict[str, Any]:
    intent, result = record_common(intent_path)
    result.update({
        "record_kind": "public_registry_adoption",
        "deployment_id": None,
        "public_manifest_sha256": public_manifest_from_evidence(evidence_path, intent["version"]),
    })
    return result


def validate_record(intent_path: Path, record_path: Path) -> dict[str, Any]:
    _, common = record_common(intent_path)
    record = load_json(record_path)
    expected_keys = set(common) | {"record_kind", "deployment_id", "public_manifest_sha256"}
    if set(record) != expected_keys or record.get("schema") != RECORD_SCHEMA:
        raise Rejected("deployment record schema is invalid")
    for field, value in common.items():
        if record.get(field) != value:
            raise Rejected(f"deployment record {field} does not match the upload intent")
    if record.get("record_kind") == "portal_deployment":
        deployment_id = record.get("deployment_id")
        if not isinstance(deployment_id, str) or UUID.fullmatch(deployment_id) is None:
            raise Rejected("deployment record ID is invalid")
        if record.get("public_manifest_sha256") is not None:
            raise Rejected("Portal deployment record contains adoption state")
    elif record.get("record_kind") == "public_registry_adoption":
        if record.get("deployment_id") is not None:
            raise Rejected("public adoption record contains a Portal deployment ID")
        digest = record.get("public_manifest_sha256")
        if not isinstance(digest, str) or SHA256.fullmatch(digest) is None:
            raise Rejected("public adoption manifest is invalid")
    else:
        raise Rejected("deployment record kind is invalid")
    return record


def validate_portal_status(intent_path: Path, record_path: Path, status_path: Path) -> dict[str, Any]:
    intent = validate_intent(load_json(intent_path))
    record = validate_record(intent_path, record_path)
    if record["record_kind"] != "portal_deployment":
        raise Rejected("Portal status cannot be applied to a public adoption record")
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
        "record_kind": record["record_kind"],
        "deployment_id": record["deployment_id"],
        "deployment_name": intent["deployment_name"],
        "deployment_state": state,
        "purls": sorted(purls),
        "public_manifest_sha256": None,
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


def create_adoption_status(intent_path: Path, record_path: Path, evidence_path: Path) -> dict[str, Any]:
    intent = validate_intent(load_json(intent_path))
    record = validate_record(intent_path, record_path)
    digest = public_manifest_from_evidence(evidence_path, intent["version"])
    if record["record_kind"] != "public_registry_adoption" or record["public_manifest_sha256"] != digest:
        raise Rejected("public adoption record does not bind the verified public manifest")
    return {
        "schema": STATUS_SCHEMA,
        "intent_sha256": sha256_file(intent_path),
        "record_sha256": sha256_file(record_path),
        "record_kind": record["record_kind"],
        "deployment_id": None,
        "deployment_name": intent["deployment_name"],
        "deployment_state": "PUBLISHED",
        "purls": sorted(intent["expected_purls"]),
        "public_manifest_sha256": digest,
    }


def validate_normalized_status(intent_path: Path, record_path: Path, status_path: Path) -> dict[str, Any]:
    intent = validate_intent(load_json(intent_path))
    record = validate_record(intent_path, record_path)
    status_value = load_json(status_path)
    expected_keys = {
        "schema", "intent_sha256", "record_sha256", "record_kind", "deployment_id",
        "deployment_name", "deployment_state", "purls", "public_manifest_sha256",
    }
    if status_value.get("deployment_state") == "FAILED":
        expected_keys.add("errors_sha256")
    if set(status_value) != expected_keys or status_value.get("schema") != STATUS_SCHEMA:
        raise Rejected("deployment status schema is invalid")
    expected = {
        "intent_sha256": sha256_file(intent_path),
        "record_sha256": sha256_file(record_path),
        "record_kind": record["record_kind"],
        "deployment_id": record["deployment_id"],
        "deployment_name": intent["deployment_name"],
    }
    for field, value in expected.items():
        if status_value.get(field) != value:
            raise Rejected(f"deployment status {field} binding is invalid")
    state = status_value.get("deployment_state")
    if state not in STATES:
        raise Rejected("deployment status state is invalid")
    purls = status_value.get("purls")
    if not isinstance(purls, list) or purls != sorted(set(purls)) or not set(purls).issubset(set(intent["expected_purls"])):
        raise Rejected("deployment status PURLs are invalid")
    if state in {"VALIDATED", "PUBLISHING", "PUBLISHED"} and purls != sorted(intent["expected_purls"]):
        raise Rejected("deployment status omits required coordinates")
    if record["record_kind"] == "public_registry_adoption":
        if state != "PUBLISHED" or status_value.get("public_manifest_sha256") != record["public_manifest_sha256"]:
            raise Rejected("public adoption status is incomplete")
    elif status_value.get("public_manifest_sha256") is not None:
        raise Rejected("Portal status contains a public adoption manifest")
    return status_value


def select_deployment(intent_path: Path, listing_path: Path) -> str:
    intent = validate_intent(load_json(intent_path))
    regular_file(listing_path, maximum=MAXIMUM_JSON_BYTES)
    try:
        raw = json.loads(listing_path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise Rejected("Portal deployment listing is invalid JSON") from error
    expected_keys = {"deployments", "page", "pageSize", "pageCount", "totalResultCount"}
    if not isinstance(raw, dict) or set(raw) != expected_keys:
        raise Rejected("Portal deployment listing schema is unreviewed")
    rows = raw.get("deployments")
    integers = [raw.get(field) for field in ("page", "pageSize", "pageCount", "totalResultCount")]
    if not isinstance(rows, list) or any(not isinstance(value, int) or isinstance(value, bool) for value in integers):
        raise Rejected("Portal deployment listing pagination is invalid")
    if raw["page"] != 0 or raw["pageSize"] < 1 or raw["pageCount"] not in {0, 1}:
        raise Rejected("Portal deployment listing is incomplete or unexpectedly paginated")
    if raw["totalResultCount"] != len(rows):
        raise Rejected("Portal deployment listing result count is inconsistent")
    matching: set[str] = set()
    for row in rows:
        if not isinstance(row, dict):
            raise Rejected("Portal deployment listing contains a non-object row")
        name = row.get("deploymentName", row.get("name"))
        deployment_id = row.get("deploymentId", row.get("id"))
        if name == intent["deployment_name"]:
            if not isinstance(deployment_id, str) or UUID.fullmatch(deployment_id) is None:
                raise Rejected("matching Portal deployment has an invalid ID")
            matching.add(deployment_id.lower())
    if len(matching) > 1:
        raise Rejected("Portal contains multiple deployments with the exact deterministic name")
    return next(iter(matching), "")


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    intent = commands.add_parser("create-intent")
    intent.add_argument("--repository", type=Path, required=True)
    intent.add_argument("--archive", type=Path, required=True)
    intent.add_argument("--portal-bundle", type=Path, required=True)
    intent.add_argument("--public-key", type=Path, required=True)
    intent.add_argument("--source-commit", required=True)
    intent.add_argument("--tag", required=True)
    intent.add_argument("--version", required=True)
    intent.add_argument("--namespace", default="dev.latchway")
    intent.add_argument("--publishing-type", choices=("user_managed",), required=True)
    intent.add_argument("--output", type=Path, required=True)
    record = commands.add_parser("create-record")
    record.add_argument("--intent", type=Path, required=True)
    record.add_argument("--deployment-id", required=True)
    record.add_argument("--output", type=Path, required=True)
    adoption = commands.add_parser("create-adoption-record")
    adoption.add_argument("--intent", type=Path, required=True)
    adoption.add_argument("--public-evidence", type=Path, required=True)
    adoption.add_argument("--output", type=Path, required=True)
    adoption_status = commands.add_parser("create-adoption-status")
    adoption_status.add_argument("--intent", type=Path, required=True)
    adoption_status.add_argument("--record", type=Path, required=True)
    adoption_status.add_argument("--public-evidence", type=Path, required=True)
    adoption_status.add_argument("--output", type=Path, required=True)
    validate_intent_parser = commands.add_parser("validate-intent")
    validate_intent_parser.add_argument("--intent", type=Path, required=True)
    validate_intent_parser.add_argument("--field", choices=(
        "deployment_name", "publishing_type", "namespace", "version", "source_commit", "reviewed_portal_bundle_sha256",
    ))
    validate_inputs_parser = commands.add_parser("validate-inputs")
    validate_inputs_parser.add_argument("--intent", type=Path, required=True)
    validate_inputs_parser.add_argument("--repository", type=Path, required=True)
    validate_inputs_parser.add_argument("--archive", type=Path, required=True)
    validate_inputs_parser.add_argument("--portal-bundle", type=Path, required=True)
    validate_inputs_parser.add_argument("--public-key", type=Path, required=True)
    validate_record_parser = commands.add_parser("validate-record")
    validate_record_parser.add_argument("--intent", type=Path, required=True)
    validate_record_parser.add_argument("--record", type=Path, required=True)
    validate_record_parser.add_argument("--field", choices=(
        "record_kind", "deployment_id", "deployment_name", "publishing_type", "namespace", "version", "source_commit",
    ))
    status = commands.add_parser("validate-status")
    status.add_argument("--intent", type=Path, required=True)
    status.add_argument("--record", type=Path, required=True)
    status.add_argument("--status", type=Path, required=True)
    status.add_argument("--output", type=Path, required=True)
    complete = commands.add_parser("validate-complete")
    complete.add_argument("--intent", type=Path, required=True)
    complete.add_argument("--record", type=Path, required=True)
    complete.add_argument("--status", type=Path, required=True)
    complete.add_argument("--public-manifest-sha256", required=True)
    select = commands.add_parser("select-deployment")
    select.add_argument("--intent", type=Path, required=True)
    select.add_argument("--listing", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    try:
        if arguments.command == "create-intent":
            write_no_clobber(arguments.output, create_intent(arguments))
        elif arguments.command == "create-record":
            write_no_clobber(arguments.output, create_record(arguments.intent, arguments.deployment_id))
        elif arguments.command == "create-adoption-record":
            write_no_clobber(arguments.output, create_adoption_record(arguments.intent, arguments.public_evidence))
        elif arguments.command == "create-adoption-status":
            write_no_clobber(arguments.output, create_adoption_status(arguments.intent, arguments.record, arguments.public_evidence))
        elif arguments.command == "validate-intent":
            intent_value = validate_intent(load_json(arguments.intent))
            print(intent_value[arguments.field] if arguments.field else json.dumps(intent_value, sort_keys=True))
        elif arguments.command == "validate-inputs":
            validate_intent_inputs(arguments.intent, arguments.repository, arguments.archive, arguments.portal_bundle, arguments.public_key)
        elif arguments.command == "validate-record":
            record_value = validate_record(arguments.intent, arguments.record)
            value = record_value[arguments.field] if arguments.field else json.dumps(record_value, sort_keys=True)
            print("" if value is None else value)
        elif arguments.command == "validate-status":
            result = validate_portal_status(arguments.intent, arguments.record, arguments.status)
            write_no_clobber(arguments.output, result)
            print(result["deployment_state"])
        elif arguments.command == "validate-complete":
            result = validate_normalized_status(arguments.intent, arguments.record, arguments.status)
            if result["deployment_state"] != "PUBLISHED":
                raise Rejected("deployment evidence is not complete and PUBLISHED")
            if SHA256.fullmatch(arguments.public_manifest_sha256) is None:
                raise Rejected("public manifest SHA-256 is invalid")
            if result["record_kind"] == "public_registry_adoption" and result["public_manifest_sha256"] != arguments.public_manifest_sha256:
                raise Rejected("public adoption does not bind the current public manifest")
            print(result["record_kind"])
        elif arguments.command == "select-deployment":
            print(select_deployment(arguments.intent, arguments.listing))
        else:  # pragma: no cover
            raise Rejected("unknown command")
    except (OSError, Rejected) as error:
        print(f"Central deployment evidence rejected: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
