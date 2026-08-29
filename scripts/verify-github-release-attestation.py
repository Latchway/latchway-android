#!/usr/bin/env python3
"""Bind verified GitHub release-attestation JSON to the promoted commit and tag."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import stat
import sys
from pathlib import Path
from typing import Any


REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
TAG = re.compile(r"^v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
GIT_OBJECT = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
MAXIMUM_JSON_BYTES = 8 * 1024 * 1024


class Rejected(RuntimeError):
    """The verified output is not strictly bound to this promoted release."""


def load_json(path: Path) -> dict[str, Any]:
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or path.is_symlink() or not 0 < metadata.st_size <= MAXIMUM_JSON_BYTES:
        raise Rejected(f"expected a bounded regular JSON file: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise Rejected(f"invalid JSON: {path}") from error
    if not isinstance(value, dict):
        raise Rejected(f"expected one verified JSON object: {path}")
    return value


def validate_binding(binding: dict[str, Any], tag: str, commit: str, message: str) -> str:
    if set(binding) != {"schema", "tag", "tag_object_sha", "commit", "message_sha256"}:
        raise Rejected("tag binding schema is invalid")
    if binding.get("schema") != "latchway.github-release-tag-binding.v1":
        raise Rejected("tag binding version is invalid")
    tag_object = binding.get("tag_object_sha")
    if binding.get("tag") != tag or binding.get("commit") != commit:
        raise Rejected("tag binding does not target the promoted tag and commit")
    if not isinstance(tag_object, str) or GIT_OBJECT.fullmatch(tag_object) is None:
        raise Rejected("tag binding object identifier is invalid")
    if binding.get("message_sha256") != hashlib.sha256(message.encode("utf-8")).hexdigest():
        raise Rejected("tag binding message hash is invalid")
    return tag_object


def release_statement(value: dict[str, Any]) -> dict[str, Any]:
    if set(value) != {"attestation", "verificationResult"}:
        raise Rejected("GitHub verification result schema is invalid")
    if not isinstance(value.get("verificationResult"), dict) or not value["verificationResult"]:
        raise Rejected("GitHub verification result does not contain cryptographic verification evidence")
    attestation = value.get("attestation")
    if not isinstance(attestation, dict) or set(attestation) != {"bundle", "bundle_url", "initiator"}:
        raise Rejected("GitHub verified attestation envelope is invalid")
    if not isinstance(attestation.get("bundle_url"), str) or not attestation["bundle_url"].startswith("https://"):
        raise Rejected("GitHub verified attestation URL is invalid")
    bundle = attestation.get("bundle")
    if not isinstance(bundle, dict) or set(bundle) != {"mediaType", "verificationMaterial", "dsseEnvelope"}:
        raise Rejected("Sigstore bundle schema is invalid")
    if bundle.get("mediaType") != "application/vnd.dev.sigstore.bundle.v0.3+json":
        raise Rejected("Sigstore bundle media type is invalid")
    envelope = bundle.get("dsseEnvelope")
    if not isinstance(envelope, dict) or set(envelope) != {"payload", "payloadType", "signatures"}:
        raise Rejected("DSSE envelope schema is invalid")
    if envelope.get("payloadType") != "application/vnd.in-toto+json":
        raise Rejected("DSSE payload type is invalid")
    signatures = envelope.get("signatures")
    if not isinstance(signatures, list) or len(signatures) != 1 or not isinstance(signatures[0], dict) or not signatures[0].get("sig"):
        raise Rejected("DSSE signature set is invalid")
    payload = envelope.get("payload")
    if not isinstance(payload, str):
        raise Rejected("DSSE payload is invalid")
    try:
        decoded = base64.b64decode(payload, validate=True)
        statement = json.loads(decoded)
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise Rejected("DSSE release statement is invalid") from error
    if not isinstance(statement, dict):
        raise Rejected("DSSE release statement is not an object")
    return statement


def verify(release: dict[str, Any], binding: dict[str, Any], repository: str, tag: str, commit: str, message: str) -> dict[str, Any]:
    tag_object = validate_binding(binding, tag, commit, message)
    statement = release_statement(release)
    if set(statement) != {"_type", "subject", "predicateType", "predicate"}:
        raise Rejected("release statement fields are invalid")
    if statement.get("_type") != "https://in-toto.io/Statement/v1":
        raise Rejected("release statement type is invalid")
    if statement.get("predicateType") != "https://in-toto.io/attestation/release/v0.1":
        raise Rejected("release predicate type is invalid")
    predicate = statement.get("predicate")
    if not isinstance(predicate, dict) or set(predicate) != {"ownerId", "purl", "releaseId", "repository", "repositoryId", "tag"}:
        raise Rejected("release predicate schema is invalid")
    purl = f"pkg:github/{repository}@{tag}"
    if predicate.get("repository") != repository or predicate.get("tag") != tag or predicate.get("purl") != purl:
        raise Rejected("release predicate identity is invalid")
    for field in ("ownerId", "releaseId", "repositoryId"):
        if not isinstance(predicate.get(field), str) or not predicate[field].isdigit():
            raise Rejected(f"release predicate {field} is invalid")
    subjects = statement.get("subject")
    if not isinstance(subjects, list) or not subjects:
        raise Rejected("release statement subjects are invalid")
    algorithm = "sha1" if len(tag_object) == 40 else "sha256"
    matching = []
    for subject in subjects:
        if not isinstance(subject, dict) or set(subject) not in ({"uri", "digest"}, {"name", "digest"}):
            raise Rejected("release statement contains an invalid subject")
        if subject.get("uri") == purl:
            matching.append(subject)
    if len(matching) != 1 or matching[0].get("digest") != {algorithm: tag_object}:
        raise Rejected("release attestation subject is not the exact annotated tag object")
    return {
        "schema": "latchway.github-release-attestation-proof.v1",
        "repository": repository,
        "tag": tag,
        "tag_object_sha": tag_object,
        "commit": commit,
        "release_predicate_type": statement["predicateType"],
        "verified_bundle_sha256": hashlib.sha256(
            (json.dumps(release["attestation"]["bundle"], sort_keys=True, separators=(",", ":"))).encode("utf-8")
        ).hexdigest(),
    }


def bounded_message(path: Path) -> str:
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or path.is_symlink() or not 0 < metadata.st_size <= 64 * 1024:
        raise Rejected("tag message is not a bounded regular file")
    message = path.read_text(encoding="utf-8")
    if "\r" in message or "\x00" in message:
        raise Rejected("tag message contains unsafe bytes")
    return message


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release-json", type=Path, required=True)
    parser.add_argument("--tag-binding", type=Path, required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--tag-message-file", type=Path, required=True)
    arguments = parser.parse_args()
    if REPOSITORY.fullmatch(arguments.repository) is None:
        parser.error("--repository is invalid")
    if TAG.fullmatch(arguments.tag) is None:
        parser.error("--tag is invalid")
    if COMMIT.fullmatch(arguments.commit) is None:
        parser.error("--commit is invalid")
    return arguments


def main() -> int:
    arguments = parse_arguments()
    try:
        result = verify(
            load_json(arguments.release_json), load_json(arguments.tag_binding),
            arguments.repository, arguments.tag, arguments.commit,
            bounded_message(arguments.tag_message_file),
        )
    except (OSError, Rejected, UnicodeDecodeError) as error:
        print(f"GitHub release attestation rejected: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
