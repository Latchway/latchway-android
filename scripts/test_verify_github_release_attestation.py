#!/usr/bin/env python3
"""Adversarial tests for GitHub release-attestation commit binding."""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import unittest


SCRIPT = Path(__file__).with_name("verify-github-release-attestation.py")
SPEC = importlib.util.spec_from_file_location("verify_github_release_attestation", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)
REPOSITORY = "Latchway/latchway-android"
TAG = "v1.0.0"
COMMIT = "a" * 40
TAG_OBJECT = "b" * 40
MESSAGE = "Android SDK v1.0.0\n\nCore promotion: v1.0.0\nPromotion evidence SHA-256: " + "c" * 64


def fixture() -> tuple[dict[str, object], dict[str, object]]:
    purl = f"pkg:github/{REPOSITORY}@{TAG}"
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [
            {"uri": purl, "digest": {"sha1": TAG_OBJECT}},
            {"name": "asset.zip", "digest": {"sha256": "d" * 64}},
        ],
        "predicateType": "https://in-toto.io/attestation/release/v0.1",
        "predicate": {
            "ownerId": "1", "purl": purl, "releaseId": "2",
            "repository": REPOSITORY, "repositoryId": "3", "tag": TAG,
        },
    }
    release = {
        "attestation": {
            "bundle": {
                "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
                "verificationMaterial": {"certificate": {"rawBytes": "verified"}},
                "dsseEnvelope": {
                    "payload": base64.b64encode(json.dumps(statement).encode()).decode(),
                    "payloadType": "application/vnd.in-toto+json",
                    "signatures": [{"sig": "verified-signature"}],
                },
            },
            "bundle_url": "https://github.com/example/attestation",
            "initiator": "github",
        },
        "verificationResult": {"statement": statement},
    }
    binding = {
        "schema": "latchway.github-release-tag-binding.v1",
        "tag": TAG,
        "tag_object_sha": TAG_OBJECT,
        "commit": COMMIT,
        "message_sha256": hashlib.sha256(MESSAGE.encode()).hexdigest(),
    }
    return release, binding


class GitHubReleaseAttestationTests(unittest.TestCase):
    def test_accepts_exact_verified_tag_object_commit_and_predicate(self) -> None:
        release, binding = fixture()
        result = MODULE.verify(release, binding, REPOSITORY, TAG, COMMIT, MESSAGE)
        self.assertEqual(result["tag_object_sha"], TAG_OBJECT)
        self.assertEqual(result["commit"], COMMIT)

    def test_rejects_tag_object_or_commit_substitution(self) -> None:
        for field, value in (("tag_object_sha", "e" * 40), ("commit", "f" * 40)):
            release, binding = fixture()
            binding[field] = value
            with self.subTest(field=field), self.assertRaises(MODULE.Rejected):
                MODULE.verify(release, binding, REPOSITORY, TAG, COMMIT, MESSAGE)

    def test_rejects_subject_predicate_or_repository_substitution(self) -> None:
        for mutation in ("subject", "tag", "repository"):
            release, binding = fixture()
            statement = json.loads(base64.b64decode(release["attestation"]["bundle"]["dsseEnvelope"]["payload"]))
            if mutation == "subject":
                statement["subject"][0]["digest"] = {"sha1": "e" * 40}
            elif mutation == "tag":
                statement["predicate"]["tag"] = "v9.9.9"
            else:
                statement["predicate"]["repository"] = "attacker/repo"
            release["attestation"]["bundle"]["dsseEnvelope"]["payload"] = base64.b64encode(
                json.dumps(statement).encode()
            ).decode()
            with self.subTest(mutation=mutation), self.assertRaises(MODULE.Rejected):
                MODULE.verify(release, binding, REPOSITORY, TAG, COMMIT, MESSAGE)

    def test_rejects_empty_verification_or_loose_unknown_fields(self) -> None:
        release, binding = fixture()
        release["verificationResult"] = None
        with self.assertRaisesRegex(MODULE.Rejected, "cryptographic"):
            MODULE.verify(release, binding, REPOSITORY, TAG, COMMIT, MESSAGE)
        release, binding = fixture()
        release["accepted_without_verification"] = True
        with self.assertRaisesRegex(MODULE.Rejected, "schema"):
            MODULE.verify(release, binding, REPOSITORY, TAG, COMMIT, MESSAGE)

    def test_rejects_tag_message_rewrite(self) -> None:
        release, binding = fixture()
        with self.assertRaisesRegex(MODULE.Rejected, "message hash"):
            MODULE.verify(release, binding, REPOSITORY, TAG, COMMIT, MESSAGE + "\nrewritten")


if __name__ == "__main__":
    unittest.main()
