#!/usr/bin/env python3
"""Verify an explicit single-maintainer Android v1 publication request.

This is an additive, lower-assurance publication path. It does not weaken or
replace the evidence-gated repository-dispatch release verifier. The command
binds a manual dispatch to the exact main commit and checked-in Android release
metadata, then emits a durable intent that names every deferred assurance.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
from typing import Any, Mapping


ROOT = Path(__file__).resolve().parents[1]
PROFILE = "single_maintainer_v1"
REPOSITORY = "Latchway/latchway-android"
VERSION = "1.0.0"
TAG = "v1.0.0"
CONFIRMATION = "publish-v1.0.0-with-deferred-assurance"
COMMIT = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
MAXIMUM_JSON_SAFE_INTEGER = 9_007_199_254_740_991
DEFERRED_EVIDENCE = [
    "independent_human_review",
    "live_sdk_conformance",
    "physical_devices",
    "apple_distribution_and_extensions",
    "play_integrity_and_android_device",
    "firebase_app_check",
    "turnstile",
    "live_provider",
    "cloud_deployments.aws_verified",
    "cloud_deployments.fly_io_verified",
    "cloud_deployments.cloudflare_containers_verified",
    "operational_resilience",
    "public_registries.documentation_production_verified",
    "mintlify_production",
]
FORBIDDEN_CLAIMS = [
    "release_qualified",
    "fully_evidence_gated",
    "independently_reviewed",
]
MAVEN_COORDINATES = [
    "dev.latchway:latchway-core:1.0.0",
    "dev.latchway:latchway-okhttp:1.0.0",
    "dev.latchway:latchway-play-integrity:1.0.0",
    "dev.latchway:latchway-firebase-auth:1.0.0",
    "dev.latchway:latchway-bom:1.0.0",
]


class Rejected(Exception):
    """A stable, redaction-safe request-verification failure."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def git(*arguments: str) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", str(ROOT), *arguments],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError):
        raise Rejected("maintainer_release_git_invalid") from None
    return result.stdout.strip()


def regular_text(path: Path, error: str, maximum: int = 1024 * 1024) -> str:
    try:
        metadata = path.lstat()
        if (
            path.is_symlink()
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_size <= 0
            or metadata.st_size > maximum
        ):
            raise Rejected(error)
        return path.read_text(encoding="utf-8")
    except Rejected:
        raise
    except (OSError, UnicodeDecodeError):
        raise Rejected(error) from None


def contract_lock() -> dict[str, str]:
    values: dict[str, str] = {}
    for line in regular_text(
        ROOT / "contract.lock", "maintainer_release_contract_lock_invalid"
    ).splitlines():
        match = re.fullmatch(r'([a-z0-9_]+):\s*(?:"([^"]*)"|([^\s]+))', line)
        if match is None or match.group(1) in values:
            raise Rejected("maintainer_release_contract_lock_invalid")
        values[match.group(1)] = match.group(2) or match.group(3)
    required = {
        "contract_version",
        "wire_protocol",
        "core_release",
        "core_commit",
        "bundle_sha256",
        "minimum_server_version",
        "maximum_tested_server_version",
    }
    if (
        set(values) != required
        or values["contract_version"] != VERSION
        or values["wire_protocol"] != "2"
        or values["core_release"] != TAG
        or COMMIT.fullmatch(values["core_commit"]) is None
        or SHA256.fullmatch(values["bundle_sha256"]) is None
    ):
        raise Rejected("maintainer_release_contract_lock_invalid")
    return values


def verify_android_release_metadata(contract: Mapping[str, str]) -> None:
    runtime = regular_text(
        ROOT / "latchway-core/src/main/kotlin/dev/latchway/core/LatchwayApi.kt",
        "maintainer_release_local_version_invalid",
    )
    if (
        re.search(r'\bLATCHWAY_SDK_VERSION:\s*String\s*=\s*"1\.0\.0"', runtime)
        is None
        or re.search(
            r'\bLATCHWAY_CONTRACT_VERSION:\s*String\s*=\s*"1\.0\.0"',
            runtime,
        )
        is None
        or contract["contract_version"] != VERSION
    ):
        raise Rejected("maintainer_release_local_version_invalid")
    changelog = regular_text(
        ROOT / "CHANGELOG.md", "maintainer_release_changelog_invalid"
    )
    if re.search(r"(?m)^## \[1\.0\.0\](?:\s+-\s+\d{4}-\d{2}-\d{2})?$", changelog) is None:
        raise Rejected("maintainer_release_changelog_invalid")


def positive_run_number(value: str) -> int:
    if re.fullmatch(r"[1-9][0-9]{0,15}", value) is None:
        raise Rejected("maintainer_release_run_identity_invalid")
    number = int(value)
    if number > MAXIMUM_JSON_SAFE_INTEGER:
        raise Rejected("maintainer_release_run_identity_invalid")
    return number


def write_intent(path: Path, value: Mapping[str, Any]) -> str:
    payload = (
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    ).encode("utf-8")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists() and (path.is_symlink() or not path.is_file()):
            raise Rejected("maintainer_release_intent_output_invalid")
        temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
        temporary.write_bytes(payload)
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    except Rejected:
        raise
    except OSError:
        raise Rejected("maintainer_release_intent_output_invalid") from None
    return hashlib.sha256(payload).hexdigest()


def append_outputs(path: Path, values: Mapping[str, str]) -> None:
    try:
        with path.open("a", encoding="utf-8") as output:
            for key in sorted(values):
                value = values[key]
                if "\n" in value or "\r" in value:
                    raise Rejected("maintainer_release_output_invalid")
                output.write(f"{key}={value}\n")
    except Rejected:
        raise
    except OSError:
        raise Rejected("maintainer_release_output_invalid") from None


def verify(arguments: argparse.Namespace) -> dict[str, str]:
    if (
        ROOT.name != "latchway-android"
        or arguments.repository_name != REPOSITORY
        or arguments.profile != PROFILE
        or arguments.release_version != VERSION
        or arguments.release_commit != arguments.workflow_commit
        or COMMIT.fullmatch(arguments.release_commit) is None
        or arguments.workflow_ref != "refs/heads/main"
        or arguments.confirmation != CONFIRMATION
    ):
        raise Rejected("maintainer_release_dispatch_invalid")
    if git("rev-parse", "--verify", "HEAD") != arguments.release_commit:
        raise Rejected("maintainer_release_commit_mismatch")
    if git("status", "--porcelain=v1", "--untracked-files=all"):
        raise Rejected("maintainer_release_worktree_dirty")

    contract = contract_lock()
    verify_android_release_metadata(contract)
    run_id = positive_run_number(arguments.run_id)
    run_attempt = positive_run_number(arguments.run_attempt)
    intent = {
        "schema_version": 1,
        "kind": "latchway_single_maintainer_release_intent",
        "profile": PROFILE,
        "status": "maintainer_requested",
        "status_claim": "v1_publication_in_progress_with_deferred_assurance",
        "publication_ready": False,
        "release_qualified": False,
        "requires_independent_human_review": False,
        "source": {
            "repository": REPOSITORY,
            "commit": arguments.release_commit,
            "version": VERSION,
            "tag": TAG,
            "ref": arguments.workflow_ref,
        },
        "contract": {
            "core_commit": contract["core_commit"],
            "core_tag": contract["core_release"],
            "bundle_sha256": contract["bundle_sha256"],
            "wire_protocol": 2,
        },
        "workflow": {
            "file": ".github/workflows/single-maintainer-release.yml",
            "event": "workflow_dispatch",
            "run_id": run_id,
            "run_attempt": run_attempt,
        },
        "maintainer_confirmation": "accepted_exact_phrase",
        "maven_coordinates": MAVEN_COORDINATES,
        "deferred_evidence": DEFERRED_EVIDENCE,
        "forbidden_claims": FORBIDDEN_CLAIMS,
        "global_profile_required_evidence": [
            "cloud_deployments.compose_verified",
            "cloud_deployments.gcp_cloud_run_verified",
        ],
        "downstream_required_gates": [
            "complete_local_release_tests_before_tag",
            "dependency_vulnerability_scan_before_tag",
            "deterministic_maven_repository_before_tag",
            "annotated_tag_exact_commit",
            "openpgp_signed_maven_artifacts",
            "exact_maven_central_byte_verification",
            "build_provenance_attestation",
            "exact_github_release",
        ],
    }
    digest = write_intent(arguments.intent_output, intent)
    return {
        "commit": arguments.release_commit,
        "core_commit": contract["core_commit"],
        "core_tag": contract["core_release"],
        "intent_sha256": digest,
        "tag": TAG,
        "version": VERSION,
    }


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--repository-name", required=True)
    result.add_argument("--profile", required=True)
    result.add_argument("--release-commit", required=True)
    result.add_argument("--release-version", required=True)
    result.add_argument("--workflow-commit", required=True)
    result.add_argument("--workflow-ref", required=True)
    result.add_argument("--run-id", required=True)
    result.add_argument("--run-attempt", required=True)
    result.add_argument("--confirmation", required=True)
    result.add_argument("--intent-output", type=Path, required=True)
    result.add_argument("--github-output", type=Path)
    return result


def main() -> int:
    arguments = parser().parse_args()
    try:
        outputs = verify(arguments)
        if arguments.github_output is not None:
            append_outputs(arguments.github_output, outputs)
    except Rejected as error:
        print(f"single-maintainer release rejected: {error.code}", file=sys.stderr)
        return 1
    print(json.dumps(outputs, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
