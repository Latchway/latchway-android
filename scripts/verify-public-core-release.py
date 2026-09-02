#!/usr/bin/env python3
"""Verify the closed public core single-maintainer v1 evidence directory."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import stat
import tarfile
from typing import Any, Iterable


TAG = "v1.0.0"
VERSION = "1.0.0"
CORE_REPOSITORY = "ghcr.io/latchway/latchway"
COMMIT = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
RUN = re.compile(r"^[1-9][0-9]{0,19}$")
MAX_FILE = 32 * 1024 * 1024
CANDIDATE_ASSETS = {
    "latchway-contract.tar.gz",
    "latchway-linux-amd64.spdx.json",
    "latchway-linux-arm64.spdx.json",
    "latchway-linux-amd64-vulnerability.json",
    "latchway-linux-arm64-vulnerability.json",
    "latchway-linux-amd64-license.json",
    "latchway-linux-arm64-license.json",
}
EVIDENCE_ASSETS = {
    "latchway-candidate.json",
    "latchway-candidate.attestation.sigstore.json",
    *CANDIDATE_ASSETS,
    "compose.tar.gz",
    "compose.attestation.json",
    "cloud_run.tar.gz",
    "cloud_run.attestation.json",
}
EXPECTED_FILES = {"SHA256SUMS", "latchway-single-maintainer-v1.json", *EVIDENCE_ASSETS}
CAPTURE_FILES = {
    "control_plane.json",
    "health.json",
    "identity.json",
    "manifest.json",
    "migration.json",
    "readiness.json",
    "secrets.json",
    "shutdown.json",
    "latchway-deployment-binding.json",
}
DEFERRED_EVIDENCE = (
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
)
RELEASE_POLICY = {
    "mode": "single_maintainer_v1",
    "independent_reviewer_required": False,
    "strict_full_controls_satisfied": False,
    "environment_policy_ids": {
        "release_evidence_signing": "latchway-release-profile-v1:latchway:single_maintainer_v1:release-evidence-signing",
        "release_image_publishing": "latchway-release-profile-v1:latchway:single_maintainer_v1:release-image-publishing",
    },
}


class Rejected(Exception):
    pass


def strict_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise Rejected("core_release_json_duplicate_member")
        result[key] = value
    return result


def regular(path: Path) -> None:
    try:
        metadata = path.lstat()
    except OSError:
        raise Rejected("core_release_file_missing") from None
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode) or not 0 < metadata.st_size <= MAX_FILE:
        raise Rejected("core_release_file_unsafe")


def read_json(path: Path) -> dict[str, Any]:
    regular(path)
    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=strict_pairs)
    except Rejected:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        raise Rejected("core_release_json_invalid") from None
    if not isinstance(value, dict):
        raise Rejected("core_release_json_invalid")
    return value


def sha256(path: Path) -> str:
    regular(path)
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def exact_fields(value: Any, names: Iterable[str], code: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != set(names):
        raise Rejected(code)
    return value


def json_integer(value: Any, *, expected: int | None = None, minimum: int | None = None) -> bool:
    if isinstance(value, bool) or not isinstance(value, int):
        return False
    if expected is not None and value != expected:
        return False
    return minimum is None or value >= minimum


def verify_checksums(root: Path) -> None:
    try:
        entries = list(root.iterdir())
    except OSError:
        raise Rejected("core_release_directory_invalid") from None
    if {item.name for item in entries} != EXPECTED_FILES or any(item.is_symlink() or not item.is_file() for item in entries):
        raise Rejected("core_release_asset_closure_invalid")
    regular(root / "SHA256SUMS")
    observed: dict[str, str] = {}
    try:
        lines = (root / "SHA256SUMS").read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError):
        raise Rejected("core_release_checksums_invalid") from None
    for line in lines:
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._-]{0,255})", line)
        if match is None or match.group(2) in observed:
            raise Rejected("core_release_checksums_invalid")
        observed[match.group(2)] = match.group(1)
    expected = EXPECTED_FILES - {"SHA256SUMS"}
    if set(observed) != expected or list(observed) != sorted(observed):
        raise Rejected("core_release_checksums_invalid")
    if any(sha256(root / name) != digest for name, digest in observed.items()):
        raise Rejected("core_release_checksum_mismatch")


def verify_scan(path: Path, field: str) -> None:
    value = read_json(path)
    if not json_integer(value.get("SchemaVersion"), minimum=1) or not isinstance(value.get("Results"), list):
        raise Rejected("core_release_scan_invalid")
    for result in value["Results"]:
        if not isinstance(result, dict) or not isinstance(result.get(field, []), list):
            raise Rejected("core_release_scan_invalid")
        for finding in result.get(field, []):
            if not isinstance(finding, dict) or finding.get("Severity") in {"HIGH", "CRITICAL"}:
                raise Rejected("core_release_scan_failed")


def verify_sbom(path: Path) -> None:
    value = read_json(path)
    packages = value.get("packages")
    if value.get("spdxVersion") != "SPDX-2.3" or not isinstance(packages, list) or not packages:
        raise Rejected("core_release_sbom_invalid")
    if any(not isinstance(item, dict) or not str(item.get("SPDXID", "")).startswith("SPDXRef-") or not item.get("name") for item in packages):
        raise Rejected("core_release_sbom_invalid")


def verify_candidate(root: Path) -> dict[str, Any]:
    candidate = read_json(root / "latchway-candidate.json")
    exact_fields(candidate, {"schema_version", "kind", "status", "created_at", "candidate_commit", "intended_tag", "version", "contract", "image", "artifacts"}, "core_candidate_fields_invalid")
    commit = candidate.get("candidate_commit")
    if not json_integer(candidate.get("schema_version"), expected=1) or candidate.get("kind") != "latchway_release_candidate" or candidate.get("status") != "passed" or not isinstance(commit, str) or COMMIT.fullmatch(commit) is None or candidate.get("intended_tag") != TAG or candidate.get("version") != VERSION:
        raise Rejected("core_candidate_identity_invalid")
    contract = exact_fields(candidate.get("contract"), {"version", "status", "released_at", "bundle_file_name", "bundle_sha256"}, "core_candidate_contract_invalid")
    if contract.get("status") != "released" or contract.get("bundle_file_name") != f"latchway-contract-{contract.get('version')}.tar.gz" or not isinstance(contract.get("bundle_sha256"), str) or SHA256.fullmatch(contract["bundle_sha256"]) is None:
        raise Rejected("core_candidate_contract_invalid")
    image = exact_fields(candidate.get("image"), {"repository", "index_digest", "platforms"}, "core_candidate_image_invalid")
    platforms = image.get("platforms")
    if image.get("repository") != CORE_REPOSITORY or not isinstance(image.get("index_digest"), str) or DIGEST.fullmatch(image["index_digest"]) is None or not isinstance(platforms, dict) or set(platforms) != {"linux/amd64", "linux/arm64"} or any(not isinstance(value, str) or DIGEST.fullmatch(value) is None for value in platforms.values()) or len(set(platforms.values())) != 2:
        raise Rejected("core_candidate_image_invalid")
    artifacts = candidate.get("artifacts")
    if not isinstance(artifacts, list) or len(artifacts) != len(CANDIDATE_ASSETS):
        raise Rejected("core_candidate_artifacts_invalid")
    observed: dict[str, str] = {}
    for item in artifacts:
        exact_fields(item, {"path", "sha256"}, "core_candidate_artifacts_invalid")
        name, digest = item.get("path"), item.get("sha256")
        if name not in CANDIDATE_ASSETS or name in observed or not isinstance(digest, str) or SHA256.fullmatch(digest) is None or sha256(root / name) != digest:
            raise Rejected("core_candidate_artifacts_invalid")
        observed[name] = digest
    if set(observed) != CANDIDATE_ASSETS or observed["latchway-contract.tar.gz"] != contract["bundle_sha256"]:
        raise Rejected("core_candidate_artifacts_invalid")
    read_json(root / "latchway-candidate.attestation.sigstore.json")
    for architecture in ("amd64", "arm64"):
        verify_scan(root / f"latchway-linux-{architecture}-vulnerability.json", "Vulnerabilities")
        verify_scan(root / f"latchway-linux-{architecture}-license.json", "Licenses")
        verify_sbom(root / f"latchway-linux-{architecture}.spdx.json")
    return candidate


def archive_json(path: Path) -> dict[str, dict[str, Any]]:
    regular(path)
    values: dict[str, dict[str, Any]] = {}
    try:
        with tarfile.open(fileobj=io.BytesIO(path.read_bytes()), mode="r:gz") as archive:
            members = archive.getmembers()
            if {member.name for member in members} != CAPTURE_FILES or len(members) != len(CAPTURE_FILES):
                raise Rejected("core_deployment_archive_closure_invalid")
            for member in members:
                relative = PurePosixPath(member.name)
                if not member.isfile() or relative.as_posix() != member.name or len(relative.parts) != 1 or member.uid != 0 or member.gid != 0 or member.uname != "" or member.gname != "" or member.mode != 0o644 or member.mtime != 0 or not 0 < member.size <= 8 * 1024 * 1024:
                    raise Rejected("core_deployment_archive_entry_unsafe")
                source = archive.extractfile(member)
                if source is None:
                    raise Rejected("core_deployment_archive_invalid")
                try:
                    value = json.loads(source.read().decode("utf-8"), object_pairs_hook=strict_pairs)
                except (UnicodeDecodeError, json.JSONDecodeError):
                    raise Rejected("core_deployment_archive_json_invalid") from None
                if not isinstance(value, dict):
                    raise Rejected("core_deployment_archive_json_invalid")
                values[member.name] = value
    except Rejected:
        raise
    except (OSError, tarfile.TarError):
        raise Rejected("core_deployment_archive_invalid") from None
    return values


def verify_deployment(root: Path, record: dict[str, Any], platform: str, commit: str, coordinate: str, bundle_sha256: str) -> None:
    evidence = exact_fields(record["deployment_evidence"].get(platform), {"platform", "run_id", "run_attempt", "endpoint", "provider_resource_id", "archive_sha256", "attestation_sha256"}, "core_deployment_record_invalid")
    run_id, run_attempt = evidence.get("run_id"), evidence.get("run_attempt")
    if evidence.get("platform") != platform or not isinstance(run_id, str) or RUN.fullmatch(run_id) is None or not json_integer(run_attempt, minimum=1) or evidence.get("archive_sha256") != sha256(root / f"{platform}.tar.gz") or evidence.get("attestation_sha256") != sha256(root / f"{platform}.attestation.json"):
        raise Rejected("core_deployment_record_invalid")
    read_json(root / f"{platform}.attestation.json")
    values = archive_json(root / f"{platform}.tar.gz")
    manifest = values["manifest.json"]
    binding = values["latchway-deployment-binding.json"]
    exact_fields(manifest, {"schema_version", "kind", "platform", "started_at", "finished_at", "core_commit", "core_release", "contract_version", "bundle_sha256", "oci_image_digest", "endpoint", "provider_resource_id", "collector", "observations"}, "core_deployment_manifest_fields_invalid")
    exact_fields(binding, {"schema_version", "kind", "platform", "candidate_commit", "core_release", "contract_version", "bundle_sha256", "oci_image_digest", "endpoint", "provider_resource_id", "collector", "candidate_archive", "raw_capture"}, "core_deployment_binding_fields_invalid")
    collector = {"repository": "Latchway/latchway", "workflow_ref": "Latchway/latchway/.github/workflows/deployment-evidence.yml@refs/heads/main", "ref": "refs/heads/main", "sha": commit, "run_id": run_id, "run_attempt": run_attempt, "runner_environment": "github-hosted", "environment": f"deployment-evidence-{platform}"}
    for document, kind, commit_field in ((manifest, "latchway_cloud_deployment_capture", "core_commit"), (binding, "latchway_authenticated_deployment_capture", "candidate_commit")):
        if not json_integer(document.get("schema_version"), expected=1) or document.get("kind") != kind or document.get("platform") != platform or document.get(commit_field) != commit or document.get("core_release") != TAG or document.get("contract_version") != VERSION or document.get("bundle_sha256") != bundle_sha256 or document.get("oci_image_digest") != coordinate or document.get("collector") != collector or document.get("endpoint") != evidence.get("endpoint") or document.get("provider_resource_id") != evidence.get("provider_resource_id"):
            raise Rejected("core_deployment_identity_invalid")
    if not isinstance(manifest.get("started_at"), str) or not manifest["started_at"] or not isinstance(manifest.get("finished_at"), str) or not manifest["finished_at"] or not isinstance(manifest.get("observations"), dict) or not isinstance(binding.get("candidate_archive"), dict) or not isinstance(binding.get("raw_capture"), dict):
        raise Rejected("core_deployment_identity_invalid")


def release_body(commit: str, image: str) -> str:
    return "\n".join((f"Latchway {TAG} core release.", "", "Release profile: single_maintainer_v1", "Profile status: incomplete until every required public package and registry check passes.", "Authenticated profile-wide publication readiness is not claimed by this core-only record.", f"Candidate commit: {commit}", f"Image: {image}", "Required deployment evidence: Docker Compose and Google Cloud Run passed for this exact image.", "", "Deferred evidence remains unverified. This release is not release-qualified, fully evidence-gated, or independently reviewed."))


def verify(root: Path, locked_commit: str) -> dict[str, Any]:
    if COMMIT.fullmatch(locked_commit) is None:
        raise Rejected("core_locked_commit_invalid")
    verify_checksums(root)
    candidate = verify_candidate(root)
    commit = candidate["candidate_commit"]
    coordinate = f"{CORE_REPOSITORY}@{candidate['image']['index_digest']}"
    record = read_json(root / "latchway-single-maintainer-v1.json")
    exact_fields(record, {"schema_version", "kind", "profile", "profile_status", "release_policy", "core_publication_gate", "candidate_commit", "tag", "version", "image", "candidate_run", "deployment_evidence", "supply_chain", "github_release", "claims", "deferred_evidence", "assets"}, "core_release_record_fields_invalid")
    expected_supply = {"multi_arch_image_verified": True, "vulnerability_scan_verified": True, "license_scan_verified": True, "sbom_verified": True, "signature_verified": True, "provenance_verified": True}
    expected_claims = {"release_qualified": False, "fully_evidence_gated": False, "independently_reviewed": False}
    image = record.get("image")
    expected_message = "\n".join((f"Latchway {TAG}", "", "Release profile: single_maintainer_v1", f"Candidate commit: {commit}", f"Image: {coordinate}"))
    release = record.get("github_release")
    if not json_integer(record.get("schema_version"), expected=1) or record.get("kind") != "latchway_single_maintainer_v1_core_release" or record.get("profile") != "single_maintainer_v1" or record.get("profile_status") != "incomplete" or record.get("release_policy") != RELEASE_POLICY or record.get("core_publication_gate") != "passed" or record.get("candidate_commit") != commit or record.get("tag") != TAG or record.get("version") != VERSION or image != {"repository": CORE_REPOSITORY, "index_digest": candidate["image"]["index_digest"], "coordinate": coordinate, "platforms": candidate["image"]["platforms"]} or record.get("supply_chain") != expected_supply or record.get("claims") != expected_claims or record.get("deferred_evidence") != list(DEFERRED_EVIDENCE) or release != {"title": "Latchway v1.0.0 — single_maintainer_v1", "body": release_body(commit, coordinate), "tag_message": expected_message}:
        raise Rejected("core_release_record_identity_invalid")
    candidate_run = exact_fields(record.get("candidate_run"), {"run_id", "run_attempt"}, "core_candidate_run_invalid")
    if not isinstance(candidate_run.get("run_id"), str) or RUN.fullmatch(candidate_run["run_id"]) is None or not json_integer(candidate_run.get("run_attempt"), minimum=1):
        raise Rejected("core_candidate_run_invalid")
    deployments = exact_fields(record.get("deployment_evidence"), {"compose", "cloud_run"}, "core_deployment_record_invalid")
    del deployments
    assets = record.get("assets")
    if not isinstance(assets, list) or len(assets) != len(EVIDENCE_ASSETS):
        raise Rejected("core_release_record_assets_invalid")
    observed: dict[str, str] = {}
    for item in assets:
        exact_fields(item, {"path", "sha256"}, "core_release_record_assets_invalid")
        name, digest = item.get("path"), item.get("sha256")
        if name not in EVIDENCE_ASSETS or name in observed or not isinstance(digest, str) or SHA256.fullmatch(digest) is None or sha256(root / name) != digest:
            raise Rejected("core_release_record_assets_invalid")
        observed[name] = digest
    if set(observed) != EVIDENCE_ASSETS or list(observed) != sorted(observed):
        raise Rejected("core_release_record_assets_invalid")
    for platform in ("compose", "cloud_run"):
        verify_deployment(root, record, platform, commit, coordinate, candidate["contract"]["bundle_sha256"])
    return {"candidate_commit": commit, "locked_commit": locked_commit, "image": coordinate, "title": release["title"], "body": release["body"], "tag_message": release["tag_message"]}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release-directory", type=Path, required=True)
    parser.add_argument("--locked-core-commit", required=True)
    arguments = parser.parse_args()
    try:
        result = verify(arguments.release_directory, arguments.locked_core_commit)
    except Rejected as error:
        print(f"public core release rejected: {error}", file=__import__("sys").stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
