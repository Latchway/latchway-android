#!/usr/bin/env python3
"""Verify one SDK publication against an attested core promotion report."""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import re
import stat
import subprocess
import sys
from typing import Any, Mapping


ROOT = Path(__file__).resolve().parents[1]
MAXIMUM_REPORT_BYTES = 2 * 1024 * 1024
MAXIMUM_LOCAL_METADATA_BYTES = 1024 * 1024
MAXIMUM_AGE = timedelta(days=7)
REPOSITORY_IDS = ("core", "javascript", "ios", "android", "react_native")
PROMOTION_DOMAINS = {
    "live_sdk_conformance",
    "physical_devices",
    "live_provider",
    "cloud_deployments",
    "operational_resilience",
    "supply_chain",
}
PUBLICATION_DOMAINS = {"public_tags", "public_registries"}
LOCAL_DOMAINS = {"local_source", "local_promotion", "local_release"}
REPORT_FIELDS = {
    "schema_version",
    "kind",
    "scope",
    "verdict",
    "source_conformance_passed",
    "promotion_ready",
    "release_ready",
    "contract",
    "repositories",
    "evidence_window",
    "evidence_domains",
    "checks",
}
CONTRACT_FIELDS = {
    "version",
    "status",
    "released_at",
    "wire_protocol",
    "bundle_file_name",
    "bundle_sha256",
    "core_release",
    "oci_image_digest",
}
DOMAIN_FIELDS = {
    "id",
    "required",
    "status",
    "started_at",
    "finished_at",
    "document_sha256",
    "oci_image_digest",
    "artifact_sha256",
}
CHECK_FIELDS = {"id", "domain", "required", "status", "summary", "reason", "details"}
REQUIRED_DOMAINS = {"local_source", "local_promotion"} | PROMOTION_DOMAINS
UNVERIFIED_DOMAINS = {"local_release"} | PUBLICATION_DOMAINS
SEMVER_PATTERN = (
    r"(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
)
SEMVER = re.compile(rf"^{SEMVER_PATTERN}$")
TAG = re.compile(rf"^v{SEMVER_PATTERN}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
OCI_DIGEST = re.compile(r"^ghcr\.io/latchway/latchway@sha256:[0-9a-f]{64}$")
CANONICAL_TIME = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
CHECK_IDENTIFIER = re.compile(r"^[a-z][a-z0-9_.]{0,127}$")
DOMAIN_IDENTIFIER = re.compile(r"^[a-z][a-z0-9_]{0,127}$")
DIAGNOSTIC_KEY = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")


class PromotionVerificationError(Exception):
    """Stable, redaction-safe SDK promotion failure."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def sha256_file(path: Path) -> str:
    try:
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or path.is_symlink() or metadata.st_size > MAXIMUM_REPORT_BYTES:
            raise PromotionVerificationError("promotion_report_file_invalid")
        digest = hashlib.sha256()
        with path.open("rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except PromotionVerificationError:
        raise
    except OSError:
        raise PromotionVerificationError("promotion_report_file_invalid") from None


def load_json(path: Path) -> dict[str, Any]:
    def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise PromotionVerificationError("promotion_report_duplicate_key")
            result[key] = value
        return result

    sha256_file(path)
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=strict_object
        )
    except PromotionVerificationError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        raise PromotionVerificationError("promotion_report_json_invalid") from None
    if not isinstance(value, dict):
        raise PromotionVerificationError("promotion_report_json_invalid")
    return value


def parse_time(value: Any, code: str) -> datetime:
    if not isinstance(value, str) or CANONICAL_TIME.fullmatch(value) is None:
        raise PromotionVerificationError(code)
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError:
        raise PromotionVerificationError(code) from None


def git(root: Path, *arguments: str) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", str(root), *arguments],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=20,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise PromotionVerificationError("promotion_local_git_invalid") from None
    if result.returncode != 0:
        raise PromotionVerificationError("promotion_local_git_invalid")
    return result.stdout.rstrip("\n")


def local_metadata(path: Path) -> str:
    try:
        metadata = path.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or path.is_symlink()
            or metadata.st_size > MAXIMUM_LOCAL_METADATA_BYTES
        ):
            raise PromotionVerificationError("promotion_local_version_invalid")
        return path.read_text(encoding="utf-8")
    except PromotionVerificationError:
        raise
    except (OSError, UnicodeDecodeError):
        raise PromotionVerificationError("promotion_local_version_invalid") from None


def local_version(root: Path, repository_id: str) -> str:
    try:
        if repository_id in ("javascript", "react_native"):
            value = json.loads(local_metadata(root / "package.json"))
            version = value.get("version") if isinstance(value, dict) else None
        elif repository_id == "ios":
            source = local_metadata(
                root / "Sources/Latchway/LatchwayVersion.swift"
            )
            match = re.search(r'\bsdk\s*=\s*"([^"]+)"', source)
            version = match.group(1) if match is not None else None
        elif repository_id == "android":
            source = local_metadata(
                root
                / "latchway-core/src/main/kotlin/dev/latchway/core/LatchwayApi.kt"
            )
            match = re.search(
                r'LATCHWAY_SDK_VERSION:\s*String\s*=\s*"([^"]+)"', source
            )
            version = match.group(1) if match is not None else None
        else:
            raise PromotionVerificationError("promotion_repository_id_invalid")
    except PromotionVerificationError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        raise PromotionVerificationError("promotion_local_version_invalid") from None
    if not isinstance(version, str) or SEMVER.fullmatch(version) is None:
        raise PromotionVerificationError("promotion_local_version_invalid")
    return version


def validate_coordinate(value: Any) -> dict[str, str]:
    if not isinstance(value, dict) or set(value) != {
        "id",
        "commit",
        "version",
        "intended_tag",
    }:
        raise PromotionVerificationError("promotion_repository_coordinate_invalid")
    repository_id = value.get("id")
    commit = value.get("commit")
    version = value.get("version")
    intended_tag = value.get("intended_tag")
    if (
        repository_id not in REPOSITORY_IDS
        or not isinstance(commit, str)
        or COMMIT.fullmatch(commit) is None
        or not isinstance(version, str)
        or SEMVER.fullmatch(version) is None
        or intended_tag != f"v{version}"
        or TAG.fullmatch(str(intended_tag)) is None
    ):
        raise PromotionVerificationError("promotion_repository_coordinate_invalid")
    return {
        "id": repository_id,
        "commit": commit,
        "version": version,
        "intended_tag": intended_tag,
    }


def validate_contract(
    value: Any,
    *,
    core_tag: str,
    oci_image_digest: str,
    now: datetime,
) -> tuple[datetime, Mapping[str, Any]]:
    if not isinstance(value, dict) or set(value) != CONTRACT_FIELDS:
        raise PromotionVerificationError("promotion_contract_invalid")
    version = value.get("version")
    released_at = parse_time(
        value.get("released_at"), "promotion_contract_time_invalid"
    )
    wire_protocol = value.get("wire_protocol")
    bundle_sha256 = value.get("bundle_sha256")
    if (
        not isinstance(version, str)
        or SEMVER.fullmatch(version) is None
        or value.get("status") != "released"
        or not isinstance(wire_protocol, int)
        or isinstance(wire_protocol, bool)
        or wire_protocol < 1
        or value.get("bundle_file_name") != f"latchway-contract-{version}.tar.gz"
        or not isinstance(bundle_sha256, str)
        or SHA256.fullmatch(bundle_sha256) is None
        or value.get("core_release") != core_tag
        or value.get("oci_image_digest") != oci_image_digest
        or released_at > now
        or now - released_at > MAXIMUM_AGE
    ):
        raise PromotionVerificationError("promotion_contract_invalid")
    return released_at, value


def validate_window(
    value: Any, *, released_at: datetime, now: datetime
) -> tuple[datetime, datetime]:
    if not isinstance(value, dict) or set(value) != {
        "started_at",
        "finished_at",
        "maximum_age_seconds",
    }:
        raise PromotionVerificationError("promotion_evidence_window_invalid")
    started = parse_time(
        value.get("started_at"), "promotion_evidence_window_invalid"
    )
    finished = parse_time(
        value.get("finished_at"), "promotion_evidence_window_invalid"
    )
    if (
        value.get("maximum_age_seconds") != int(MAXIMUM_AGE.total_seconds())
        or started < released_at
        or finished <= started
        or finished > now
        or now - finished > MAXIMUM_AGE
        or finished - started > MAXIMUM_AGE
    ):
        raise PromotionVerificationError("promotion_evidence_window_invalid")
    return started, finished


def validate_domains(
    value: Any,
    *,
    window_started: datetime,
    window_finished: datetime,
    oci_image_digest: str,
) -> None:
    if not isinstance(value, list) or len(value) != 11:
        raise PromotionVerificationError("promotion_evidence_domains_invalid")
    domains: dict[str, Mapping[str, Any]] = {}
    required_started: list[datetime] = []
    required_finished: list[datetime] = []
    for domain in value:
        if not isinstance(domain, dict) or set(domain) != DOMAIN_FIELDS:
            raise PromotionVerificationError("promotion_evidence_domains_invalid")
        identifier = domain.get("id")
        if (
            not isinstance(identifier, str)
            or identifier in domains
            or identifier
            not in LOCAL_DOMAINS | PROMOTION_DOMAINS | PUBLICATION_DOMAINS
        ):
            raise PromotionVerificationError("promotion_evidence_domains_invalid")
        domains[identifier] = domain

    if set(domains) != LOCAL_DOMAINS | PROMOTION_DOMAINS | PUBLICATION_DOMAINS:
        raise PromotionVerificationError("promotion_evidence_domains_invalid")
    expected_simple = {
        "local_source": (True, "passed"),
        "local_promotion": (True, "passed"),
        "local_release": (False, "unverified"),
        "public_tags": (False, "unverified"),
        "public_registries": (False, "unverified"),
    }
    for identifier, (required, status) in expected_simple.items():
        domain = domains[identifier]
        if (
            domain.get("required") is not required
            or domain.get("status") != status
            or domain.get("started_at") is not None
            or domain.get("finished_at") is not None
            or domain.get("document_sha256") is not None
            or domain.get("oci_image_digest") is not None
            or domain.get("artifact_sha256") != []
        ):
            raise PromotionVerificationError("promotion_evidence_domains_invalid")

    for identifier in PROMOTION_DOMAINS:
        domain = domains[identifier]
        document_sha256 = domain.get("document_sha256")
        artifacts = domain.get("artifact_sha256")
        started = parse_time(
            domain.get("started_at"), "promotion_evidence_domains_invalid"
        )
        finished = parse_time(
            domain.get("finished_at"), "promotion_evidence_domains_invalid"
        )
        if (
            domain.get("required") is not True
            or domain.get("status") != "passed"
            or not isinstance(document_sha256, str)
            or SHA256.fullmatch(document_sha256) is None
            or domain.get("oci_image_digest") != oci_image_digest
            or not isinstance(artifacts, list)
            or not 1 <= len(artifacts) <= 64
            or len(set(artifacts)) != len(artifacts)
            or any(
                not isinstance(item, str) or SHA256.fullmatch(item) is None
                for item in artifacts
            )
            or started < window_started
            or finished > window_finished
            or finished <= started
        ):
            raise PromotionVerificationError("promotion_evidence_domains_invalid")
        required_started.append(started)
        required_finished.append(finished)
    if min(required_started) != window_started or max(required_finished) != window_finished:
        raise PromotionVerificationError("promotion_evidence_window_invalid")


def diagnostic_scalar(value: Any) -> bool:
    return (
        value is None
        or isinstance(value, (str, bool))
        or (isinstance(value, int) and not isinstance(value, bool))
    )


def diagnostic_value(value: Any) -> bool:
    if diagnostic_scalar(value):
        return True
    if isinstance(value, list):
        return len(value) <= 128 and all(diagnostic_scalar(item) for item in value)
    if isinstance(value, dict):
        return (
            len(value) <= 128
            and all(
                isinstance(key, str) and DIAGNOSTIC_KEY.fullmatch(key) is not None
                for key in value
            )
            and all(diagnostic_scalar(item) for item in value.values())
        )
    return False


def validate_checks(value: Any) -> None:
    if not isinstance(value, list) or not 1 <= len(value) <= 64:
        raise PromotionVerificationError("promotion_checks_invalid")
    identifiers: set[str] = set()
    required_domains_seen: set[str] = set()
    for check in value:
        identifier = check.get("id") if isinstance(check, dict) else None
        domain = check.get("domain") if isinstance(check, dict) else None
        summary = check.get("summary") if isinstance(check, dict) else None
        reason = check.get("reason") if isinstance(check, dict) else None
        details = check.get("details") if isinstance(check, dict) else None
        if (
            not isinstance(check, dict)
            or not set(check).issubset(CHECK_FIELDS)
            or not {"id", "domain", "required", "status", "summary"}.issubset(check)
            or not isinstance(identifier, str)
            or CHECK_IDENTIFIER.fullmatch(identifier) is None
            or identifier in identifiers
            or not isinstance(domain, str)
            or DOMAIN_IDENTIFIER.fullmatch(domain) is None
            or domain not in LOCAL_DOMAINS | PROMOTION_DOMAINS | PUBLICATION_DOMAINS
            or not isinstance(check.get("required"), bool)
            or check.get("status") not in ("passed", "failed", "unverified")
            or not isinstance(summary, str)
            or not 1 <= len(summary) <= 500
            or (
                "reason" in check
                and (
                    not isinstance(reason, str)
                    or DOMAIN_IDENTIFIER.fullmatch(reason) is None
                )
            )
            or (
                "details" in check
                and (
                    not isinstance(details, dict)
                    or len(details) > 64
                    or any(
                        not isinstance(key, str)
                        or DOMAIN_IDENTIFIER.fullmatch(key) is None
                        for key in details
                    )
                    or any(not diagnostic_value(item) for item in details.values())
                )
            )
        ):
            raise PromotionVerificationError("promotion_checks_invalid")
        identifiers.add(identifier)
        if check["required"] is True and check["status"] != "passed":
            raise PromotionVerificationError("promotion_required_check_failed")
        if domain in REQUIRED_DOMAINS:
            if check["status"] != "passed":
                raise PromotionVerificationError("promotion_required_check_failed")
            if check["required"] is True:
                required_domains_seen.add(domain)
        elif (
            check["required"] is not False
            or check["status"] != "unverified"
        ):
            raise PromotionVerificationError("promotion_checks_invalid")
    if required_domains_seen != REQUIRED_DOMAINS:
        raise PromotionVerificationError("promotion_checks_invalid")


def verify(
    report_path: Path,
    repository_root: Path,
    *,
    report_url: str,
    report_sha256: str,
    repository_id: str,
    repository_commit: str,
    repository_version: str,
    repository_tag: str,
    workflow_commit: str,
    core_tag: str,
    oci_image_digest: str,
    now: datetime,
) -> dict[str, str]:
    if repository_id not in REPOSITORY_IDS[1:]:
        raise PromotionVerificationError("promotion_repository_id_invalid")
    if (
        not isinstance(report_sha256, str)
        or SHA256.fullmatch(report_sha256) is None
        or not isinstance(repository_commit, str)
        or COMMIT.fullmatch(repository_commit) is None
        or not isinstance(workflow_commit, str)
        or COMMIT.fullmatch(workflow_commit) is None
        or workflow_commit != repository_commit
        or not isinstance(repository_version, str)
        or SEMVER.fullmatch(repository_version) is None
        or repository_tag != f"v{repository_version}"
        or TAG.fullmatch(repository_tag) is None
        or TAG.fullmatch(core_tag) is None
        or OCI_DIGEST.fullmatch(oci_image_digest) is None
    ):
        raise PromotionVerificationError("promotion_dispatch_coordinate_invalid")
    expected_url = (
        "https://github.com/Latchway/latchway/releases/download/"
        f"{core_tag}/latchway-cross-repository-promotion.json"
    )
    if report_url != expected_url:
        raise PromotionVerificationError("promotion_report_url_invalid")
    actual_report_sha256 = sha256_file(report_path)
    if actual_report_sha256 != report_sha256:
        raise PromotionVerificationError("promotion_report_sha256_mismatch")

    repository_root = repository_root.resolve()
    if git(repository_root, "rev-parse", "--verify", "HEAD") != repository_commit:
        raise PromotionVerificationError("promotion_local_commit_mismatch")
    if git(repository_root, "status", "--porcelain=v1", "--untracked-files=all"):
        raise PromotionVerificationError("promotion_local_worktree_dirty")
    if local_version(repository_root, repository_id) != repository_version:
        raise PromotionVerificationError("promotion_local_version_mismatch")

    report = load_json(report_path)
    if set(report) != REPORT_FIELDS:
        raise PromotionVerificationError("promotion_report_fields_invalid")
    if (
        report.get("schema_version") != 1
        or report.get("kind")
        != "latchway_cross_repository_conformance_evidence"
        or report.get("scope") != "promotion"
        or report.get("verdict") != "passed"
        or report.get("source_conformance_passed") is not True
        or report.get("promotion_ready") is not True
        or report.get("release_ready") is not False
    ):
        raise PromotionVerificationError("promotion_report_not_ready")

    released_at, _ = validate_contract(
        report.get("contract"),
        core_tag=core_tag,
        oci_image_digest=oci_image_digest,
        now=now,
    )
    repositories = report.get("repositories")
    if not isinstance(repositories, list) or len(repositories) != len(REPOSITORY_IDS):
        raise PromotionVerificationError("promotion_repositories_invalid")
    by_id: dict[str, dict[str, str]] = {}
    for value in repositories:
        coordinate = validate_coordinate(value)
        if coordinate["id"] in by_id:
            raise PromotionVerificationError("promotion_repositories_invalid")
        by_id[coordinate["id"]] = coordinate
    if set(by_id) != set(REPOSITORY_IDS):
        raise PromotionVerificationError("promotion_repositories_invalid")
    expected_coordinate = {
        "id": repository_id,
        "commit": repository_commit,
        "version": repository_version,
        "intended_tag": repository_tag,
    }
    if by_id[repository_id] != expected_coordinate:
        raise PromotionVerificationError("promotion_repository_binding_mismatch")
    if by_id["core"]["intended_tag"] != core_tag:
        raise PromotionVerificationError("promotion_core_tag_mismatch")

    window_started, window_finished = validate_window(
        report.get("evidence_window"), released_at=released_at, now=now
    )
    validate_domains(
        report.get("evidence_domains"),
        window_started=window_started,
        window_finished=window_finished,
        oci_image_digest=oci_image_digest,
    )
    validate_checks(report.get("checks"))
    return {
        "release_commit": repository_commit,
        "release_tag": repository_tag,
        "release_version": repository_version,
        "core_tag": core_tag,
        "oci_image_digest": oci_image_digest,
        "report_sha256": actual_report_sha256,
    }


def append_github_output(path: Path, values: Mapping[str, str]) -> None:
    try:
        with path.open("a", encoding="utf-8") as output:
            for key in sorted(values):
                value = values[key]
                if "\n" in value or "\r" in value:
                    raise PromotionVerificationError("promotion_output_invalid")
                output.write(f"{key}={value}\n")
    except PromotionVerificationError:
        raise
    except OSError:
        raise PromotionVerificationError("promotion_output_invalid") from None


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--repository-root", type=Path, default=ROOT)
    parser.add_argument("--report-url", required=True)
    parser.add_argument("--report-sha256", required=True)
    parser.add_argument("--repository-id", required=True)
    parser.add_argument("--repository-commit", required=True)
    parser.add_argument("--repository-version", required=True)
    parser.add_argument("--repository-tag", required=True)
    parser.add_argument("--workflow-commit", required=True)
    parser.add_argument("--core-tag", required=True)
    parser.add_argument("--oci-image-digest", required=True)
    parser.add_argument("--github-output", type=Path)
    return parser


def main() -> int:
    arguments = build_parser().parse_args()
    try:
        result = verify(
            arguments.report,
            arguments.repository_root,
            report_url=arguments.report_url,
            report_sha256=arguments.report_sha256,
            repository_id=arguments.repository_id,
            repository_commit=arguments.repository_commit,
            repository_version=arguments.repository_version,
            repository_tag=arguments.repository_tag,
            workflow_commit=arguments.workflow_commit,
            core_tag=arguments.core_tag,
            oci_image_digest=arguments.oci_image_digest,
            now=datetime.now(timezone.utc).replace(microsecond=0),
        )
        if arguments.github_output is not None:
            append_github_output(arguments.github_output, result)
    except PromotionVerificationError as error:
        print(f"SDK promotion verification failed: {error.code}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
