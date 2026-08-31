#!/usr/bin/env python3
"""Validate bounded OSV JSON and enforce Latchway's release severity policy."""

from __future__ import annotations

import argparse
import json
import os
import re
import tempfile
from pathlib import Path

MAX_REPORT_BYTES = 32 * 1024 * 1024
COMMIT = re.compile(r"^[0-9a-f]{40}$")
DIGEST = re.compile(r"^[0-9a-f]{64}$")
SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
SAFE_PACKAGE = re.compile(r"^[A-Za-z0-9@][A-Za-z0-9@._/+:-]{0,199}$")
SAFE_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+:-]{0,127}$")
NON_BLOCKING = {"LOW", "MEDIUM", "MODERATE", "NONE"}
BLOCKING = {"HIGH", "CRITICAL"}


def fail(message: str) -> "NoReturn":
    raise SystemExit(message)


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--inventory-sha256", required=True)
    parser.add_argument("--database-sha256", required=True)
    parser.add_argument("--evidence", type=Path)
    return parser.parse_args()


def require_safe(value: object, pattern: re.Pattern[str], label: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        fail(f"OSV report contains an invalid {label}")
    return value


def main() -> None:
    arguments = parse_arguments()
    if COMMIT.fullmatch(arguments.source_commit) is None:
        fail("source commit must be a lowercase 40-character Git commit")
    for value, label in (
        (arguments.inventory_sha256, "inventory SHA-256"),
        (arguments.database_sha256, "database SHA-256"),
    ):
        if DIGEST.fullmatch(value) is None:
            fail(f"{label} must be lowercase hexadecimal")

    try:
        size = arguments.report.stat().st_size
    except OSError:
        fail("OSV report is unavailable")
    if size <= 0 or size > MAX_REPORT_BYTES:
        fail("OSV report is empty or exceeds the 32 MiB policy limit")
    try:
        document = json.loads(arguments.report.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        fail("OSV report is not valid bounded UTF-8 JSON")
    if not isinstance(document, dict) or not isinstance(document.get("results"), list):
        fail("OSV report does not contain a results array")

    packages: set[tuple[str, str, str]] = set()
    blocking: set[tuple[str, str, str, str]] = set()
    vulnerabilities: set[tuple[str, str, str]] = set()
    for result in document["results"]:
        if not isinstance(result, dict) or not isinstance(result.get("packages"), list):
            fail("OSV result does not contain a packages array")
        for entry in result["packages"]:
            if not isinstance(entry, dict) or not isinstance(entry.get("package"), dict):
                fail("OSV package entry is malformed")
            package = entry["package"]
            name = require_safe(package.get("name"), SAFE_PACKAGE, "package name")
            version = require_safe(package.get("version"), SAFE_VERSION, "package version")
            ecosystem = require_safe(package.get("ecosystem"), SAFE_PACKAGE, "ecosystem")
            packages.add((ecosystem, name, version))
            findings = entry.get("vulnerabilities", [])
            if not isinstance(findings, list):
                fail("OSV vulnerability collection is malformed")
            for finding in findings:
                if not isinstance(finding, dict):
                    fail("OSV vulnerability entry is malformed")
                identifier = require_safe(finding.get("id"), SAFE_ID, "vulnerability ID")
                vulnerabilities.add((identifier, name, version))
                database_specific = finding.get("database_specific", {})
                if not isinstance(database_specific, dict):
                    fail("OSV database-specific metadata is malformed")
                raw_severity = database_specific.get("severity")
                severity = raw_severity.upper() if isinstance(raw_severity, str) else "UNKNOWN"
                if severity in NON_BLOCKING:
                    continue
                if severity not in BLOCKING:
                    severity = "UNKNOWN"
                blocking.add((identifier, name, version, severity))

    if not packages:
        fail("OSV scan inventoried zero packages")

    evidence = {
        "schema_version": "latchway.dependency-vulnerability-scan.v1",
        "scanner": {
            "name": "OSV-Scanner",
            "version": "2.4.0",
            "commit": "b56b5191101d5f27d4787d5583d8d01e9518a7af",
            "mode": "offline",
        },
        "source_commit": arguments.source_commit,
        "inventory_sha256": arguments.inventory_sha256,
        "database_sha256": arguments.database_sha256,
        "package_count": len(packages),
        "vulnerability_count": len(vulnerabilities),
        "blocking_vulnerability_count": len(blocking),
        "policy": "block-critical-high-and-unknown-severity",
        "status": "passed" if not blocking else "failed",
    }
    if arguments.evidence is not None:
        arguments.evidence.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=".dependency-vulnerability-scan.",
            dir=arguments.evidence.parent,
        )
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as output:
                json.dump(evidence, output, sort_keys=True, separators=(",", ":"))
                output.write("\n")
            os.chmod(temporary_name, 0o600)
            os.replace(temporary_name, arguments.evidence)
        except BaseException:
            Path(temporary_name).unlink(missing_ok=True)
            raise

    print(
        "OSV dependency scan inventoried "
        f"{len(packages)} packages and found {len(blocking)} blocking findings."
    )
    if blocking:
        for identifier, name, version, severity in sorted(blocking):
            print(f"{severity}: {identifier} affects {name}@{version}")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
