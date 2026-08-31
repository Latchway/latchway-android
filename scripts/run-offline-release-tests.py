#!/usr/bin/env python3
"""Run every repository Python release regression through one inventory."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
TEST_PATHS = (
    "scripts/test_build_docs_bundle.py",
    "scripts/test_central_deployment_record.py",
    "scripts/test_central_fixture.py",
    "scripts/test_offline_release_inventory.py",
    "scripts/test_publish_central_policy.py",
    "scripts/test_reconcile_github_release.py",
    "scripts/test_release_promotion.py",
    "scripts/test_require_gh_version.py",
    "scripts/test_verify_central_release.py",
    "scripts/test_verify_github_release_attestation.py",
    "scripts/test_verify_gpg_status.py",
)


def repository_test_paths() -> tuple[str, ...]:
    result = subprocess.run(
        [
            "git",
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
            "--",
            "scripts/test_*.py",
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
    )
    return tuple(sorted(path for path in result.stdout.decode().split("\0") if path))


def validate_inventory() -> None:
    repository_tests = repository_test_paths()
    expected = tuple(sorted(TEST_PATHS))
    if repository_tests != expected:
        missing = sorted(set(repository_tests) - set(expected))
        stale = sorted(set(expected) - set(repository_tests))
        raise SystemExit(
            "offline release test inventory mismatch; "
            f"uncovered repository tests={missing!r}; stale entries={stale!r}"
        )
    for relative in expected:
        path = ROOT / relative
        if not path.is_file() or path.is_symlink():
            raise SystemExit(f"offline release test must be a regular file: {relative}")


def main() -> None:
    validate_inventory()
    environment = os.environ.copy()
    python_path = environment.get("PYTHONPATH")
    environment["PYTHONPATH"] = str(ROOT / "scripts")
    if python_path:
        environment["PYTHONPATH"] += os.pathsep + python_path
    subprocess.run(
        [sys.executable, "-m", "unittest", *TEST_PATHS],
        cwd=ROOT,
        env=environment,
        check=True,
    )
    print(f"offline release test inventory passed: {len(TEST_PATHS)} repository modules")


if __name__ == "__main__":
    main()
