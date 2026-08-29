#!/usr/bin/env python3
"""Offline tests for Maven Central verify-or-publish state selection."""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/publish-central.sh"


class CentralPublicationPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.scripts = self.root / "scripts"
        self.scripts.mkdir()
        shutil.copy2(SCRIPT, self.scripts / SCRIPT.name)
        (self.root / "build/release/repository/dev/latchway").mkdir(parents=True)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.log = self.root / "verify.log"
        self.write_executable("git", """#!/bin/bash
set -euo pipefail
case "$*" in
  *"status --porcelain") exit 0 ;;
  *"rev-parse HEAD") printf '%040d\n' 0 ;;
  *"rev-list -n 1 v1.0.0") printf '%040d\n' 0 ;;
  *) echo "unexpected git command: $*" >&2; exit 2 ;;
esac
""")
        self.write_executable("curl", """#!/bin/bash
set -euo pipefail
printf '%s' "$FAKE_CENTRAL_STATUS"
""")
        self.write_executable_at(self.scripts / "verify-central-release.sh", """#!/bin/bash
set -euo pipefail
test "$1" = 1.0.0
test "$LATCHWAY_CENTRAL_EXPECTED_REPOSITORY" = "$FAKE_EXPECTED_REPOSITORY"
printf 'verified\n' >>"$FAKE_VERIFY_LOG"
""")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_executable(self, name: str, source: str) -> None:
        self.write_executable_at(self.bin / name, source)

    @staticmethod
    def write_executable_at(path: Path, source: str) -> None:
        path.write_text(source, encoding="utf-8")
        path.chmod(0o755)

    def invoke(self, status: str) -> subprocess.CompletedProcess[str]:
        environment = {
            **os.environ,
            "PATH": f"{self.bin}:/usr/bin:/bin",
            "LATCHWAY_RELEASE_VERSION": "1.0.0",
            "FAKE_CENTRAL_STATUS": status,
            "FAKE_EXPECTED_REPOSITORY": str(self.root / "build/release/repository"),
            "FAKE_VERIFY_LOG": str(self.log),
        }
        for name in (
            "LATCHWAY_MAVEN_CENTRAL_USERNAME",
            "LATCHWAY_MAVEN_CENTRAL_PASSWORD",
            "LATCHWAY_SIGNING_KEY",
            "LATCHWAY_SIGNING_PASSWORD",
        ):
            environment.pop(name, None)
        return subprocess.run(
            ["/bin/bash", str(self.scripts / SCRIPT.name)],
            cwd=self.root,
            env=environment,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    def test_existing_coordinates_are_verified_without_credentials_or_upload(self) -> None:
        result = self.invoke("200")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.log.read_text(encoding="utf-8"), "verified\n")

    def test_absent_coordinates_require_all_publication_secrets(self) -> None:
        result = self.invoke("404")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("credentials and in-memory OpenPGP", result.stderr)
        self.assertFalse(self.log.exists())

    def test_unknown_registry_state_never_uploads(self) -> None:
        result = self.invoke("503")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("HTTP 503", result.stderr)
        self.assertFalse(self.log.exists())


if __name__ == "__main__":
    unittest.main()
