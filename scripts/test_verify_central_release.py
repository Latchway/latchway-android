#!/usr/bin/env python3
"""Offline tests for exact Maven Central release verification."""

from __future__ import annotations

import hashlib
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/verify-central-release.sh"
MODULES = (
    "latchway-core",
    "latchway-okhttp",
    "latchway-play-integrity",
    "latchway-firebase-auth",
    "latchway-bom",
)


class CentralVerificationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.remote = self.root / "remote"
        self.expected = self.root / "expected"
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.fingerprint = "A" * 40
        self.write_executable("curl", """#!/bin/bash
set -euo pipefail
output=
head_only=false
url=${!#}
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output) output=$2; shift 2 ;;
    --head) head_only=true; shift ;;
    *) shift ;;
  esac
done
relative=${url#https://central.test/}
source="$FAKE_CENTRAL_ROOT/$relative"
[[ -f "$source" ]] || exit 22
if [[ "$head_only" == true ]]; then
  exit 0
fi
cp "$source" "$output"
""")
        self.write_executable("gpg", """#!/bin/bash
set -euo pipefail
if [[ " $* " == *" --with-colons "* ]]; then
  printf 'fpr:::::::::AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:\n'
elif [[ " $* " == *" --status-fd "* ]]; then
  printf '[GNUPG:] VALIDSIG AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA 2026-01-01 0 4 0 1 10 00 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n'
fi
""")
        self.public_key = self.root / "public-key.asc"
        self.public_key.write_text("reviewed public key\n", encoding="utf-8")
        for module in MODULES:
            extensions = ["pom", "module", "sources.jar", "javadoc.jar"]
            if module != "latchway-bom":
                extensions.append("aar")
            for extension in extensions:
                name = f"{module}-1.0.0-{extension}"
                if extension in {"pom", "module", "aar"}:
                    name = f"{module}-1.0.0.{extension}"
                payload = (
                    f"<project><tag>v1.0.0</tag><artifact>{module}</artifact></project>\n".encode()
                    if extension == "pom"
                    else f"immutable {module} {extension}\n".encode()
                )
                relative = Path("dev/latchway", module, "1.0.0", name)
                self.write_artifact(self.remote / relative, payload)
                expected = self.expected / relative
                expected.parent.mkdir(parents=True, exist_ok=True)
                expected.write_bytes(payload)
                for algorithm in ("md5", "sha1", "sha256", "sha512"):
                    expected.with_name(f"{expected.name}.{algorithm}").write_bytes(
                        (self.remote / relative).with_name(f"{name}.{algorithm}").read_bytes()
                    )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_executable(self, name: str, source: str) -> None:
        path = self.bin / name
        path.write_text(source, encoding="utf-8")
        path.chmod(0o755)

    @staticmethod
    def write_artifact(path: Path, payload: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        for algorithm in ("md5", "sha1", "sha256", "sha512"):
            path.with_name(f"{path.name}.{algorithm}").write_text(
                hashlib.new(algorithm, payload).hexdigest(), encoding="utf-8"
            )
        path.with_name(f"{path.name}.asc").write_text("-----BEGIN PGP SIGNATURE-----\ntest\n", encoding="utf-8")

    def invoke(self, *, expected: bool = True) -> subprocess.CompletedProcess[str]:
        environment = {
            **os.environ,
            "PATH": f"{self.bin}:/usr/bin:/bin",
            "FAKE_CENTRAL_ROOT": str(self.remote),
            "LATCHWAY_MAVEN_CENTRAL_BASE_URL": "https://central.test/dev/latchway",
            "LATCHWAY_CENTRAL_VERIFY_ATTEMPTS": "1",
            "LATCHWAY_CENTRAL_VERIFY_DELAY_SECONDS": "1",
        }
        environment.pop("LATCHWAY_CENTRAL_EXPECTED_REPOSITORY", None)
        if expected:
            environment["LATCHWAY_CENTRAL_EXPECTED_REPOSITORY"] = str(self.expected)
            environment["LATCHWAY_CENTRAL_SIGNING_FINGERPRINT"] = self.fingerprint
            environment["LATCHWAY_CENTRAL_SIGNING_PUBLIC_KEY"] = str(self.public_key)
        return subprocess.run(
            ["/bin/bash", str(SCRIPT), "1.0.0"],
            cwd=ROOT,
            env=environment,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    def test_exact_public_repository_matches_reviewed_bytes(self) -> None:
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('"primary_artifacts_byte_identical": true', result.stdout)

    def test_self_consistent_but_different_public_artifact_is_rejected(self) -> None:
        path = self.remote / "dev/latchway/latchway-core/1.0.0/latchway-core-1.0.0.aar"
        self.write_artifact(path, b"different but internally checksummed bytes\n")
        result = self.invoke()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("differs from the reviewed release byte-for-byte", result.stderr)

    def test_independent_consumer_mode_remains_available(self) -> None:
        path = self.remote / "dev/latchway/latchway-core/1.0.0/latchway-core-1.0.0.aar"
        self.write_artifact(path, b"different but internally checksummed bytes\n")
        result = self.invoke(expected=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('"signature_files_present": true', result.stdout)

    def test_invalid_public_checksum_is_rejected_before_byte_comparison(self) -> None:
        checksum = self.remote / "dev/latchway/latchway-core/1.0.0/latchway-core-1.0.0.aar.sha256"
        checksum.write_text("0" * 64, encoding="utf-8")
        result = self.invoke()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("checksum mismatch", result.stderr)


if __name__ == "__main__":
    unittest.main()
