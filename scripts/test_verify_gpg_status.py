#!/usr/bin/env python3
"""Adversarial tests for the fail-closed GnuPG status parser."""

from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/verify-gpg-status.py"
PRIMARY = "A" * 40
SUBKEY = "B" * 40


def valid_status(signing: str = PRIMARY, primary: str | None = None) -> str:
    primary_field = f" {primary}" if primary is not None else ""
    return "\n".join((
        "[GNUPG:] NEWSIG",
        f"[GNUPG:] KEY_CONSIDERED {PRIMARY} 0",
        "[GNUPG:] SIG_ID abcdefghijklmnopqrstuvwx 1787961600 2026-08-29",
        f"[GNUPG:] GOODSIG {signing[-16:]} Latchway Release <release@example.invalid>",
        (
            f"[GNUPG:] VALIDSIG {signing} 2026-08-29 1787961600 0 4 0 1 10 00"
            f"{primary_field}"
        ),
        f"[GNUPG:] KEY_CONSIDERED {PRIMARY} 0",
        "[GNUPG:] TRUST_UNDEFINED 0 pgp",
        "",
    ))


class GnuPGStatusTests(unittest.TestCase):
    def invoke(self, status: str) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "status")
            path.write_text(status, encoding="utf-8")
            return subprocess.run(
                [
                    "python3", str(SCRIPT),
                    "--status", str(path),
                    "--expected-primary-fingerprint", PRIMARY,
                ],
                cwd=ROOT,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

    def test_accepts_primary_key_signature(self) -> None:
        result = self.invoke(valid_status() + "[GNUPG:] VERIFICATION_COMPLIANCE_MODE 23\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["primary_fingerprint"], PRIMARY)

    def test_accepts_signing_subkey_with_documented_primary_fingerprint(self) -> None:
        result = self.invoke(valid_status(SUBKEY, PRIMARY))
        self.assertEqual(result.returncode, 0, result.stderr)
        evidence = json.loads(result.stdout)
        self.assertEqual(evidence["signing_fingerprint"], SUBKEY)
        self.assertEqual(evidence["primary_fingerprint"], PRIMARY)

        full_fingerprint = self.invoke(
            valid_status(SUBKEY, PRIMARY).replace(
                f"GOODSIG {SUBKEY[-16:]}", f"GOODSIG {SUBKEY}",
            )
        )
        self.assertEqual(full_fingerprint.returncode, 0, full_fingerprint.stderr)

    def test_rejects_expired_revoked_bad_and_error_statuses(self) -> None:
        for tag in (
            "EXPSIG", "EXPKEYSIG", "REVKEYSIG", "BADSIG", "ERRSIG", "FAILURE",
            "KEYEXPIRED", "SIGEXPIRED", "KEYREVOKED",
        ):
            with self.subTest(tag=tag):
                result = self.invoke(valid_status() + f"[GNUPG:] {tag} rejected\n")
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(tag, result.stderr)

    def test_rejects_unknown_status_fail_closed(self) -> None:
        result = self.invoke(valid_status() + "[GNUPG:] FUTURE_SUCCESS maybe\n")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unreviewed status", result.stderr)

    def test_rejects_wrong_primary_fingerprint_and_ambiguous_validsig(self) -> None:
        wrong = self.invoke(valid_status(SUBKEY, "C" * 40))
        self.assertNotEqual(wrong.returncode, 0)
        self.assertIn("pinned primary key", wrong.stderr)

        ambiguous = self.invoke(valid_status() + (
            f"[GNUPG:] VALIDSIG {PRIMARY} 2026-08-29 1787961600 0 4 0 1 10 00\n"
        ))
        self.assertNotEqual(ambiguous.returncode, 0)
        self.assertIn("exactly one valid signature", ambiguous.stderr)

    def test_rejects_non_status_output_and_considered_key_mismatch(self) -> None:
        injected = self.invoke(valid_status() + "gpg: forged human-readable success\n")
        self.assertNotEqual(injected.returncode, 0)
        self.assertIn("non-status", injected.stderr)

        mismatch = self.invoke(valid_status().replace(
            f"KEY_CONSIDERED {PRIMARY}", f"KEY_CONSIDERED {'C' * 40}", 1,
        ))
        self.assertNotEqual(mismatch.returncode, 0)
        self.assertIn("other than the pinned", mismatch.stderr)


if __name__ == "__main__":
    unittest.main()
