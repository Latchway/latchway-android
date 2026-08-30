#!/usr/bin/env python3
"""Enforce fail-closed Play conformance candidate staging boundaries."""

from __future__ import annotations

import hashlib
import os
import pathlib
import re
import shutil
import stat
import struct
import subprocess
import tempfile
import unittest
import zipfile


ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = (ROOT / "scripts" / "stage-play-conformance-candidate.sh").read_text(encoding="utf-8")
BUILD = (ROOT / "sample-conformance" / "build.gradle.kts").read_text(encoding="utf-8")
VERIFIER_PATH = ROOT / "scripts" / "VerifyPlayAabSignature.java"
VERIFIER = VERIFIER_PATH.read_text(encoding="utf-8")
WORKFLOW = (ROOT / ".github" / "workflows" / "play-conformance-candidate.yml").read_text(
    encoding="utf-8"
)
MANIFEST = (ROOT / "sample-conformance" / "src" / "main" / "AndroidManifest.xml").read_text(
    encoding="utf-8"
)


class NonSeekableZipOutput:
    """Force zipfile to emit unambiguous signed data descriptors like Gradle."""

    def __init__(self, target: pathlib.Path) -> None:
        self.handle = target.open("wb")

    def write(self, value: bytes) -> int:
        return self.handle.write(value)

    def tell(self) -> int:
        return self.handle.tell()

    def seek(self, *_arguments: object) -> int:
        raise OSError("intentionally non-seekable")

    def flush(self) -> None:
        self.handle.flush()

    def close(self) -> None:
        self.handle.close()


class PlayConformanceCandidateTests(unittest.TestCase):
    def test_candidate_is_exact_source_and_contract_bound(self) -> None:
        for marker in (
            'git -C "$repository_root" rev-parse HEAD',
            "candidate production requires a clean source worktree",
            "source mutated during candidate build",
            "candidate output directory must be outside the source repository",
            "contract.lock",
            '"core_commit": os.environ["LATCHWAY_CORE_COMMIT"]',
            '"contract_version": os.environ["LATCHWAY_CONTRACT_VERSION"]',
            '"contract_bundle_sha256": os.environ["LATCHWAY_CONTRACT_BUNDLE_SHA256"]',
            "HEAD^{tree}",
            "SOURCE_DATE_EPOCH",
            "gradle-wrapper.jar",
        ):
            self.assertIn(marker, SCRIPT)

    def test_repository_producer_is_strictly_unsigned(self) -> None:
        for marker in (
            "repository candidate production supports unsigned mode only",
            "signing material is prohibited on the unsigned candidate producer",
            ":sample-conformance:bundleRelease",
            "--no-daemon",
            "--no-configuration-cache",
            '"signing_mode": "unsigned"',
            '"upload_certificate_sha256": None',
            "--emit-presign-manifest",
            "play-conformance-presign-payload.manifest",
            "latchway.android-aab-presign-payload.v1",
        ):
            self.assertIn(marker, SCRIPT)
        for prohibited_build_marker in (
            "signingConfigs",
            "storePassword",
            "keyPassword",
            "System.getenv",
        ):
            self.assertNotIn(prohibited_build_marker, BUILD)
        for prohibited_producer_command in ("jarsigner -verify", "keytool -exportcert"):
            self.assertNotIn(prohibited_producer_command, SCRIPT)
        self.assertIn("upload_certificate_sha256", SCRIPT)
        self.assertIn("expected_play_app_signing_certificate_sha256", SCRIPT)
        self.assertIn("repository candidate builds must be unsigned", BUILD)

    def test_unsigned_producer_rejects_canonical_signer_secrets_without_tracing_values(self) -> None:
        required = {
            "LATCHWAY_CANDIDATE_OUTPUT_DIR": "/tmp/latchway-candidate-test-output",
            "LATCHWAY_PACKAGE_NAME": "dev.latchway.test",
            "LATCHWAY_APP_VERSION": "1.0.0",
            "LATCHWAY_VERSION_CODE": "1",
            "LATCHWAY_SIGNING_CERTIFICATE_SHA256": "0" * 64,
            "LATCHWAY_PLAY_TRACK": "internal",
            "LATCHWAY_CLOUD_PROJECT_NUMBER": "123456789",
            "LATCHWAY_SOURCE_COMMIT": "0" * 40,
            "LATCHWAY_CORE_COMMIT": "1" * 40,
            "LATCHWAY_SDK_VERSION": "1.0.0",
            "LATCHWAY_CONTRACT_VERSION": "1.0.0",
            "LATCHWAY_CONTRACT_BUNDLE_SHA256": "2" * 64,
            "LATCHWAY_GATEWAY_IMAGE_DIGEST": "sha256:" + "3" * 64,
            "LATCHWAY_GATEWAY_CONFIGURATION_SHA256": "4" * 64,
            "LATCHWAY_GATEWAY_ORIGIN": "https://gateway.example.com",
            "LATCHWAY_GATEWAY_DEPLOYMENT_KEY_ID": "test-key",
            "LATCHWAY_GATEWAY_DEPLOYMENT_STATEMENT_SHA256": "5" * 64,
            "LATCHWAY_GATEWAY_DEPLOYMENT_PUBLIC_KEY_SHA256": "6" * 64,
            "LATCHWAY_ENVIRONMENT": "production",
            "LATCHWAY_IDENTITY_PROVIDER": "firebase",
            "LATCHWAY_APPLICATION_ID": "app_01J00000000000000000000000",
            "LATCHWAY_FEATURE": "assistant",
            "LATCHWAY_ERROR_MAPPING_FEATURE": "missing_feature",
            "LATCHWAY_MODEL": "assistant-default",
            "LATCHWAY_PLAY_SIGNING_MODE": "unsigned",
        }
        prohibited = (
            "LATCHWAY_PLAY_UPLOAD_KEYSTORE_BASE64",
            "LATCHWAY_PLAY_UPLOAD_KEYSTORE_PASSWORD",
            "LATCHWAY_PLAY_UPLOAD_KEY_ALIAS",
            "LATCHWAY_PLAY_UPLOAD_KEY_PASSWORD",
        )
        sentinel = "canonical-upload-secret-sentinel"
        all_prohibited = re.findall(
            r"(?m)^  ([A-Z][A-Z0-9_]+) \\\n",
            SCRIPT.split("for prohibited_signing_input in", 1)[1].split("; do", 1)[0],
        )
        for name in prohibited:
            environment = dict(os.environ)
            environment.update(required)
            for candidate in all_prohibited:
                environment.pop(candidate, None)
            environment[name] = sentinel
            result = subprocess.run(
                ("bash", "-x", str(ROOT / "scripts" / "stage-play-conformance-candidate.sh")),
                cwd=ROOT,
                env=environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=10,
                check=False,
            )
            self.assertEqual(2, result.returncode, result.stderr)
            self.assertIn(name.encode("ascii"), result.stderr)
            self.assertIn(b"signing material is prohibited", result.stderr)
            self.assertNotIn(sentinel.encode("ascii"), result.stdout + result.stderr)

    def test_exact_verifier_requires_every_payload_entry_and_one_pinned_signer(self) -> None:
        for marker in (
            "entry.getCodeSigners()",
            "signers.length != 1",
            "leafCertificateSha256",
            "AAB payload entry is unsigned or has an additional signer",
            "AAB contains an additional signer control set",
            "AAB must contain exactly one signer file and one signer block",
            "AAB payload signer does not match the pinned certificate",
            "AAB contains duplicate ZIP entry names",
            "payloadNames.equals(manifest.getEntries().keySet())",
            "readCompletely(",
            "signed AAB payload does not match the independently carried pre-sign manifest",
            "raw_name_hex",
            "content_sha256",
            "version_needed_hex",
            "dos_time_hex",
            "dos_date_hex",
            "made_by_hex",
            "internal_attributes_hex",
            "external_mode_hex",
            "extra_hex",
            "local and central ZIP entry names differ",
            "local and central ZIP extra fields differ",
            "ZIP entry has an unsafe non-regular external mode",
            "central directory is not the exact trailing ZIP structure",
            "only one canonical mtime-only extended-timestamp ZIP extra field is supported",
            "data descriptor does not exactly match the central entry",
            "unsigned AAB already contains JAR signature metadata",
        ):
            self.assertIn(marker, VERIFIER)

    def test_workflow_separates_unsigned_build_signing_and_no_secret_verification(self) -> None:
        signing = WORKFLOW.split("  sign-isolated:", 1)[1].split("  verify-signed:", 1)[0]
        verification = WORKFLOW.split("  verify-signed:", 1)[1]
        secret_step = signing.split(
            "- name: Sign only the validated AAB with isolated upload-key material",
            1,
        )[1].split("- name: Seal the signed bytes", 1)[0]
        for marker in (
            "Sign the closed AAB without checkout or Gradle",
            "Validate the exact closed unsigned set before secrets exist",
            "Download the independently pinned verifier source",
            "EXPECTED_VERIFIER_SHA256",
            "VerifyPlayAabSignature --emit-presign-manifest",
            "signer-observed-presign.manifest",
            "unsigned candidate is not the exact four-file set",
            "Sign only the validated AAB with isolated upload-key material",
            "LATCHWAY_PLAY_UPLOAD_KEYSTORE_BASE64",
            "-storepass:env LATCHWAY_SIGNER_STORE_PASSWORD",
            "-keypass:env LATCHWAY_SIGNER_KEY_PASSWORD",
            "play-conformance-signed-unverified",
        ):
            self.assertIn(marker, signing)
        self.assertNotIn("actions/checkout", signing)
        self.assertNotIn("gradlew", signing)
        self.assertNotIn("VerifyPlayAabSignature", secret_step)
        self.assertNotIn("javac", secret_step)
        self.assertLess(
            signing.index("VerifyPlayAabSignature --emit-presign-manifest"),
            signing.index("- name: Sign only the validated AAB"),
        )
        for marker in (
            "Verify exact AAB entry coverage without checkout or secrets",
            "environment: play-candidate-verification",
            "LATCHWAY_PLAY_AAB_VERIFIER_SHA256",
            "certificate != expected_certificate",
            "play-aab-verifier",
            "javac -d",
            "VerifyPlayAabSignature",
            "signed candidate is not the exact five-file set",
            "play-conformance-signed-",
        ):
            self.assertIn(marker, verification)
        self.assertNotIn("actions/checkout", verification)
        self.assertNotIn("secrets.", verification)
        self.assertNotIn("gradlew", verification)
        actions = re.findall(r"(?m)^\s+uses:\s+([^\s#]+)", WORKFLOW)
        self.assertGreaterEqual(len(actions), 10)
        for action in actions:
            self.assertRegex(action, r"^[^@]+@[0-9a-f]{40}$")

    def test_signed_aab_rejects_unsigned_append_extra_signer_and_wrong_pin(self) -> None:
        for tool in ("java", "jarsigner", "keytool"):
            self.assertIsNotNone(shutil.which(tool), f"required test tool is unavailable: {tool}")
        password = "latchway-functional-test-only"
        with tempfile.TemporaryDirectory(prefix="latchway-aab-signature-test-") as temporary:
            root = pathlib.Path(temporary)
            aab = root / "candidate.aab"
            output = NonSeekableZipOutput(aab)
            try:
                with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                    self._write_regular_entry(archive, "BundleConfig.pb", b"bounded bundle configuration")
                    self._write_regular_entry(
                        archive,
                        "base/manifest/AndroidManifest.xml",
                        b"bounded manifest",
                    )
                    self._write_regular_entry(archive, "base/dex/classes.dex", b"bounded dex payload")
            finally:
                output.close()
            self._set_utf8_flags(aab)

            payload_manifest = root / "presign-payload.manifest"
            self._run(
                "java", str(VERIFIER_PATH), "--emit-presign-manifest",
                str(aab), str(payload_manifest),
            )
            manifest_text = payload_manifest.read_text(encoding="ascii")
            self.assertIn("schema=latchway.android-aab-presign-payload.v1", manifest_text)
            self.assertIn("sort=raw_name_unsigned_byte_lexicographic", manifest_text)
            self.assertIn("raw_name_hex", manifest_text)

            keystore = root / "upload.p12"
            signer_environment = dict(os.environ)
            signer_environment["LATCHWAY_TEST_STORE_PASSWORD"] = password
            signer_environment["LATCHWAY_TEST_KEY_PASSWORD"] = password
            self._run(
                "keytool", "-genkeypair", "-noprompt",
                "-storetype", "PKCS12", "-keystore", str(keystore),
                "-storepass", password, "-keypass", password,
                "-alias", "upload", "-keyalg", "RSA", "-keysize", "2048",
                "-sigalg", "SHA256withRSA", "-validity", "2",
                "-dname", "CN=Latchway Functional Upload",
            )
            certificate = self._run(
                "keytool", "-exportcert", "-storetype", "PKCS12",
                "-keystore", str(keystore),
                "-storepass:env", "LATCHWAY_TEST_STORE_PASSWORD",
                "-alias", "upload", "-keypass:env", "LATCHWAY_TEST_KEY_PASSWORD",
                environment=signer_environment,
            ).stdout
            certificate_sha256 = hashlib.sha256(certificate).hexdigest()
            self._run(
                "jarsigner", "-keystore", str(keystore), "-storetype", "PKCS12",
                "-storepass:env", "LATCHWAY_TEST_STORE_PASSWORD",
                "-keypass:env", "LATCHWAY_TEST_KEY_PASSWORD",
                "-digestalg", "SHA-256", "-sigalg", "SHA256withRSA",
                str(aab), "upload",
                environment=signer_environment,
            )

            accepted = self._verify(aab, certificate_sha256, payload_manifest)
            self.assertEqual(0, accepted.returncode, accepted.stderr)
            self.assertIn("Verified raw ZIP structure, pre-sign continuity", accepted.stdout)

            wrong_pin = self._verify(aab, "0" * 64, payload_manifest)
            self.assertNotEqual(0, wrong_pin.returncode)
            self.assertIn("does not match the pinned certificate", wrong_pin.stderr)

            changed_manifest = root / "changed-presign-payload.manifest"
            changed_manifest.write_bytes(payload_manifest.read_bytes() + b"unexpected\n")
            changed_manifest_result = self._verify(aab, certificate_sha256, changed_manifest)
            self.assertNotEqual(0, changed_manifest_result.returncode)
            self.assertIn("does not match the independently carried pre-sign manifest", changed_manifest_result.stderr)

            additional_signer = root / "additional-signer.aab"
            shutil.copyfile(aab, additional_signer)
            self._run(
                "keytool", "-genkeypair", "-noprompt",
                "-storetype", "PKCS12", "-keystore", str(keystore),
                "-storepass", password, "-keypass", password,
                "-alias", "second", "-keyalg", "RSA", "-keysize", "2048",
                "-sigalg", "SHA256withRSA", "-validity", "2",
                "-dname", "CN=Unexpected Additional Signer",
            )
            self._run(
                "jarsigner", "-keystore", str(keystore), "-storetype", "PKCS12",
                "-storepass:env", "LATCHWAY_TEST_STORE_PASSWORD",
                "-keypass:env", "LATCHWAY_TEST_KEY_PASSWORD",
                "-digestalg", "SHA-256", "-sigalg", "SHA256withRSA",
                str(additional_signer), "second",
                environment=signer_environment,
            )
            extra_signer_result = self._verify(additional_signer, certificate_sha256, payload_manifest)
            self.assertNotEqual(0, extra_signer_result.returncode)
            self.assertIn("additional signer", extra_signer_result.stderr)

            appended = root / "unsigned-append.aab"
            shutil.copyfile(aab, appended)
            with zipfile.ZipFile(appended, "a", compression=zipfile.ZIP_DEFLATED) as archive:
                self._write_regular_entry(
                    archive,
                    "base/assets/unsigned-after-signing.txt",
                    b"must be rejected",
                )
            # This is the behavior that motivated the exact verifier: default
            # jarsigner reports success while warning about unsigned entries.
            plain_jarsigner = self._run("jarsigner", "-verify", str(appended))
            self.assertEqual(0, plain_jarsigner.returncode)
            append_result = self._verify(appended, certificate_sha256, payload_manifest)
            self.assertNotEqual(0, append_result.returncode)
            self.assertIn("does not match the independently carried pre-sign manifest", append_result.stderr)

            deleted = root / "deleted-signed-entry.aab"
            with zipfile.ZipFile(aab, "r") as source, zipfile.ZipFile(deleted, "w") as target:
                for entry in source.infolist():
                    if entry.filename != "base/dex/classes.dex":
                        entry.create_system = 3
                        entry.external_attr = (stat.S_IFREG | 0o644) << 16
                        entry.internal_attr = 0
                        entry.extra = b""
                        target.writestr(entry, source.read(entry))
            deletion_jarsigner = self._run("jarsigner", "-verify", str(deleted))
            self.assertEqual(0, deletion_jarsigner.returncode)
            deletion_result = self._verify(deleted, certificate_sha256, payload_manifest)
            self.assertNotEqual(0, deletion_result.returncode)
            self.assertIn("does not match the independently carried pre-sign manifest", deletion_result.stderr)

            local_mismatch = root / "local-traversal-mismatch.aab"
            shutil.copyfile(aab, local_mismatch)
            self._replace_local_name(local_mismatch, "base/dex/classes.dex")
            plain_local_mismatch = self._run("jarsigner", "-verify", str(local_mismatch))
            self.assertEqual(0, plain_local_mismatch.returncode)
            local_mismatch_result = self._verify(
                local_mismatch,
                certificate_sha256,
                payload_manifest,
            )
            self.assertNotEqual(0, local_mismatch_result.returncode)
            self.assertIn("local and central ZIP entry names differ", local_mismatch_result.stderr)

            symlink_mode = root / "symlink-external-mode.aab"
            shutil.copyfile(aab, symlink_mode)
            self._replace_central_mode_with_symlink(symlink_mode, "base/dex/classes.dex")
            plain_symlink = self._run("jarsigner", "-verify", str(symlink_mode))
            self.assertEqual(0, plain_symlink.returncode)
            symlink_result = self._verify(symlink_mode, certificate_sha256, payload_manifest)
            self.assertNotEqual(0, symlink_result.returncode)
            self.assertIn("unsafe non-regular external mode", symlink_result.stderr)

            special_mode = root / "setuid-external-mode.aab"
            shutil.copyfile(aab, special_mode)
            self._replace_central_mode_with_special_bits(
                special_mode,
                "base/dex/classes.dex",
            )
            special_result = self._verify(special_mode, certificate_sha256, payload_manifest)
            self.assertNotEqual(0, special_result.returncode)
            self.assertIn("unsafe non-regular external mode", special_result.stderr)

            version_mismatch = root / "local-version-mismatch.aab"
            shutil.copyfile(aab, version_mismatch)
            self._replace_local_version_needed(version_mismatch, "base/dex/classes.dex")
            version_result = self._verify(version_mismatch, certificate_sha256, payload_manifest)
            self.assertNotEqual(0, version_result.returncode)
            self.assertIn("required version", version_result.stderr)

            invalid_version = root / "invalid-required-version.aab"
            shutil.copyfile(aab, invalid_version)
            self._replace_local_and_central_version_needed(
                invalid_version,
                "base/dex/classes.dex",
                0,
            )
            invalid_version_result = self._verify(
                invalid_version,
                certificate_sha256,
                payload_manifest,
            )
            self.assertNotEqual(0, invalid_version_result.returncode)
            self.assertIn(
                "non-canonical required version",
                invalid_version_result.stderr,
            )

            timestamp_mismatch = root / "local-timestamp-mismatch.aab"
            shutil.copyfile(aab, timestamp_mismatch)
            self._replace_local_modification_time(timestamp_mismatch, "base/dex/classes.dex")
            timestamp_result = self._verify(
                timestamp_mismatch,
                certificate_sha256,
                payload_manifest,
            )
            self.assertNotEqual(0, timestamp_result.returncode)
            self.assertIn("timestamp differ", timestamp_result.stderr)

            internal_attributes = root / "internal-attributes.aab"
            shutil.copyfile(aab, internal_attributes)
            self._replace_central_internal_attributes(
                internal_attributes,
                "base/dex/classes.dex",
            )
            internal_result = self._verify(
                internal_attributes,
                certificate_sha256,
                payload_manifest,
            )
            self.assertNotEqual(0, internal_result.returncode)
            self.assertIn("internal file attributes are unsupported", internal_result.stderr)

            trailing = root / "trailing-polyglot.aab"
            shutil.copyfile(aab, trailing)
            with trailing.open("ab") as output:
                output.write(b"unreviewed trailing polyglot bytes")
            trailing_result = self._verify(trailing, certificate_sha256, payload_manifest)
            self.assertNotEqual(0, trailing_result.returncode)
            self.assertIn("invalid end of central directory signature", trailing_result.stderr)

            canonical_extra = root / "canonical-extra.aab"
            with zipfile.ZipFile(canonical_extra, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                entry = zipfile.ZipInfo("base/dex/classes.dex")
                entry.create_system = 3
                entry.external_attr = (stat.S_IFREG | 0o644) << 16
                entry.compress_type = zipfile.ZIP_DEFLATED
                entry.extra = struct.pack("<HHBI", 0x5455, 5, 0x01, 0)
                archive.writestr(entry, b"bounded dex payload")
            canonical_manifest = root / "canonical-extra.manifest"
            canonical_result = subprocess.run(
                (
                    "java", str(VERIFIER_PATH), "--emit-presign-manifest",
                    str(canonical_extra), str(canonical_manifest),
                ),
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=60,
            )
            self.assertEqual(0, canonical_result.returncode, canonical_result.stderr)

            extra_mismatch = root / "local-extra-mismatch.aab"
            shutil.copyfile(canonical_extra, extra_mismatch)
            self._replace_local_extended_timestamp(extra_mismatch, "base/dex/classes.dex")
            mismatch_manifest = root / "local-extra-mismatch.manifest"
            mismatch_result = subprocess.run(
                (
                    "java", str(VERIFIER_PATH), "--emit-presign-manifest",
                    str(extra_mismatch), str(mismatch_manifest),
                ),
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=60,
            )
            self.assertNotEqual(0, mismatch_result.returncode)
            self.assertIn("local and central ZIP extra fields differ", mismatch_result.stderr)

            alternate_name_extra = root / "alternate-name-extra.aab"
            with zipfile.ZipFile(alternate_name_extra, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                entry = zipfile.ZipInfo("base/dex/classes.dex")
                entry.create_system = 3
                entry.external_attr = (stat.S_IFREG | 0o644) << 16
                entry.compress_type = zipfile.ZIP_DEFLATED
                entry.extra = struct.pack("<HHB", 0x7075, 1, 1)
                archive.writestr(entry, b"bounded dex payload")
            alternate_manifest = root / "alternate-name-extra.manifest"
            alternate_result = subprocess.run(
                (
                    "java", str(VERIFIER_PATH), "--emit-presign-manifest",
                    str(alternate_name_extra), str(alternate_manifest),
                ),
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=60,
            )
            self.assertNotEqual(0, alternate_result.returncode)
            self.assertIn(
                "only one canonical mtime-only extended-timestamp ZIP extra field is supported",
                alternate_result.stderr,
            )

    @staticmethod
    def _run(
        *arguments: str,
        environment: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(
            arguments,
            check=True,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=60,
        )

    @staticmethod
    def _verify(
        aab: pathlib.Path,
        certificate_sha256: str,
        payload_manifest: pathlib.Path,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            (
                "java", str(VERIFIER_PATH), str(aab), certificate_sha256,
                str(payload_manifest),
            ),
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=60,
        )

    @staticmethod
    def _write_regular_entry(
        archive: zipfile.ZipFile,
        name: str,
        content: bytes,
    ) -> None:
        entry = zipfile.ZipInfo(name)
        entry.create_system = 3
        entry.external_attr = (stat.S_IFREG | 0o644) << 16
        entry.compress_type = zipfile.ZIP_DEFLATED
        archive.writestr(entry, content)

    @staticmethod
    def _replace_local_name(path: pathlib.Path, name: str) -> None:
        with zipfile.ZipFile(path) as archive:
            entry = archive.getinfo(name)
            offset = entry.header_offset
        replacement = b"../" + b"x" * (len(name.encode("ascii")) - 3)
        with path.open("r+b") as target:
            target.seek(offset + 26)
            name_length, extra_length = struct.unpack("<HH", target.read(4))
            del extra_length
            assert name_length == len(replacement)
            target.seek(offset + 30)
            target.write(replacement)

    @staticmethod
    def _replace_central_mode_with_symlink(path: pathlib.Path, name: str) -> None:
        content = bytearray(path.read_bytes())
        end_offset = len(content) - 22
        assert struct.unpack_from("<I", content, end_offset)[0] == 0x06054B50
        entry_count = struct.unpack_from("<H", content, end_offset + 10)[0]
        position = struct.unpack_from("<I", content, end_offset + 16)[0]
        for _ in range(entry_count):
            assert struct.unpack_from("<I", content, position)[0] == 0x02014B50
            name_length, extra_length, comment_length = struct.unpack_from(
                "<HHH",
                content,
                position + 28,
            )
            raw_name = bytes(content[position + 46 : position + 46 + name_length])
            if raw_name == name.encode("ascii"):
                struct.pack_into("<H", content, position + 4, (3 << 8) | 20)
                struct.pack_into(
                    "<I",
                    content,
                    position + 38,
                    (stat.S_IFLNK | 0o777) << 16,
                )
                path.write_bytes(content)
                return
            position += 46 + name_length + extra_length + comment_length
        raise AssertionError(f"central entry not found: {name}")

    @staticmethod
    def _replace_central_mode_with_special_bits(path: pathlib.Path, name: str) -> None:
        content = bytearray(path.read_bytes())
        end_offset = len(content) - 22
        assert struct.unpack_from("<I", content, end_offset)[0] == 0x06054B50
        entry_count = struct.unpack_from("<H", content, end_offset + 10)[0]
        position = struct.unpack_from("<I", content, end_offset + 16)[0]
        for _ in range(entry_count):
            assert struct.unpack_from("<I", content, position)[0] == 0x02014B50
            name_length, extra_length, comment_length = struct.unpack_from(
                "<HHH",
                content,
                position + 28,
            )
            raw_name = bytes(content[position + 46 : position + 46 + name_length])
            if raw_name == name.encode("ascii"):
                struct.pack_into("<H", content, position + 4, (3 << 8) | 20)
                struct.pack_into(
                    "<I",
                    content,
                    position + 38,
                    (stat.S_IFREG | stat.S_ISUID | 0o755) << 16,
                )
                path.write_bytes(content)
                return
            position += 46 + name_length + extra_length + comment_length
        raise AssertionError(f"central entry not found: {name}")

    @staticmethod
    def _replace_local_version_needed(path: pathlib.Path, name: str) -> None:
        with zipfile.ZipFile(path) as archive:
            entry = archive.getinfo(name)
            offset = entry.header_offset
        content = bytearray(path.read_bytes())
        current = struct.unpack_from("<H", content, offset + 4)[0]
        replacement = 10 if current != 10 else 20
        struct.pack_into("<H", content, offset + 4, replacement)
        path.write_bytes(content)

    @staticmethod
    def _replace_local_and_central_version_needed(
        path: pathlib.Path,
        name: str,
        replacement: int,
    ) -> None:
        content = bytearray(path.read_bytes())
        end_offset = len(content) - 22
        assert struct.unpack_from("<I", content, end_offset)[0] == 0x06054B50
        entry_count = struct.unpack_from("<H", content, end_offset + 10)[0]
        position = struct.unpack_from("<I", content, end_offset + 16)[0]
        for _ in range(entry_count):
            assert struct.unpack_from("<I", content, position)[0] == 0x02014B50
            name_length, extra_length, comment_length = struct.unpack_from(
                "<HHH",
                content,
                position + 28,
            )
            raw_name = bytes(content[position + 46 : position + 46 + name_length])
            if raw_name == name.encode("ascii"):
                local_offset = struct.unpack_from("<I", content, position + 42)[0]
                struct.pack_into("<H", content, position + 6, replacement)
                struct.pack_into("<H", content, local_offset + 4, replacement)
                path.write_bytes(content)
                return
            position += 46 + name_length + extra_length + comment_length
        raise AssertionError(f"central entry not found: {name}")

    @staticmethod
    def _replace_local_modification_time(path: pathlib.Path, name: str) -> None:
        with zipfile.ZipFile(path) as archive:
            entry = archive.getinfo(name)
            offset = entry.header_offset
        content = bytearray(path.read_bytes())
        current = struct.unpack_from("<H", content, offset + 10)[0]
        struct.pack_into("<H", content, offset + 10, current ^ 0x0001)
        path.write_bytes(content)

    @staticmethod
    def _replace_central_internal_attributes(path: pathlib.Path, name: str) -> None:
        content = bytearray(path.read_bytes())
        end_offset = len(content) - 22
        assert struct.unpack_from("<I", content, end_offset)[0] == 0x06054B50
        entry_count = struct.unpack_from("<H", content, end_offset + 10)[0]
        position = struct.unpack_from("<I", content, end_offset + 16)[0]
        for _ in range(entry_count):
            assert struct.unpack_from("<I", content, position)[0] == 0x02014B50
            name_length, extra_length, comment_length = struct.unpack_from(
                "<HHH",
                content,
                position + 28,
            )
            raw_name = bytes(content[position + 46 : position + 46 + name_length])
            if raw_name == name.encode("ascii"):
                struct.pack_into("<H", content, position + 36, 1)
                path.write_bytes(content)
                return
            position += 46 + name_length + extra_length + comment_length
        raise AssertionError(f"central entry not found: {name}")

    @staticmethod
    def _replace_local_extended_timestamp(path: pathlib.Path, name: str) -> None:
        with zipfile.ZipFile(path) as archive:
            entry = archive.getinfo(name)
            offset = entry.header_offset
        content = bytearray(path.read_bytes())
        name_length, extra_length = struct.unpack_from("<HH", content, offset + 26)
        extra_offset = offset + 30 + name_length
        extra = bytes(content[extra_offset : extra_offset + extra_length])
        assert extra == struct.pack("<HHBI", 0x5455, 5, 0x01, 0)
        struct.pack_into("<I", content, extra_offset + 5, 1)
        path.write_bytes(content)

    @staticmethod
    def _set_utf8_flags(path: pathlib.Path) -> None:
        content = bytearray(path.read_bytes())
        end_offset = len(content) - 22
        assert struct.unpack_from("<I", content, end_offset)[0] == 0x06054B50
        entry_count = struct.unpack_from("<H", content, end_offset + 10)[0]
        position = struct.unpack_from("<I", content, end_offset + 16)[0]
        for _ in range(entry_count):
            assert struct.unpack_from("<I", content, position)[0] == 0x02014B50
            flags = struct.unpack_from("<H", content, position + 8)[0] | 0x0800
            local_offset = struct.unpack_from("<I", content, position + 42)[0]
            struct.pack_into("<H", content, position + 8, flags)
            struct.pack_into("<H", content, local_offset + 6, flags)
            name_length, extra_length, comment_length = struct.unpack_from(
                "<HHH",
                content,
                position + 28,
            )
            position += 46 + name_length + extra_length + comment_length
        path.write_bytes(content)

    def test_candidate_embeds_all_non_secret_runtime_pins(self) -> None:
        properties = (
            "packageName",
            "versionName",
            "versionCode",
            "gatewayUrl",
            "gatewayOrigin",
            "gatewayDeploymentKeyId",
            "gatewayDeploymentStatementSha256",
            "gatewayDeploymentPublicKeySha256",
            "gatewayConfigurationSha256",
            "gatewayImageDigest",
            "applicationId",
            "environment",
            "identityProvider",
            "feature",
            "errorMappingFeature",
            "model",
            "cloudProjectNumber",
            "playTrack",
            "sourceCommit",
            "coreCommit",
            "contractBundleSha256",
            "signingCertificateSha256",
            "requireLicensed",
        )
        for name in properties:
            self.assertIn(f"latchway.{name}", SCRIPT)
            self.assertIn(f'"latchway.{name}"', BUILD)
        self.assertIn("a Play conformance candidate must require licensed accounts", BUILD)
        self.assertIn("dotted Android application ID", BUILD)
        self.assertIn("Google Play range", BUILD)
        self.assertIn('android:value="${latchwayIdentityProvider}"', MANIFEST)

    def test_staging_manifest_and_output_are_closed_and_hash_verified(self) -> None:
        for marker in (
            "latchway.android-play-conformance-candidate.v1",
            "run-bound-one-use-external-identity-jwt",
            "play-conformance-candidate.json",
            "SHA256SUMS",
            "shasum -a 256 --check --strict",
            "candidate output directory must be absent or empty",
            "umask 077",
            "configuration_cache\": False",
            "persistent_gradle_daemon\": False",
        ):
            self.assertIn(marker, SCRIPT)
        self.assertNotIn("play upload", SCRIPT.lower())
        self.assertNotIn("play publish", SCRIPT.lower())
        self.assertNotIn("service-account", SCRIPT.lower())


if __name__ == "__main__":
    unittest.main()
