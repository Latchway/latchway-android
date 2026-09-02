#!/usr/bin/env python3
"""Enforce credential and OIDC isolation in the physical Play workflow."""

from __future__ import annotations

import os
import pathlib
import re
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "physical-play-integrity.yml"
RUNNER = ROOT / "scripts" / "run-physical-play-integrity.sh"
ACTIVITY = ROOT / "sample-conformance" / "src" / "main" / "kotlin" / "dev" / "latchway" / "sample" / "conformance" / "ConformanceActivity.kt"
BOOTSTRAP = ROOT / "sample-conformance" / "src" / "main" / "kotlin" / "dev" / "latchway" / "sample" / "conformance" / "OneTimeIdentityGrant.kt"
MANIFEST = ROOT / "sample-conformance" / "src" / "main" / "AndroidManifest.xml"


def job_block(source: str, job: str) -> str:
    match = re.search(rf"(?m)^  {re.escape(job)}:\n", source)
    if match is None:
        raise AssertionError(f"missing job: {job}")
    following = re.search(r"(?m)^  [a-z0-9][a-z0-9-]*:\n", source[match.end() :])
    end = len(source) if following is None else match.end() + following.start()
    return source[match.start() : end]


class PhysicalEvidenceWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = WORKFLOW.read_text(encoding="utf-8")
        cls.authorize = job_block(cls.source, "authorize-source")
        cls.collect = job_block(cls.source, "play-integrity-production")
        cls.attest = job_block(cls.source, "attest")
        cls.runner = RUNNER.read_text(encoding="utf-8")
        cls.activity = ACTIVITY.read_text(encoding="utf-8")
        cls.bootstrap = BOOTSTRAP.read_text(encoding="utf-8")
        cls.manifest = MANIFEST.read_text(encoding="utf-8")

    def test_source_authorization_is_github_hosted_and_candidate_code_free(self) -> None:
        self.assertIn("runs-on: ubuntu-24.04", self.authorize)
        self.assertIn("id-token: write", self.authorize)
        self.assertIn("artifact-metadata: write", self.authorize)
        self.assertIn("actions/attest@", self.authorize)
        self.assertIn("latchway.physical-source-authorization.v1", self.authorize)
        self.assertEqual(
            self.authorize.count("${{ vars.LATCHWAY_RELEASE_CONTROL_POLICY_ID }}"),
            1,
        )
        self.assertEqual(self.authorize.count("${{ vars."), 1)
        for forbidden in ("secrets.", "scripts/", "gradle", "adb ", "apksigner"):
            self.assertNotIn(forbidden, self.authorize)

    def test_every_physical_environment_consumer_starts_with_exact_sentinel(self) -> None:
        expected = {
            "authorize-source": "physical-evidence-signing",
            "play-integrity-production": "play-integrity-production",
            "attest": "physical-evidence-signing",
        }
        for job_name, environment in expected.items():
            with self.subTest(job=job_name):
                block = job_block(self.source, job_name)
                self.assertIn(f"    environment: {environment}\n", block)
                prefix = (
                    "    steps:\n"
                    f"      - name: Verify the exact protected {environment} environment\n"
                    "        shell: bash\n"
                    "        env:\n"
                    "          OBSERVED_POLICY_ID: "
                    "${{ vars.LATCHWAY_RELEASE_CONTROL_POLICY_ID }}\n"
                    "        run: |\n"
                    "          set -Eeuo pipefail\n"
                    "          test \"$OBSERVED_POLICY_ID\" = "
                    f"\"latchway-release-controls-v1:latchway-android:{environment}\"\n"
                )
                self.assertEqual(block.index(prefix), block.index("    steps:\n"))

    def test_candidate_runner_is_one_job_jit_and_has_no_privileged_authority(self) -> None:
        self.assertIn("permissions: {}", self.source.split("jobs:", 1)[0])
        self.assertIn(
            "runs-on: [self-hosted, Linux, latchway-physical-android, latchway-ephemeral-jit]",
            self.collect,
        )
        self.assertIn("needs: authorize-source", self.collect)
        self.assertIn("actions: read\n      contents: read", self.collect)
        self.assertIn("actions/checkout@", self.collect)
        self.assertIn("run: scripts/run-physical-play-integrity.sh", self.collect)
        self.assertIn("secrets.LATCHWAY_ANDROID_DEVICE_SERIAL", self.collect)
        for forbidden in (
            "id-token:", "attestations:", "artifact-metadata:", "actions/attest@",
            "packages:", "GHCR",
        ):
            self.assertNotIn(forbidden, self.collect)
        self.assertIn("ACTIONS_ID_TOKEN_REQUEST_URL", self.collect)
        self.assertIn("AWS_ACCESS_KEY_ID", self.collect)
        self.assertIn("CLOUDFLARE_API_TOKEN", self.collect)
        self.assertIn(
            "prohibited credential class is present on physical collector",
            self.collect,
        )
        for forbidden_env in (
            "\n          AWS_ACCESS_KEY_ID:",
            "\n          AWS_SECRET_ACCESS_KEY:",
            "\n          CLOUDFLARE_API_TOKEN:",
        ):
            self.assertNotIn(forbidden_env, self.collect)

    def test_signed_lease_and_unconditional_cleanup_contract(self) -> None:
        for marker in (
            'test "$RUNNER_NAME" = "latchway-android-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}"',
            ".runner.ephemeral == true", ".runner.jit == true", ".runner.max_jobs == 1",
            ".runner.fresh_boot == true", ".runner.clean_workspace == true",
            ".runner.destroy_after_job == true",
            ".credentials == {long_lived:false,organization:false,administration:false,registry:false,oidc:false}",
            "caller_supplied_claims_accepted:false", "out_of_band_watchdog:true",
            "destroy_on_disconnect:true",
            'latchway-physical-evidence/android-play-integrity', ".grant.single_use == true",
            ".grant.application_id == $application_id",
            ".grant.package_name == $package_name",
            ".grant.identity_provider == $identity_provider",
            '(.grant | keys) == ["application_id","audience"',
            ".grant.issued_at_unix",
            ".grant.expires_at_unix <= .expires_at_unix",
            "(.grant.expires_at_unix - .grant.issued_at_unix) <= 300",
            "installed_apk_set_sha256", "source_authorization_sha256",
            "--deny-self-hosted-runners", "openssl dgst -sha256 -verify",
        ):
            self.assertIn(marker, self.collect)

    def test_one_use_identity_grant_is_hash_bound_and_streamed_only_over_stdin(self) -> None:
        self.assertIn(
            "LATCHWAY_ONE_TIME_DEVICE_GRANT: ${{ secrets.LATCHWAY_ONE_TIME_DEVICE_GRANT }}",
            self.collect,
        )
        self.assertEqual(self.authorize.count("LATCHWAY_ONE_TIME_DEVICE_GRANT"), 0)
        self.assertEqual(self.attest.count("LATCHWAY_ONE_TIME_DEVICE_GRANT"), 0)
        for marker in (
            "LATCHWAY_RUN_ATTEMPT",
            "LATCHWAY_ANDROID_DEVICE_GRANT_SHA256",
            "actual_grant_sha256",
            'one_time_device_grant="${LATCHWAY_ONE_TIME_DEVICE_GRANT:-}"',
            "set +x",
            "export -n one_time_device_grant",
            "unset LATCHWAY_ONE_TIME_DEVICE_GRANT",
            'shell pm clear "$LATCHWAY_PACKAGE_NAME"',
            "content write --uri \"$grant_uri\"",
            "latchway-physical-evidence/android-play-integrity",
            "application_id=$LATCHWAY_APPLICATION_ID",
            "package_name=$LATCHWAY_PACKAGE_NAME",
            "identity_provider=$LATCHWAY_IDENTITY_PROVIDER",
            "--es dev.latchway.RUN_ATTEMPT",
            "--es dev.latchway.IDENTITY_GRANT_SHA256",
        ):
            self.assertIn(marker, self.runner)
        self.assertLess(
            self.runner.index("unset LATCHWAY_ONE_TIME_DEVICE_GRANT"),
            self.runner.index('repository_root="$(cd'),
        )
        self.assertLess(
            self.runner.index('shell pm clear "$LATCHWAY_PACKAGE_NAME"'),
            self.runner.index("content write --uri \"$grant_uri\""),
        )
        self.assertIn(
            'printf \'%s\' "$one_time_device_grant" | adb_device shell content write',
            self.runner,
        )
        for forbidden in (
            "--es dev.latchway.IDENTITY_GRANT ",
            "--es dev.latchway.ONE_TIME_DEVICE_GRANT ",
            "echo \"$one_time_device_grant\"",
            "play-integrity-observation.json\" \"$one_time_device_grant",
        ):
            self.assertNotIn(forbidden, self.runner)

        self.assertNotIn("jti_sha256", self.runner + self.collect)
        self.assertNotIn("hash-jwt-jti.py", self.runner + self.collect)
        self.assertLess(
            self.runner.index('actual_grant_sha256="$(printf'),
            self.runner.index('content write --uri "$grant_uri"'),
        )

    def test_provider_agnostic_digest_one_use_contract_is_signed_and_observed(self) -> None:
        for marker in (
            'latchway.physical-collector-lease.v2',
            'identity_grant_digest_one_use_enforced:true',
            'latchway.physical-collector-teardown.v2',
            'identity_grant_digest_consumed_once:true',
            'gateway_run_receipt_binds_identity_grant_digest:true',
            '.observations.identity_grant_sha256 == $grant',
            '.observations.gateway_run_receipt_sha256',
            '(.grant | keys) == ["application_id","audience","expires_at_unix","identity_provider","issued_at_unix","package_name","run_attempt","run_id","sha256","single_use","source_commit"]',
        ):
            self.assertIn(marker, self.collect)
        self.assertEqual(0, self.source.count("jti_sha256"))
        self.assertIn('.supervisor.identity_grant_digest_one_use_enforced == true', self.runner)
        finalize = self.collect.split(
            "- name: Unconditionally finalize, deregister, and arm collector destruction",
            1,
        )[1].split("- name: Retain bounded unsigned physical evidence", 1)[0]
        protected_digest = (
            "DEVICE_GRANT_SHA256: ${{ vars.LATCHWAY_ANDROID_DEVICE_GRANT_SHA256 }}"
        )
        self.assertIn(protected_digest, finalize)
        self.assertIn(protected_digest, self.attest)

    def test_grant_is_not_traced_or_reexported_from_an_ambient_lowercase_name(self) -> None:
        upper_sentinel = "eyJhbGciOiJSUzI1NiJ9.dXBwZXItc2VjcmV0.c2lnbmF0dXJl"
        lower_sentinel = "ambient-lowercase-secret-sentinel"
        with tempfile.TemporaryDirectory(prefix="latchway-runner-path-") as temporary:
            fake_dirname = pathlib.Path(temporary) / "dirname"
            fake_dirname.write_text(
                "#!/bin/sh\n"
                "if [ -n \"${one_time_device_grant+x}\" ]; then\n"
                "  echo \"child inherited lowercase grant\" >&2\n"
                "fi\n"
                "exec /usr/bin/dirname \"$@\"\n",
                encoding="utf-8",
            )
            fake_dirname.chmod(0o700)
            environment = dict(os.environ)
            environment.update(
                {
                    "LATCHWAY_ONE_TIME_DEVICE_GRANT": upper_sentinel,
                    "one_time_device_grant": lower_sentinel,
                    "PATH": temporary + os.pathsep + environment["PATH"],
                }
            )
            result = subprocess.run(
                ("bash", "-x", str(RUNNER)),
                cwd=ROOT,
                env=environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=10,
                check=False,
            )
        combined = result.stdout + result.stderr
        self.assertNotEqual(0, result.returncode)
        self.assertNotIn(upper_sentinel.encode("ascii"), combined)
        self.assertNotIn(lower_sentinel.encode("ascii"), combined)
        self.assertNotIn(b"child inherited lowercase grant", combined)

    def test_installed_apk_set_is_recollected_after_observation_and_bound_to_profile(self) -> None:
        for marker in (
            "capture_installed_apk_set()",
            'pre_run_apk_set_sha256="$(capture_installed_apk_set pre-run',
            'post_run_apk_set_sha256="$(capture_installed_apk_set post-run',
            'cmp --silent "$apk_set_manifest" "$post_run_apk_set_manifest"',
            'export LATCHWAY_OBSERVED_INSTALLED_APK_SET_SHA256="$post_run_apk_set_sha256"',
            'os.environ["LATCHWAY_OBSERVED_INSTALLED_APK_SET_SHA256"]',
        ):
            self.assertIn(marker, self.runner)
        self.assertEqual(2, self.runner.count("capture_installed_apk_set "))
        self.assertLess(
            self.runner.index('[[ "$observation_ready" == true ]]'),
            self.runner.index('post_run_apk_set_sha256="$(capture_installed_apk_set post-run'),
        )
        self.assertLess(
            self.runner.index('post_run_apk_set_sha256="$(capture_installed_apk_set post-run'),
            self.runner.index('python3 "$repository_root/scripts/device-evidence.py" finalize'),
        )

    def test_app_bootstrap_is_shell_only_memory_only_and_terminal(self) -> None:
        for marker in (
            "android:writePermission=\"android.permission.DUMP\"",
            "${applicationId}.device-bootstrap",
        ):
            self.assertIn(marker, self.manifest)
        for marker in (
            "Binder.getCallingUid()",
            "ANDROID_SHELL_UID",
            "ParcelFileDescriptor.createReliablePipe()",
            "State.Staging",
            "State.Terminal",
            "compareAndSet(State.Empty, State.Staging)",
            "OneUseIdentityTokenProvider",
            "pending.getAndSet(null)",
            "token=[REDACTED]",
            'one("application_id")',
            'one("package_name")',
            'one("identity_provider")',
            'applicationId == embeddedMetadata(context, "dev.latchway.APPLICATION_ID")',
            "packageName == context.packageName",
            'identityProvider == embeddedMetadata(context, "dev.latchway.IDENTITY_PROVIDER")',
        ):
            self.assertIn(marker, self.bootstrap)
        for forbidden in (
            "SharedPreferences",
            "openFileOutput",
            "FileOutputStream",
            "FirebaseAuth",
            "currentUser",
            "signInWithCustomToken",
        ):
            self.assertNotIn(forbidden, self.bootstrap + self.activity)
        self.assertIn("OneTimeIdentityGrantSlot.takeProvider(grantCoordinates)", self.activity)
        self.assertIn("identityProvider = values.identityProvider", self.activity)
        self.assertGreaterEqual(self.collect.count("if: ${{ always() }}"), 2)
        self.assertIn("Wipe device app data even when collection fails", self.collect)
        self.assertIn("shell pm clear", self.collect)
        self.assertIn("Unconditionally finalize, deregister, and arm collector destruction", self.collect)
        self.assertIn("--source-authorization \"$source/source-authorization.json\"", self.collect)
        self.assertIn("--evidence-directory \"$evidence\"", self.collect)
        for forbidden in (
            "--source-authorization-sha256", "--lease-sha256",
            "--device-wipe-sha256", "--evidence-manifest-sha256",
        ):
            self.assertNotIn(forbidden, self.collect)
        for marker in (
            ".evidence_eligible == true", "private_key_isolated:true",
            "independent_device_verification:true", "independent_provider_verification:true",
            "gateway_run_receipt_verified:true", "one_use_invocation:true",
            "watchdog_armed:true", ".observations.device_inventory_sha256",
            ".observations.provider_observation_sha256",
            ".observations.gateway_run_receipt_sha256",
            ".runner.deregistered == true", ".runner.destroy_scheduled == true",
        ):
            self.assertIn(marker, self.collect)

    def test_unsigned_handoff_is_bounded_and_short_lived(self) -> None:
        self.assertIn(
            "name: play-integrity-physical-unsigned-${{ github.run_id }}-${{ github.run_attempt }}",
            self.collect,
        )
        self.assertIn("if-no-files-found: error", self.collect)
        self.assertIn("compression-level: 0", self.collect)
        self.assertIn("retention-days: 1", self.collect)
        self.assertIn("play-integrity-collector-isolation-unsigned-", self.collect)

    def test_fresh_signer_is_protected_and_candidate_code_free(self) -> None:
        self.assertIn("needs: play-integrity-production", self.attest)
        self.assertIn("environment: physical-evidence-signing", self.attest)
        self.assertIn("runs-on: ubuntu-24.04", self.attest)
        for permission in (
            "actions: read",
            "artifact-metadata: write",
            "attestations: write",
            "contents: read",
            "id-token: write",
        ):
            self.assertIn(permission, self.attest)
        for forbidden in ("actions/checkout@", "secrets.", "scripts/", "gradle", "adb ", "apksigner"):
            self.assertNotIn(forbidden, self.attest)
        for validation in (
            "jq --exit-status", "sha256sum", "cmp --silent", "find \"$root\"",
            "collector-isolation-validation.json", "--deny-self-hosted-runners",
            "caller_supplied_claims_accepted:false", "gateway_run_receipt_verified:true",
        ):
            self.assertIn(validation, self.attest)
        self.assertEqual(self.source.count("actions/attest@"), 2)

    def test_final_observer_contract_is_unchanged(self) -> None:
        self.assertIn(
            "name: play-integrity-physical-${{ github.run_id }}-${{ github.run_attempt }}",
            self.attest,
        )
        observer_files = {
            "SHA256SUMS",
            "device-inventory.json",
            "gateway-client-policy.json",
            "gateway-deployment-public-key.pem",
            "gateway-deployment-statement.json",
            "gateway-deployment-statement.sig",
            "gateway-deployment-verification.json",
            "github-attestation.sigstore.json",
            "installed-apk-set.sha256",
            "play-integrity-evidence.json",
            "play-integrity-junit.xml",
            "play-integrity-observation.json",
            "play-integrity-profile.json",
            "play-integrity-validation.json",
        }
        for name in observer_files:
            self.assertIn(name, self.attest)
        self.assertIn("retention-days: 30", self.attest)
        self.assertIn("play-integrity-collector-isolation-${{ github.run_id }}", self.attest)

    def test_all_actions_are_commit_pinned(self) -> None:
        actions = re.findall(r"(?m)^\s+uses:\s+([^\s#]+)", self.source)
        self.assertGreaterEqual(len(actions), 11)
        for action in actions:
            self.assertRegex(action, r"^[^@]+@[0-9a-f]{40}$")


if __name__ == "__main__":
    unittest.main()
