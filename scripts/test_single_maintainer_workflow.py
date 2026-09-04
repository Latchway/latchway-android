#!/usr/bin/env python3
"""Static regression tests for the additive single-maintainer v1 workflow."""

from __future__ import annotations

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/single-maintainer-release.yml"
STRICT_WORKFLOW = ROOT / ".github/workflows/release.yml"


def job(source: str, name: str, following: str | None) -> str:
    start = source.index(f"  {name}:\n")
    end = len(source) if following is None else source.index(f"  {following}:\n", start)
    return source[start:end]


def shell_run_blocks(workflow: str) -> list[str]:
    lines = workflow.splitlines()
    result: list[str] = []
    index = 0
    while index < len(lines):
        match = re.match(r"^(\s*)run:\s*(.*)$", lines[index])
        if match is None:
            index += 1
            continue
        indent = len(match.group(1))
        block = [match.group(2)]
        index += 1
        while index < len(lines):
            following = lines[index]
            if following.strip() and len(following) - len(following.lstrip()) <= indent:
                break
            block.append(following)
            index += 1
        result.append("\n".join(block))
    return result


class SingleMaintainerWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = WORKFLOW.read_text(encoding="utf-8")
        cls.intent = job(cls.source, "intent", "verify")
        cls.verify = job(cls.source, "verify", "core-release-gate")
        cls.core = job(cls.source, "core-release-gate", "tag")
        cls.tag = job(cls.source, "tag", "sign")
        cls.sign = job(cls.source, "sign", "publish-central")
        cls.publish = job(cls.source, "publish-central", "verify-publication")
        cls.public = job(cls.source, "verify-publication", "github-release")
        cls.github = job(cls.source, "github-release", None)

    def test_strict_repository_dispatch_path_is_still_separate(self) -> None:
        strict = STRICT_WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("types: [latchway_release_promoted]", strict)
        self.assertNotIn("workflow_dispatch:", strict)
        self.assertNotIn("single_maintainer_v1", strict)

    def test_exact_request_is_bound_before_every_release_job(self) -> None:
        self.assertIn("python3 scripts/verify-maintainer-release.py", self.intent)
        self.assertIn("publish-v1.0.0-with-deferred-assurance", self.source)
        self.assertIn("needs: [intent, verify, core-release-gate]", self.tag)
        self.assertIn("needs: [intent, tag, sign]", self.publish)
        self.assertIn("needs: [intent, tag, sign, publish-central]", self.public)
        self.assertIn("needs: [intent, tag, verify-publication]", self.github)

    def test_main_run_is_authenticated_before_candidate_code_or_tag_mutation(self) -> None:
        steps = self.intent.split("\n    steps:\n", 1)[1].lstrip()
        self.assertTrue(steps.startswith("- name: Authenticate this exact main workflow run before candidate checkout"))
        authentication = steps.split("\n      - name: Check out", 1)[0]
        for value in (
            "actions/runs/$GITHUB_RUN_ID/attempts/$GITHUB_RUN_ATTEMPT",
            '.head_sha == $commit and .head_branch == "main"',
            '.path == ".github/workflows/single-maintainer-release.yml"',
            "github.ref == 'refs/heads/main'",
        ):
            self.assertIn(value, self.intent)
        self.assertNotIn("scripts/verify-maintainer-release.py", authentication)
        self.assertIn('test "$RELEASE_COMMIT" = "$REQUESTED_COMMIT"', self.tag)
        self.assertIn('test "$RELEASE_COMMIT" = "$WORKFLOW_COMMIT"', self.tag)
        self.assertIn("git/ref/heads/main", self.tag)

    def test_dispatch_inputs_are_never_interpolated_directly_into_shell(self) -> None:
        blocks = shell_run_blocks(self.source)
        self.assertGreater(len(blocks), 0)
        for block in blocks:
            self.assertNotIn("${{ inputs.", block)
        for name in ("RELEASE_PROFILE", "RELEASE_COMMIT", "RELEASE_VERSION_INPUT", "CONFIRMATION"):
            self.assertIn(name, self.intent)

    def test_complete_local_and_pinned_core_gates_precede_tag(self) -> None:
        required = (
            "scripts/test-device-evidence.py",
            "scripts/run-offline-release-tests.py",
            "scripts/scan-dependencies.sh",
            "./gradlew test assemble lint --no-daemon",
            "scripts/build-release-artifacts.sh",
            "scripts/build_docs_bundle.py",
            "scripts/run-pr-core-conformance.sh",
        )
        for command in required:
            self.assertIn(command, self.verify)
        self.assertNotIn("gh api --method POST", self.verify)
        self.assertNotIn("secrets.", self.verify)

    def test_public_core_and_same_run_transaction_are_fail_closed(self) -> None:
        self.assertIn("Reject a v1 tag owned by another workflow transaction", self.intent)
        self.assertIn("scripts/verify-public-core-release.sh", self.core)
        verifier = (ROOT / "scripts/verify-public-core-release.sh").read_text(encoding="utf-8")
        semantic = (ROOT / "scripts/verify-public-core-release.py").read_text(encoding="utf-8")
        for value in (
            "single-maintainer-release.yml",
            "release.yml",
            "compare/$locked_core_commit...$core_commit",
            "gh attestation verify",
            "registry-only; cloud deployment evidence is explicitly deferred",
            ".immutable == true",
            "(.assets | length) == 11",
        ):
            self.assertIn(value, verifier)
        for value in ("core_publication_gate", "vulnerability_scan_verified", "sbom_verified", 'record.get("deployment_evidence") != {}', '"cloud_deployments"', '"publication_scope": "registry_only"'):
            self.assertIn(value, semantic)
        self.assertNotIn("deployment-evidence.yml", verifier)
        self.assertNotIn("compose.tar.gz", semantic)
        self.assertNotIn("cloud_run.tar.gz", semantic)
        self.assertNotIn("secrets.", self.core)
        self.assertNotIn("contents: write", self.core)
        self.assertNotIn("retention-days: 14", self.source)
        self.assertGreaterEqual(self.source.count("retention-days: 90"), 5)

    def test_signing_and_portal_credentials_remain_separated(self) -> None:
        self.assertIn("secrets.LATCHWAY_SIGNING_KEY", self.sign)
        self.assertIn("secrets.LATCHWAY_SIGNING_PASSWORD", self.sign)
        self.assertNotIn("MAVEN_CENTRAL_USERNAME", self.sign)
        self.assertNotIn("MAVEN_CENTRAL_PASSWORD", self.sign)
        self.assertIn("secrets.LATCHWAY_MAVEN_CENTRAL_USERNAME", self.publish)
        self.assertIn("secrets.LATCHWAY_MAVEN_CENTRAL_PASSWORD", self.publish)
        self.assertNotIn("secrets.LATCHWAY_SIGNING_KEY", self.publish)
        self.assertNotIn("secrets.LATCHWAY_SIGNING_PASSWORD", self.publish)
        self.assertNotIn("secrets.", self.public)
        self.assertNotIn("secrets.", self.github)

    def test_exact_maven_adoption_publication_and_verification_are_required(self) -> None:
        self.assertIn("scripts/publish-central.sh", self.publish)
        self.assertIn("scripts/publish-validated-central.sh", self.publish)
        self.assertIn("scripts/verify-central-release.sh", self.public)
        self.assertIn("LATCHWAY_CENTRAL_PORTAL_BUNDLE", self.public)
        central_verifier = (ROOT / "scripts/verify-central-release.sh").read_text(encoding="utf-8")
        self.assertIn("Maven Central signature differs from the exact signed Portal candidate", central_verifier)
        self.assertIn('"signature_files_byte_identical": bool(expected_portal_bundle)', central_verifier)
        self.assertIn("Require exact public signature bytes from the signed Portal candidate", self.public)
        self.assertIn(".expected_signature_sha256 == .signature_sha256", self.public)
        self.assertIn('LATCHWAY_CENTRAL_REQUIRE_DEPLOYMENT_EVIDENCE: "true"', self.public)
        self.assertIn("LATCHWAY_MAVEN_SIGNING_FINGERPRINT", self.sign)
        self.assertIn("LATCHWAY_MAVEN_SIGNING_FINGERPRINT", self.publish)
        self.assertIn("LATCHWAY_MAVEN_SIGNING_FINGERPRINT", self.public)

    def test_github_release_adoption_checks_exact_body_metadata_assets_and_bytes(self) -> None:
        self.assertGreaterEqual(self.github.count(".body == $body"), 3)
        self.assertIn(".name == $title", self.github)
        self.assertIn(".draft == false", self.github)
        self.assertIn(".prerelease == false", self.github)
        self.assertIn("cmp --silent \"$RUNNER_TEMP/release/$name\"", self.github)
        self.assertIn("cmp --silent \"$RUNNER_TEMP/local-assets.txt\"", self.github)
        self.assertIn("diff -qr \"$RUNNER_TEMP/release\"", self.github)
        self.assertNotIn("--clobber", self.github)
        self.assertIn("not \\`release_qualified\\`", self.github)
        self.assertIn("registry-only release", self.github)
        self.assertIn("global_profile_required_evidence:[]", self.public)
        self.assertIn('"cloud_deployments"', self.public)
        self.assertNotIn("cloud_deployments.compose_verified", self.public)
        self.assertNotIn("cloud_deployments.gcp_cloud_run_verified", self.public)
        self.assertIn(".immutable == true", self.github)
        self.assertIn("If-None-Match:", self.github)
        self.assertIn("304( |$)", self.github)
        self.assertIn("gh release verify-asset", self.github)
        self.assertIn('gh release verify "$RELEASE_TAG"', self.github)
        self.assertIn("pre-publish-tag-ref.json", self.github)

    def test_selected_profile_has_no_prepublication_administration_dependency(self) -> None:
        self.assertNotIn("\n  immutable-release-settings:\n", self.source)
        self.assertNotIn("single-maintainer-v1-administration", self.source)
        self.assertNotIn("LATCHWAY_RELEASE_PROFILE_POLICY_ID", self.source)
        self.assertNotIn("LATCHWAY_GITHUB_RELEASE_ADMIN_TOKEN", self.source)
        self.assertNotIn("repos/$GITHUB_REPOSITORY/immutable-releases", self.source)

    def test_every_github_release_command_names_the_repository(self) -> None:
        commands = [line.strip() for line in self.source.splitlines() if "gh release " in line]
        self.assertGreater(len(commands), 0)
        for command in commands:
            with self.subTest(command=command):
                self.assertIn('--repo "$GITHUB_REPOSITORY"', command)

    def test_all_mutating_environments_have_distinct_exact_policy_ids(self) -> None:
        expected = {
            "single-maintainer-v1-signing",
            "single-maintainer-v1-maven",
            "single-maintainer-v1-verification",
            "single-maintainer-v1-github",
        }
        observed = set(
            re.findall(
                r"latchway-release-controls-v1:latchway-android:(single-maintainer-v1-[a-z]+)",
                self.source,
            )
        )
        self.assertEqual(observed, expected)
        self.assertNotIn("environment: github-release", self.source)
        self.assertNotIn("environment: maven-central", self.source)


if __name__ == "__main__":
    unittest.main()
