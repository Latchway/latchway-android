#!/usr/bin/env python3
"""Adversarial tests for public core single-maintainer evidence closure."""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("verify-public-core-release.py")
SPEC = importlib.util.spec_from_file_location("verify_public_core_release", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class PublicCoreReleaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="latchway-public-core-")
        self.root = Path(self.temporary.name)
        self.commit = "b" * 40
        self.locked = "a" * 40
        self.image_digest = "sha256:" + "1" * 64
        self.platforms = {"linux/amd64": "sha256:" + "2" * 64, "linux/arm64": "sha256:" + "3" * 64}
        (self.root / "latchway-contract.tar.gz").write_bytes(b"contract")
        for architecture in ("amd64", "arm64"):
            write_json(self.root / f"latchway-linux-{architecture}-vulnerability.json", {"SchemaVersion": 2, "Results": []})
            write_json(self.root / f"latchway-linux-{architecture}-license.json", {"SchemaVersion": 2, "Results": []})
            write_json(self.root / f"latchway-linux-{architecture}.spdx.json", {"spdxVersion": "SPDX-2.3", "packages": [{"SPDXID": "SPDXRef-package", "name": "latchway"}]})
        write_json(self.root / "latchway-candidate.attestation.sigstore.json", {"bundle": "fixture"})
        self.candidate = {
            "schema_version": 1,
            "kind": "latchway_release_candidate",
            "status": "passed",
            "created_at": "2026-09-01T00:00:00Z",
            "candidate_commit": self.commit,
            "intended_tag": "v1.0.0",
            "version": "1.0.0",
            "contract": {"version": "1.0.0", "status": "released", "released_at": "2026-09-01T00:00:00Z", "bundle_file_name": "latchway-contract-1.0.0.tar.gz", "bundle_sha256": digest(self.root / "latchway-contract.tar.gz")},
            "image": {"repository": "ghcr.io/latchway/latchway", "index_digest": self.image_digest, "platforms": self.platforms},
            "artifacts": [],
        }
        self.refresh_candidate()
        self.deployments: dict[str, dict[str, object]] = {}
        for index, platform in enumerate(("compose", "cloud_run"), start=100):
            self.write_deployment(platform, str(index))
        self.record = {
            "schema_version": 1,
            "kind": "latchway_single_maintainer_v1_core_release",
            "profile": "single_maintainer_v1",
            "profile_status": "incomplete",
            "release_policy": {
                **MODULE.RELEASE_POLICY,
                "environment_policy_ids": dict(MODULE.RELEASE_POLICY["environment_policy_ids"]),
            },
            "core_publication_gate": "passed",
            "candidate_commit": self.commit,
            "tag": "v1.0.0",
            "version": "1.0.0",
            "image": {"repository": "ghcr.io/latchway/latchway", "index_digest": self.image_digest, "coordinate": f"ghcr.io/latchway/latchway@{self.image_digest}", "platforms": self.platforms},
            "candidate_run": {"run_id": "99", "run_attempt": 1},
            "deployment_evidence": self.deployments,
            "supply_chain": {"multi_arch_image_verified": True, "vulnerability_scan_verified": True, "license_scan_verified": True, "sbom_verified": True, "signature_verified": True, "provenance_verified": True},
            "github_release": {"title": "Latchway v1.0.0 — single_maintainer_v1", "body": MODULE.release_body(self.commit, f"ghcr.io/latchway/latchway@{self.image_digest}"), "tag_message": "\n".join(("Latchway v1.0.0", "", "Release profile: single_maintainer_v1", f"Candidate commit: {self.commit}", f"Image: ghcr.io/latchway/latchway@{self.image_digest}"))},
            "claims": {"release_qualified": False, "fully_evidence_gated": False, "independently_reviewed": False},
            "deferred_evidence": list(MODULE.DEFERRED_EVIDENCE),
            "assets": [],
        }
        self.reseal()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def refresh_candidate(self) -> None:
        self.candidate["artifacts"] = [
            {"path": name, "sha256": digest(self.root / name)}
            for name in sorted(MODULE.CANDIDATE_ASSETS)
        ]
        write_json(self.root / "latchway-candidate.json", self.candidate)

    def write_deployment(self, platform: str, run_id: str, override_platform: str | None = None) -> None:
        coordinate = f"ghcr.io/latchway/latchway@{self.image_digest}"
        collector = {"repository": "Latchway/latchway", "workflow_ref": "Latchway/latchway/.github/workflows/deployment-evidence.yml@refs/heads/main", "ref": "refs/heads/main", "sha": self.commit, "run_id": run_id, "run_attempt": 1, "runner_environment": "github-hosted", "environment": f"deployment-evidence-{platform}"}
        identity = override_platform or platform
        values = {name: {} for name in MODULE.CAPTURE_FILES}
        common = {"schema_version": 1, "platform": identity, "core_release": "v1.0.0", "contract_version": "1.0.0", "bundle_sha256": self.candidate["contract"]["bundle_sha256"], "oci_image_digest": coordinate, "endpoint": f"https://{platform}.example", "provider_resource_id": f"resource-{platform}", "collector": collector}
        values["manifest.json"] = {**common, "kind": "latchway_cloud_deployment_capture", "core_commit": self.commit, "started_at": "2026-09-01T00:00:00Z", "finished_at": "2026-09-01T00:01:00Z", "observations": {}}
        values["latchway-deployment-binding.json"] = {**common, "kind": "latchway_authenticated_deployment_capture", "candidate_commit": self.commit, "candidate_archive": {}, "raw_capture": {}}
        archive_path = self.root / f"{platform}.tar.gz"
        with tarfile.open(archive_path, "w:gz", format=tarfile.PAX_FORMAT) as archive:
            for name in sorted(values):
                payload = (json.dumps(values[name], sort_keys=True) + "\n").encode()
                info = tarfile.TarInfo(name)
                info.size = len(payload)
                info.mode = 0o644
                info.uid = info.gid = 0
                info.uname = info.gname = ""
                info.mtime = 0
                archive.addfile(info, io.BytesIO(payload))
        write_json(self.root / f"{platform}.attestation.json", {"bundle": platform})
        self.deployments[platform] = {"platform": platform, "run_id": run_id, "run_attempt": 1, "endpoint": common["endpoint"], "provider_resource_id": common["provider_resource_id"], "archive_sha256": digest(archive_path), "attestation_sha256": digest(self.root / f"{platform}.attestation.json")}

    def reseal(self) -> None:
        self.record["assets"] = [
            {"path": name, "sha256": digest(self.root / name)}
            for name in sorted(MODULE.EVIDENCE_ASSETS)
        ]
        write_json(self.root / "latchway-single-maintainer-v1.json", self.record)
        names = sorted(MODULE.EXPECTED_FILES - {"SHA256SUMS"})
        (self.root / "SHA256SUMS").write_text("".join(f"{digest(self.root / name)}  {name}\n" for name in names), encoding="utf-8")

    def test_accepts_exact_closed_core_record(self) -> None:
        result = MODULE.verify(self.root, self.locked)
        self.assertEqual(result["candidate_commit"], self.commit)
        self.assertEqual(result["image"], f"ghcr.io/latchway/latchway@{self.image_digest}")

    def test_rejects_high_scan_even_when_all_hashes_are_resealed(self) -> None:
        path = self.root / "latchway-linux-amd64-vulnerability.json"
        write_json(path, {"SchemaVersion": 2, "Results": [{"Vulnerabilities": [{"Severity": "HIGH"}]}]})
        self.refresh_candidate()
        self.reseal()
        with self.assertRaisesRegex(MODULE.Rejected, "core_release_scan_failed"):
            MODULE.verify(self.root, self.locked)

    def test_rejects_boolean_values_for_json_integers_even_when_resealed(self) -> None:
        self.candidate["schema_version"] = True
        self.refresh_candidate()
        self.reseal()
        with self.assertRaisesRegex(MODULE.Rejected, "core_candidate_identity_invalid"):
            MODULE.verify(self.root, self.locked)

        self.candidate["schema_version"] = 1
        self.refresh_candidate()
        self.record["schema_version"] = True
        self.reseal()
        with self.assertRaisesRegex(MODULE.Rejected, "core_release_record_identity_invalid"):
            MODULE.verify(self.root, self.locked)

        self.record["schema_version"] = 1
        self.record["candidate_run"]["run_attempt"] = True
        self.reseal()
        with self.assertRaisesRegex(MODULE.Rejected, "core_candidate_run_invalid"):
            MODULE.verify(self.root, self.locked)

        self.record["candidate_run"]["run_attempt"] = 1
        path = self.root / "latchway-linux-amd64-vulnerability.json"
        write_json(path, {"SchemaVersion": True, "Results": []})
        self.refresh_candidate()
        self.reseal()
        with self.assertRaisesRegex(MODULE.Rejected, "core_release_scan_invalid"):
            MODULE.verify(self.root, self.locked)

    def test_rejects_deployment_platform_substitution_with_matching_hashes(self) -> None:
        self.write_deployment("compose", "100", override_platform="cloud_run")
        self.record["deployment_evidence"] = self.deployments
        self.reseal()
        with self.assertRaisesRegex(MODULE.Rejected, "core_deployment_identity_invalid"):
            MODULE.verify(self.root, self.locked)

    def test_rejects_unexpected_release_asset(self) -> None:
        (self.root / "unexpected").write_text("unexpected\n", encoding="utf-8")
        with self.assertRaisesRegex(MODULE.Rejected, "core_release_asset_closure_invalid"):
            MODULE.verify(self.root, self.locked)

    def test_rejects_changed_deferred_profile_even_when_resealed(self) -> None:
        self.record["deferred_evidence"] = list(MODULE.DEFERRED_EVIDENCE[:-1])
        self.reseal()
        with self.assertRaisesRegex(MODULE.Rejected, "core_release_record_identity_invalid"):
            MODULE.verify(self.root, self.locked)

    def test_rejects_missing_or_tampered_release_policy_even_when_resealed(self) -> None:
        original = json.loads(json.dumps(self.record))
        for mode in ("missing", "tampered"):
            with self.subTest(mode=mode):
                self.record = json.loads(json.dumps(original))
                if mode == "missing":
                    del self.record["release_policy"]
                else:
                    self.record["release_policy"]["strict_full_controls_satisfied"] = True
                self.reseal()
                with self.assertRaisesRegex(MODULE.Rejected, r"core_release_record_(?:fields|identity)_invalid"):
                    MODULE.verify(self.root, self.locked)


if __name__ == "__main__":
    unittest.main()
