#!/usr/bin/env python3
"""Offline tests for fail-closed GitHub release reconciliation."""

from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch


SCRIPT = Path(__file__).with_name("reconcile-github-release.py")
SPEC = importlib.util.spec_from_file_location("reconcile_github_release", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

COMMIT = "c" * 40
TAG_OBJECT = "d" * 40
TAG_MESSAGE = "Android SDK v1.0.0\n\nCore promotion: v1.0.0\nPromotion evidence SHA-256: " + "e" * 64


class FakeClient:
    def __init__(self, release: dict[str, Any] | None = None, contents: dict[int, bytes] | None = None) -> None:
        self.value = release
        self.contents = dict(contents or {})
        self.created = 0
        self.uploaded: list[str] = []
        self.finalized = 0
        self.immutable_releases = True
        self.tag_bindings = [MODULE.TagBinding("v1.0.0", TAG_OBJECT, COMMIT, TAG_MESSAGE)]
        self.tag_binding_calls = 0

    def immutability_enabled(self, repository: str) -> bool:
        del repository
        return self.immutable_releases

    def tag_binding(self, repository: str, tag: str) -> MODULE.TagBinding:
        del repository, tag
        index = min(self.tag_binding_calls, len(self.tag_bindings) - 1)
        self.tag_binding_calls += 1
        return self.tag_bindings[index]

    def release(self, repository: str, tag: str) -> dict[str, Any] | None:
        del repository, tag
        if self.value is None:
            return None
        return {
            **self.value,
            "assets": [dict(asset) for asset in self.value["assets"]],
        }

    def create(self, repository: str, tag: str, title: str, prerelease: bool) -> None:
        del repository
        self.created += 1
        self.value = {
            "tag_name": tag,
            "name": title,
            "draft": True,
            "immutable": False,
            "prerelease": prerelease,
            "assets": [],
        }

    def download(self, repository: str, asset_id: int, destination: Path) -> None:
        del repository
        destination.write_bytes(self.contents[asset_id])

    def upload(self, repository: str, tag: str, path: Path) -> None:
        del repository, tag
        assert self.value is not None
        asset_id = max(self.contents, default=0) + 1
        payload = path.read_bytes()
        self.contents[asset_id] = payload
        self.value["assets"].append({
            "id": asset_id,
            "name": path.name,
            "size": len(payload),
            "state": "uploaded",
        })
        self.uploaded.append(path.name)

    def finalize(self, repository: str, tag: str, prerelease: bool) -> None:
        del repository, tag, prerelease
        assert self.value is not None
        self.finalized += 1
        self.value["draft"] = False
        self.value["immutable"] = True


def release(
    *,
    draft: bool,
    assets: list[dict[str, Any]],
    title: str = "Latchway v1.0.0",
    immutable: bool | None = None,
) -> dict[str, Any]:
    return {
        "tag_name": "v1.0.0",
        "name": title,
        "draft": draft,
        "immutable": not draft if immutable is None else immutable,
        "prerelease": False,
        "assets": assets,
    }


class ReconciliationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        self.first_path = root / "first.tgz"
        self.second_path = root / "SHA256SUMS"
        self.first_path.write_bytes(b"first immutable bytes")
        self.second_path.write_bytes(b"digest  first.tgz\n")
        self.assets = MODULE.inspect_assets([str(self.first_path), str(self.second_path)])

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def reconcile(self, client: FakeClient) -> None:
        MODULE.reconcile(
            repository="Latchway/example",
            tag="v1.0.0",
            title="Latchway v1.0.0",
            prerelease=False,
            assets=self.assets,
            client=client,
            expected_commit=COMMIT,
            expected_tag_message=TAG_MESSAGE,
        )

    def test_creates_uploads_and_finalizes_new_release(self) -> None:
        client = FakeClient()
        self.reconcile(client)
        self.assertEqual(client.created, 1)
        self.assertEqual(client.uploaded, ["SHA256SUMS", "first.tgz"])
        self.assertEqual(client.finalized, 1)

    def test_resumes_partial_draft_without_overwriting_identical_asset(self) -> None:
        first = next(asset for asset in self.assets if asset.name == "first.tgz")
        client = FakeClient(
            release(
                draft=True,
                assets=[{
                    "id": 7,
                    "name": first.name,
                    "size": first.size,
                    "state": "uploaded",
                    "digest": f"sha256:{first.sha256}",
                }],
            ),
            {7: self.first_path.read_bytes()},
        )
        self.reconcile(client)
        self.assertEqual(client.created, 0)
        self.assertEqual(client.uploaded, ["SHA256SUMS"])
        self.assertEqual(client.finalized, 1)

    def test_exact_final_release_is_a_read_only_success(self) -> None:
        remote_assets = []
        contents: dict[int, bytes] = {}
        for identifier, asset in enumerate(self.assets, 1):
            remote_assets.append({
                "id": identifier,
                "name": asset.name,
                "size": asset.size,
                "state": "uploaded",
                "digest": f"sha256:{asset.sha256}",
            })
            contents[identifier] = asset.path.read_bytes()
        client = FakeClient(release(draft=False, assets=remote_assets), contents)
        self.reconcile(client)
        self.assertEqual(client.created, 0)
        self.assertEqual(client.uploaded, [])
        self.assertEqual(client.finalized, 0)

    def test_rejects_different_existing_bytes(self) -> None:
        first = next(asset for asset in self.assets if asset.name == "first.tgz")
        client = FakeClient(
            release(draft=True, assets=[{
                "id": 1,
                "name": first.name,
                "size": first.size,
                "state": "uploaded",
            }]),
            {1: b"x" * first.size},
        )
        with self.assertRaisesRegex(MODULE.Rejected, "not byte-identical"):
            self.reconcile(client)
        self.assertEqual(client.uploaded, [])
        self.assertEqual(client.finalized, 0)

    def test_rejects_unexpected_asset_and_metadata_mismatch(self) -> None:
        unexpected = FakeClient(release(draft=True, assets=[{
            "id": 1, "name": "foreign.bin", "size": 1, "state": "uploaded",
        }]), {1: b"x"})
        with self.assertRaisesRegex(MODULE.Rejected, "unexpected asset"):
            self.reconcile(unexpected)

        wrong_title = FakeClient(release(draft=True, assets=[], title="wrong"))
        with self.assertRaisesRegex(MODULE.Rejected, "title"):
            self.reconcile(wrong_title)

    def test_final_release_cannot_be_backfilled(self) -> None:
        client = FakeClient(release(draft=False, assets=[]))
        with self.assertRaisesRegex(MODULE.Rejected, "missing immutable asset"):
            self.reconcile(client)
        self.assertEqual(client.uploaded, [])

    def test_draft_preparation_predeclares_fixed_assets_and_reports_guard_upload(self) -> None:
        client = FakeClient()
        result = MODULE.reconcile(
            repository="Latchway/example",
            tag="v1.0.0",
            title="Latchway v1.0.0",
            prerelease=False,
            assets=[self.assets[0]],
            client=client,
            expected_commit=COMMIT,
            expected_tag_message=TAG_MESSAGE,
            draft_only=True,
            allowed_asset_names={asset.name for asset in self.assets},
        )
        self.assertEqual(result.uploaded, {self.assets[0].name})
        self.assertEqual(client.finalized, 0)
        self.assertTrue(client.value["draft"])

    def test_rejects_disabled_immutability_and_nonimmutable_final_release(self) -> None:
        disabled = FakeClient()
        disabled.immutable_releases = False
        with self.assertRaisesRegex(MODULE.Rejected, "not enabled"):
            self.reconcile(disabled)

        remote_assets = []
        contents: dict[int, bytes] = {}
        for identifier, asset in enumerate(self.assets, 1):
            remote_assets.append({
                "id": identifier,
                "name": asset.name,
                "size": asset.size,
                "state": "uploaded",
                "digest": f"sha256:{asset.sha256}",
            })
            contents[identifier] = asset.path.read_bytes()
        mutable = FakeClient(release(draft=False, immutable=False, assets=remote_assets), contents)
        with self.assertRaisesRegex(MODULE.Rejected, "not immutable"):
            self.reconcile(mutable)

    def test_settings_check_uses_only_the_protected_administration_token(self) -> None:
        completed = MODULE.subprocess.CompletedProcess(
            args=[], returncode=0, stdout='{"enabled":true}', stderr="",
        )
        with (
            patch.dict(
                MODULE.os.environ,
                {
                    "GH_TOKEN": "workflow-token",
                    "LATCHWAY_GITHUB_RELEASE_ADMIN_TOKEN": "administration-token",
                },
                clear=False,
            ),
            patch.object(MODULE.subprocess, "run", return_value=completed) as run,
        ):
            self.assertTrue(MODULE.GitHubClient().immutability_enabled("Latchway/example"))
            self.assertNotIn("LATCHWAY_GITHUB_RELEASE_ADMIN_TOKEN", MODULE.os.environ)
        environment = run.call_args.kwargs["env"]
        self.assertEqual(environment["GH_TOKEN"], "administration-token")
        self.assertNotIn("LATCHWAY_GITHUB_RELEASE_ADMIN_TOKEN", environment)

    def test_revalidates_annotated_tag_immediately_before_immutable_publish(self) -> None:
        client = FakeClient()
        client.tag_bindings = [
            MODULE.TagBinding("v1.0.0", TAG_OBJECT, COMMIT, TAG_MESSAGE),
            MODULE.TagBinding("v1.0.0", "f" * 40, "a" * 40, TAG_MESSAGE),
        ]
        with self.assertRaisesRegex(MODULE.Rejected, "no longer targets"):
            self.reconcile(client)
        self.assertEqual(client.tag_binding_calls, 2)
        self.assertEqual(client.finalized, 0)
        self.assertTrue(client.value["draft"])

    def test_rejects_identically_messaged_tag_object_rewrite_before_publish(self) -> None:
        client = FakeClient()
        client.tag_bindings = [
            MODULE.TagBinding("v1.0.0", TAG_OBJECT, COMMIT, TAG_MESSAGE),
            MODULE.TagBinding("v1.0.0", "f" * 40, COMMIT, TAG_MESSAGE),
        ]
        with self.assertRaisesRegex(MODULE.Rejected, "object changed"):
            self.reconcile(client)
        self.assertEqual(client.finalized, 0)
        self.assertTrue(client.value["draft"])

    def test_durable_tag_object_binding_is_checked_before_any_mutation(self) -> None:
        client = FakeClient()
        client.tag_bindings = [MODULE.TagBinding("v1.0.0", "f" * 40, COMMIT, TAG_MESSAGE)]
        with self.assertRaisesRegex(MODULE.Rejected, "object changed"):
            MODULE.reconcile(
                repository="Latchway/example",
                tag="v1.0.0",
                title="Latchway v1.0.0",
                prerelease=False,
                assets=self.assets,
                client=client,
                expected_commit=COMMIT,
                expected_tag_message=TAG_MESSAGE,
                expected_tag_object_sha=TAG_OBJECT,
            )
        self.assertEqual(client.created, 0)
        self.assertEqual(client.uploaded, [])

    def test_rejects_rewritten_tag_message_before_any_release_mutation(self) -> None:
        client = FakeClient()
        client.tag_bindings = [MODULE.TagBinding("v1.0.0", TAG_OBJECT, COMMIT, "rewritten")]
        with self.assertRaisesRegex(MODULE.Rejected, "message"):
            self.reconcile(client)
        self.assertEqual(client.created, 0)
        self.assertEqual(client.uploaded, [])

    def test_tag_binding_proof_is_commit_and_message_hash_bound(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "binding.json")
            MODULE.write_tag_binding(
                path, MODULE.TagBinding("v1.0.0", TAG_OBJECT, COMMIT, TAG_MESSAGE),
            )
            value = __import__("json").loads(path.read_text(encoding="utf-8"))
            self.assertEqual(
                MODULE.load_tag_binding(path, "v1.0.0", COMMIT, TAG_MESSAGE), TAG_OBJECT,
            )
        self.assertEqual(value["commit"], COMMIT)
        self.assertEqual(value["tag_object_sha"], TAG_OBJECT)
        self.assertEqual(
            value["message_sha256"], __import__("hashlib").sha256(TAG_MESSAGE.encode()).hexdigest(),
        )


if __name__ == "__main__":
    unittest.main()
