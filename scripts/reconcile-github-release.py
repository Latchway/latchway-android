#!/usr/bin/env python3
"""Create or resume an immutable GitHub release without overwriting assets."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import quote


REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
TAG = re.compile(r"^v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$")
MAXIMUM_ASSET_BYTES = 2 * 1024 * 1024 * 1024


class Rejected(RuntimeError):
    """The existing public release differs from the intended immutable state."""


@dataclass(frozen=True)
class Asset:
    path: Path
    name: str
    size: int
    sha256: str


class Client(Protocol):
    def immutability_enabled(self, repository: str) -> bool: ...

    def release(self, repository: str, tag: str) -> dict[str, Any] | None: ...

    def create(self, repository: str, tag: str, title: str, prerelease: bool) -> None: ...

    def download(self, repository: str, asset_id: int, destination: Path) -> None: ...

    def upload(self, repository: str, tag: str, path: Path) -> None: ...

    def finalize(self, repository: str, tag: str, prerelease: bool) -> None: ...


class GitHubClient:
    def immutability_enabled(self, repository: str) -> bool:
        # Consume the protected token for this one read-only administration
        # call, then remove it before any draft or asset subprocess can run.
        administration_token = os.environ.pop("LATCHWAY_GITHUB_RELEASE_ADMIN_TOKEN", "")
        if not administration_token:
            raise RuntimeError(
                "LATCHWAY_GITHUB_RELEASE_ADMIN_TOKEN is required to read immutable-release settings."
            )
        environment = os.environ.copy()
        environment["GH_TOKEN"] = administration_token
        result = subprocess.run(
            [
                "gh", "api",
                "-H", "Accept: application/vnd.github+json",
                "-H", "X-GitHub-Api-Version: 2026-03-10",
                f"repos/{repository}/immutable-releases",
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=environment,
        )
        if result.returncode != 0:
            return False
        try:
            value = json.loads(result.stdout)
        except json.JSONDecodeError as error:
            raise RuntimeError("GitHub returned invalid immutable-release settings JSON.") from error
        return isinstance(value, dict) and value.get("enabled") is True

    def release(self, repository: str, tag: str) -> dict[str, Any] | None:
        endpoint = f"repos/{repository}/releases/tags/{quote(tag, safe='')}"
        result = subprocess.run(
            [
                "gh", "api",
                "-H", "Accept: application/vnd.github+json",
                "-H", "X-GitHub-Api-Version: 2026-03-10",
                endpoint,
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if result.returncode != 0:
            if re.search(r"(?:HTTP\s+404|404\s+Not Found|release not found)", result.stderr, re.IGNORECASE):
                return None
            raise RuntimeError(f"GitHub release lookup failed: {result.stderr.strip()}")
        try:
            value = json.loads(result.stdout)
        except json.JSONDecodeError as error:
            raise RuntimeError("GitHub returned invalid release JSON.") from error
        if not isinstance(value, dict):
            raise RuntimeError("GitHub returned an invalid release document.")
        return value

    def create(self, repository: str, tag: str, title: str, prerelease: bool) -> None:
        arguments = [
            "gh", "release", "create", tag,
            "--repo", repository,
            "--verify-tag",
            "--draft",
            "--generate-notes",
            "--title", title,
        ]
        if prerelease:
            arguments.append("--prerelease")
        _run(arguments, "GitHub draft release creation")

    def download(self, repository: str, asset_id: int, destination: Path) -> None:
        endpoint = f"repos/{repository}/releases/assets/{asset_id}"
        with destination.open("wb") as output:
            result = subprocess.run(
                [
                    "gh", "api", "--method", "GET",
                    "-H", "Accept: application/octet-stream",
                    "-H", "X-GitHub-Api-Version: 2026-03-10",
                    endpoint,
                ],
                check=False,
                stdout=output,
                stderr=subprocess.PIPE,
            )
        if result.returncode != 0:
            raise RuntimeError(f"GitHub release asset download failed: {result.stderr.decode(errors='replace').strip()}")

    def upload(self, repository: str, tag: str, path: Path) -> None:
        # Deliberately omit --clobber. Existing assets are downloaded and
        # verified before this method is called; immutable bytes are never replaced.
        _run(
            ["gh", "release", "upload", tag, str(path), "--repo", repository],
            "GitHub release asset upload",
        )

    def finalize(self, repository: str, tag: str, prerelease: bool) -> None:
        arguments = ["gh", "release", "edit", tag, "--repo", repository, "--draft=false"]
        if prerelease:
            arguments.append("--prerelease")
        else:
            arguments.extend(["--prerelease=false", "--latest"])
        _run(arguments, "GitHub release finalization")


def _run(arguments: list[str], operation: str) -> None:
    result = subprocess.run(arguments, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"{operation} failed: {result.stderr.strip()}")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def inspect_assets(paths: list[str]) -> list[Asset]:
    if not paths:
        raise Rejected("At least one release asset is required.")
    assets: list[Asset] = []
    names: set[str] = set()
    for raw_path in paths:
        path = Path(raw_path)
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
            raise Rejected(f"Release asset must be a regular file: {path}")
        if metadata.st_size <= 0 or metadata.st_size > MAXIMUM_ASSET_BYTES:
            raise Rejected(f"Release asset has an invalid size: {path}")
        name = path.name
        if name in {"", ".", ".."} or "/" in name or "\\" in name or name in names:
            raise Rejected(f"Release asset has an unsafe or duplicate name: {name}")
        names.add(name)
        digest = sha256_file(path)
        assets.append(Asset(path=path.resolve(), name=name, size=metadata.st_size, sha256=digest))
    return sorted(assets, key=lambda asset: asset.name)


def validate_release(
    release: dict[str, Any],
    *,
    tag: str,
    title: str,
    prerelease: bool,
    expected_names: set[str],
    allow_draft: bool,
    require_immutable: bool = False,
) -> dict[str, dict[str, Any]]:
    if release.get("tag_name") != tag:
        raise Rejected("Existing GitHub release tag does not match the promoted tag.")
    if release.get("name") != title:
        raise Rejected("Existing GitHub release title does not match the promoted release.")
    if release.get("prerelease") is not prerelease:
        raise Rejected("Existing GitHub release prerelease state does not match the promoted version.")
    if not isinstance(release.get("draft"), bool) or (release["draft"] and not allow_draft):
        raise Rejected("Existing GitHub release is not finalized.")
    if require_immutable and release.get("immutable") is not True:
        raise Rejected("Final GitHub release is not immutable.")
    raw_assets = release.get("assets")
    if not isinstance(raw_assets, list):
        raise Rejected("Existing GitHub release has an invalid asset list.")
    observed: dict[str, dict[str, Any]] = {}
    for raw_asset in raw_assets:
        if not isinstance(raw_asset, dict) or not isinstance(raw_asset.get("name"), str):
            raise Rejected("Existing GitHub release has invalid asset metadata.")
        name = raw_asset["name"]
        if name in observed:
            raise Rejected(f"Existing GitHub release has duplicate asset {name}.")
        if name not in expected_names:
            raise Rejected(f"Existing GitHub release has unexpected asset {name}.")
        if raw_asset.get("state") != "uploaded":
            raise Rejected(f"Existing GitHub release asset {name} is not fully uploaded.")
        if not isinstance(raw_asset.get("id"), int) or raw_asset["id"] <= 0:
            raise Rejected(f"Existing GitHub release asset {name} has an invalid identifier.")
        observed[name] = raw_asset
    return observed


def verify_remote_asset(client: Client, repository: str, local: Asset, remote: dict[str, Any]) -> None:
    if remote.get("size") != local.size:
        raise Rejected(f"Existing GitHub release asset {local.name} has different bytes.")
    advertised_digest = remote.get("digest")
    if advertised_digest not in (None, "", f"sha256:{local.sha256}"):
        raise Rejected(f"Existing GitHub release asset {local.name} has a different digest.")
    with tempfile.TemporaryDirectory(prefix="latchway-release-asset-") as temporary:
        downloaded = Path(temporary, local.name)
        client.download(repository, remote["id"], downloaded)
        metadata = downloaded.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size != local.size:
            raise Rejected(f"Existing GitHub release asset {local.name} downloaded with a different size.")
        digest = sha256_file(downloaded)
        if digest != local.sha256:
            raise Rejected(f"Existing GitHub release asset {local.name} is not byte-identical.")


def reconcile(
    *,
    repository: str,
    tag: str,
    title: str,
    prerelease: bool,
    assets: list[Asset],
    client: Client,
    draft_only: bool = False,
    allowed_asset_names: set[str] | None = None,
) -> set[str]:
    if not client.immutability_enabled(repository):
        raise Rejected("GitHub immutable releases are not enabled for this repository.")
    local_names = {asset.name for asset in assets}
    expected_names = set(allowed_asset_names or local_names)
    if not local_names.issubset(expected_names):
        raise Rejected("Local release assets are not included in the fixed asset set.")
    if not draft_only and expected_names != local_names:
        raise Rejected("Final reconciliation requires every fixed release asset locally.")
    release = client.release(repository, tag)
    if release is None:
        client.create(repository, tag, title, prerelease)
        release = client.release(repository, tag)
        if release is None:
            raise RuntimeError("GitHub did not expose the newly created draft release.")

    observed = validate_release(
        release,
        tag=tag,
        title=title,
        prerelease=prerelease,
        expected_names=expected_names,
        allow_draft=True,
    )
    # Prove every existing byte before making any mutation. A mismatched
    # partial release must fail without uploading otherwise-missing assets.
    for asset in assets:
        remote = observed.get(asset.name)
        if remote is not None:
            verify_remote_asset(client, repository, asset, remote)
    uploaded: set[str] = set()
    for asset in assets:
        if asset.name not in observed:
            if release["draft"] is not True:
                raise Rejected(f"Final GitHub release is missing immutable asset {asset.name}.")
            client.upload(repository, tag, asset.path)
            uploaded.add(asset.name)

    release = client.release(repository, tag)
    if release is None:
        raise RuntimeError("GitHub release disappeared during asset reconciliation.")
    observed = validate_release(
        release,
        tag=tag,
        title=title,
        prerelease=prerelease,
        expected_names=expected_names,
        allow_draft=True,
    )
    if not local_names.issubset(set(observed)):
        raise Rejected("GitHub draft release does not contain every supplied immutable asset.")
    for asset in assets:
        verify_remote_asset(client, repository, asset, observed[asset.name])

    if draft_only:
        if release["draft"] is not True:
            if set(observed) != expected_names:
                raise Rejected("Final GitHub release does not contain the fixed asset set.")
            if release.get("immutable") is not True:
                raise Rejected("Final GitHub release is not immutable.")
        return uploaded

    if set(observed) != expected_names:
        raise Rejected("GitHub draft release does not contain the complete immutable asset set.")

    if release["draft"]:
        client.finalize(repository, tag, prerelease)

    final = client.release(repository, tag)
    if final is None:
        raise RuntimeError("GitHub release disappeared after finalization.")
    final_assets = validate_release(
        final,
        tag=tag,
        title=title,
        prerelease=prerelease,
        expected_names=expected_names,
        allow_draft=False,
        require_immutable=True,
    )
    if set(final_assets) != {asset.name for asset in assets}:
        raise Rejected("Final GitHub release does not contain the complete immutable asset set.")
    for asset in assets:
        verify_remote_asset(client, repository, asset, final_assets[asset.name])
    return uploaded


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", default=os.environ.get("GITHUB_REPOSITORY"))
    parser.add_argument("--tag", required=True)
    parser.add_argument("--title", required=True)
    parser.add_argument("--prerelease", action="store_true")
    parser.add_argument("--draft-only", action="store_true")
    parser.add_argument("--allowed-asset-name", action="append", default=[])
    parser.add_argument("--guard-asset")
    parser.add_argument("--github-output", type=Path)
    parser.add_argument("assets", nargs="+")
    arguments = parser.parse_args()
    if not isinstance(arguments.repository, str) or REPOSITORY.fullmatch(arguments.repository) is None:
        parser.error("--repository must be an owner/repository name")
    if TAG.fullmatch(arguments.tag) is None:
        parser.error("--tag must be a canonical semantic-version release tag")
    if not arguments.title or "\n" in arguments.title or "\r" in arguments.title:
        parser.error("--title must be a non-empty single line")
    for name in arguments.allowed_asset_name:
        if name in {"", ".", ".."} or "/" in name or "\\" in name or len(name) > 255:
            parser.error("--allowed-asset-name must be a safe file name")
    if len(arguments.allowed_asset_name) != len(set(arguments.allowed_asset_name)):
        parser.error("--allowed-asset-name values must be unique")
    if arguments.allowed_asset_name and not arguments.draft_only:
        parser.error("--allowed-asset-name is only valid with --draft-only")
    if arguments.guard_asset and not arguments.draft_only:
        parser.error("--guard-asset is only valid with --draft-only")
    if arguments.guard_asset and arguments.guard_asset not in {Path(path).name for path in arguments.assets}:
        parser.error("--guard-asset must name one supplied local asset")
    return arguments


def main() -> int:
    arguments = parse_arguments()
    try:
        assets = inspect_assets(arguments.assets)
        uploaded = reconcile(
            repository=arguments.repository,
            tag=arguments.tag,
            title=arguments.title,
            prerelease=arguments.prerelease,
            assets=assets,
            client=GitHubClient(),
            draft_only=arguments.draft_only,
            allowed_asset_names=set(arguments.allowed_asset_name) or None,
        )
        if arguments.github_output is not None:
            arguments.github_output.parent.mkdir(parents=True, exist_ok=True)
            with arguments.github_output.open("a", encoding="utf-8") as output:
                output.write(f"guard_uploaded={'true' if arguments.guard_asset in uploaded else 'false'}\n")
    except (OSError, Rejected, RuntimeError) as error:
        print(f"release reconciliation rejected: {error}", file=sys.stderr)
        return 1
    state = "draft" if arguments.draft_only else "immutable release"
    print(f"Verified GitHub {state} {arguments.repository}@{arguments.tag}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
