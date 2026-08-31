#!/usr/bin/env python3
"""Build a reproducible, source-provenanced Latchway SDK documentation bundle."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import re
import stat
import subprocess
import tarfile
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CONFIG = ROOT / "docs-bundle.config.json"
SCHEMA = "latchway.sdk-documentation-bundle.v1"
SEMVER = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")


class BundleError(RuntimeError):
    pass


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def json_bytes(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")


def safe_relative(value: str) -> PurePosixPath:
    if not isinstance(value, str) or not value or "\\" in value or any(ord(char) < 32 for char in value):
        raise BundleError("bundle paths must be non-empty printable POSIX paths")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise BundleError(f"unsafe bundle path: {value}")
    return path


def source_file(relative: str) -> Path:
    path = safe_relative(relative)
    current = ROOT
    for part in path.parts:
        current = current / part
        try:
            mode = current.lstat().st_mode
        except FileNotFoundError as error:
            raise BundleError(f"source file does not exist: {relative}") from error
        if stat.S_ISLNK(mode):
            raise BundleError(f"source path must not contain symlinks: {relative}")
    if not stat.S_ISREG(current.lstat().st_mode):
        raise BundleError(f"source path is not a regular file: {relative}")
    if not current.resolve().is_relative_to(ROOT.resolve()):
        raise BundleError(f"source path escapes the repository: {relative}")
    return current


def git(*arguments: str) -> str:
    result = subprocess.run(
        ["git", *arguments], cwd=ROOT, check=True, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True, encoding="utf-8",
    )
    return result.stdout.strip()


def provenance(config: dict[str, Any], commit: str, spec: dict[str, Any]) -> tuple[bytes, dict[str, Any]]:
    relative = str(safe_relative(spec["file"]))
    raw = source_file(relative).read_bytes()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise BundleError(f"source file is not UTF-8: {relative}") from error
    lines = text.splitlines(keepends=True)
    start = spec.get("start_line", 1)
    end = spec.get("end_line", len(lines))
    if not isinstance(start, int) or not isinstance(end, int) or start < 1 or end < start or end > len(lines):
        raise BundleError(f"invalid source region {relative}:{start}-{end}")
    region = "".join(lines[start - 1:end]).encode("utf-8")
    return region, {
        "commit": commit,
        "file": relative,
        "region": {"start_line": start, "end_line": end},
        "region_sha256": sha256(region),
        "release": config["release"],
        "repository": config["repository"],
        "source_sha256": sha256(raw),
    }


def catalog_sources(entry: dict[str, Any]) -> list[dict[str, Any]]:
    if "file" in entry:
        return [entry]
    pattern = entry.get("glob")
    if (not isinstance(pattern, str) or not pattern or "\\" in pattern
            or any(ord(char) < 32 for char in pattern)):
        raise BundleError("catalog glob is invalid")
    candidate = PurePosixPath(pattern)
    if candidate.is_absolute() or any(part in {"", ".", ".."} for part in candidate.parts):
        raise BundleError("catalog glob is invalid")
    paths = sorted(path for path in ROOT.glob(pattern) if path.is_file())
    if not paths:
        raise BundleError(f"catalog glob matched no files: {pattern}")
    return [{"file": path.relative_to(ROOT).as_posix()} for path in paths]


def scan_catalog(config: dict[str, Any], commit: str, entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    seen: set[tuple[str, str, int]] = set()
    for entry in entries:
        expression = entry.get("pattern")
        if not isinstance(expression, str) or len(expression) > 1024:
            raise BundleError("catalog pattern is invalid")
        try:
            matcher = re.compile(expression)
        except re.error as error:
            raise BundleError("catalog pattern does not compile") from error
        for spec in catalog_sources(entry):
            region, source = provenance(config, commit, spec)
            text = region.decode("utf-8")
            for match in matcher.finditer(text):
                name = match.groupdict().get("name") or match.group(1)
                if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]*|[a-z][a-z0-9_]*", name):
                    raise BundleError(f"catalog produced invalid name: {name}")
                line = source["region"]["start_line"] + text.count("\n", 0, match.start())
                key = (name, source["file"], line)
                if key in seen:
                    continue
                seen.add(key)
                item_source = dict(source)
                item_source["region"] = {"start_line": line, "end_line": line}
                line_text = text.splitlines(keepends=True)[line - source["region"]["start_line"]]
                item_source["region_sha256"] = sha256(line_text.encode("utf-8"))
                results.append({"name": name, "source": item_source})
    if not results:
        raise BundleError("catalog must produce at least one entry")
    return sorted(results, key=lambda item: (item["name"], item["source"]["file"], item["source"]["region"]["start_line"]))


def generated_record(config: dict[str, Any], commit: str, entry: dict[str, Any]) -> dict[str, Any]:
    _, source = provenance(config, commit, entry["source"])
    value = {key: item for key, item in entry.items() if key != "source"}
    literal = value.get("version") or value.get("value")
    if isinstance(literal, str):
        region, _ = provenance(config, commit, entry["source"])
        if literal.encode("utf-8") not in region:
            raise BundleError(f"declared value {literal!r} is absent from {source['file']}")
    value["source"] = source
    return value


def add_payload(
    payloads: dict[str, bytes], manifest_files: list[dict[str, Any]], path: str,
    kind: str, data: bytes, sources: list[dict[str, Any]],
) -> None:
    relative = str(safe_relative(path))
    if relative in payloads or relative in {"bundle-manifest.json", "SHA256SUMS"}:
        raise BundleError(f"duplicate or reserved bundle path: {relative}")
    payloads[relative] = data
    manifest_files.append({
        "bytes": len(data), "kind": kind, "path": relative,
        "provenance": sources, "sha256": sha256(data),
    })


def verify_archive(path: Path, expected_root: str) -> None:
    expected = safe_relative(expected_root)
    if len(expected.parts) != 1:
        raise BundleError("archive root must be one safe path segment")
    seen: set[str] = set()
    with tarfile.open(path, "r:gz") as archive:
        members = archive.getmembers()
        if [member.name for member in members] != sorted(member.name for member in members):
            raise BundleError("archive members are not sorted")
        for member in members:
            if "\\" in member.name or any(ord(char) < 32 for char in member.name):
                raise BundleError(f"unsafe archive member: {member.name}")
            candidate = PurePosixPath(member.name)
            if (candidate.as_posix() != member.name or candidate.is_absolute() or not candidate.parts
                    or candidate.parts[0] != expected_root or ".." in candidate.parts):
                raise BundleError(f"unsafe archive member: {member.name}")
            safe_relative("/".join(candidate.parts[1:]))
            if member.name in seen or not member.isfile() or member.issym() or member.islnk():
                raise BundleError(f"invalid archive member: {member.name}")
            if (member.uid != 0 or member.gid != 0 or member.mode != 0o644
                    or member.uname != "" or member.gname != "" or member.pax_headers):
                raise BundleError(f"non-canonical archive metadata: {member.name}")
            seen.add(member.name)


def build(config_path: Path, output_dir: Path, version_override: str | None, commit_override: str | None,
          epoch_override: int | None, require_clean: bool) -> Path:
    config = json.loads(config_path.read_text(encoding="utf-8"))
    required = {"schema_version", "repository", "release", "version", "package", "documents", "supported_versions", "public_symbols", "errors", "examples"}
    if not isinstance(config, dict) or not required.issubset(config) or config["schema_version"] != 1:
        raise BundleError("documentation bundle configuration is invalid")
    version = version_override or config["version"]
    if not isinstance(version, str) or not SEMVER.fullmatch(version) or config["version"] != version or config["release"] != f"v{version}":
        raise BundleError("bundle version must equal the configured semantic release")
    commit = commit_override or git("rev-parse", "HEAD")
    if not COMMIT.fullmatch(commit):
        raise BundleError("bundle commit must be a full lowercase Git commit")
    if commit != git("rev-parse", "HEAD"):
        raise BundleError("bundle commit must equal the checked-out source commit")
    clean = git("status", "--porcelain", "--untracked-files=all") == ""
    if require_clean and not clean:
        raise BundleError("release documentation bundles require a clean source tree")
    if epoch_override is None:
        raw_epoch = os.environ.get("SOURCE_DATE_EPOCH") or git("show", "-s", "--format=%ct", commit)
        if not raw_epoch.isdigit():
            raise BundleError("SOURCE_DATE_EPOCH must be a non-negative integer")
        epoch = int(raw_epoch)
    else:
        epoch = epoch_override
    if epoch < 0 or epoch > 253402300799:
        raise BundleError("source date epoch is out of range")

    payloads: dict[str, bytes] = {}
    manifest_files: list[dict[str, Any]] = []
    for document in config["documents"]:
        data, source = provenance(config, commit, document["source"])
        add_payload(payloads, manifest_files, document["path"], document["kind"], data, [source])

    supported = [generated_record(config, commit, item) for item in config["supported_versions"]]
    examples = [generated_record(config, commit, item) for item in config["examples"]]
    public_symbols = scan_catalog(config, commit, config["public_symbols"])
    errors = scan_catalog(config, commit, config["errors"])
    catalogs = [
        ("supported-versions.json", "supported_versions", {"schema_version": 1, "versions": supported}, [item["source"] for item in supported]),
        ("public-symbols.json", "public_symbols", {"schema_version": 1, "symbols": public_symbols}, [item["source"] for item in public_symbols]),
        ("errors.json", "errors", {"errors": errors, "schema_version": 1}, [item["source"] for item in errors]),
        ("examples.json", "examples", {"examples": examples, "schema_version": 1}, [item["source"] for item in examples]),
    ]
    for path, kind, value, sources in catalogs:
        add_payload(payloads, manifest_files, path, kind, json_bytes(value), sources)

    generator_relative = Path(__file__).resolve().relative_to(ROOT).as_posix()
    manifest = {
        "archive": f"docs-bundle-{version}.tar.gz",
        "bundle_root": f"docs-bundle-{version}",
        "files": sorted(manifest_files, key=lambda item: item["path"]),
        "generator": {"file": generator_relative, "sha256": sha256(Path(__file__).read_bytes())},
        "package": config["package"],
        "release": {"commit": commit, "tag": config["release"], "version": version},
        "repository": config["repository"],
        "schema_version": SCHEMA,
        "source_date_epoch": epoch,
        "source_tree_clean": clean,
    }
    payloads["bundle-manifest.json"] = json_bytes(manifest)
    payloads["SHA256SUMS"] = "".join(
        f"{sha256(payloads[name])}  {name}\n" for name in sorted(payloads) if name != "SHA256SUMS"
    ).encode("ascii")

    output_dir.mkdir(parents=True, exist_ok=True)
    destination = output_dir / f"docs-bundle-{version}.tar.gz"
    root_name = f"docs-bundle-{version}"
    with tempfile.NamedTemporaryFile(prefix=".docs-bundle-", suffix=".tar.gz", dir=output_dir, delete=False) as temporary:
        temporary_path = Path(temporary.name)
        with gzip.GzipFile(filename="", mode="wb", fileobj=temporary, mtime=epoch, compresslevel=9) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT) as archive:
                for name in sorted(payloads):
                    data = payloads[name]
                    info = tarfile.TarInfo(f"{root_name}/{name}")
                    info.size = len(data)
                    info.mode = 0o644
                    info.mtime = epoch
                    info.uid = info.gid = 0
                    info.uname = info.gname = ""
                    archive.addfile(info, __import__("io").BytesIO(data))
        os.replace(temporary_path, destination)
    verify_archive(destination, root_name)
    return destination


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--output-dir", type=Path, default=ROOT / ".artifacts")
    parser.add_argument("--version")
    parser.add_argument("--commit")
    parser.add_argument("--source-date-epoch", type=int)
    parser.add_argument("--require-clean", action="store_true")
    arguments = parser.parse_args()
    try:
        result = build(arguments.config, arguments.output_dir, arguments.version, arguments.commit,
                       arguments.source_date_epoch, arguments.require_clean)
    except (BundleError, KeyError, TypeError, ValueError, json.JSONDecodeError, subprocess.CalledProcessError) as error:
        parser.exit(2, f"documentation bundle rejected: {error}\n")
    print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
