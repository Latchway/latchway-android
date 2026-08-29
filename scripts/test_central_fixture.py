"""Exact Maven repository fixtures shared by release-policy tests."""

from __future__ import annotations

import hashlib
import zipfile
from pathlib import Path


MODULES = (
    "latchway-core", "latchway-okhttp", "latchway-play-integrity",
    "latchway-firebase-auth", "latchway-bom",
)
ALGORITHMS = ("md5", "sha1", "sha256", "sha512")


def primary_paths(version: str) -> list[str]:
    result: list[str] = []
    for module in MODULES:
        extensions = ["pom", "module", "sources.jar", "javadoc.jar"]
        if module != "latchway-bom":
            extensions.append("aar")
        for extension in extensions:
            separator = "." if extension in {"pom", "module", "aar"} else "-"
            result.append(
                f"dev/latchway/{module}/{version}/{module}-{version}{separator}{extension}"
            )
    return sorted(result)


def write_zip(path: Path, repository: Path, *, signed: bool) -> None:
    entries = sorted(item for item in repository.rglob("*") if item.is_file())
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as output:
        for item in entries:
            relative = item.relative_to(repository).as_posix()
            info = zipfile.ZipInfo(relative, (1980, 1, 1, 0, 0, 0))
            info.external_attr = 0o100644 << 16
            output.writestr(info, item.read_bytes())
        if signed:
            for relative in primary_paths(_version_from_repository(repository)):
                info = zipfile.ZipInfo(f"{relative}.asc", (1980, 1, 1, 0, 0, 0))
                info.external_attr = 0o100644 << 16
                output.writestr(info, b"-----BEGIN PGP SIGNATURE-----\nfixture\n")


def _version_from_repository(repository: Path) -> str:
    sample = next(repository.glob("dev/latchway/*/*"))
    return sample.name


def create_release_inputs(root: Path, version: str = "1.0.0") -> tuple[Path, Path, Path, Path]:
    repository = root / "repository"
    for relative in primary_paths(version):
        artifact = repository / relative
        artifact.parent.mkdir(parents=True, exist_ok=True)
        artifact.write_bytes(f"fixture:{relative}\n".encode())
        payload = artifact.read_bytes()
        for algorithm in ALGORITHMS:
            (repository / f"{relative}.{algorithm}").write_text(
                hashlib.new(algorithm, payload).hexdigest(), encoding="ascii",
            )
    archive = root / f"latchway-android-{version}-maven-repository.zip"
    portal_bundle = root / f"latchway-android-{version}-central-portal.zip"
    write_zip(archive, repository, signed=False)
    write_zip(portal_bundle, repository, signed=True)
    public_key = root / "latchway-maven-signing-public-key.asc"
    public_key.write_bytes(b"reviewed public key")
    return repository, archive, portal_bundle, public_key
