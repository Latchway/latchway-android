#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 || ! "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "usage: $0 MAJOR.MINOR.PATCH" >&2
  exit 64
fi

version=$1
script_directory=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repository_root=$(cd "$script_directory/.." && pwd)
temporary_root=$(mktemp -d "${TMPDIR:-/tmp}/latchway-android-release.XXXXXX")
cleanup() {
  rm -rf "$temporary_root"
}
trap cleanup EXIT HUP INT TERM

modules=(
  latchway-core
  latchway-okhttp
  latchway-play-integrity
  latchway-firebase-auth
  latchway-bom
)

snapshot_repository() {
  local destination=$1
  mkdir -p "$destination/dev/latchway"
  for module in "${modules[@]}"; do
    mkdir -p "$destination/dev/latchway/$module"
    cp -R \
      "$repository_root/build/publication-test-repository/dev/latchway/$module/$version" \
      "$destination/dev/latchway/$module/$version"
  done
}

LATCHWAY_PUBLICATION_TEST_VERSION="$version" "$script_directory/verify-local-publication.sh"
snapshot_repository "$temporary_root/first"
LATCHWAY_PUBLICATION_TEST_VERSION="$version" "$script_directory/verify-local-publication.sh"
snapshot_repository "$temporary_root/second"
diff -ru "$temporary_root/first" "$temporary_root/second"

release_directory="$repository_root/build/release"
rm -rf "$release_directory"
mkdir -p "$release_directory/repository"
cp -R "$temporary_root/second/dev" "$release_directory/repository/dev"
find "$release_directory/repository" -exec touch -t 198001010000 {} +

archive="$release_directory/latchway-android-$version-maven-repository.zip"
(
  cd "$release_directory/repository"
  find . -type f -print | LC_ALL=C sort | zip -X -q "$archive" -@
)
(
  cd "$release_directory"
  shasum -a 256 "${archive##*/}" >SHA256SUMS
)

echo "Built reproducible Android release bundle ${archive##*/}"
