#!/usr/bin/env bash
set -euo pipefail

script_directory=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repository_root=$(cd "$script_directory/.." && pwd)
version=${LATCHWAY_PUBLICATION_TEST_VERSION:-1.0.0}
test_repository="$repository_root/build/publication-test-repository"

if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z][0-9A-Za-z.-]*)?$ ]]; then
  echo "LATCHWAY_PUBLICATION_TEST_VERSION must be a semantic version" >&2
  exit 64
fi

"$repository_root/gradlew" \
  --no-daemon \
  -Platchway.central.enabled=false \
  -Platchway.signing.enabled=false \
  -Platchway.version="$version" \
  cleanPublicationTestRepository \
  publishPublicArtifactsToPublicationTestRepository

"$script_directory/verify-publication-repository.sh" "$test_repository" "$version"

"$repository_root/gradlew" \
  --no-daemon \
  --no-configuration-cache \
  -p "$repository_root/publication-smoke" \
  -Platchway.testRepository="$test_repository" \
  -Platchway.metadataMode=gradle \
  -Platchway.version="$version" \
  verifyResolvedLatchwayArtifacts

"$repository_root/gradlew" \
  --no-daemon \
  --no-configuration-cache \
  -p "$repository_root/publication-smoke" \
  -Platchway.testRepository="$test_repository" \
  -Platchway.metadataMode=pom \
  -Platchway.version="$version" \
  verifyResolvedLatchwayArtifacts

"$repository_root/gradlew" \
  --no-daemon \
  --no-configuration-cache \
  --offline \
  -p "$repository_root/publication-smoke" \
  -Platchway.testRepository="$test_repository" \
  -Platchway.metadataMode=gradle \
  -Platchway.version="$version" \
  clean \
  assemble

"$repository_root/gradlew" \
  --no-daemon \
  --no-configuration-cache \
  --offline \
  -p "$repository_root/publication-smoke" \
  -Platchway.testRepository="$test_repository" \
  -Platchway.metadataMode=pom \
  -Platchway.version="$version" \
  clean \
  assemble

echo "Independent offline Android consumers compiled with Gradle metadata and POM-only resolution"
