#!/usr/bin/env bash
set -euo pipefail
set +x
umask 077

script_directory=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repository_root=$(cd "$script_directory/.." && pwd)

: "${LATCHWAY_RELEASE_VERSION:?Set LATCHWAY_RELEASE_VERSION to the exact release version}"
: "${LATCHWAY_MAVEN_CENTRAL_USERNAME:?Set the Maven Central Portal token username}"
: "${LATCHWAY_MAVEN_CENTRAL_PASSWORD:?Set the Maven Central Portal token password}"
: "${LATCHWAY_SIGNING_KEY:?Set the ASCII-armored OpenPGP private key}"
: "${LATCHWAY_SIGNING_PASSWORD:?Set the OpenPGP private-key password}"

namespace=${LATCHWAY_MAVEN_CENTRAL_NAMESPACE:-dev.latchway}
publishing_type=${LATCHWAY_CENTRAL_PUBLISHING_TYPE:-user_managed}
if [[ ! "$LATCHWAY_RELEASE_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z][0-9A-Za-z.-]*)?$ ]]; then
  echo "LATCHWAY_RELEASE_VERSION must be a non-SNAPSHOT semantic version" >&2
  exit 64
fi
if [[ "$LATCHWAY_RELEASE_VERSION" == *-SNAPSHOT ]]; then
  echo "Maven Central releases cannot use a SNAPSHOT version" >&2
  exit 64
fi
if [[ ! "$namespace" =~ ^[A-Za-z0-9]+([._-][A-Za-z0-9]+)*$ ]]; then
  echo "LATCHWAY_MAVEN_CENTRAL_NAMESPACE is invalid" >&2
  exit 64
fi
case "$publishing_type" in
  user_managed|automatic|portal_api) ;;
  *)
    echo "LATCHWAY_CENTRAL_PUBLISHING_TYPE must be user_managed, automatic, or portal_api" >&2
    exit 64
    ;;
esac

if [[ -n "$(git -C "$repository_root" status --porcelain)" ]]; then
  echo "Refusing to stage a Maven Central release from a dirty worktree" >&2
  exit 1
fi

release_tag="v$LATCHWAY_RELEASE_VERSION"
head_commit=$(git -C "$repository_root" rev-parse HEAD)
tag_commit=$(git -C "$repository_root" rev-list -n 1 "$release_tag" 2>/dev/null || true)
if [[ "$tag_commit" != "$head_commit" && "${LATCHWAY_ALLOW_UNTAGGED_RELEASE_FOR_STAGING:-false}" != "true" ]]; then
  echo "HEAD must be tagged $release_tag before release staging" >&2
  exit 1
fi

central_pom="https://repo1.maven.org/maven2/dev/latchway/latchway-core/$LATCHWAY_RELEASE_VERSION/latchway-core-$LATCHWAY_RELEASE_VERSION.pom"
central_status=$(curl --silent --show-error --location --head --output /dev/null --write-out '%{http_code}' "$central_pom")
case "$central_status" in
  404) ;;
  200)
    echo "dev.latchway:latchway-core:$LATCHWAY_RELEASE_VERSION already exists on Maven Central" >&2
    exit 1
    ;;
  *)
    echo "Could not prove Maven Central version availability (HTTP $central_status)" >&2
    exit 1
    ;;
esac

(
  unset LATCHWAY_MAVEN_CENTRAL_USERNAME
  unset LATCHWAY_MAVEN_CENTRAL_PASSWORD
  unset LATCHWAY_SIGNING_KEY
  unset LATCHWAY_SIGNING_PASSWORD
  LATCHWAY_PUBLICATION_TEST_VERSION="$LATCHWAY_RELEASE_VERSION" \
    "$script_directory/verify-local-publication.sh"
)

(
  unset LATCHWAY_MAVEN_CENTRAL_USERNAME
  unset LATCHWAY_MAVEN_CENTRAL_PASSWORD
  unset LATCHWAY_SIGNING_KEY
  unset LATCHWAY_SIGNING_PASSWORD
  "$repository_root/gradlew" \
    --no-daemon \
    -Platchway.central.enabled=false \
    -Platchway.signing.enabled=false \
    -Platchway.version="$LATCHWAY_RELEASE_VERSION" \
    test \
    assemble \
    lint
)

"$repository_root/gradlew" \
  --no-daemon \
  --no-configuration-cache \
  -Platchway.central.enabled=true \
  -Platchway.version="$LATCHWAY_RELEASE_VERSION" \
  publishPublicArtifactsToCentralRepository

unset LATCHWAY_SIGNING_KEY
unset LATCHWAY_SIGNING_PASSWORD
authorization=$(printf '%s:%s' \
  "$LATCHWAY_MAVEN_CENTRAL_USERNAME" \
  "$LATCHWAY_MAVEN_CENTRAL_PASSWORD" | base64 | tr -d '\r\n')
header_file=$(mktemp "${TMPDIR:-/tmp}/latchway-central-header.XXXXXX")
cleanup() {
  rm -f "$header_file"
}
trap cleanup EXIT HUP INT TERM
printf 'Authorization: Bearer %s\n' "$authorization" >"$header_file"
unset authorization
unset LATCHWAY_MAVEN_CENTRAL_USERNAME
unset LATCHWAY_MAVEN_CENTRAL_PASSWORD

curl \
  --fail-with-body \
  --silent \
  --show-error \
  --request POST \
  --header "@$header_file" \
  "https://ossrh-staging-api.central.sonatype.com/manual/upload/defaultRepository/$namespace?publishing_type=$publishing_type"
printf '\nArtifacts transferred to the Maven Central Portal with publishing type %s.\n' "$publishing_type"
