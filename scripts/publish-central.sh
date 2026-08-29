#!/usr/bin/env bash
set -euo pipefail
set +x
umask 077

script_directory=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repository_root=$(cd "$script_directory/.." && pwd)

: "${LATCHWAY_RELEASE_VERSION:?Set LATCHWAY_RELEASE_VERSION to the exact release version}"

namespace=${LATCHWAY_MAVEN_CENTRAL_NAMESPACE:-dev.latchway}
publishing_type=${LATCHWAY_CENTRAL_PUBLISHING_TYPE:-user_managed}
intent=${LATCHWAY_CENTRAL_UPLOAD_INTENT:-}
deployment_record=${LATCHWAY_CENTRAL_DEPLOYMENT_RECORD:-}
deployment_status=${LATCHWAY_CENTRAL_DEPLOYMENT_STATUS:-}
allow_new_upload=${LATCHWAY_CENTRAL_ALLOW_NEW_UPLOAD:-false}
stop_after_record=${LATCHWAY_CENTRAL_STOP_AFTER_RECORD:-false}
status_attempts=${LATCHWAY_CENTRAL_STATUS_ATTEMPTS:-90}
status_delay=${LATCHWAY_CENTRAL_STATUS_DELAY_SECONDS:-20}
if [[ ! "$LATCHWAY_RELEASE_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "LATCHWAY_RELEASE_VERSION must be a stable semantic version" >&2
  exit 64
fi
if [[ ! "$namespace" =~ ^[A-Za-z0-9]+([._-][A-Za-z0-9]+)*$ ]]; then
  echo "LATCHWAY_MAVEN_CENTRAL_NAMESPACE is invalid" >&2
  exit 64
fi
case "$publishing_type" in
  user_managed|automatic) ;;
  *)
    echo "LATCHWAY_CENTRAL_PUBLISHING_TYPE must be user_managed or automatic" >&2
    exit 64
    ;;
esac
for boolean in "$allow_new_upload" "$stop_after_record"; do
  [[ "$boolean" == true || "$boolean" == false ]] || {
    echo "Central publication boolean settings must be true or false" >&2
    exit 64
  }
done
if [[ ! "$status_attempts" =~ ^[0-9]+$ || "$status_attempts" -lt 1 || "$status_attempts" -gt 180 ||
      ! "$status_delay" =~ ^[0-9]+$ || "$status_delay" -lt 1 || "$status_delay" -gt 60 ]]; then
  echo "Central deployment status retry settings are invalid" >&2
  exit 64
fi

if [[ -n "$(git -C "$repository_root" status --porcelain)" ]]; then
  echo "Refusing to stage a Maven Central release from a dirty worktree" >&2
  exit 1
fi

release_tag="v$LATCHWAY_RELEASE_VERSION"
head_commit=$(git -C "$repository_root" rev-parse HEAD)
tag_commit=$(git -C "$repository_root" rev-list -n 1 "$release_tag" 2>/dev/null || true)
if [[ "$tag_commit" != "$head_commit" && "${LATCHWAY_ALLOW_UNTAGGED_RELEASE_FOR_STAGING:-false}" != true ]]; then
  echo "HEAD must be tagged $release_tag before release staging" >&2
  exit 1
fi

modules=(latchway-core latchway-okhttp latchway-play-integrity latchway-firebase-auth latchway-bom)
central_base_url=${LATCHWAY_MAVEN_CENTRAL_BASE_URL:-https://repo1.maven.org/maven2/dev/latchway}
published_modules=0
for module in "${modules[@]}"; do
  central_pom="$central_base_url/$module/$LATCHWAY_RELEASE_VERSION/$module-$LATCHWAY_RELEASE_VERSION.pom"
  if ! central_code=$(curl \
    --proto '=https' --proto-redir '=https' --tlsv1.2 \
    --connect-timeout 15 --max-time 60 \
    --silent --show-error --location --head --output /dev/null \
    --write-out '%{http_code}' "$central_pom"); then
    echo "Could not prove Maven Central version availability for $module" >&2
    exit 1
  fi
  case "$central_code" in
    200) published_modules=$((published_modules + 1)) ;;
    404) ;;
    *)
      echo "Could not prove Maven Central version availability for $module (HTTP $central_code)" >&2
      exit 1
      ;;
  esac
done

if (( published_modules > 0 )) && [[ ! -e "$deployment_record" ]]; then
  # A partially propagated public release is never uploaded again. Wait for
  # every coordinate and prove every immutable public byte instead.
  expected_repository="$repository_root/build/release/repository"
  if [[ ! -d "$expected_repository/dev/latchway" ]]; then
    (
      unset LATCHWAY_MAVEN_CENTRAL_USERNAME LATCHWAY_MAVEN_CENTRAL_PASSWORD
      unset LATCHWAY_SIGNING_KEY LATCHWAY_SIGNING_PASSWORD
      LATCHWAY_PUBLICATION_TEST_VERSION="$LATCHWAY_RELEASE_VERSION" \
        "$script_directory/verify-local-publication.sh"
    )
    expected_repository="$repository_root/build/publication-test-repository"
  fi
  LATCHWAY_CENTRAL_EXPECTED_REPOSITORY="$expected_repository" \
    "$script_directory/verify-central-release.sh" "$LATCHWAY_RELEASE_VERSION"
  echo "dev.latchway:$LATCHWAY_RELEASE_VERSION already exists with the exact reviewed artifacts"
  exit 0
fi

[[ -n "$intent" && -f "$intent" && ! -L "$intent" ]] || {
  echo "An immutable Maven Central upload intent is required before any Portal action" >&2
  exit 64
}
[[ -n "$deployment_record" && -n "$deployment_status" ]] || {
  echo "Exact Central deployment record and status paths are required" >&2
  exit 64
}
intent_type=$(python3 "$script_directory/central-deployment-record.py" validate-intent \
  --intent "$intent" --field publishing_type)
intent_namespace=$(python3 "$script_directory/central-deployment-record.py" validate-intent \
  --intent "$intent" --field namespace)
intent_version=$(python3 "$script_directory/central-deployment-record.py" validate-intent \
  --intent "$intent" --field version)
intent_commit=$(python3 "$script_directory/central-deployment-record.py" validate-intent \
  --intent "$intent" --field source_commit)
[[ "$intent_type" == "$publishing_type" && "$intent_namespace" == "$namespace" &&
   "$intent_version" == "$LATCHWAY_RELEASE_VERSION" && "$intent_commit" == "$head_commit" ]] || {
  echo "Maven Central upload intent does not bind this exact release" >&2
  exit 1
}

temporary_root=$(mktemp -d "${TMPDIR:-/tmp}/latchway-central-publish.XXXXXX")
cleanup() {
  rm -rf "$temporary_root"
}
trap cleanup EXIT HUP INT TERM

portal_api=${LATCHWAY_CENTRAL_PORTAL_API_BASE_URL:-https://central.sonatype.com/api/v1/publisher}

configure_portal_authentication() {
  if [[ -z "${LATCHWAY_MAVEN_CENTRAL_USERNAME:-}" || -z "${LATCHWAY_MAVEN_CENTRAL_PASSWORD:-}" ]]; then
    echo "Maven Central Publisher Portal credentials are required" >&2
    exit 1
  fi
  local authorization
  authorization=$(printf '%s:%s' \
    "$LATCHWAY_MAVEN_CENTRAL_USERNAME" "$LATCHWAY_MAVEN_CENTRAL_PASSWORD" |
    base64 | tr -d '\r\n')
  header_file="$temporary_root/portal-header"
  printf 'Authorization: Bearer %s\n' "$authorization" >"$header_file"
  unset authorization LATCHWAY_MAVEN_CENTRAL_USERNAME LATCHWAY_MAVEN_CENTRAL_PASSWORD
}

query_status_once() {
  local deployment_id=$1
  local raw_status=$2
  local code
  if ! code=$(curl \
    --proto '=https' --proto-redir '=https' --tlsv1.2 \
    --connect-timeout 15 --max-time 120 --max-filesize 2097152 \
    --silent --show-error --request POST --header "@$header_file" \
    --output "$raw_status" --write-out '%{http_code}' \
    "$portal_api/status?id=$deployment_id"); then
    echo "Could not query the exact Maven Central deployment" >&2
    return 1
  fi
  [[ "$code" == 200 ]] || {
    echo "Maven Central deployment status returned HTTP $code" >&2
    return 1
  }
}

normalize_status() {
  local raw_status=$1
  local normalized_status=$2
  rm -f "$normalized_status"
  python3 "$script_directory/central-deployment-record.py" validate-status \
    --intent "$intent" --record "$deployment_record" \
    --status "$raw_status" --output "$normalized_status"
}

persist_terminal_status() {
  local normalized_status=$1
  if [[ -e "$deployment_status" ]]; then
    cmp -s "$normalized_status" "$deployment_status" || {
      echo "Existing immutable Central deployment status differs" >&2
      exit 1
    }
  else
    mkdir -p "$(dirname "$deployment_status")"
    cp "$normalized_status" "$deployment_status"
    chmod 600 "$deployment_status"
  fi
}

wait_for_deployment() {
  local deployment_id=$1
  local raw_status="$temporary_root/portal-status.json"
  local normalized_status="$temporary_root/portal-status-evidence.json"
  local state
  for ((attempt = 1; attempt <= status_attempts; attempt++)); do
    query_status_once "$deployment_id" "$raw_status"
    state=$(normalize_status "$raw_status" "$normalized_status")
    case "$state" in
      PUBLISHED)
        persist_terminal_status "$normalized_status"
        echo "Maven Central deployment $deployment_id is PUBLISHED"
        return 0
        ;;
      VALIDATED)
        if [[ "$publishing_type" == user_managed ]]; then
          echo "Maven Central deployment $deployment_id is VALIDATED for operator publication"
          return 0
        fi
        ;;
      FAILED)
        persist_terminal_status "$normalized_status"
        echo "Maven Central deployment $deployment_id failed validation" >&2
        return 1
        ;;
      PENDING|VALIDATING|PUBLISHING) ;;
      *)
        echo "Maven Central returned an unreviewed deployment state" >&2
        return 1
        ;;
    esac
    if (( attempt < status_attempts )); then
      sleep "$status_delay"
    fi
  done
  echo "Maven Central deployment did not reach a terminal state within the verification window" >&2
  return 1
}

if [[ -e "$deployment_record" ]]; then
  deployment_id=$(python3 "$script_directory/central-deployment-record.py" validate-record \
    --intent "$intent" --record "$deployment_record" --field deployment_id)
  recorded_type=$(python3 "$script_directory/central-deployment-record.py" validate-record \
    --intent "$intent" --record "$deployment_record" --field publishing_type)
  [[ "$recorded_type" == "$publishing_type" ]] || {
    echo "Central deployment publishing type differs from the immutable record" >&2
    exit 1
  }
  if [[ "$stop_after_record" == true ]]; then
    echo "Validated exact Maven Central deployment record $deployment_id without uploading"
    exit 0
  fi
  configure_portal_authentication
  wait_for_deployment "$deployment_id"
  exit 0
fi

if [[ "$allow_new_upload" != true ]]; then
  echo "Upload intent already exists but its exact Portal deployment ID is absent; refusing a second upload" >&2
  echo "Recover the original deployment ID from the Central Portal and create the reviewed deployment record" >&2
  exit 1
fi
if [[ -z "${LATCHWAY_SIGNING_KEY:-}" || -z "${LATCHWAY_SIGNING_PASSWORD:-}" ]]; then
  echo "In-memory OpenPGP signing material is required for a new Central deployment" >&2
  exit 1
fi

expected_repository="$repository_root/build/release/repository"
if [[ ! -d "$expected_repository/dev/latchway" ]]; then
  "$script_directory/build-release-artifacts.sh" "$LATCHWAY_RELEASE_VERSION"
fi
reviewed_archive="$repository_root/build/release/latchway-android-$LATCHWAY_RELEASE_VERSION-maven-repository.zip"
reviewed_public_key=${LATCHWAY_CENTRAL_SIGNING_PUBLIC_KEY:-}
python3 "$script_directory/central-deployment-record.py" validate-inputs \
  --intent "$intent" \
  --repository "$expected_repository" \
  --archive "$reviewed_archive" \
  --public-key "$reviewed_public_key"

skip_local_gates=${LATCHWAY_CENTRAL_SKIP_LOCAL_GATES:-false}
if [[ "$skip_local_gates" == false ]]; then
  (
    unset LATCHWAY_MAVEN_CENTRAL_USERNAME LATCHWAY_MAVEN_CENTRAL_PASSWORD
    unset LATCHWAY_SIGNING_KEY LATCHWAY_SIGNING_PASSWORD
    LATCHWAY_PUBLICATION_TEST_VERSION="$LATCHWAY_RELEASE_VERSION" \
      "$script_directory/verify-local-publication.sh"
  )
  (
    unset LATCHWAY_MAVEN_CENTRAL_USERNAME LATCHWAY_MAVEN_CENTRAL_PASSWORD
    unset LATCHWAY_SIGNING_KEY LATCHWAY_SIGNING_PASSWORD
    "$repository_root/gradlew" --no-daemon \
      -Platchway.central.enabled=false -Platchway.signing.enabled=false \
      -Platchway.version="$LATCHWAY_RELEASE_VERSION" test assemble lint
  )
elif [[ "$skip_local_gates" != true ]]; then
  echo "LATCHWAY_CENTRAL_SKIP_LOCAL_GATES must be true or false" >&2
  exit 64
fi

bundle="$temporary_root/latchway-android-$LATCHWAY_RELEASE_VERSION-central-portal.zip"
LATCHWAY_CENTRAL_EXPECTED_REPOSITORY="$expected_repository" \
  "$script_directory/build-central-portal-bundle.sh" "$LATCHWAY_RELEASE_VERSION" "$bundle"
unset LATCHWAY_SIGNING_KEY LATCHWAY_SIGNING_PASSWORD

deployment_name=$(python3 "$script_directory/central-deployment-record.py" validate-intent \
  --intent "$intent" --field deployment_name)
configure_portal_authentication
case "$publishing_type" in
  automatic) portal_publishing_type=AUTOMATIC ;;
  user_managed) portal_publishing_type=USER_MANAGED ;;
esac
response="$temporary_root/upload-response"
if ! upload_code=$(curl \
  --proto '=https' --proto-redir '=https' --tlsv1.2 \
  --connect-timeout 15 --max-time 900 \
  --silent --show-error --request POST --header "@$header_file" \
  --form "bundle=@$bundle;type=application/octet-stream" \
  --output "$response" --write-out '%{http_code}' \
  "$portal_api/upload?name=$deployment_name&publishingType=$portal_publishing_type"); then
  echo "Central Portal upload outcome is uncertain; the immutable intent forbids retrying without the exact deployment ID" >&2
  exit 1
fi
[[ "$upload_code" == 201 ]] || {
  echo "Central Portal rejected the deployment upload with HTTP $upload_code" >&2
  exit 1
}
deployment_id=$(tr -d '[:space:]' <"$response")
python3 "$script_directory/central-deployment-record.py" create-record \
  --intent "$intent" --deployment-id "$deployment_id" --output "$deployment_record"
echo "Recorded exact Maven Central deployment $deployment_id"

if [[ "$stop_after_record" == true ]]; then
  exit 0
fi
wait_for_deployment "$deployment_id"
