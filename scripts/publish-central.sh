#!/usr/bin/env bash
set -euo pipefail
set +x
umask 077

script_directory=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repository_root=$(cd "$script_directory/.." && pwd)

# This process performs network publication and must never receive private
# signing material; signing is completed in a separate, pre-upload step.
if [[ -n "${LATCHWAY_SIGNING_KEY:-}" || -n "${LATCHWAY_SIGNING_PASSWORD:-}" ]]; then
  echo "Private signing material must not be exposed to the Portal publisher" >&2
  exit 64
fi
if [[ -n "${LATCHWAY_ALLOW_UNTAGGED_RELEASE_FOR_STAGING:-}" ||
      -n "${LATCHWAY_CENTRAL_SKIP_LOCAL_GATES:-}" ||
      -n "${LATCHWAY_CENTRAL_PUBLISH_AFTER_VALIDATION:-}" ]]; then
  echo "Maven Central publication bypass variables are forbidden" >&2
  exit 64
fi

# Copy credentials into non-exported shell variables, then remove the original
# environment entries before git, Gradle, Python, or unauthenticated curl runs.
portal_username=${LATCHWAY_MAVEN_CENTRAL_USERNAME:-}
portal_password=${LATCHWAY_MAVEN_CENTRAL_PASSWORD:-}
unset LATCHWAY_MAVEN_CENTRAL_USERNAME LATCHWAY_MAVEN_CENTRAL_PASSWORD

: "${LATCHWAY_RELEASE_VERSION:?Set LATCHWAY_RELEASE_VERSION to the exact release version}"
namespace=${LATCHWAY_MAVEN_CENTRAL_NAMESPACE:-dev.latchway}
publishing_type=${LATCHWAY_CENTRAL_PUBLISHING_TYPE:-user_managed}
intent=${LATCHWAY_CENTRAL_UPLOAD_INTENT:-}
deployment_record=${LATCHWAY_CENTRAL_DEPLOYMENT_RECORD:-}
deployment_status=${LATCHWAY_CENTRAL_DEPLOYMENT_STATUS:-}
portal_bundle=${LATCHWAY_CENTRAL_PORTAL_BUNDLE:-}
intent_fresh=${LATCHWAY_CENTRAL_INTENT_FRESH:-false}
stop_after_record=${LATCHWAY_CENTRAL_STOP_AFTER_RECORD:-false}
status_attempts=${LATCHWAY_CENTRAL_STATUS_ATTEMPTS:-90}
status_delay=${LATCHWAY_CENTRAL_STATUS_DELAY_SECONDS:-20}
adoption_attempts=${LATCHWAY_CENTRAL_ADOPTION_ATTEMPTS:-30}
adoption_delay=${LATCHWAY_CENTRAL_ADOPTION_DELAY_SECONDS:-10}

[[ "$LATCHWAY_RELEASE_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || {
  echo "LATCHWAY_RELEASE_VERSION must be a stable semantic version" >&2
  exit 64
}
[[ "$namespace" =~ ^[A-Za-z0-9]+([._-][A-Za-z0-9]+)*$ ]] || {
  echo "LATCHWAY_MAVEN_CENTRAL_NAMESPACE is invalid" >&2
  exit 64
}
[[ "$publishing_type" == user_managed ]] || {
  echo "Central releases must be staged with recoverable user_managed publication" >&2
  exit 64
}
for boolean in "$intent_fresh" "$stop_after_record"; do
  [[ "$boolean" == true || "$boolean" == false ]] || {
    echo "Central publication boolean settings must be true or false" >&2
    exit 64
  }
done
for value in "$status_attempts" "$status_delay" "$adoption_attempts" "$adoption_delay"; do
  [[ "$value" =~ ^[0-9]+$ ]] || { echo "Central retry settings are invalid" >&2; exit 64; }
done
(( status_attempts >= 1 && status_attempts <= 180 && status_delay >= 1 && status_delay <= 60 )) || {
  echo "Central deployment status retry settings are invalid" >&2
  exit 64
}
(( adoption_attempts >= 1 && adoption_attempts <= 180 && adoption_delay >= 1 && adoption_delay <= 60 )) || {
  echo "Central deployment adoption retry settings are invalid" >&2
  exit 64
}

if [[ -n "$(git -C "$repository_root" status --porcelain)" ]]; then
  echo "Refusing to stage a Maven Central release from a dirty worktree" >&2
  exit 1
fi
release_tag="v$LATCHWAY_RELEASE_VERSION"
head_commit=$(git -C "$repository_root" rev-parse HEAD)
tag_type=$(git -C "$repository_root" cat-file -t "refs/tags/$release_tag" 2>/dev/null || true)
tag_commit=$(git -C "$repository_root" rev-list -n 1 "$release_tag" 2>/dev/null || true)
if [[ "$tag_type" != tag || "$tag_commit" != "$head_commit" ]]; then
  echo "HEAD must have the exact annotated tag $release_tag before release staging" >&2
  exit 1
fi

[[ -n "$intent" && -f "$intent" && ! -L "$intent" ]] || {
  echo "An immutable Maven Central upload intent is required before any Portal action" >&2
  exit 64
}
[[ -n "$deployment_record" && -n "$deployment_status" ]] || {
  echo "Exact Central deployment record and status paths are required" >&2
  exit 64
}
expected_repository="$repository_root/build/release/repository"
reviewed_archive="$repository_root/build/release/latchway-android-$LATCHWAY_RELEASE_VERSION-maven-repository.zip"
reviewed_public_key=${LATCHWAY_CENTRAL_SIGNING_PUBLIC_KEY:-}
[[ -n "$portal_bundle" ]] || {
  echo "The pre-signed, reviewed Central Portal bundle is required" >&2
  exit 64
}
intent_type=$(python3 "$script_directory/central-deployment-record.py" validate-intent --intent "$intent" --field publishing_type)
intent_namespace=$(python3 "$script_directory/central-deployment-record.py" validate-intent --intent "$intent" --field namespace)
intent_version=$(python3 "$script_directory/central-deployment-record.py" validate-intent --intent "$intent" --field version)
intent_commit=$(python3 "$script_directory/central-deployment-record.py" validate-intent --intent "$intent" --field source_commit)
[[ "$intent_type" == "$publishing_type" && "$intent_namespace" == "$namespace" &&
   "$intent_version" == "$LATCHWAY_RELEASE_VERSION" && "$intent_commit" == "$head_commit" ]] || {
  echo "Maven Central upload intent does not bind this exact release" >&2
  exit 1
}
python3 "$script_directory/central-deployment-record.py" validate-inputs \
  --intent "$intent" --repository "$expected_repository" --archive "$reviewed_archive" \
  --portal-bundle "$portal_bundle" --public-key "$reviewed_public_key"

temporary_root=$(mktemp -d "${TMPDIR:-/tmp}/latchway-central-publish.XXXXXX")
cleanup() { rm -rf "$temporary_root"; }
trap cleanup EXIT HUP INT TERM
portal_api=${LATCHWAY_CENTRAL_PORTAL_API_BASE_URL:-https://central.sonatype.com/api/v1/publisher}
header_file="$temporary_root/portal-header"
local_release_gates_complete=false

run_local_release_gates() {
  [[ "$local_release_gates_complete" == false ]] || return 0
  LATCHWAY_PUBLICATION_TEST_VERSION="$LATCHWAY_RELEASE_VERSION" "$script_directory/verify-local-publication.sh"
  "$repository_root/gradlew" --no-daemon \
    -Platchway.central.enabled=false -Platchway.signing.enabled=false \
    -Platchway.version="$LATCHWAY_RELEASE_VERSION" test assemble lint
  local_release_gates_complete=true
}

configure_portal_authentication() {
  [[ -e "$header_file" ]] && return 0
  if [[ -z "$portal_username" || -z "$portal_password" ]]; then
    echo "Maven Central Publisher Portal credentials are required" >&2
    exit 1
  fi
  local authorization
  authorization=$(printf '%s:%s' "$portal_username" "$portal_password" | base64 | tr -d '\r\n')
  printf 'Authorization: Bearer %s\n' "$authorization" >"$header_file"
  unset authorization portal_username portal_password
}

query_deployments_once() {
  local output=$1 code
  if ! code=$(curl \
    --proto '=https' --proto-redir '=https' --tlsv1.2 \
    --connect-timeout 15 --max-time 120 --max-filesize 2097152 \
    --silent --show-error --get --header "@$header_file" \
    --data-urlencode "namespace=$namespace" \
    --data-urlencode "deploymentName=$deployment_name" \
    --data "page=0" --data "size=100" --data "sortField=createTimestamp" --data "sortDirection=desc" \
    --output "$output" --write-out '%{http_code}' "$portal_api/deployments"); then
    echo "Could not list Maven Central deployments for deterministic recovery" >&2
    return 1
  fi
  [[ "$code" == 200 ]] || {
    echo "Maven Central deployment listing returned HTTP $code" >&2
    return 1
  }
}

find_existing_deployment() {
  local attempts=$1 listing="$temporary_root/deployments.json" candidate
  for ((attempt = 1; attempt <= attempts; attempt++)); do
    query_deployments_once "$listing" || return 2
    if ! candidate=$(python3 "$script_directory/central-deployment-record.py" select-deployment \
      --intent "$intent" --listing "$listing"); then
      return 2
    fi
    if [[ -n "$candidate" ]]; then
      printf '%s\n' "$candidate"
      return 0
    fi
    if (( attempt < attempts )); then sleep "$adoption_delay"; fi
  done
  return 1
}

query_status_once() {
  local deployment_id=$1 raw_status=$2 code
  if ! code=$(curl \
    --proto '=https' --proto-redir '=https' --tlsv1.2 \
    --connect-timeout 15 --max-time 120 --max-filesize 2097152 \
    --silent --show-error --request POST --header "@$header_file" \
    --output "$raw_status" --write-out '%{http_code}' "$portal_api/status?id=$deployment_id"); then
    echo "Could not query the exact Maven Central deployment" >&2
    return 1
  fi
  [[ "$code" == 200 ]] || { echo "Maven Central deployment status returned HTTP $code" >&2; return 1; }
}

normalize_status() {
  local raw_status=$1 normalized_status=$2
  rm -f "$normalized_status"
  python3 "$script_directory/central-deployment-record.py" validate-status \
    --intent "$intent" --record "$deployment_record" --status "$raw_status" --output "$normalized_status"
}

persist_status() {
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
  local deployment_id=$1 raw_status="$temporary_root/portal-status.json"
  local normalized_status="$temporary_root/portal-status-evidence.json" state
  for ((attempt = 1; attempt <= status_attempts; attempt++)); do
    query_status_once "$deployment_id" "$raw_status"
    state=$(normalize_status "$raw_status" "$normalized_status")
    case "$state" in
      PUBLISHED)
        persist_status "$normalized_status"
        echo "Maven Central deployment $deployment_id is PUBLISHED"
        return 0
        ;;
      VALIDATED)
        echo "Maven Central deployment $deployment_id is VALIDATED for protected-workflow publication"
        return 0
        ;;
      FAILED)
        persist_status "$normalized_status"
        echo "Maven Central deployment $deployment_id failed validation" >&2
        return 1
        ;;
      PENDING|VALIDATING|PUBLISHING) ;;
      *) echo "Maven Central returned an unreviewed deployment state" >&2; return 1 ;;
    esac
    if (( attempt < status_attempts )); then sleep "$status_delay"; fi
  done
  echo "Maven Central deployment did not reach the required state within the verification window" >&2
  return 1
}

# Public coordinates are an authoritative recovery source if Portal history is
# unavailable. Emit a complete adoption record/status rather than returning
# without the durable state required by final verification.
modules=(latchway-core latchway-okhttp latchway-play-integrity latchway-firebase-auth latchway-bom)
central_base_url=${LATCHWAY_MAVEN_CENTRAL_BASE_URL:-https://repo1.maven.org/maven2/dev/latchway}
published_modules=0
for module in "${modules[@]}"; do
  central_pom="$central_base_url/$module/$LATCHWAY_RELEASE_VERSION/$module-$LATCHWAY_RELEASE_VERSION.pom"
  if ! central_code=$(curl \
    --proto '=https' --proto-redir '=https' --tlsv1.2 --connect-timeout 15 --max-time 60 \
    --silent --show-error --location --head --output /dev/null --write-out '%{http_code}' "$central_pom"); then
    echo "Could not prove Maven Central version availability for $module" >&2
    exit 1
  fi
  case "$central_code" in
    200) published_modules=$((published_modules + 1)) ;;
    404) ;;
    *) echo "Could not prove Maven Central version availability for $module (HTTP $central_code)" >&2; exit 1 ;;
  esac
done
if (( published_modules > 0 )); then
  public_evidence="$temporary_root/public-adoption-evidence.json"
  LATCHWAY_CENTRAL_EXPECTED_REPOSITORY="$expected_repository" \
    "$script_directory/verify-central-release.sh" "$LATCHWAY_RELEASE_VERSION" >"$public_evidence"
  if [[ ! -e "$deployment_record" ]]; then
    python3 "$script_directory/central-deployment-record.py" create-adoption-record \
      --intent "$intent" --public-evidence "$public_evidence" --output "$deployment_record"
  fi
  public_record_kind=$(python3 "$script_directory/central-deployment-record.py" validate-record \
    --intent "$intent" --record "$deployment_record" --field record_kind)
  if [[ "$public_record_kind" == public_registry_adoption ]]; then
    python3 "$script_directory/central-deployment-record.py" create-adoption-status \
      --intent "$intent" --record "$deployment_record" --public-evidence "$public_evidence" --output "$deployment_status"
    echo "Recorded complete public-registry adoption for dev.latchway:$LATCHWAY_RELEASE_VERSION"
    exit 0
  fi
fi

if [[ -e "$deployment_record" ]]; then
  record_kind=$(python3 "$script_directory/central-deployment-record.py" validate-record \
    --intent "$intent" --record "$deployment_record" --field record_kind)
  if [[ "$record_kind" == public_registry_adoption ]]; then
    [[ -e "$deployment_status" ]] || { echo "Public adoption status evidence is missing" >&2; exit 1; }
    echo "Validated complete public-registry adoption record"
    exit 0
  fi
  deployment_id=$(python3 "$script_directory/central-deployment-record.py" validate-record \
    --intent "$intent" --record "$deployment_record" --field deployment_id)
  if [[ "$stop_after_record" == true ]]; then
    echo "Validated exact Maven Central deployment record $deployment_id without publishing"
    exit 0
  fi
  configure_portal_authentication
  wait_for_deployment "$deployment_id"
  exit 0
fi

run_local_release_gates

deployment_name=$(python3 "$script_directory/central-deployment-record.py" validate-intent \
  --intent "$intent" --field deployment_name)
configure_portal_authentication
lookup_attempts=$adoption_attempts
[[ "$intent_fresh" == true ]] && lookup_attempts=1
lookup_result=0
if deployment_id=$(find_existing_deployment "$lookup_attempts"); then
  lookup_result=0
else
  lookup_result=$?
fi
if [[ "$lookup_result" == 2 ]]; then
  echo "Central deterministic deployment reconciliation failed closed" >&2
  exit 1
elif [[ -n "$deployment_id" ]]; then
  python3 "$script_directory/central-deployment-record.py" create-record \
    --intent "$intent" --deployment-id "$deployment_id" --output "$deployment_record"
  echo "Adopted exact existing Maven Central deployment $deployment_id"
else
  response="$temporary_root/upload-response"
  upload_code=
  upload_succeeded=false
  if upload_code=$(curl \
    --proto '=https' --proto-redir '=https' --tlsv1.2 --connect-timeout 15 --max-time 900 \
    --silent --show-error --request POST --header "@$header_file" \
    --form "bundle=@$portal_bundle;type=application/octet-stream" \
    --output "$response" --write-out '%{http_code}' \
    "$portal_api/upload?name=$deployment_name&publishingType=USER_MANAGED"); then
    [[ "$upload_code" == 201 ]] && upload_succeeded=true
  fi
  if [[ "$upload_succeeded" == true ]]; then
    deployment_id=$(tr -d '[:space:]' <"$response")
  else
    echo "Central upload did not return a durable ID; reconciling the deterministic deployment" >&2
    lookup_result=0
    if deployment_id=$(find_existing_deployment "$adoption_attempts"); then
      lookup_result=0
    else
      lookup_result=$?
    fi
    if [[ "$lookup_result" == 2 ]]; then
      echo "Central deterministic deployment reconciliation failed closed" >&2
      exit 1
    elif [[ -z "$deployment_id" ]]; then
      echo "Central upload outcome is unresolved (HTTP ${upload_code:-transport failure}); rerun to adopt before any new POST" >&2
      exit 1
    fi
  fi
  python3 "$script_directory/central-deployment-record.py" create-record \
    --intent "$intent" --deployment-id "$deployment_id" --output "$deployment_record"
  echo "Recorded exact Maven Central deployment $deployment_id"
fi

if [[ "$stop_after_record" == true ]]; then exit 0; fi
wait_for_deployment "$deployment_id"
