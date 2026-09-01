#!/bin/sh
set -eu
umask 077

sdk_kind=${LATCHWAY_SDK_KIND:?LATCHWAY_SDK_KIND is required}
core_dir=${LATCHWAY_CORE_DIR:-_core}
evidence_dir=${LATCHWAY_EVIDENCE_DIR:?LATCHWAY_EVIDENCE_DIR is required}
database_url=${LATCHWAY_CONFORMANCE_DATABASE_URL:?LATCHWAY_CONFORMANCE_DATABASE_URL is required}
postgres_image='docker.io/library/postgres@sha256:d3e1620b530c944afa6e887d22eb899824da68e19c52024bf98f5220c88a65b2'

case "$sdk_kind" in
  javascript) fixture_dir='test/fixtures/contract' ;;
  ios) fixture_dir='Tests/ConformanceTests/Fixtures' ;;
  android) fixture_dir='latchway-core/src/test/resources/contract' ;;
  react_native) fixture_dir='test/fixtures/contract' ;;
  *) echo "unsupported LATCHWAY_SDK_KIND: $sdk_kind" >&2; exit 64 ;;
esac

core_commit=$(awk '$1 == "core_commit:" {print $2}' contract.lock)
contract_version=$(awk '$1 == "contract_version:" {print $2}' contract.lock)
bundle_sha256=$(awk '$1 == "bundle_sha256:" {gsub(/"/, "", $2); print $2}' contract.lock)
test "$(wc -l < contract.lock | tr -d ' ')" = 7
test "${#core_commit}" = 40
test "${#bundle_sha256}" = 64
case "$core_commit$bundle_sha256" in *[!0-9a-f]*) echo 'contract.lock contains a non-canonical digest' >&2; exit 1 ;; esac
test "$(git -C "$core_dir" rev-parse --verify HEAD)" = "$core_commit"
test -z "$(git -C "$core_dir" status --porcelain=v1 --untracked-files=all)"

mkdir -p "$evidence_dir"
contract_build_dir=$(mktemp -d "${RUNNER_TEMP:-/tmp}/latchway-contract.XXXXXX")
contract_extract_dir=$(mktemp -d "${RUNNER_TEMP:-/tmp}/latchway-contract-extract.XXXXXX")
develop_name=
develop_pid=
ready_file=
develop_log=
cleanup() {
  if [ -n "$develop_name" ]; then docker stop "$develop_name" >/dev/null 2>&1 || true; fi
  if [ -n "$develop_pid" ]; then wait "$develop_pid" 2>/dev/null || true; fi
  rm -rf "$contract_build_dir" "$contract_extract_dir"
  if [ -n "$ready_file" ]; then rm -f "$ready_file"; fi
  if [ -n "$develop_log" ]; then rm -f "$develop_log"; fi
}
trap cleanup EXIT HUP INT TERM
python3 "$core_dir/scripts/build-contract-bundle.py" --output-directory "$contract_build_dir"
contract_bundle="$contract_build_dir/latchway-contract-$contract_version.tar.gz"
test -f "$contract_bundle"
actual_bundle_sha256=$(sha256sum "$contract_bundle" | awk '{print $1}')
test "$actual_bundle_sha256" = "$bundle_sha256"
cp "$contract_bundle" "$evidence_dir/"
tar -xzf "$contract_bundle" -C "$contract_extract_dir"

cmp "$contract_extract_dir/protocol-version.json" "$fixture_dir/protocol-version.json"
cmp "$contract_extract_dir/test-vectors/dpop/v1.json" "$fixture_dir/dpop-v1.json"
cmp "$contract_extract_dir/test-vectors/attestation-binding/v1.json" "$fixture_dir/attestation-binding-v1.json"
cmp "$contract_extract_dir/test-vectors/component-attestation-binding/v2.json" "$fixture_dir/component-attestation-binding-v2.json"
cmp "$contract_extract_dir/test-vectors/installation-family/v2.json" "$fixture_dir/installation-family-v2.json"

core_image_tag="latchway-pr-conformance:${core_commit}"
docker build --pull \
  --build-arg "VERSION=$contract_version-pr" \
  --build-arg "COMMIT=$core_commit" \
  --build-arg 'BUILD_DATE=1970-01-01T00:00:00Z' \
  --tag "$core_image_tag" "$core_dir"
core_image_id=$(docker image inspect --format '{{.Id}}' "$core_image_tag")
image_revision=$(docker image inspect --format '{{index .Config.Labels "org.opencontainers.image.revision"}}' "$core_image_id")
test "$image_revision" = "$core_commit"
postgres_image_id=$(docker image inspect --format '{{.Id}}' "$postgres_image")

docker run --rm --network host \
  --user "$(id -u):$(id -g)" \
  --env "LATCHWAY_CONFORMANCE_DATABASE_URL=$database_url" \
  --volume "$evidence_dir:/evidence" \
  "$core_image_id" --output json verify local \
  --database-url-env LATCHWAY_CONFORMANCE_DATABASE_URL \
  --timeout 3m --junit /evidence/latchway-local-conformance.junit.xml \
  > "$evidence_dir/latchway-local-conformance.json"

jq --exit-status '
  .version == 1 and .kind == "local" and .state == "passed" and
  ([.checks[] | select(.state != "passed")] | length) == 0 and
  ([.checks[].name] | index("database_connectivity")) != null and
  ([.checks[].name] | index("oidc_debug_dpop_session")) != null and
  ([.checks[].name] | index("non_streaming")) != null and
  ([.checks[].name] | index("dpop_replay")) != null and
  ([.checks[].name] | index("request_quota")) != null and
  ([.checks[].name] | index("ephemeral_cleanup")) != null
' "$evidence_dir/latchway-local-conformance.json" >/dev/null

sdk_runtime_request_claimed=false
if [ "$#" -gt 0 ]; then
  ready_file=$(mktemp "${RUNNER_TEMP:-/tmp}/latchway-develop-ready.XXXXXX")
  develop_log=$(mktemp "${RUNNER_TEMP:-/tmp}/latchway-develop-log.XXXXXX")
  develop_name="latchway-sdk-pr-${sdk_kind}-${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-1}"
  docker run --rm --name "$develop_name" --network host \
    --env "LATCHWAY_CONFORMANCE_DATABASE_URL=$database_url" \
    "$core_image_id" --output json develop \
    --database-url-env LATCHWAY_CONFORMANCE_DATABASE_URL \
    --listen 127.0.0.1:18080 --browser-origin http://localhost:5173 \
    > "$ready_file" 2> "$develop_log" &
  develop_pid=$!
  attempt=0
  until jq --exit-status '
    .state == "ready" and .gateway_url == "http://127.0.0.1:18080" and
    (.application_id | type == "string") and .environment == "development" and
    (.feature | type == "string") and (.identity_token_url | type == "string") and
    (.attestation_evidence_url | type == "string")
  ' "$ready_file" >/dev/null 2>&1; do
    attempt=$((attempt + 1))
    if ! kill -0 "$develop_pid" 2>/dev/null || [ "$attempt" -ge 90 ]; then
      echo 'the exact core development server did not become ready' >&2
      exit 1
    fi
    sleep 1
  done
  LATCHWAY_DEVELOP_BASE_URL=$(jq --raw-output .gateway_url "$ready_file")
  LATCHWAY_DEVELOP_APPLICATION_ID=$(jq --raw-output .application_id "$ready_file")
  LATCHWAY_DEVELOP_ENVIRONMENT=$(jq --raw-output .environment "$ready_file")
  LATCHWAY_DEVELOP_FEATURE=$(jq --raw-output .feature "$ready_file")
  LATCHWAY_DEVELOP_MODEL=$(jq --raw-output .model "$ready_file")
  LATCHWAY_DEVELOP_IDENTITY_TOKEN_URL=$(jq --raw-output .identity_token_url "$ready_file")
  LATCHWAY_DEVELOP_ATTESTATION_EVIDENCE_URL=$(jq --raw-output .attestation_evidence_url "$ready_file")
  export LATCHWAY_DEVELOP_BASE_URL LATCHWAY_DEVELOP_APPLICATION_ID LATCHWAY_DEVELOP_ENVIRONMENT
  export LATCHWAY_DEVELOP_FEATURE LATCHWAY_DEVELOP_MODEL LATCHWAY_DEVELOP_IDENTITY_TOKEN_URL
  export LATCHWAY_DEVELOP_ATTESTATION_EVIDENCE_URL
  LATCHWAY_SDK_CONFORMANCE_OUTPUT="$evidence_dir/sdk-live-conformance.json"
  export LATCHWAY_SDK_CONFORMANCE_OUTPUT
  "$@"
  jq --exit-status --arg sdk_kind "$sdk_kind" '
    .schema_version == 1 and .kind == "latchway_sdk_live_debug_conformance" and
    .sdk_kind == $sdk_kind and .status == "passed" and
    .physical_attestation_claimed == false and
    (.checks.debug_attestation == true) and (.checks.dpop_session == true) and
    (.checks.proxied_mock_request == true) and (.checks.quota == true) and
    (.checks.session_refresh == true)
  ' "$LATCHWAY_SDK_CONFORMANCE_OUTPUT" >/dev/null
  docker stop "$develop_name" >/dev/null
  wait "$develop_pid"
  develop_name=
  develop_pid=
  rm -f "$ready_file" "$develop_log"
  ready_file=
  develop_log=
  sdk_runtime_request_claimed=true
fi

sdk_commit=$(git rev-parse --verify HEAD)
jq --null-input \
  --arg sdk_kind "$sdk_kind" \
  --arg sdk_commit "$sdk_commit" \
  --arg core_commit "$core_commit" \
  --arg contract_version "$contract_version" \
  --arg bundle_sha256 "$bundle_sha256" \
  --arg core_image_id "$core_image_id" \
  --arg postgres_image "$postgres_image" \
  --arg postgres_image_id "$postgres_image_id" \
  --argjson sdk_runtime_request_claimed "$sdk_runtime_request_claimed" '
  {
    schema_version: 1,
    kind: "latchway_sdk_pr_core_conformance",
    sdk: {kind: $sdk_kind, commit: $sdk_commit},
    contract: {version: $contract_version, core_commit: $core_commit, bundle_sha256: $bundle_sha256},
    runtime: {
      core_image_id: $core_image_id,
      core_image_revision: $core_commit,
      postgres_image: $postgres_image,
      postgres_image_id: $postgres_image_id,
      network: "ubuntu_host_loopback",
      image_coordinate_kind: "source_built_local_image_id",
      sdk_runtime_request_claimed: $sdk_runtime_request_claimed,
      physical_attestation_claimed: false
    },
    evidence: {
      debug_attestation: "signed_challenge_bound_debug",
      proxied_mock_request: "deterministic_non_streaming",
      session: ["dpop_exchange", "dpop_replay_rejection"],
      quota: "request_quota"
    }
  }
' > "$evidence_dir/identity.json"
