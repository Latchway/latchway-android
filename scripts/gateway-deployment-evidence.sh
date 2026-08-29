#!/usr/bin/env bash

# Shared fail-closed gateway-deployment capture for physical evidence runners.
# The caller must enable `set -euo pipefail` and define repository_root.

latchway_fetch_gateway_artifact() {
  local url="$1"
  local destination="$2"
  local maximum_bytes="$3"
  local status
  status="$(curl --silent --show-error --proto '=https' --tlsv1.2 \
    --connect-timeout 10 --max-time 30 --max-filesize "$maximum_bytes" \
    --output "$destination" --write-out '%{http_code}' -- "$url")"
  [[ "$status" == 200 && -s "$destination" && ! -L "$destination" ]] || {
    echo "gateway deployment artifact fetch was not an exact HTTP 200 response" >&2
    return 1
  }
}

latchway_verify_gateway_files() {
  local statement="$1"
  local signature="$2"
  local public_key="$3"
  local client_policy="$4"
  local summary="$5"
  python3 "$repository_root/scripts/verify-gateway-deployment.py" \
    --statement "$statement" \
    --signature "$signature" \
    --public-key "$public_key" \
    --public-key-sha256 "$LATCHWAY_GATEWAY_DEPLOYMENT_PUBLIC_KEY_SHA256" \
    --client-policy "$client_policy" \
    --key-id "$LATCHWAY_GATEWAY_DEPLOYMENT_KEY_ID" \
    --gateway-origin "$LATCHWAY_GATEWAY_ORIGIN" \
    --environment "$LATCHWAY_ENVIRONMENT" \
    --core-commit "$LATCHWAY_CORE_COMMIT" \
    --contract-version "$LATCHWAY_CONTRACT_VERSION" \
    --contract-bundle-sha256 "$LATCHWAY_CONTRACT_BUNDLE_SHA256" \
    --gateway-image-digest "$LATCHWAY_GATEWAY_IMAGE_DIGEST" \
    --gateway-configuration-sha256 "$LATCHWAY_GATEWAY_CONFIGURATION_SHA256" \
    >"$summary"
}

latchway_capture_gateway_deployment() {
  local output_dir="$1"
  local client_policy="$2"
  local statement="$output_dir/gateway-deployment-statement.json"
  local signature="$output_dir/gateway-deployment-statement.sig"
  local public_key="$output_dir/gateway-deployment-public-key.pem"
  local retained_policy="$output_dir/gateway-client-policy.json"
  local summary="$output_dir/gateway-deployment-verification.json"

  [[ -f "$LATCHWAY_GATEWAY_DEPLOYMENT_PUBLIC_KEY_PATH" && ! -L "$LATCHWAY_GATEWAY_DEPLOYMENT_PUBLIC_KEY_PATH" ]] || {
    echo "gateway deployment public key is missing or unsafe" >&2
    return 1
  }
  install -m 600 "$LATCHWAY_GATEWAY_DEPLOYMENT_PUBLIC_KEY_PATH" "$public_key"
  install -m 600 "$client_policy" "$retained_policy"
  latchway_fetch_gateway_artifact \
    "$LATCHWAY_GATEWAY_ORIGIN/.well-known/latchway/deployment-statement-v1.json" \
    "$statement" 32768
  latchway_fetch_gateway_artifact \
    "$LATCHWAY_GATEWAY_ORIGIN/.well-known/latchway/deployment-statement-v1.sig" \
    "$signature" 256
  latchway_verify_gateway_files "$statement" "$signature" "$public_key" "$retained_policy" "$summary"
  local actual_statement_sha256
  actual_statement_sha256="$(shasum -a 256 "$statement" | awk '{print $1}')"
  [[ "$actual_statement_sha256" == "$LATCHWAY_GATEWAY_DEPLOYMENT_STATEMENT_SHA256" ]] || {
    echo "live gateway deployment statement does not match the protected release pin" >&2
    return 1
  }
}

latchway_recheck_gateway_deployment() {
  local output_dir="$1"
  local scratch_dir="$2"
  local post_statement="$scratch_dir/gateway-deployment-post.json"
  local post_signature="$scratch_dir/gateway-deployment-post.sig"
  local post_summary="$scratch_dir/gateway-deployment-post-verification.json"
  latchway_fetch_gateway_artifact \
    "$LATCHWAY_GATEWAY_ORIGIN/.well-known/latchway/deployment-statement-v1.json" \
    "$post_statement" 32768
  latchway_fetch_gateway_artifact \
    "$LATCHWAY_GATEWAY_ORIGIN/.well-known/latchway/deployment-statement-v1.sig" \
    "$post_signature" 256
  latchway_verify_gateway_files \
    "$post_statement" "$post_signature" \
    "$output_dir/gateway-deployment-public-key.pem" \
    "$output_dir/gateway-client-policy.json" "$post_summary"
  cmp -s "$output_dir/gateway-deployment-statement.json" "$post_statement" || {
    echo "gateway deployment statement changed during the physical run" >&2
    return 1
  }
  cmp -s "$output_dir/gateway-deployment-statement.sig" "$post_signature" || {
    echo "gateway deployment statement signature changed during the physical run" >&2
    return 1
  }
  cmp -s "$output_dir/gateway-deployment-verification.json" "$post_summary" || {
    echo "gateway deployment verification result changed during the physical run" >&2
    return 1
  }
}

latchway_verify_observation_against_gateway_policy() {
  local observation="$1"
  local client_policy="$2"
  python3 - "$observation" "$client_policy" <<'PY'
import json, pathlib, sys

observation = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
policy = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))
if observation.get("platform") != policy.get("platform"):
    raise SystemExit("gateway client policy platform mismatch")
application = observation.get("application", {})
provider = observation.get("provider", {})
device = observation.get("device", {})
for observed, expected in (
    (application.get("identifier"), policy.get("application_identifier")),
    (application.get("version"), policy.get("app_version")),
    (application.get("build"), policy.get("build_number")),
    (application.get("signing_certificate_sha256"), policy.get("signing_certificate_sha256")),
):
    if observed != expected:
        raise SystemExit("application identity differs from signed gateway client policy")
if policy["platform"].endswith("ios_app_attest"):
    platform_pairs = (
        (application.get("team_id"), policy.get("team_id")),
        (application.get("app_attest_environment"), policy.get("app_attest_environment")),
    )
else:
    platform_pairs = (
        (application.get("cloud_project_number"), policy.get("cloud_project_number")),
        (application.get("installer_package"), policy.get("installer_package")),
        (application.get("play_track"), policy.get("play_track")),
    )
if any(observed != expected for observed, expected in platform_pairs):
    raise SystemExit("platform identity differs from signed gateway client policy")
trust_rank = {"device_verified": 1, "strong_device_verified": 2}
if (
    provider.get("name") != policy.get("provider")
    or provider.get("environment") != "production"
    or provider.get("request_hash_bound") is not policy.get("require_request_hash")
    or trust_rank.get(provider.get("trust_level"), 0) < trust_rank[policy["minimum_trust_level"]]
):
    raise SystemExit("accepted session does not meet signed gateway trust policy")
if policy.get("require_play_recognized") and provider.get("app_recognition") != "PLAY_RECOGNIZED":
    raise SystemExit("signed gateway Play-recognition policy was not observed")
if policy.get("require_licensed") and provider.get("account_licensing") != "LICENSED":
    raise SystemExit("signed gateway Play licensing policy was not observed")
if policy.get("allow_testing") is False and device.get("testing") is not False:
    raise SystemExit("testing runtime rejected by signed gateway policy")
if policy.get("allow_debug") is False and (
    application.get("debuggable") is not False or device.get("debugger_attached") is not False
):
    raise SystemExit("debug runtime rejected by signed gateway policy")
PY
}
