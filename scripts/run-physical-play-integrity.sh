#!/usr/bin/env bash
set +x
set -euo pipefail

one_time_device_grant="${LATCHWAY_ONE_TIME_DEVICE_GRANT:-}"
export -n one_time_device_grant
unset LATCHWAY_ONE_TIME_DEVICE_GRANT
if [[ -z "$one_time_device_grant" ]]; then
  echo "required protected variable is missing: LATCHWAY_ONE_TIME_DEVICE_GRANT" >&2
  exit 2
fi

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
schema_path="$repository_root/Conformance/physical-device-evidence.schema.json"

required=(
  GITHUB_JOB
  GITHUB_REPOSITORY
  GITHUB_RUN_ATTEMPT
  GITHUB_RUN_ID
  LATCHWAY_EVIDENCE_OUTPUT_DIR
  LATCHWAY_ANDROID_DEVICE_SERIAL
  LATCHWAY_PACKAGE_NAME
  LATCHWAY_APP_VERSION
  LATCHWAY_VERSION_CODE
  LATCHWAY_SIGNING_CERTIFICATE_SHA256
  LATCHWAY_INSTALLED_APK_SET_SHA256
  LATCHWAY_PLAY_TRACK
  LATCHWAY_CLOUD_PROJECT_NUMBER
  LATCHWAY_SOURCE_COMMIT
  LATCHWAY_CORE_COMMIT
  LATCHWAY_SDK_VERSION
  LATCHWAY_CONTRACT_VERSION
  LATCHWAY_CONTRACT_BUNDLE_SHA256
  LATCHWAY_GATEWAY_IMAGE_DIGEST
  LATCHWAY_GATEWAY_CONFIGURATION_SHA256
  LATCHWAY_GATEWAY_ORIGIN
  LATCHWAY_GATEWAY_DEPLOYMENT_KEY_ID
  LATCHWAY_GATEWAY_DEPLOYMENT_STATEMENT_SHA256
  LATCHWAY_GATEWAY_DEPLOYMENT_PUBLIC_KEY_PATH
  LATCHWAY_GATEWAY_DEPLOYMENT_PUBLIC_KEY_SHA256
  LATCHWAY_GATEWAY_MINIMUM_TRUST_LEVEL
  LATCHWAY_APPLICATION_ID
  LATCHWAY_ENVIRONMENT
  LATCHWAY_IDENTITY_PROVIDER
  LATCHWAY_ERROR_MAPPING_FEATURE
  LATCHWAY_RUN_ID
  LATCHWAY_WORKFLOW_RUN_ID
  LATCHWAY_RUN_ATTEMPT
  LATCHWAY_ANDROID_DEVICE_GRANT_SHA256
)
for variable_name in "${required[@]}"; do
  if [[ -z "${!variable_name:-}" ]]; then
    echo "required protected variable is missing: $variable_name" >&2
    exit 2
  fi
done
for tool in adb apksigner apkanalyzer cmp curl install java jq openssl python3 shasum; do
  command -v "$tool" >/dev/null || { echo "required tool is unavailable: $tool" >&2; exit 2; }
done

# shellcheck source=scripts/gateway-deployment-evidence.sh
source "$repository_root/scripts/gateway-deployment-evidence.sh"

[[ "$LATCHWAY_PACKAGE_NAME" =~ ^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+$ && ${#LATCHWAY_PACKAGE_NAME} -le 255 ]] || { echo "invalid package pin" >&2; exit 2; }
[[ "$LATCHWAY_APP_VERSION" =~ ^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$ ]] || { echo "invalid version pin" >&2; exit 2; }
[[ "$LATCHWAY_VERSION_CODE" =~ ^[1-9][0-9]{0,9}$ ]] || { echo "invalid version-code pin" >&2; exit 2; }
(( LATCHWAY_VERSION_CODE <= 2100000000 )) || { echo "version-code pin exceeds the Google Play limit" >&2; exit 2; }
[[ "$LATCHWAY_SIGNING_CERTIFICATE_SHA256" =~ ^[0-9a-f]{64}$ ]] || { echo "invalid certificate pin" >&2; exit 2; }
[[ "$LATCHWAY_INSTALLED_APK_SET_SHA256" =~ ^[0-9a-f]{64}$ ]] || { echo "invalid installed APK-set pin" >&2; exit 2; }
[[ "$LATCHWAY_CLOUD_PROJECT_NUMBER" =~ ^[1-9][0-9]{0,18}$ ]] || { echo "invalid cloud-project pin" >&2; exit 2; }
[[ "$LATCHWAY_SOURCE_COMMIT" =~ ^[0-9a-f]{40}$ ]] || { echo "invalid source commit" >&2; exit 2; }
[[ "$LATCHWAY_CORE_COMMIT" =~ ^[0-9a-f]{40}$ ]] || { echo "invalid core commit" >&2; exit 2; }
[[ "$LATCHWAY_CONTRACT_BUNDLE_SHA256" =~ ^[0-9a-f]{64}$ ]] || { echo "invalid contract hash" >&2; exit 2; }
[[ "$LATCHWAY_GATEWAY_IMAGE_DIGEST" =~ ^sha256:[0-9a-f]{64}$ ]] || { echo "invalid gateway digest" >&2; exit 2; }
[[ "$LATCHWAY_GATEWAY_CONFIGURATION_SHA256" =~ ^[0-9a-f]{64}$ ]] || { echo "invalid configuration hash" >&2; exit 2; }
[[ "$LATCHWAY_GATEWAY_DEPLOYMENT_STATEMENT_SHA256" =~ ^[0-9a-f]{64}$ && "$LATCHWAY_GATEWAY_DEPLOYMENT_PUBLIC_KEY_SHA256" =~ ^[0-9a-f]{64}$ ]] || { echo "invalid gateway deployment hash pin" >&2; exit 2; }
[[ "$LATCHWAY_APPLICATION_ID" =~ ^app_[0-7][0-9A-HJKMNP-TV-Z]{25}$ ]] || { echo "invalid Latchway application ID" >&2; exit 2; }
[[ "$LATCHWAY_IDENTITY_PROVIDER" =~ ^[a-z][a-z0-9_-]{0,62}$ ]] || { echo "invalid identity provider" >&2; exit 2; }
case "$LATCHWAY_GATEWAY_MINIMUM_TRUST_LEVEL" in
  device_verified|strong_device_verified) ;;
  *) echo "invalid gateway minimum trust level" >&2; exit 2 ;;
esac
[[ "$LATCHWAY_RUN_ID" =~ ^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$ ]] || { echo "invalid run ID" >&2; exit 2; }
[[ "$LATCHWAY_WORKFLOW_RUN_ID" =~ ^[1-9][0-9]{0,19}$ ]] || { echo "invalid workflow run ID" >&2; exit 2; }
[[ "$LATCHWAY_RUN_ATTEMPT" =~ ^[1-9][0-9]{0,8}$ ]] || { echo "invalid run attempt" >&2; exit 2; }
[[ "$GITHUB_RUN_ID" == "$LATCHWAY_WORKFLOW_RUN_ID" && "$GITHUB_RUN_ATTEMPT" == "$LATCHWAY_RUN_ATTEMPT" ]] || { echo "workflow run coordinates do not match" >&2; exit 2; }
[[ "$LATCHWAY_RUN_ID" == "play-integrity-$LATCHWAY_WORKFLOW_RUN_ID-$LATCHWAY_RUN_ATTEMPT" ]] || { echo "physical run ID does not match workflow coordinates" >&2; exit 2; }
[[ "$LATCHWAY_ANDROID_DEVICE_GRANT_SHA256" =~ ^[0-9a-f]{64}$ ]] || { echo "invalid device-grant hash" >&2; exit 2; }
case "$LATCHWAY_PLAY_TRACK" in
  internal|closed|open|production) ;;
  *) echo "Play track is not release eligible" >&2; exit 2 ;;
esac

mkdir -p "$LATCHWAY_EVIDENCE_OUTPUT_DIR"
output_dir="$(cd "$LATCHWAY_EVIDENCE_OUTPUT_DIR" && pwd -P)"
temporary_root="$(mktemp -d "${TMPDIR:-/tmp}/latchway-play-integrity.XXXXXX")"
cleanup() {
  one_time_device_grant=""
  if [[ -n "$temporary_root" && -d "$temporary_root" && "$temporary_root" == */latchway-play-integrity.* ]]; then
    rm -rf "$temporary_root"
  fi
}
trap cleanup EXIT

actual_commit="$(git -C "$repository_root" rev-parse HEAD)"
[[ "$actual_commit" == "$LATCHWAY_SOURCE_COMMIT" ]] || { echo "source commit does not match run input" >&2; exit 1; }
[[ -z "$(git -C "$repository_root" status --porcelain=v1 --untracked-files=all)" ]] || {
  echo "physical release evidence requires a clean source worktree" >&2
  exit 1
}

adb_device() { adb -s "$LATCHWAY_ANDROID_DEVICE_SERIAL" "$@"; }
[[ "$(adb_device get-state)" == "device" ]] || { echo "the selected Android device is not ready" >&2; exit 1; }

build_type="$(adb_device shell getprop ro.build.type | tr -d '\r')"
build_tags="$(adb_device shell getprop ro.build.tags | tr -d '\r')"
debuggable="$(adb_device shell getprop ro.debuggable | tr -d '\r')"
secure="$(adb_device shell getprop ro.secure | tr -d '\r')"
qemu="$(adb_device shell getprop ro.kernel.qemu | tr -d '\r')"
verified_boot="$(adb_device shell getprop ro.boot.verifiedbootstate | tr -d '\r')"
flash_locked="$(adb_device shell getprop ro.boot.flash.locked | tr -d '\r')"
[[ "$build_type" == user && "$debuggable" == 0 && "$secure" == 1 && "$qemu" != 1 ]] || {
  echo "emulator, debug, or non-user Android builds cannot produce release evidence" >&2
  exit 1
}
[[ "$build_tags" != *test-keys* && "$verified_boot" == green && "$flash_locked" == 1 ]] || {
  echo "test-key or unlocked/unverified Android devices cannot produce release evidence" >&2
  exit 1
}

capture_installed_apk_set() {
  local phase="$1"
  local output_manifest="$2"
  [[ "$phase" =~ ^[a-z][a-z0-9-]{0,31}$ ]] || { echo "invalid installed APK capture phase" >&2; return 1; }
  local install_source
  install_source="$(adb_device shell cmd package get-install-source "$LATCHWAY_PACKAGE_NAME" | tr -d '\r')"
  if [[ "$install_source" != *"com.android.vending"* ]]; then
    echo "the exact candidate must be installed by Google Play" >&2
    return 1
  fi

  local remote_paths_raw="$temporary_root/$phase-remote-apk-paths.raw"
  local remote_paths="$temporary_root/$phase-remote-apk-paths.txt"
  adb_device shell pm path "$LATCHWAY_PACKAGE_NAME" >"$remote_paths_raw"
  python3 - "$remote_paths_raw" "$remote_paths" <<'PY'
import pathlib, re, sys
raw = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
paths = []
for line in raw.splitlines():
    if not line.startswith("package:"):
        raise SystemExit("unexpected package-path output")
    value = line.removeprefix("package:").rstrip("\r")
    if re.fullmatch(r"/[A-Za-z0-9_./=+-]+\.apk", value) is None:
        raise SystemExit("unsafe installed APK path")
    paths.append(value)
if not 1 <= len(paths) <= 64 or len(paths) != len(set(paths)):
    raise SystemExit("invalid installed APK path set")
if sum(path.endswith("/base.apk") for path in paths) != 1:
    raise SystemExit("installed APK set does not contain exactly one base.apk")
names = [path.rsplit("/", 1)[-1] for path in paths]
if len(names) != len(set(names)):
    raise SystemExit("installed APK filenames are ambiguous")
pathlib.Path(sys.argv[2]).write_text("".join(path + "\n" for path in sorted(paths)), encoding="utf-8")
PY

  local apk_set_dir="$temporary_root/$phase-apk-set"
  local manifest_unsorted="$temporary_root/$phase-installed-apk-set.unsorted"
  mkdir "$apk_set_dir"
  while IFS= read -r remote_apk; do
    local apk_name="${remote_apk##*/}"
    local local_apk="$apk_set_dir/$apk_name"
    adb_device exec-out cat "$remote_apk" >"$local_apk"
    [[ -s "$local_apk" && ! -L "$local_apk" ]] || { echo "installed APK could not be collected" >&2; return 1; }
    apksigner verify --verbose --print-certs "$local_apk" >/dev/null
    local actual_certificate
    actual_certificate="$(apksigner verify --print-certs "$local_apk" | sed -n 's/^Signer #1 certificate SHA-256 digest: //p' | tr '[:upper:]' '[:lower:]')"
    [[ "$actual_certificate" == "$LATCHWAY_SIGNING_CERTIFICATE_SHA256" ]] || { echo "installed split signer does not match protected pin" >&2; return 1; }
    local actual_package actual_code actual_version
    actual_package="$(apkanalyzer manifest application-id "$local_apk")"
    actual_code="$(apkanalyzer manifest version-code "$local_apk")"
    [[ "$actual_package" == "$LATCHWAY_PACKAGE_NAME" && "$actual_code" == "$LATCHWAY_VERSION_CODE" ]] || { echo "installed split package/version code mismatch" >&2; return 1; }
    actual_version="$(apkanalyzer manifest version-name "$local_apk" 2>/dev/null || true)"
    if [[ "$apk_name" == base.apk ]]; then
      [[ "$actual_version" == "$LATCHWAY_APP_VERSION" ]] || { echo "installed base APK version name mismatch" >&2; return 1; }
    else
      [[ -z "$actual_version" || "$actual_version" == "$LATCHWAY_APP_VERSION" ]] || { echo "installed split version name mismatch" >&2; return 1; }
    fi
    local apk_sha256
    apk_sha256="$(shasum -a 256 "$local_apk" | awk '{print $1}')"
    printf '%s\t%s\n' "$apk_name" "$apk_sha256" >>"$manifest_unsorted"
  done <"$remote_paths"
  LC_ALL=C sort "$manifest_unsorted" >"$output_manifest"
  shasum -a 256 "$output_manifest" | awk '{print $1}'
}

apk_set_manifest="$output_dir/installed-apk-set.sha256"
pre_run_apk_set_sha256="$(capture_installed_apk_set pre-run "$apk_set_manifest")"
[[ "$pre_run_apk_set_sha256" == "$LATCHWAY_INSTALLED_APK_SET_SHA256" ]] || { echo "installed APK set does not match protected pin" >&2; exit 1; }

client_policy_path="$temporary_root/gateway-client-policy.json"
python3 - "$client_policy_path" <<'PY'
import json, os, pathlib, sys
policy = {
    "allow_debug": False,
    "allow_testing": False,
    "app_version": os.environ["LATCHWAY_APP_VERSION"],
    "application_identifier": os.environ["LATCHWAY_PACKAGE_NAME"],
    "build_number": os.environ["LATCHWAY_VERSION_CODE"],
    "cloud_project_number": os.environ["LATCHWAY_CLOUD_PROJECT_NUMBER"],
    "installer_package": "com.android.vending",
    "minimum_trust_level": os.environ["LATCHWAY_GATEWAY_MINIMUM_TRUST_LEVEL"],
    "platform": "android_play_integrity",
    "play_track": os.environ["LATCHWAY_PLAY_TRACK"],
    "provider": "play_integrity",
    "require_licensed": True,
    "require_play_recognized": True,
    "require_request_hash": True,
    "signing_certificate_sha256": os.environ["LATCHWAY_SIGNING_CERTIFICATE_SHA256"],
}
pathlib.Path(sys.argv[1]).write_text(
    json.dumps(policy, allow_nan=False, ensure_ascii=False, separators=(",", ":"), sort_keys=True),
    encoding="utf-8",
)
PY
latchway_capture_gateway_deployment "$output_dir" "$client_policy_path"

collector_lease=/etc/latchway/physical-collector/lease.json
[[ -f "$collector_lease" && ! -L "$collector_lease" ]] || { echo "signed collector lease is unavailable" >&2; exit 1; }
grant_check_time="$(date +%s)"
jq --exit-status \
  --arg repository "$GITHUB_REPOSITORY" \
  --arg source "$LATCHWAY_SOURCE_COMMIT" \
  --arg run_id "$LATCHWAY_WORKFLOW_RUN_ID" \
  --arg run_attempt "$LATCHWAY_RUN_ATTEMPT" \
  --arg job "$GITHUB_JOB" \
  --arg grant_sha256 "$LATCHWAY_ANDROID_DEVICE_GRANT_SHA256" \
  --arg application_id "$LATCHWAY_APPLICATION_ID" \
  --arg package_name "$LATCHWAY_PACKAGE_NAME" \
  --arg identity_provider "$LATCHWAY_IDENTITY_PROVIDER" \
  --argjson now "$grant_check_time" '
    .schema_version == "latchway.physical-collector-lease.v2" and
    .repository == $repository and .source_commit == $source and
    .workflow == {run_id:$run_id,run_attempt:$run_attempt,job:$job,audience:"android-play-integrity"} and
    .supervisor.identity_grant_digest_one_use_enforced == true and
    (.grant | keys) == ["application_id","audience","expires_at_unix","identity_provider","issued_at_unix","package_name","run_attempt","run_id","sha256","single_use","source_commit"] and
    .grant.audience == "latchway-physical-evidence/android-play-integrity" and
    .grant.source_commit == $source and .grant.run_id == $run_id and
    .grant.run_attempt == $run_attempt and .grant.sha256 == $grant_sha256 and
    .grant.application_id == $application_id and .grant.package_name == $package_name and
    .grant.identity_provider == $identity_provider and
    .grant.single_use == true and
    (.grant.issued_at_unix | type == "number") and
    (.grant.expires_at_unix | type == "number") and
    .grant.issued_at_unix <= $now and .grant.expires_at_unix > $now and
    .grant.expires_at_unix <= .expires_at_unix and
    .grant.expires_at_unix > .grant.issued_at_unix and
    (.grant.expires_at_unix - .grant.issued_at_unix) <= 300
  ' "$collector_lease" >/dev/null || {
  echo "one-use device grant is not valid for the current signed lease" >&2
  exit 1
}
adb_device shell am force-stop "$LATCHWAY_PACKAGE_NAME"
[[ "$(adb_device shell pm clear "$LATCHWAY_PACKAGE_NAME" | tr -d '\r')" == Success ]] || {
  echo "the Play candidate app data could not be reset before bootstrap" >&2
  exit 1
}
[[ -z "$(adb_device shell pidof "$LATCHWAY_PACKAGE_NAME" 2>/dev/null | tr -d '\r' || true)" ]] || {
  echo "the Play candidate process remained after reset" >&2
  exit 1
}
grant_length="${#one_time_device_grant}"
(( grant_length >= 16 && grant_length <= 65536 )) || { echo "invalid one-use device grant length" >&2; exit 2; }
[[ "$one_time_device_grant" =~ ^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$ ]] || {
  echo "one-use device grant is not a compact identity JWT" >&2
  exit 2
}
actual_grant_sha256="$(printf '%s' "$one_time_device_grant" | shasum -a 256 | awk '{print $1}')"
[[ "$actual_grant_sha256" == "$LATCHWAY_ANDROID_DEVICE_GRANT_SHA256" ]] || {
  echo "one-use device grant does not match the signed lease hash" >&2
  exit 1
}
grant_uri="content://$LATCHWAY_PACKAGE_NAME.device-bootstrap/v1/one-time-identity-grant?audience=latchway-physical-evidence/android-play-integrity&source_commit=$LATCHWAY_SOURCE_COMMIT&application_id=$LATCHWAY_APPLICATION_ID&package_name=$LATCHWAY_PACKAGE_NAME&identity_provider=$LATCHWAY_IDENTITY_PROVIDER&run_id=$LATCHWAY_RUN_ID&workflow_run_id=$LATCHWAY_WORKFLOW_RUN_ID&run_attempt=$LATCHWAY_RUN_ATTEMPT&grant_sha256=$LATCHWAY_ANDROID_DEVICE_GRANT_SHA256"
grant_streamed=false
if printf '%s' "$one_time_device_grant" | adb_device shell content write --uri "$grant_uri" >/dev/null; then
  grant_streamed=true
fi
one_time_device_grant=""
[[ "$grant_streamed" == true ]] || { echo "one-use device grant could not enter app-private memory" >&2; exit 1; }
adb_device shell am start \
  -n "$LATCHWAY_PACKAGE_NAME/dev.latchway.sample.conformance.ConformanceActivity" \
  --es dev.latchway.RUN_ID "$LATCHWAY_RUN_ID" \
  --es dev.latchway.WORKFLOW_RUN_ID "$LATCHWAY_WORKFLOW_RUN_ID" \
  --es dev.latchway.RUN_ATTEMPT "$LATCHWAY_RUN_ATTEMPT" \
  --es dev.latchway.IDENTITY_GRANT_SHA256 "$LATCHWAY_ANDROID_DEVICE_GRANT_SHA256" \
  --ez dev.latchway.AUTORUN true >/dev/null

observation_path="$output_dir/play-integrity-observation.json"
observation_ready=false
for _ in {1..180}; do
  candidate="$temporary_root/observation.json"
  if adb_device exec-out content read \
    --uri "content://$LATCHWAY_PACKAGE_NAME.device-evidence/v1/latest" >"$candidate" 2>/dev/null; then
    if python3 - "$candidate" "$LATCHWAY_RUN_ID" <<'PY'
import json, pathlib, sys
path = pathlib.Path(sys.argv[1])
try:
    value = json.loads(path.read_text(encoding="utf-8"))
except (OSError, UnicodeError, json.JSONDecodeError):
    raise SystemExit(1)
raise SystemExit(0 if value.get("run", {}).get("id") == sys.argv[2] else 1)
PY
    then
      cp "$candidate" "$observation_path"
      observation_ready=true
      break
    fi
  fi
  sleep 5
done
[[ "$observation_ready" == true ]] || { echo "the physical app did not produce this run's observation" >&2; exit 1; }

post_run_apk_set_manifest="$temporary_root/installed-apk-set-post-run.sha256"
post_run_apk_set_sha256="$(capture_installed_apk_set post-run "$post_run_apk_set_manifest")"
[[ "$post_run_apk_set_sha256" == "$pre_run_apk_set_sha256" && "$post_run_apk_set_sha256" == "$LATCHWAY_INSTALLED_APK_SET_SHA256" ]] || {
  echo "installed APK set changed during physical evidence collection" >&2
  exit 1
}
cmp --silent "$apk_set_manifest" "$post_run_apk_set_manifest" || {
  echo "installed APK manifest changed during physical evidence collection" >&2
  exit 1
}
export LATCHWAY_OBSERVED_INSTALLED_APK_SET_SHA256="$post_run_apk_set_sha256"

latchway_recheck_gateway_deployment "$output_dir" "$temporary_root"
latchway_verify_observation_against_gateway_policy \
  "$observation_path" "$output_dir/gateway-client-policy.json"

device_inventory_path="$output_dir/device-inventory.json"
export LATCHWAY_DEVICE_MODEL="$(adb_device shell getprop ro.product.manufacturer | tr -d '\r') $(adb_device shell getprop ro.product.model | tr -d '\r')"
export LATCHWAY_DEVICE_OS_VERSION="$(adb_device shell getprop ro.build.version.release | tr -d '\r')"
export LATCHWAY_DEVICE_OS_BUILD="$(adb_device shell getprop ro.build.id | tr -d '\r')"
export LATCHWAY_DEVICE_SECURITY_PATCH="$(adb_device shell getprop ro.build.version.security_patch | tr -d '\r')"
export LATCHWAY_VERIFIED_BOOT="$verified_boot"
python3 - "$observation_path" "$device_inventory_path" <<'PY'
import json, os, pathlib, sys
observation = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
device = observation.get("device", {})
if device.get("physical") is not True or device.get("emulator") is not False:
    raise SystemExit("application did not report physical Android hardware")
safe = {
    "schema_version": "latchway.physical-device-inventory.v1",
    "collector": "adb-getprop",
    "collector_version": "1",
    "physical": True,
    "model": os.environ["LATCHWAY_DEVICE_MODEL"][:128],
    "os_name": "Android",
    "os_version": os.environ["LATCHWAY_DEVICE_OS_VERSION"][:64],
    "os_build": os.environ["LATCHWAY_DEVICE_OS_BUILD"][:64],
    "security_patch": os.environ["LATCHWAY_DEVICE_SECURITY_PATCH"][:64],
    "verified_boot": os.environ["LATCHWAY_VERIFIED_BOOT"],
}
pathlib.Path(sys.argv[2]).write_text(json.dumps(safe, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
device_inventory_sha256="$(shasum -a 256 "$device_inventory_path" | awk '{print $1}')"

export LATCHWAY_RUNNER_OS="$(uname -s) $(uname -r)"
export LATCHWAY_RUNNER_ARCH="$(uname -m)"
export LATCHWAY_COMPILER="$(java -version 2>&1 | head -n 1)"
export LATCHWAY_BUILD_TOOL="$(apksigner --version 2>&1 | head -n 1)"
export LATCHWAY_DEVICE_INVENTORY_SHA256="$device_inventory_sha256"
profile_path="$output_dir/play-integrity-profile.json"
python3 - "$profile_path" <<'PY'
import json, os, pathlib, sys
expected = {
    "application_identifier": os.environ["LATCHWAY_PACKAGE_NAME"],
    "app_version": os.environ["LATCHWAY_APP_VERSION"],
    "build_number": os.environ["LATCHWAY_VERSION_CODE"],
    "signing_certificate_sha256": os.environ["LATCHWAY_SIGNING_CERTIFICATE_SHA256"],
    "cloud_project_number": os.environ["LATCHWAY_CLOUD_PROJECT_NUMBER"],
    "installer_package": "com.android.vending",
    "play_track": os.environ["LATCHWAY_PLAY_TRACK"],
    "require_licensed": "true",
    "source_commit": os.environ["LATCHWAY_SOURCE_COMMIT"],
    "core_commit": os.environ["LATCHWAY_CORE_COMMIT"],
    "contract_bundle_sha256": os.environ["LATCHWAY_CONTRACT_BUNDLE_SHA256"],
    "gateway_image_digest": os.environ["LATCHWAY_GATEWAY_IMAGE_DIGEST"],
    "gateway_configuration_sha256": os.environ["LATCHWAY_GATEWAY_CONFIGURATION_SHA256"],
    "gateway_origin": os.environ["LATCHWAY_GATEWAY_ORIGIN"],
    "gateway_environment": os.environ["LATCHWAY_ENVIRONMENT"],
    "gateway_deployment_key_id": os.environ["LATCHWAY_GATEWAY_DEPLOYMENT_KEY_ID"],
    "gateway_deployment_statement_sha256": os.environ["LATCHWAY_GATEWAY_DEPLOYMENT_STATEMENT_SHA256"],
    "gateway_deployment_public_key_sha256": os.environ["LATCHWAY_GATEWAY_DEPLOYMENT_PUBLIC_KEY_SHA256"],
    "error_mapping_feature": os.environ["LATCHWAY_ERROR_MAPPING_FEATURE"],
}
profile = {
    "schema_version": "latchway.physical-device-profile.v1",
    "platform": "android_play_integrity",
    "repository": "Latchway/latchway-android",
    "source": {
        "commit": os.environ["LATCHWAY_SOURCE_COMMIT"],
        "core_commit": os.environ["LATCHWAY_CORE_COMMIT"],
        "worktree_clean": True,
        "sdk_version": os.environ["LATCHWAY_SDK_VERSION"],
        "contract_version": os.environ["LATCHWAY_CONTRACT_VERSION"],
        "contract_bundle_sha256": os.environ["LATCHWAY_CONTRACT_BUNDLE_SHA256"],
        "gateway_image_digest": os.environ["LATCHWAY_GATEWAY_IMAGE_DIGEST"],
        "gateway_configuration_sha256": os.environ["LATCHWAY_GATEWAY_CONFIGURATION_SHA256"],
        "gateway_origin": os.environ["LATCHWAY_GATEWAY_ORIGIN"],
        "gateway_deployment_key_id": os.environ["LATCHWAY_GATEWAY_DEPLOYMENT_KEY_ID"],
        "gateway_deployment_statement_sha256": os.environ["LATCHWAY_GATEWAY_DEPLOYMENT_STATEMENT_SHA256"],
        "gateway_deployment_public_key_sha256": os.environ["LATCHWAY_GATEWAY_DEPLOYMENT_PUBLIC_KEY_SHA256"],
    },
    "toolchain": {
        "runner_os": os.environ["LATCHWAY_RUNNER_OS"],
        "runner_arch": os.environ["LATCHWAY_RUNNER_ARCH"],
        "compiler": os.environ["LATCHWAY_COMPILER"],
        "build_tool": os.environ["LATCHWAY_BUILD_TOOL"],
        "collector_version": "1",
    },
    "expected_pins": expected,
    "application_binary_sha256": os.environ["LATCHWAY_OBSERVED_INSTALLED_APK_SET_SHA256"],
    "device_inventory_sha256": os.environ["LATCHWAY_DEVICE_INVENTORY_SHA256"],
}
pathlib.Path(sys.argv[1]).write_text(json.dumps(profile, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

evidence_path="$output_dir/play-integrity-evidence.json"
junit_path="$output_dir/play-integrity-junit.xml"
summary_path="$output_dir/play-integrity-validation.json"
python3 "$repository_root/scripts/device-evidence.py" finalize \
  --schema "$schema_path" \
  --profile "$profile_path" \
  --observation "$observation_path" \
  --evidence "$evidence_path" \
  --junit "$junit_path" \
  --summary "$summary_path"

(
  cd "$output_dir"
  shasum -a 256 \
    device-inventory.json \
    gateway-client-policy.json \
    gateway-deployment-public-key.pem \
    gateway-deployment-statement.json \
    gateway-deployment-statement.sig \
    gateway-deployment-verification.json \
    installed-apk-set.sha256 \
    play-integrity-evidence.json \
    play-integrity-junit.xml \
    play-integrity-observation.json \
    play-integrity-profile.json \
    play-integrity-validation.json > SHA256SUMS
)
chmod 600 "$output_dir"/*.json "$output_dir"/*.pem "$output_dir"/*.sig "$output_dir"/*.xml "$output_dir"/*.sha256 "$output_dir/SHA256SUMS"
echo "physical Play Integrity evidence accepted: $evidence_path"
