#!/usr/bin/env bash
set +x
set -euo pipefail
umask 077

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
required=(
  LATCHWAY_CANDIDATE_OUTPUT_DIR
  LATCHWAY_PACKAGE_NAME
  LATCHWAY_APP_VERSION
  LATCHWAY_VERSION_CODE
  LATCHWAY_SIGNING_CERTIFICATE_SHA256
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
  LATCHWAY_GATEWAY_DEPLOYMENT_PUBLIC_KEY_SHA256
  LATCHWAY_ENVIRONMENT
  LATCHWAY_IDENTITY_PROVIDER
  LATCHWAY_APPLICATION_ID
  LATCHWAY_FEATURE
  LATCHWAY_ERROR_MAPPING_FEATURE
  LATCHWAY_MODEL
)
for variable_name in "${required[@]}"; do
  [[ -n "${!variable_name:-}" ]] || { echo "required candidate input is missing: $variable_name" >&2; exit 2; }
done
for tool in git java python3 shasum; do
  command -v "$tool" >/dev/null || { echo "required candidate tool is unavailable: $tool" >&2; exit 2; }
done

# Candidate-controlled Gradle and repository code must never share a process
# environment with upload-key material. This producer is deliberately
# unsigned-only; a fresh no-checkout signer consumes the closed staged set.
for prohibited_signing_input in \
  LATCHWAY_PLAY_UPLOAD_KEYSTORE_BASE64 \
  LATCHWAY_PLAY_UPLOAD_KEYSTORE_PASSWORD \
  LATCHWAY_PLAY_UPLOAD_KEY_ALIAS \
  LATCHWAY_PLAY_UPLOAD_KEY_PASSWORD \
  LATCHWAY_PLAY_KEYSTORE_PATH \
  LATCHWAY_PLAY_KEYSTORE_PASSWORD \
  LATCHWAY_PLAY_KEY_ALIAS \
  LATCHWAY_PLAY_KEY_PASSWORD \
  PLAY_KEYSTORE_BASE64 \
  PLAY_KEYSTORE_PASSWORD \
  PLAY_KEY_ALIAS \
  PLAY_KEY_PASSWORD \
  LATCHWAY_SIGNER_STORE_PASSWORD \
  LATCHWAY_SIGNER_KEY_PASSWORD \
  LATCHWAY_PLAY_UPLOAD_CERTIFICATE_SHA256; do
  [[ -z "${!prohibited_signing_input:-}" ]] || {
    echo "signing material is prohibited on the unsigned candidate producer: $prohibited_signing_input" >&2
    exit 2
  }
done
if [[ -n "${LATCHWAY_PLAY_SIGNING_MODE:-}" && "$LATCHWAY_PLAY_SIGNING_MODE" != unsigned ]]; then
  echo "repository candidate production supports unsigned mode only" >&2
  exit 2
fi
export LATCHWAY_PLAY_SIGNING_MODE=unsigned

[[ "$LATCHWAY_PACKAGE_NAME" =~ ^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+$ && ${#LATCHWAY_PACKAGE_NAME} -le 255 ]] || { echo "invalid Android application ID" >&2; exit 2; }
[[ "$LATCHWAY_APP_VERSION" =~ ^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$ ]] || { echo "invalid app version" >&2; exit 2; }
[[ "$LATCHWAY_VERSION_CODE" =~ ^[1-9][0-9]{0,9}$ ]] || { echo "invalid version code" >&2; exit 2; }
(( LATCHWAY_VERSION_CODE <= 2100000000 )) || { echo "version code exceeds the Google Play limit" >&2; exit 2; }
[[ "$LATCHWAY_SIGNING_CERTIFICATE_SHA256" =~ ^[0-9a-f]{64}$ ]] || { echo "invalid Play App Signing certificate pin" >&2; exit 2; }
[[ "$LATCHWAY_CLOUD_PROJECT_NUMBER" =~ ^[1-9][0-9]{0,18}$ ]] || { echo "invalid cloud project number" >&2; exit 2; }
[[ "$LATCHWAY_SOURCE_COMMIT" =~ ^[0-9a-f]{40}$ && "$LATCHWAY_CORE_COMMIT" =~ ^[0-9a-f]{40}$ ]] || { echo "invalid source commit pin" >&2; exit 2; }
[[ "$LATCHWAY_CONTRACT_BUNDLE_SHA256" =~ ^[0-9a-f]{64}$ ]] || { echo "invalid contract bundle pin" >&2; exit 2; }
[[ "$LATCHWAY_GATEWAY_IMAGE_DIGEST" =~ ^sha256:[0-9a-f]{64}$ ]] || { echo "invalid gateway image digest" >&2; exit 2; }
[[ "$LATCHWAY_GATEWAY_CONFIGURATION_SHA256" =~ ^[0-9a-f]{64}$ ]] || { echo "invalid gateway configuration hash" >&2; exit 2; }
[[ "$LATCHWAY_GATEWAY_DEPLOYMENT_STATEMENT_SHA256" =~ ^[0-9a-f]{64}$ ]] || { echo "invalid deployment statement hash" >&2; exit 2; }
[[ "$LATCHWAY_GATEWAY_DEPLOYMENT_PUBLIC_KEY_SHA256" =~ ^[0-9a-f]{64}$ ]] || { echo "invalid deployment public-key hash" >&2; exit 2; }
[[ "$LATCHWAY_GATEWAY_DEPLOYMENT_KEY_ID" =~ ^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$ ]] || { echo "invalid deployment key ID" >&2; exit 2; }
[[ "$LATCHWAY_GATEWAY_ORIGIN" =~ ^https://[a-z0-9][A-Za-z0-9.-]*(:[1-9][0-9]{0,4})?(/[A-Za-z0-9_~.-]+)*$ ]] || { echo "invalid gateway origin" >&2; exit 2; }
[[ "$LATCHWAY_APPLICATION_ID" =~ ^app_[0-7][0-9A-HJKMNP-TV-Z]{25}$ ]] || { echo "invalid Latchway application ID" >&2; exit 2; }
[[ "$LATCHWAY_ENVIRONMENT" =~ ^[a-z][a-z0-9_-]{0,62}$ ]] || { echo "invalid environment" >&2; exit 2; }
[[ "$LATCHWAY_IDENTITY_PROVIDER" =~ ^[a-z][a-z0-9_-]{0,62}$ ]] || { echo "invalid identity provider" >&2; exit 2; }
[[ "$LATCHWAY_FEATURE" =~ ^[a-z][a-z0-9_-]{0,62}$ ]] || { echo "invalid feature" >&2; exit 2; }
[[ "$LATCHWAY_ERROR_MAPPING_FEATURE" =~ ^[a-z][a-z0-9_-]{0,62}$ && "$LATCHWAY_ERROR_MAPPING_FEATURE" != "$LATCHWAY_FEATURE" ]] || { echo "invalid error-mapping feature" >&2; exit 2; }
python3 - "$LATCHWAY_MODEL" <<'PY'
import sys
value = sys.argv[1]
encoded = value.encode("utf-8")
if not (1 <= len(encoded) <= 256) or value != value.strip() or any(
    ord(character) < 32 or 127 <= ord(character) <= 159 for character in value
):
    raise SystemExit("invalid model")
PY
case "$LATCHWAY_PLAY_TRACK" in
  internal|closed|open|production) ;;
  *) echo "invalid Play track" >&2; exit 2 ;;
esac

actual_commit="$(git -C "$repository_root" rev-parse HEAD)"
[[ "$actual_commit" == "$LATCHWAY_SOURCE_COMMIT" ]] || { echo "candidate source commit mismatch" >&2; exit 1; }
[[ -z "$(git -C "$repository_root" status --porcelain=v1 --untracked-files=all)" ]] || {
  echo "candidate production requires a clean source worktree" >&2
  exit 1
}
source_tree="$(git -C "$repository_root" rev-parse 'HEAD^{tree}')"

python3 - "$repository_root/contract.lock" <<'PY'
import os, pathlib, re, sys
text = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
values = {}
for line in text.splitlines():
    match = re.fullmatch(r"([a-z_]+):\s*\"?([^\"]+)\"?", line)
    if match:
        values[match.group(1)] = match.group(2)
expected = {
    "contract_version": os.environ["LATCHWAY_CONTRACT_VERSION"],
    "core_commit": os.environ["LATCHWAY_CORE_COMMIT"],
    "bundle_sha256": os.environ["LATCHWAY_CONTRACT_BUNDLE_SHA256"],
}
if any(values.get(name) != value for name, value in expected.items()):
    raise SystemExit("candidate core/contract pins do not match contract.lock")
PY

runtime_sdk_version="$(sed -n 's/^public const val LATCHWAY_SDK_VERSION: String = "\([^"]*\)"/\1/p' "$repository_root/latchway-core/src/main/kotlin/dev/latchway/core/LatchwayApi.kt")"
[[ "$runtime_sdk_version" == "$LATCHWAY_SDK_VERSION" ]] || { echo "candidate SDK version does not match runtime" >&2; exit 1; }

output_parent="$(dirname "$LATCHWAY_CANDIDATE_OUTPUT_DIR")"
[[ -d "$output_parent" && ! -L "$output_parent" ]] || {
  echo "candidate output parent must be an existing real directory" >&2
  exit 2
}
output_parent="$(cd "$output_parent" && pwd -P)"
output_name="$(basename "$LATCHWAY_CANDIDATE_OUTPUT_DIR")"
[[ "$output_name" != . && "$output_name" != .. && -n "$output_name" ]] || { echo "invalid candidate output directory" >&2; exit 2; }
output_dir="$output_parent/$output_name"
case "$output_dir/" in
  "$repository_root/"*) echo "candidate output directory must be outside the source repository" >&2; exit 2 ;;
esac
if [[ -e "$output_dir" ]]; then
  [[ -d "$output_dir" && ! -L "$output_dir" && -z "$(find "$output_dir" -mindepth 1 -print -quit)" ]] || {
    echo "candidate output directory must be absent or empty" >&2
    exit 1
  }
else
  mkdir "$output_dir"
fi

temporary_root="$(mktemp -d "${TMPDIR:-/tmp}/latchway-play-candidate.XXXXXX")"
cleanup() {
  if [[ -n "$temporary_root" && -d "$temporary_root" && "$temporary_root" == */latchway-play-candidate.* ]]; then
    rm -rf "$temporary_root"
  fi
}
trap cleanup EXIT

export SOURCE_DATE_EPOCH="$(git -C "$repository_root" show -s --format=%ct "$LATCHWAY_SOURCE_COMMIT")"
gradle_arguments=(
  :sample-conformance:clean
  :sample-conformance:bundleRelease
  --no-daemon
  --no-configuration-cache
  -Platchway.playCandidate=true
  -Platchway.playSigningMode=unsigned
  "-Platchway.packageName=$LATCHWAY_PACKAGE_NAME"
  "-Platchway.versionName=$LATCHWAY_APP_VERSION"
  "-Platchway.versionCode=$LATCHWAY_VERSION_CODE"
  "-Platchway.gatewayUrl=$LATCHWAY_GATEWAY_ORIGIN"
  "-Platchway.gatewayOrigin=$LATCHWAY_GATEWAY_ORIGIN"
  "-Platchway.gatewayDeploymentKeyId=$LATCHWAY_GATEWAY_DEPLOYMENT_KEY_ID"
  "-Platchway.gatewayDeploymentStatementSha256=$LATCHWAY_GATEWAY_DEPLOYMENT_STATEMENT_SHA256"
  "-Platchway.gatewayDeploymentPublicKeySha256=$LATCHWAY_GATEWAY_DEPLOYMENT_PUBLIC_KEY_SHA256"
  "-Platchway.gatewayConfigurationSha256=$LATCHWAY_GATEWAY_CONFIGURATION_SHA256"
  "-Platchway.gatewayImageDigest=$LATCHWAY_GATEWAY_IMAGE_DIGEST"
  "-Platchway.applicationId=$LATCHWAY_APPLICATION_ID"
  "-Platchway.environment=$LATCHWAY_ENVIRONMENT"
  "-Platchway.identityProvider=$LATCHWAY_IDENTITY_PROVIDER"
  "-Platchway.feature=$LATCHWAY_FEATURE"
  "-Platchway.errorMappingFeature=$LATCHWAY_ERROR_MAPPING_FEATURE"
  "-Platchway.model=$LATCHWAY_MODEL"
  "-Platchway.cloudProjectNumber=$LATCHWAY_CLOUD_PROJECT_NUMBER"
  "-Platchway.playTrack=$LATCHWAY_PLAY_TRACK"
  "-Platchway.sourceCommit=$LATCHWAY_SOURCE_COMMIT"
  "-Platchway.coreCommit=$LATCHWAY_CORE_COMMIT"
  "-Platchway.contractBundleSha256=$LATCHWAY_CONTRACT_BUNDLE_SHA256"
  "-Platchway.signingCertificateSha256=$LATCHWAY_SIGNING_CERTIFICATE_SHA256"
  -Platchway.requireLicensed=true
)
(cd "$repository_root" && ./gradlew "${gradle_arguments[@]}")

[[ "$(git -C "$repository_root" rev-parse HEAD)" == "$LATCHWAY_SOURCE_COMMIT" && \
   "$(git -C "$repository_root" rev-parse 'HEAD^{tree}')" == "$source_tree" && \
   -z "$(git -C "$repository_root" status --porcelain=v1 --untracked-files=all)" ]] || {
  echo "source mutated during candidate build" >&2
  exit 1
}

built_aab="$repository_root/sample-conformance/build/outputs/bundle/release/sample-conformance-release.aab"
[[ -f "$built_aab" && ! -L "$built_aab" && -s "$built_aab" ]] || { echo "Release AAB was not produced" >&2; exit 1; }
aab_name="latchway-play-conformance-$LATCHWAY_APP_VERSION-$LATCHWAY_VERSION_CODE.aab"
staged_aab="$temporary_root/$aab_name"
install -m 0600 "$built_aab" "$staged_aab"
payload_manifest_name="play-conformance-presign-payload.manifest"
payload_manifest="$temporary_root/$payload_manifest_name"
java "$repository_root/scripts/VerifyPlayAabSignature.java" \
  --emit-presign-manifest "$staged_aab" "$payload_manifest"
aab_sha256="$(shasum -a 256 "$staged_aab" | awk '{print $1}')"
payload_manifest_sha256="$(shasum -a 256 "$payload_manifest" | awk '{print $1}')"
gradle_wrapper_sha256="$(shasum -a 256 "$repository_root/gradle/wrapper/gradle-wrapper.jar" | awk '{print $1}')"
export LATCHWAY_CANDIDATE_AAB_NAME="$aab_name"
export LATCHWAY_CANDIDATE_AAB_SHA256="$aab_sha256"
export LATCHWAY_CANDIDATE_PAYLOAD_MANIFEST_NAME="$payload_manifest_name"
export LATCHWAY_CANDIDATE_PAYLOAD_MANIFEST_SHA256="$payload_manifest_sha256"
export LATCHWAY_CANDIDATE_SOURCE_TREE="$source_tree"
export LATCHWAY_CANDIDATE_GRADLE_WRAPPER_SHA256="$gradle_wrapper_sha256"
python3 - "$temporary_root/play-conformance-candidate.json" <<'PY'
import json, os, pathlib, sys
value = {
    "schema_version": "latchway.android-play-conformance-candidate.v1",
    "repository": "Latchway/latchway-android",
    "source": {
        "commit": os.environ["LATCHWAY_SOURCE_COMMIT"],
        "tree": os.environ["LATCHWAY_CANDIDATE_SOURCE_TREE"],
        "sdk_version": os.environ["LATCHWAY_SDK_VERSION"],
        "core_commit": os.environ["LATCHWAY_CORE_COMMIT"],
        "contract_version": os.environ["LATCHWAY_CONTRACT_VERSION"],
        "contract_bundle_sha256": os.environ["LATCHWAY_CONTRACT_BUNDLE_SHA256"],
    },
    "candidate": {
        "aab_file": os.environ["LATCHWAY_CANDIDATE_AAB_NAME"],
        "aab_sha256": os.environ["LATCHWAY_CANDIDATE_AAB_SHA256"],
        "signing_mode": "unsigned",
        "upload_certificate_sha256": None,
        "presign_payload_manifest": {
            "file": os.environ["LATCHWAY_CANDIDATE_PAYLOAD_MANIFEST_NAME"],
            "schema": "latchway.android-aab-presign-payload.v1",
            "sha256": os.environ["LATCHWAY_CANDIDATE_PAYLOAD_MANIFEST_SHA256"],
        },
        "expected_play_app_signing_certificate_sha256": os.environ["LATCHWAY_SIGNING_CERTIFICATE_SHA256"],
        "package_name": os.environ["LATCHWAY_PACKAGE_NAME"],
        "version_name": os.environ["LATCHWAY_APP_VERSION"],
        "version_code": os.environ["LATCHWAY_VERSION_CODE"],
        "play_track": os.environ["LATCHWAY_PLAY_TRACK"],
        "cloud_project_number": os.environ["LATCHWAY_CLOUD_PROJECT_NUMBER"],
        "require_licensed": True,
    },
    "identity": {
        "provider": os.environ["LATCHWAY_IDENTITY_PROVIDER"],
        "bootstrap": "run-bound-one-use-external-identity-jwt",
    },
    "latchway": {
        "application_id": os.environ["LATCHWAY_APPLICATION_ID"],
        "environment": os.environ["LATCHWAY_ENVIRONMENT"],
        "feature": os.environ["LATCHWAY_FEATURE"],
        "error_mapping_feature": os.environ["LATCHWAY_ERROR_MAPPING_FEATURE"],
        "model": os.environ["LATCHWAY_MODEL"],
    },
    "gateway": {
        "origin": os.environ["LATCHWAY_GATEWAY_ORIGIN"],
        "image_digest": os.environ["LATCHWAY_GATEWAY_IMAGE_DIGEST"],
        "configuration_sha256": os.environ["LATCHWAY_GATEWAY_CONFIGURATION_SHA256"],
        "deployment_key_id": os.environ["LATCHWAY_GATEWAY_DEPLOYMENT_KEY_ID"],
        "deployment_statement_sha256": os.environ["LATCHWAY_GATEWAY_DEPLOYMENT_STATEMENT_SHA256"],
        "deployment_public_key_sha256": os.environ["LATCHWAY_GATEWAY_DEPLOYMENT_PUBLIC_KEY_SHA256"],
    },
    "build": {
        "source_date_epoch": int(os.environ["SOURCE_DATE_EPOCH"]),
        "gradle_wrapper_sha256": os.environ["LATCHWAY_CANDIDATE_GRADLE_WRAPPER_SHA256"],
        "configuration_cache": False,
        "persistent_gradle_daemon": False,
    },
}
pathlib.Path(sys.argv[1]).write_bytes(
    json.dumps(value, allow_nan=False, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
)
PY
(
  cd "$temporary_root"
  shasum -a 256 \
    "$aab_name" \
    "$payload_manifest_name" \
    play-conformance-candidate.json > SHA256SUMS
)
install -m 0600 \
  "$temporary_root/$aab_name" \
  "$temporary_root/$payload_manifest_name" \
  "$temporary_root/play-conformance-candidate.json" \
  "$temporary_root/SHA256SUMS" \
  "$output_dir/"
test "$(find "$output_dir" -mindepth 1 -maxdepth 1 -type f | wc -l | tr -d ' ')" = 4
test -z "$(find "$output_dir" -mindepth 1 ! -type f -print -quit)"
(cd "$output_dir" && shasum -a 256 --check --strict SHA256SUMS)
echo "Play conformance candidate staged: $output_dir"
