#!/usr/bin/env bash
set -Eeuo pipefail

# compileSdk/targetSdk 37 select the base Android 37.0 platform. Google
# publishes that stable package with the explicit minor component in its ID.
# AGP 9.3.2 resolves Build Tools 36.0.0 unless buildToolsVersion is overridden.
readonly platform_package="platforms;android-37.0"
readonly build_tools_package="build-tools;36.0.0"

sdk_root="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-}}"
if [[ -z "$sdk_root" ]]; then
  echo "ANDROID_SDK_ROOT or ANDROID_HOME must identify the Android SDK." >&2
  exit 1
fi

if ! command -v sdkmanager >/dev/null 2>&1; then
  echo "sdkmanager is required to install the pinned Android SDK packages." >&2
  exit 1
fi

sdkmanager \
  --sdk_root="$sdk_root" \
  --channel=0 \
  "$platform_package" \
  "$build_tools_package"

verify_package() {
  local package_xml=$1
  local package_id=$2
  if [[ ! -f "$package_xml" ]] || ! grep -Fq "path=\"$package_id\"" "$package_xml"; then
    echo "Android SDK package verification failed for $package_id." >&2
    exit 1
  fi
}

verify_package \
  "$sdk_root/platforms/android-37.0/package.xml" \
  "$platform_package"
verify_package \
  "$sdk_root/build-tools/36.0.0/package.xml" \
  "$build_tools_package"

if [[ ! -f "$sdk_root/platforms/android-37.0/android.jar" ]]; then
  echo "Android SDK Platform 37.0 is missing android.jar." >&2
  exit 1
fi
if [[ ! -x "$sdk_root/build-tools/36.0.0/aapt2" ]]; then
  echo "Android SDK Build Tools 36.0.0 is missing executable aapt2." >&2
  exit 1
fi
