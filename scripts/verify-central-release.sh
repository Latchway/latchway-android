#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 || ! "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "usage: $0 MAJOR.MINOR.PATCH" >&2
  exit 64
fi

version=$1
attempts=${LATCHWAY_CENTRAL_VERIFY_ATTEMPTS:-90}
delay=${LATCHWAY_CENTRAL_VERIFY_DELAY_SECONDS:-20}
if [[ ! "$attempts" =~ ^[0-9]+$ || "$attempts" -lt 1 || "$attempts" -gt 180 ||
      ! "$delay" =~ ^[0-9]+$ || "$delay" -lt 1 || "$delay" -gt 60 ]]; then
  echo "Central verification retry settings are invalid" >&2
  exit 64
fi

base_url=${LATCHWAY_MAVEN_CENTRAL_BASE_URL:-https://repo1.maven.org/maven2/dev/latchway}
temporary_root=$(mktemp -d "${TMPDIR:-/tmp}/latchway-central-verify.XXXXXX")
cleanup() {
  rm -rf "$temporary_root"
}
trap cleanup EXIT HUP INT TERM

bom_url="$base_url/latchway-bom/$version/latchway-bom-$version.pom"
available=false
for ((attempt = 1; attempt <= attempts; attempt++)); do
  if curl --fail --silent --show-error --location --head "$bom_url" >/dev/null 2>&1; then
    available=true
    break
  fi
  if (( attempt < attempts )); then
    sleep "$delay"
  fi
done
[[ "$available" == true ]] || {
  echo "Maven Central did not expose dev.latchway artifacts within the verification window" >&2
  exit 1
}

modules=(latchway-core latchway-okhttp latchway-play-integrity latchway-firebase-auth latchway-bom)
for module in "${modules[@]}"; do
  extensions=(pom module sources.jar javadoc.jar)
  if [[ "$module" != latchway-bom ]]; then
    extensions+=(aar)
  fi
  for extension in "${extensions[@]}"; do
    name="$module-$version-$extension"
    if [[ "$extension" == pom || "$extension" == module || "$extension" == aar ]]; then
      name="$module-$version.$extension"
    fi
    url="$base_url/$module/$version/$name"
    curl --fail --silent --show-error --location --output "$temporary_root/$name" "$url"
    curl --fail --silent --show-error --location --output "$temporary_root/$name.sha256" "$url.sha256"
    curl --fail --silent --show-error --location --output "$temporary_root/$name.asc" "$url.asc"
    expected=$(awk '{print $1}' "$temporary_root/$name.sha256")
    actual=$(shasum -a 256 "$temporary_root/$name" | awk '{print $1}')
    [[ "$expected" == "$actual" && "$expected" =~ ^[0-9a-fA-F]{64}$ ]] || {
      echo "Maven Central checksum mismatch for $name" >&2
      exit 1
    }
    [[ -s "$temporary_root/$name.asc" ]] || {
      echo "Maven Central signature is missing for $name" >&2
      exit 1
    }
  done
  grep -Fq "<tag>v$version</tag>" "$temporary_root/$module-$version.pom" || {
    echo "Maven Central POM metadata is invalid for $module" >&2
    exit 1
  }
done

echo "Verified signed dev.latchway:$version artifacts on Maven Central"
