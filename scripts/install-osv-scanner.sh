#!/usr/bin/env bash
set -euo pipefail

readonly version="2.4.0"
readonly commit="b56b5191101d5f27d4787d5583d8d01e9518a7af"
readonly release_base="https://github.com/google/osv-scanner/releases/download/v${version}"

if [[ "$#" -ne 1 || -z "$1" ]]; then
  echo "usage: scripts/install-osv-scanner.sh <destination>" >&2
  exit 2
fi

case "$(uname -s):$(uname -m)" in
  Darwin:arm64)
    asset="osv-scanner_darwin_arm64"
    expected_bytes="54304354"
    expected_sha256="9ca3185ad63e9ab54f7cb90f46a7362be02d80e37f0123d095a54355ea202f5d"
    ;;
  Darwin:x86_64)
    asset="osv-scanner_darwin_amd64"
    expected_bytes="57832640"
    expected_sha256="088119325156321c34c456ac3703d6013538fd71cbac82b891ab34db491e4d66"
    ;;
  Linux:aarch64|Linux:arm64)
    asset="osv-scanner_linux_arm64"
    expected_bytes="52756642"
    expected_sha256="44e580752910f0ff36ec99aff59af20f65df1e859aa31e5605a8f0d055b496e9"
    ;;
  Linux:x86_64|Linux:amd64)
    asset="osv-scanner_linux_amd64"
    expected_bytes="56676514"
    expected_sha256="15314940c10d26af9c6649f150b8a47c1262e8fc7e17b1d1029b0e479e8ed8a0"
    ;;
  *)
    echo "unsupported OSV-Scanner platform" >&2
    exit 2
    ;;
esac

destination=$1
destination_directory=$(dirname "$destination")
mkdir -p "$destination_directory"
temporary=$(mktemp "$destination_directory/.osv-scanner.XXXXXX")
trap 'rm -f -- "$temporary"' EXIT

curl --proto '=https' --proto-redir '=https' --tlsv1.2 \
  --fail --location --silent --show-error \
  --connect-timeout 15 --max-time 180 --max-filesize 70000000 \
  --output "$temporary" "$release_base/$asset"

actual_bytes=$(wc -c < "$temporary" | tr -d '[:space:]')
[[ "$actual_bytes" = "$expected_bytes" ]] || {
  echo "OSV-Scanner byte count mismatch" >&2
  exit 1
}

if command -v sha256sum >/dev/null 2>&1; then
  actual_sha256=$(sha256sum "$temporary" | awk '{print $1}')
else
  actual_sha256=$(shasum -a 256 "$temporary" | awk '{print $1}')
fi
[[ "$actual_sha256" = "$expected_sha256" ]] || {
  echo "OSV-Scanner SHA-256 mismatch" >&2
  exit 1
}

chmod 0755 "$temporary"
version_output=$("$temporary" --version)
grep -Fxq "osv-scanner version: $version" <<<"$version_output"
grep -Fxq "commit: $commit" <<<"$version_output"
mv -f -- "$temporary" "$destination"
trap - EXIT
