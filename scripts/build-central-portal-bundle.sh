#!/usr/bin/env bash
set -euo pipefail
set +x
umask 077

if [[ $# -ne 2 || ! "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "usage: $0 MAJOR.MINOR.PATCH OUTPUT.zip" >&2
  exit 64
fi

version=$1
output=$2
script_directory=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repository_root=$(cd "$script_directory/.." && pwd)
reviewed_repository=${LATCHWAY_CENTRAL_EXPECTED_REPOSITORY:-$repository_root/build/release/repository}
public_key=${LATCHWAY_CENTRAL_SIGNING_PUBLIC_KEY:-}
fingerprint=${LATCHWAY_CENTRAL_SIGNING_FINGERPRINT:-}

[[ -d "$reviewed_repository/dev/latchway" ]] || {
  echo "The reviewed deterministic Maven repository is missing" >&2
  exit 64
}
[[ -f "$public_key" && ! -L "$public_key" ]] || {
  echo "The reviewed Maven signing public key is missing or unsafe" >&2
  exit 64
}
[[ "$fingerprint" =~ ^[0-9A-F]{40}$ ]] || {
  echo "A pinned uppercase 40-character Maven signing fingerprint is required" >&2
  exit 64
}
[[ -n "${LATCHWAY_SIGNING_KEY:-}" && -n "${LATCHWAY_SIGNING_PASSWORD:-}" ]] || {
  echo "In-memory OpenPGP signing material is required for a new Portal bundle" >&2
  exit 64
}
signing_key=$LATCHWAY_SIGNING_KEY
signing_password=$LATCHWAY_SIGNING_PASSWORD
unset LATCHWAY_SIGNING_KEY LATCHWAY_SIGNING_PASSWORD
[[ "$signing_password" != *$'\n'* && "$signing_password" != *$'\r'* ]] || {
  echo "OpenPGP signing password must be a single line" >&2
  exit 64
}
command -v gpg >/dev/null 2>&1 || { echo "gpg is required" >&2; exit 64; }
command -v zip >/dev/null 2>&1 || { echo "zip is required" >&2; exit 64; }

temporary_root=$(mktemp -d "${TMPDIR:-/tmp}/latchway-central-bundle.XXXXXX")
cleanup() {
  rm -rf "$temporary_root"
}
trap cleanup EXIT HUP INT TERM
mkdir -m 0700 "$temporary_root/gnupg" "$temporary_root/repository"
cp -R "$reviewed_repository/dev" "$temporary_root/repository/dev"
if find "$temporary_root/repository" -type l -print -quit | grep -q .; then
  echo "The reviewed Maven repository contains a symbolic link" >&2
  exit 1
fi

printf '%s' "$signing_key" |
  gpg --batch --homedir "$temporary_root/gnupg" --import >/dev/null 2>&1 || {
    echo "Could not import the in-memory Maven signing key" >&2
    exit 1
  }
unset signing_key

gpg --batch --homedir "$temporary_root/gnupg" --import "$public_key" >/dev/null 2>&1 || {
  echo "Could not import the reviewed Maven signing public key" >&2
  exit 1
}
observed_fingerprint=$(gpg --batch --homedir "$temporary_root/gnupg" --with-colons \
  --fingerprint "$fingerprint" | awk -F: '$1 == "fpr" {print $10; exit}')
[[ "$observed_fingerprint" == "$fingerprint" ]] || {
  echo "In-memory Maven signing key does not match the pinned primary fingerprint" >&2
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
    artifact="$temporary_root/repository/dev/latchway/$module/$version/$name"
    [[ -f "$artifact" && ! -L "$artifact" ]] || {
      echo "Reviewed Maven repository is missing $name" >&2
      exit 1
    }
    printf '%s\n' "$signing_password" |
      gpg --batch --yes --homedir "$temporary_root/gnupg" \
        --pinentry-mode loopback --passphrase-fd 0 \
        --local-user "$fingerprint" --digest-algo SHA512 --armor --detach-sign \
        --output "$artifact.asc" "$artifact" >/dev/null 2>&1 || {
      echo "Could not sign $name with the pinned Maven key" >&2
      exit 1
    }
    status="$temporary_root/$name.status"
    gpg --batch --homedir "$temporary_root/gnupg" --status-fd 1 \
      --verify "$artifact.asc" "$artifact" >"$status" 2>/dev/null || {
      echo "Locally generated signature failed verification for $name" >&2
      exit 1
    }
    python3 "$script_directory/verify-gpg-status.py" \
      --status "$status" --expected-primary-fingerprint "$fingerprint" >/dev/null || {
      echo "Locally generated GnuPG status failed closed for $name" >&2
      exit 1
    }
    [[ $(wc -c <"$artifact.asc") -le 65536 ]] || {
      echo "Generated signature exceeds the reviewed size bound for $name" >&2
      exit 1
    }
  done
done
unset signing_password

find "$temporary_root/repository" -exec touch -t 198001010000 {} +
archive="$temporary_root/central-portal-bundle.zip"
(
  cd "$temporary_root/repository"
  find . -type f -print | LC_ALL=C sort | zip -X -q "$archive" -@
)
mkdir -p "$(dirname "$output")"
mv -f "$archive" "$output"
echo "Built exact signed Central Portal bundle $(basename "$output")"
