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
expected_repository=${LATCHWAY_CENTRAL_EXPECTED_REPOSITORY:-}
expected_signing_fingerprint=${LATCHWAY_CENTRAL_SIGNING_FINGERPRINT:-}
expected_signing_public_key=${LATCHWAY_CENTRAL_SIGNING_PUBLIC_KEY:-}
if [[ -n "$expected_repository" ]]; then
  [[ -d "$expected_repository/dev/latchway" ]] || {
    echo "Expected Maven repository does not contain dev/latchway" >&2
    exit 64
  }
  expected_repository=$(cd "$expected_repository" && pwd -P)
  if [[ ! "$expected_signing_fingerprint" =~ ^[0-9A-F]{40}$ ]]; then
    echo "A pinned 40-character uppercase OpenPGP signing fingerprint is required with the reviewed repository" >&2
    exit 64
  fi
  if [[ -n "$expected_signing_public_key" && ! -f "$expected_signing_public_key" ]]; then
    echo "The reviewed Maven Central public signing key is missing" >&2
    exit 64
  fi
fi
temporary_root=$(mktemp -d "${TMPDIR:-/tmp}/latchway-central-verify.XXXXXX")
proof_rows="$temporary_root/proof.tsv"
cleanup() {
  rm -rf "$temporary_root"
}
trap cleanup EXIT HUP INT TERM
if [[ -n "$expected_repository" ]]; then
  command -v gpg >/dev/null 2>&1 || {
    echo "gpg is required to verify Maven Central signatures" >&2
    exit 64
  }
  mkdir -m 0700 "$temporary_root/gnupg"
  if [[ -n "$expected_signing_public_key" ]]; then
    gpg --batch --homedir "$temporary_root/gnupg" --import "$expected_signing_public_key" >/dev/null 2>&1 || {
      echo "Could not import the reviewed Maven Central public signing key" >&2
      exit 1
    }
  else
    gpg --batch --homedir "$temporary_root/gnupg" \
      --keyserver hkps://keys.openpgp.org --recv-keys "$expected_signing_fingerprint" >/dev/null 2>&1 || {
      echo "Could not retrieve the pinned Maven Central signing key" >&2
      exit 1
    }
  fi
  observed_fingerprint=$(gpg --batch --homedir "$temporary_root/gnupg" --with-colons \
    --fingerprint "$expected_signing_fingerprint" | awk -F: '$1 == "fpr" {print $10; exit}')
  [[ "$observed_fingerprint" == "$expected_signing_fingerprint" ]] || {
    echo "Retrieved Maven Central signing key fingerprint mismatch" >&2
    exit 1
  }
fi

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
    curl --fail --silent --show-error --location --output "$temporary_root/$name.asc" "$url.asc"
    [[ -s "$temporary_root/$name.asc" ]] || {
      echo "Maven Central signature is missing for $name" >&2
      exit 1
    }
    if [[ -n "$expected_repository" ]]; then
      signature_status="$temporary_root/$name.signature-status"
      gpg --batch --homedir "$temporary_root/gnupg" --status-fd 1 \
        --verify "$temporary_root/$name.asc" "$temporary_root/$name" \
        > "$signature_status" 2>/dev/null || {
        echo "Maven Central signature verification failed for $name" >&2
        exit 1
      }
      grep -Eq "^\[GNUPG:\] VALIDSIG $expected_signing_fingerprint " "$signature_status" || {
        echo "Maven Central signature does not use the pinned key for $name" >&2
        exit 1
      }
    fi
    actual=$(shasum -a 256 "$temporary_root/$name" | awk '{print $1}')
    signature_sha256=$(shasum -a 256 "$temporary_root/$name.asc" | awk '{print $1}')
    for algorithm in md5 sha1 sha256 sha512; do
      curl --fail --silent --show-error --location \
        --output "$temporary_root/$name.$algorithm" "$url.$algorithm"
      case "$algorithm" in
        md5)
          if command -v md5sum >/dev/null 2>&1; then
            calculated=$(md5sum "$temporary_root/$name" | awk '{print $1}')
          else
            calculated=$(openssl dgst -md5 "$temporary_root/$name" | awk '{print $NF}')
          fi
          ;;
        sha1) calculated=$(shasum -a 1 "$temporary_root/$name" | awk '{print $1}') ;;
        sha256) calculated=$actual ;;
        sha512) calculated=$(shasum -a 512 "$temporary_root/$name" | awk '{print $1}') ;;
      esac
      published=$(tr -d '[:space:]' < "$temporary_root/$name.$algorithm")
      [[ "$published" == "$calculated" ]] || {
        echo "Maven Central $algorithm checksum mismatch for $name" >&2
        exit 1
      }
    done
    if [[ -n "$expected_repository" ]]; then
      expected_file="$expected_repository/dev/latchway/$module/$version/$name"
      [[ -f "$expected_file" ]] || {
        echo "Reviewed Maven repository is missing $name" >&2
        exit 1
      }
      cmp -s "$expected_file" "$temporary_root/$name" || {
        echo "Maven Central artifact differs from the reviewed release byte-for-byte: $name" >&2
        exit 1
      }
      for algorithm in md5 sha1 sha256 sha512; do
        expected_checksum="$expected_file.$algorithm"
        [[ -f "$expected_checksum" ]] || {
          echo "Reviewed Maven repository is missing $name.$algorithm" >&2
          exit 1
        }
        cmp -s "$expected_checksum" "$temporary_root/$name.$algorithm" || {
          echo "Maven Central checksum differs from the reviewed release byte-for-byte: $name.$algorithm" >&2
          exit 1
        }
      done
    fi
    printf '%s\t%s\t%s\t%s\n' \
      "$module/$version/$name" "$actual" \
      "$(wc -c < "$temporary_root/$name" | tr -d '[:space:]')" \
      "$signature_sha256" >> "$proof_rows"
  done
  grep -Fq "<tag>v$version</tag>" "$temporary_root/$module-$version.pom" || {
    echo "Maven Central POM metadata is invalid for $module" >&2
    exit 1
  }
done

public_key_sha256=
if [[ -n "$expected_signing_public_key" ]]; then
  public_key_sha256=$(shasum -a 256 "$expected_signing_public_key" | awk '{print $1}')
fi
python3 - "$version" "$expected_repository" "$expected_signing_fingerprint" "$public_key_sha256" "$proof_rows" "$temporary_root" <<'PY'
import json
from pathlib import Path
import sys

version, expected_repository, signing_fingerprint, public_key_sha256, rows_path, temporary_root = sys.argv[1:]
files = []
for line in Path(rows_path).read_text(encoding="utf-8").splitlines():
    path, sha256, size, signature_sha256 = line.split("\t")
    files.append({
        "path": path,
        "sha256": sha256,
        "bytes": int(size),
        "signature_sha256": signature_sha256,
        "signature_armored": (Path(temporary_root) / f"{Path(path).name}.asc").read_text(encoding="ascii"),
        "checksums_byte_identical": bool(expected_repository),
    })
print(json.dumps({
    "schema_version": 1,
    "registry": "maven_central",
    "namespace": "dev.latchway",
    "version": version,
    "reviewed_repository": bool(expected_repository),
    "primary_artifacts_byte_identical": bool(expected_repository),
    "checksum_files_byte_identical": bool(expected_repository),
    "signature_files_present": True,
    "signatures_cryptographically_verified": bool(expected_repository),
    "signing_fingerprint": signing_fingerprint,
    "reviewed_public_key_sha256": public_key_sha256,
    "files": files,
}, indent=2, sort_keys=True))
PY
