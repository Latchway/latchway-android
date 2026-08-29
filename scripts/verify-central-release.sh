#!/usr/bin/env bash
set -euo pipefail

script_directory=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

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
mkdir "$temporary_root/gpg-proof"
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
      signature_proof="$temporary_root/gpg-proof/$name.json"
      python3 "$script_directory/verify-gpg-status.py" \
        --status "$signature_status" \
        --expected-primary-fingerprint "$expected_signing_fingerprint" \
        > "$signature_proof" || {
        echo "Maven Central signature status is invalid for $name" >&2
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
    printf '%s\t%s\t%s\t%s\t%s\n' \
      "$module/$version/$name" "$actual" \
      "$(wc -c < "$temporary_root/$name" | tr -d '[:space:]')" \
      "$signature_sha256" "$temporary_root/gpg-proof/$name.json" >> "$proof_rows"
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
deployment_intent=${LATCHWAY_CENTRAL_UPLOAD_INTENT:-}
deployment_record=${LATCHWAY_CENTRAL_DEPLOYMENT_RECORD:-}
deployment_status=${LATCHWAY_CENTRAL_DEPLOYMENT_STATUS:-}
require_deployment_evidence=${LATCHWAY_CENTRAL_REQUIRE_DEPLOYMENT_EVIDENCE:-false}
if [[ "$require_deployment_evidence" == true ]]; then
  [[ -f "$deployment_intent" && -f "$deployment_record" && -f "$deployment_status" ]] || {
    echo "Exact Central upload intent, deployment record, and final status evidence are required" >&2
    exit 64
  }
elif [[ "$require_deployment_evidence" != false ]]; then
  echo "LATCHWAY_CENTRAL_REQUIRE_DEPLOYMENT_EVIDENCE must be true or false" >&2
  exit 64
fi
python3 - "$version" "$expected_repository" "$expected_signing_fingerprint" "$public_key_sha256" \
  "$proof_rows" "$temporary_root" "$deployment_intent" "$deployment_record" "$deployment_status" \
  "$script_directory" <<'PY'
import hashlib
import json
from pathlib import Path
import subprocess
import sys

(
    version,
    expected_repository,
    signing_fingerprint,
    public_key_sha256,
    rows_path,
    temporary_root,
    deployment_intent,
    deployment_record,
    deployment_status,
    script_directory,
) = sys.argv[1:]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


files = []
public_manifest = []
for line in Path(rows_path).read_text(encoding="utf-8").splitlines():
    path, artifact_sha256, size, signature_sha256, gpg_proof_path = line.split("\t")
    name = Path(path).name
    signature = Path(temporary_root, f"{name}.asc")
    if signature.stat().st_size > 65536:
        raise SystemExit(f"signature is unexpectedly large: {name}")
    checksums = []
    for algorithm in ("md5", "sha1", "sha256", "sha512"):
        checksum = Path(temporary_root, f"{name}.{algorithm}")
        if checksum.stat().st_size > 256:
            raise SystemExit(f"checksum is unexpectedly large: {name}.{algorithm}")
        checksums.append({
            "algorithm": algorithm,
            "path": f"{path}.{algorithm}",
            "bytes": checksum.stat().st_size,
            "sha256": sha256(checksum),
            "published_digest": checksum.read_text(encoding="ascii").strip(),
        })
    gpg_status = None
    if expected_repository:
        gpg_status = json.loads(Path(gpg_proof_path).read_text(encoding="utf-8"))
    files.append({
        "path": path,
        "sha256": artifact_sha256,
        "bytes": int(size),
        "signature_sha256": signature_sha256,
        "signature_bytes": signature.stat().st_size,
        "signature_armored": signature.read_text(encoding="ascii"),
        "gpg_status": gpg_status,
        "checksums": checksums,
        "checksums_byte_identical": bool(expected_repository),
    })
    public_manifest.append({"path": path, "bytes": int(size), "sha256": artifact_sha256})
    public_manifest.append({
        "path": f"{path}.asc",
        "bytes": signature.stat().st_size,
        "sha256": signature_sha256,
    })
    public_manifest.extend({
        "path": checksum["path"],
        "bytes": checksum["bytes"],
        "sha256": checksum["sha256"],
    } for checksum in checksums)

public_manifest.sort(key=lambda item: item["path"])
public_manifest_sha256 = hashlib.sha256(
    (json.dumps(public_manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
).hexdigest()

deployment = None
if deployment_intent or deployment_record or deployment_status:
    if not deployment_intent or not deployment_record or not deployment_status:
        raise SystemExit("deployment intent, record, and status must be supplied together")
    intent_path = Path(deployment_intent)
    record_path = Path(deployment_record)
    status_path = Path(deployment_status)
    record = json.loads(record_path.read_text(encoding="utf-8"))
    status = json.loads(status_path.read_text(encoding="utf-8"))
    helper = Path(script_directory, "central-deployment-record.py")
    validation = subprocess.run(
        [
            sys.executable, str(helper), "validate-complete",
            "--intent", str(intent_path), "--record", str(record_path),
            "--status", str(status_path),
            "--public-manifest-sha256", public_manifest_sha256,
        ],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if validation.returncode != 0:
        raise SystemExit(validation.stderr.strip() or "deployment evidence validation failed")
    deployment = {
        "intent_sha256": sha256(intent_path),
        "record_sha256": sha256(record_path),
        "status_sha256": sha256(status_path),
        "record_kind": record.get("record_kind"),
        "record": record,
        "status": status,
    }

print(json.dumps({
    "schema_version": 2,
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
    "deployment": deployment,
    "public_manifest": public_manifest,
    "public_manifest_sha256": public_manifest_sha256,
    "files": files,
}, indent=2, sort_keys=True))
PY
