#!/usr/bin/env bash
set -euo pipefail
set +x
umask 077

script_directory=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
record_helper="$script_directory/central-deployment-record.py"

if [[ -n "${LATCHWAY_SIGNING_KEY:-}" || -n "${LATCHWAY_SIGNING_PASSWORD:-}" ]]; then
  echo "Private signing material must not be exposed to the Central publication transition" >&2
  exit 64
fi

intent=${LATCHWAY_CENTRAL_UPLOAD_INTENT:-}
record=${LATCHWAY_CENTRAL_DEPLOYMENT_RECORD:-}
status=${LATCHWAY_CENTRAL_DEPLOYMENT_STATUS:-}
attempts=${LATCHWAY_CENTRAL_PUBLISH_ATTEMPTS:-90}
delay=${LATCHWAY_CENTRAL_PUBLISH_DELAY_SECONDS:-20}
portal_api=${LATCHWAY_CENTRAL_PORTAL_API_BASE_URL:-https://central.sonatype.com/api/v1/publisher}

portal_username=${LATCHWAY_MAVEN_CENTRAL_USERNAME:-}
portal_password=${LATCHWAY_MAVEN_CENTRAL_PASSWORD:-}
unset LATCHWAY_MAVEN_CENTRAL_USERNAME LATCHWAY_MAVEN_CENTRAL_PASSWORD

[[ -n "$intent" && -f "$intent" && ! -L "$intent" ]] || {
  echo "The exact Maven Central upload intent is required" >&2
  exit 64
}
[[ -n "$record" && -f "$record" && ! -L "$record" ]] || {
  echo "The exact Maven Central deployment record is required" >&2
  exit 64
}
[[ -n "$status" ]] || {
  echo "The immutable Maven Central deployment status path is required" >&2
  exit 64
}
[[ "$attempts" =~ ^[0-9]+$ && "$delay" =~ ^[0-9]+$ ]] || {
  echo "Central publication transition retry settings are invalid" >&2
  exit 64
}
(( attempts >= 1 && attempts <= 180 && delay >= 1 && delay <= 60 )) || {
  echo "Central publication transition retry settings are invalid" >&2
  exit 64
}
[[ "$portal_api" =~ ^https://[A-Za-z0-9.-]+(:[0-9]+)?(/[A-Za-z0-9._~-]+)*/api/v1/publisher$ ]] || {
  echo "Central Portal API base URL is invalid" >&2
  exit 64
}

intent_version=$(python3 "$record_helper" validate-intent --intent "$intent" --field version)
intent_name=$(python3 "$record_helper" validate-intent --intent "$intent" --field deployment_name)
record_kind=$(python3 "$record_helper" validate-record --intent "$intent" --record "$record" --field record_kind)
record_version=$(python3 "$record_helper" validate-record --intent "$intent" --record "$record" --field version)
[[ "$intent_version" == "$record_version" ]] || {
  echo "Central deployment record version differs from the upload intent" >&2
  exit 1
}

manifest_for_completion=$(python3 - "$record" <<'PY'
import json
import pathlib
import sys

value = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
manifest = value.get("public_manifest_sha256")
print(manifest if isinstance(manifest, str) else "0" * 64)
PY
)

if [[ -e "$status" ]]; then
  python3 "$record_helper" validate-complete \
    --intent "$intent" --record "$record" --status "$status" \
    --public-manifest-sha256 "$manifest_for_completion" >/dev/null
  echo "Validated existing complete Maven Central publication state"
  exit 0
fi

if [[ "$record_kind" == public_registry_adoption ]]; then
  echo "Public-registry adoption is missing its immutable completion status" >&2
  exit 1
fi
[[ "$record_kind" == portal_deployment ]] || {
  echo "Central deployment record kind is unreviewed" >&2
  exit 1
}
deployment_id=$(python3 "$record_helper" validate-record --intent "$intent" --record "$record" --field deployment_id)

[[ -n "$portal_username" && -n "$portal_password" ]] || {
  echo "Maven Central Publisher Portal credentials are required" >&2
  exit 64
}
[[ "$portal_username" != *$'\n'* && "$portal_username" != *$'\r'* &&
   "$portal_password" != *$'\n'* && "$portal_password" != *$'\r'* ]] || {
  echo "Maven Central Publisher Portal credentials must be single-line values" >&2
  exit 64
}

temporary_root=$(mktemp -d "${TMPDIR:-/tmp}/latchway-central-transition.XXXXXX")
cleanup() { rm -rf "$temporary_root"; }
trap cleanup EXIT HUP INT TERM
authorization=$(printf '%s:%s' "$portal_username" "$portal_password" | base64 | tr -d '\r\n')
printf 'Authorization: Bearer %s\n' "$authorization" > "$temporary_root/auth-header"
unset authorization portal_username portal_password

publish_requested=false
publish_outcome_uncertain=false
for ((attempt = 1; attempt <= attempts; attempt++)); do
  raw="$temporary_root/status-$attempt.json"
  code=$(curl \
    --proto '=https' --proto-redir '=https' --tlsv1.2 \
    --connect-timeout 15 --max-time 120 --max-filesize 2097152 \
    --silent --show-error --request POST --header "@$temporary_root/auth-header" \
    --output "$raw" --write-out '%{http_code}' \
    "$portal_api/status?id=$deployment_id")
  [[ "$code" == 200 ]] || {
    echo "Maven Central deployment status returned HTTP $code" >&2
    exit 1
  }
  normalized="$temporary_root/normalized-$attempt.json"
  state=$(python3 "$record_helper" validate-status \
    --intent "$intent" --record "$record" --status "$raw" --output "$normalized")
  case "$state" in
    PUBLISHED)
      python3 "$record_helper" validate-status \
        --intent "$intent" --record "$record" --status "$raw" --output "$status" >/dev/null
      python3 "$record_helper" validate-complete \
        --intent "$intent" --record "$record" --status "$status" \
        --public-manifest-sha256 "$manifest_for_completion" >/dev/null
      echo "Maven Central deployment $deployment_id is PUBLISHED"
      exit 0
      ;;
    VALIDATED)
      if [[ "$publish_requested" == false ]]; then
        # Revalidate every immutable binding immediately before the one-way
        # publication request. Only this exact deployment UUID can be changed.
        test "$(python3 "$record_helper" validate-intent --intent "$intent" --field deployment_name)" = "$intent_name"
        test "$(python3 "$record_helper" validate-record --intent "$intent" --record "$record" --field deployment_id)" = "$deployment_id"
        response="$temporary_root/publish-response"
        set +e
        publish_code=$(curl \
          --proto '=https' --proto-redir '=https' --tlsv1.2 \
          --connect-timeout 15 --max-time 120 \
          --silent --show-error --request POST --header "@$temporary_root/auth-header" \
          --output "$response" --write-out '%{http_code}' \
          "$portal_api/deployment/$deployment_id")
        publish_transport=$?
        set -e
        publish_requested=true
        if [[ "$publish_transport" -eq 0 ]]; then
          [[ "$publish_code" == 204 ]] || {
            echo "Maven Central publication transition returned HTTP $publish_code" >&2
            exit 1
          }
        else
          publish_outcome_uncertain=true
          echo "Maven Central publication response was lost; reconciling status without retrying in this invocation" >&2
        fi
      fi
      ;;
    PENDING|VALIDATING|PUBLISHING) ;;
    FAILED)
      echo "Maven Central rejected the exact deployment" >&2
      exit 1
      ;;
    *)
      echo "Maven Central returned an unreviewed deployment state" >&2
      exit 1
      ;;
  esac
  if (( attempt < attempts )); then sleep "$delay"; fi
done

if [[ "$publish_outcome_uncertain" == true ]]; then
  echo "Maven Central publication outcome remains unresolved; rerun to reconcile the same exact deployment" >&2
else
  echo "Maven Central deployment did not reach PUBLISHED within the verification window" >&2
fi
exit 1
