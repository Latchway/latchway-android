#!/usr/bin/env bash
set -Eeuo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: verify-public-core-release.sh LOCKED_CORE_COMMIT OUTPUT_DIRECTORY" >&2
  exit 64
fi

locked_core_commit=$1
output=$2
core_repository=Latchway/latchway
core_tag=v1.0.0

[[ "$locked_core_commit" =~ ^[0-9a-f]{40}$ ]]
test ! -e "$output"
mkdir -m 700 "$output"

version=$(gh --version | sed -nE '1s/^gh version ([0-9]+)\.([0-9]+)\.([0-9]+).*$/\1 \2 \3/p')
read -r major minor patch <<< "$version"
[[ "$major" =~ ^[0-9]+$ && "$minor" =~ ^[0-9]+$ && "$patch" =~ ^[0-9]+$ ]]
(( major > 2 || (major == 2 && minor >= 97) ))

gh api -H 'X-GitHub-Api-Version: 2026-03-10' \
  "repos/$core_repository/releases/tags/$core_tag" > "$RUNNER_TEMP/core-release-api.json"
jq --exit-status '
  .tag_name == "v1.0.0" and .draft == false and .prerelease == false and
  (.assets | length) == 15 and ([.assets[].name] | unique | length) == 15 and
  all(.assets[]; (.size | type == "number" and . > 0 and . <= 33554432))
' "$RUNNER_TEMP/core-release-api.json" >/dev/null
gh release download "$core_tag" --repo "$core_repository" --dir "$output"

python3 scripts/verify-public-core-release.py \
  --release-directory "$output" --locked-core-commit "$locked_core_commit" \
  > "$RUNNER_TEMP/verified-core-release.json"

core_commit=$(jq --exit-status --raw-output '.candidate_commit | select(test("^[0-9a-f]{40}$"))' "$RUNNER_TEMP/verified-core-release.json")
title=$(jq --raw-output .title "$RUNNER_TEMP/verified-core-release.json")
body=$(jq --raw-output .body "$RUNNER_TEMP/verified-core-release.json")
tag_message=$(jq --raw-output .tag_message "$RUNNER_TEMP/verified-core-release.json")
jq --exit-status --arg title "$title" --arg body "$body" '
  .name == $title and .body == $body
' "$RUNNER_TEMP/core-release-api.json" >/dev/null

gh api "repos/$core_repository/git/ref/tags/$core_tag" > "$RUNNER_TEMP/core-tag-ref.json"
test "$(jq --raw-output .object.type "$RUNNER_TEMP/core-tag-ref.json")" = tag
tag_object=$(jq --exit-status --raw-output '.object.sha | select(test("^[0-9a-f]{40}$"))' "$RUNNER_TEMP/core-tag-ref.json")
gh api "repos/$core_repository/git/tags/$tag_object" > "$RUNNER_TEMP/core-tag-object.json"
jq --exit-status --arg commit "$core_commit" --arg message "$tag_message" '
  .tag == "v1.0.0" and .object.type == "commit" and
  .object.sha == $commit and .message == $message
' "$RUNNER_TEMP/core-tag-object.json" >/dev/null

gh api "repos/$core_repository/compare/$locked_core_commit...$core_commit" > "$RUNNER_TEMP/core-ancestry.json"
jq --exit-status --arg locked "$locked_core_commit" '
  (.status == "ahead" or .status == "identical") and .merge_base_commit.sha == $locked
' "$RUNNER_TEMP/core-ancestry.json" >/dev/null

for asset in latchway-single-maintainer-v1.json SHA256SUMS; do
  gh attestation verify "$output/$asset" \
    --repo "$core_repository" \
    --signer-workflow "$core_repository/.github/workflows/single-maintainer-release.yml" \
    --source-digest "$core_commit" --signer-digest "$core_commit" \
    --source-ref refs/heads/main --deny-self-hosted-runners >/dev/null
done

gh attestation verify "$output/latchway-candidate.json" \
  --bundle "$output/latchway-candidate.attestation.sigstore.json" \
  --repo "$core_repository" \
  --signer-workflow "$core_repository/.github/workflows/release.yml" \
  --source-digest "$core_commit" --signer-digest "$core_commit" \
  --source-ref refs/heads/main --deny-self-hosted-runners >/dev/null
for platform in compose cloud_run; do
  gh attestation verify "$output/$platform.tar.gz" \
    --bundle "$output/$platform.attestation.json" \
    --repo "$core_repository" \
    --signer-workflow "$core_repository/.github/workflows/deployment-evidence.yml" \
    --source-digest "$core_commit" --signer-digest "$core_commit" \
    --source-ref refs/heads/main --deny-self-hosted-runners >/dev/null
done

printf '%s\n' "verified public core $core_tag at $core_commit with exact Compose and Cloud Run evidence"
