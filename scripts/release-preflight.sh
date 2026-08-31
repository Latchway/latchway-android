#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 vMAJOR.MINOR.PATCH" >&2
  exit 64
fi

tag=$1
if [[ ! "$tag" =~ ^v([0-9]+)\.([0-9]+)\.([0-9]+)$ ]]; then
  echo "Android releases require a stable vMAJOR.MINOR.PATCH tag" >&2
  exit 64
fi
version=${tag#v}
script_directory=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repository_root=$(cd "$script_directory/.." && pwd)

if [[ -n "$(git -C "$repository_root" status --porcelain)" ]]; then
  echo "Release preflight requires a clean worktree" >&2
  exit 1
fi
if [[ $(git -C "$repository_root" cat-file -t "refs/tags/$tag" 2>/dev/null || true) != tag ]]; then
  echo "Release tag $tag must be annotated" >&2
  exit 1
fi
if [[ $(git -C "$repository_root" rev-parse "refs/tags/$tag^{}") != $(git -C "$repository_root" rev-parse HEAD) ]]; then
  echo "Release tag $tag does not identify HEAD" >&2
  exit 1
fi

runtime_source="$repository_root/latchway-core/src/main/kotlin/dev/latchway/core/LatchwayApi.kt"
runtime_version=$(sed -n 's/.*LATCHWAY_SDK_VERSION: String = "\([^"]*\)".*/\1/p' "$runtime_source")
runtime_contract=$(sed -n 's/.*LATCHWAY_CONTRACT_VERSION: String = "\([^"]*\)".*/\1/p' "$runtime_source")
lock_value() {
  sed -n "s/^$1:[[:space:]]*\"\{0,1\}\([^\"]*\)\"\{0,1\}$/\1/p" "$repository_root/contract.lock"
}
lock_contract=$(lock_value contract_version)
lock_release=$(lock_value core_release)
lock_commit=$(lock_value core_commit)
lock_bundle=$(lock_value bundle_sha256)

[[ "$runtime_version" == "$version" ]] || {
  echo "Tag version $version does not match runtime SDK version $runtime_version" >&2
  exit 1
}
[[ "$runtime_contract" == "$lock_contract" ]] || {
  echo "Runtime and contract.lock contract versions differ" >&2
  exit 1
}
[[ "$lock_release" != unreleased && "$lock_release" =~ ^v?[0-9]+\.[0-9]+\.[0-9]+([-.][0-9A-Za-z.-]+)?$ ]] || {
  echo "contract.lock must identify a released core contract" >&2
  exit 1
}
[[ "$lock_commit" =~ ^[0-9a-f]{40}$ && "$lock_bundle" =~ ^[0-9a-f]{64}$ ]] || {
  echo "contract.lock commit or bundle digest is invalid" >&2
  exit 1
}
grep -Fq "## [$version]" "$repository_root/CHANGELOG.md" || {
  echo "CHANGELOG.md has no release section for $version" >&2
  exit 1
}

python3 "$repository_root/scripts/run-offline-release-tests.py"

echo "Android release preflight passed for $tag"
