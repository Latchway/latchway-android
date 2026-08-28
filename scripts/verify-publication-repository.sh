#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 REPOSITORY VERSION" >&2
  exit 64
fi

repository=$1
version=$2
group_directory="$repository/dev/latchway"
modules=(
  latchway-core
  latchway-okhttp
  latchway-play-integrity
  latchway-firebase-auth
  latchway-bom
)

fail() {
  echo "publication verification failed: $*" >&2
  exit 1
}

[[ -d "$group_directory" ]] || fail "missing dev.latchway repository directory"

for module in "${modules[@]}"; do
  artifact_directory="$group_directory/$module/$version"
  artifact_prefix="$artifact_directory/$module-$version"
  [[ -f "$artifact_prefix.pom" ]] || fail "missing $module POM"
  [[ -f "$artifact_prefix.module" ]] || fail "missing $module Gradle module metadata"
  [[ -f "$artifact_prefix-sources.jar" ]] || fail "missing $module sources JAR"
  [[ -f "$artifact_prefix-javadoc.jar" ]] || fail "missing $module Javadoc JAR"

  grep -Fq '<groupId>dev.latchway</groupId>' "$artifact_prefix.pom" ||
    fail "$module POM has the wrong group"
  grep -Fq "<artifactId>$module</artifactId>" "$artifact_prefix.pom" ||
    fail "$module POM has the wrong artifact ID"
  grep -Fq "<version>$version</version>" "$artifact_prefix.pom" ||
    fail "$module POM has the wrong version"
  grep -Fq '<url>https://github.com/latchway/latchway-android</url>' "$artifact_prefix.pom" ||
    fail "$module POM is missing its project URL"
  grep -Fq '<name>The Apache License, Version 2.0</name>' "$artifact_prefix.pom" ||
    fail "$module POM is missing its license"
  grep -Fq '<connection>scm:git:https://github.com/latchway/latchway-android.git</connection>' \
    "$artifact_prefix.pom" || fail "$module POM is missing SCM metadata"
  grep -Fq "<tag>v$version</tag>" "$artifact_prefix.pom" ||
    fail "$module POM does not identify the matching release tag"

  for published_file in \
    "$artifact_prefix.pom" \
    "$artifact_prefix.module" \
    "$artifact_prefix-sources.jar" \
    "$artifact_prefix-javadoc.jar"; do
    [[ -f "$published_file.sha256" ]] || fail "missing SHA-256 for ${published_file##*/}"
    [[ -f "$published_file.sha512" ]] || fail "missing SHA-512 for ${published_file##*/}"
  done
  unzip -tqq "$artifact_prefix-sources.jar" || fail "$module sources JAR is corrupt"
  unzip -tqq "$artifact_prefix-javadoc.jar" || fail "$module Javadoc JAR is corrupt"

  if [[ "$module" != "latchway-bom" ]]; then
    [[ -f "$artifact_prefix.aar" ]] || fail "missing $module AAR"
    [[ -f "$artifact_prefix.aar.sha256" ]] || fail "missing SHA-256 for $module AAR"
    [[ -f "$artifact_prefix.aar.sha512" ]] || fail "missing SHA-512 for $module AAR"
    unzip -tqq "$artifact_prefix.aar" || fail "$module AAR is corrupt"
  fi
done

[[ ! -e "$group_directory/test-support" ]] || fail "test-support must not be a public artifact"
if grep -R -Fq 'test-support' "$group_directory/latchway-bom/$version"; then
  fail "the public BOM must not expose the repository-only test-support module"
fi

echo "Verified five Maven publications at dev.latchway:*:$version"
