# Publishing the Android SDK

Latchway publishes exactly five Android coordinates under the `dev.latchway`
namespace:

```text
dev.latchway:latchway-core
dev.latchway:latchway-okhttp
dev.latchway:latchway-play-integrity
dev.latchway:latchway-firebase-auth
dev.latchway:latchway-bom
```

`test-support` contains repository conformance helpers and is deliberately not
a supported Maven artifact. The BOM constrains all four public libraries to the
same version and does not expose `test-support`.

## Safe local verification

Remote publication is absent from the Gradle task graph by default. The local
gate publishes release AARs, POMs, Gradle module metadata, source JARs, Javadoc
JARs, and checksums into `build/publication-test-repository`. It then launches a
separate Android build in offline mode. That consumer uses the BOM, declares all
four libraries without versions, resolves `dev.latchway` exclusively from the
test repository, imports one public type from each library, prefetches only
third-party transitive dependencies, and then compiles in offline mode twice:
once with Gradle module metadata and once using Maven POM metadata only.

Run the complete gate with:

```shell
./scripts/verify-local-publication.sh
```

The gate uses `1.0.0` unless `LATCHWAY_PUBLICATION_TEST_VERSION` is set. The
requested version must match `LATCHWAY_SDK_VERSION`, so a Maven release cannot
silently report a different runtime SDK version.

`scripts/build-release-artifacts.sh VERSION` runs that gate twice, rejects any
byte difference between the two Maven repositories, and emits a normalized ZIP
plus `SHA256SUMS` under `build/release`. Archive tasks disable file timestamps
and use reproducible entry ordering.

## Maven Central prerequisites

Maven Central release staging is intentionally a separate, explicit operation.
Before running it:

1. Verify ownership of the `dev.latchway` namespace in the Maven Central
   Publisher Portal.
2. Generate a Publisher Portal user token.
3. Provision an OpenPGP key whose public key is available from a supported key
   server.
   Store its uppercase 40-character fingerprint in the repository or
   organization Actions variable `LATCHWAY_MAVEN_SIGNING_FINGERPRINT`. The release
   workflow exports only the minimal public half as an attested immutable
   release asset; private signing material is never written to the repository
   or release assets.
4. Update every source and Gradle version declaration, run the repository test
   suite, and commit the exact release. Do not create or push the matching
   `vVERSION` tag manually: the evidence-gated `.github/workflows/release.yml`
   promotion creates, or verifies, the annotated tag only after the protected
   release inputs pass.
5. Start from a clean worktree. Do not place credentials or signing material in
   this repository, `gradle.properties`, command-line properties, build output,
   or CI logs.

The supported secret inputs are environment variables:

```text
LATCHWAY_MAVEN_CENTRAL_USERNAME
LATCHWAY_MAVEN_CENTRAL_PASSWORD
LATCHWAY_SIGNING_KEY
LATCHWAY_SIGNING_PASSWORD
LATCHWAY_GITHUB_RELEASE_ADMIN_TOKEN
```

CI keeps those inputs in separate protected environments. The unprivileged
`package` job receives none of them. `maven-central-signing` supplies only the
private OpenPGP key and password to a fresh no-checkout signing job;
`maven-central` supplies only the Portal username and password to a different
fresh no-checkout network publisher; `release-administration` supplies only the
read-only administration token; and `github-release` protects the final
GitHub-token/OIDC publication. Each environment must require an authorized
reviewer, enable **Prevent self-review**, disable administrator bypass where
GitHub offers it, and allow deployments only from the exact `main` branch. Each
environment owns the reserved non-secret
`LATCHWAY_RELEASE_CONTROL_POLICY_ID` variable with the unique value below:

```text
maven-central-signing  = latchway-release-controls-v1:latchway-android:maven-central-signing
release-administration = latchway-release-controls-v1:latchway-android:release-administration
maven-central          = latchway-release-controls-v1:latchway-android:maven-central
github-release         = latchway-release-controls-v1:latchway-android:github-release
```

Never define that variable at repository or organization scope. GitHub would
otherwise auto-create a missing referenced environment without protection
rules; the first step in every privileged job checks the exact environment-only
value before any action or step uses a credential, requests an OIDC token, or
performs a mutation. Do not duplicate one environment's secrets into another.

Both immutable-release administration checks require `enabled: true` and
`enforced_by_owner: true`, then emit a SHA-256-bound lease naming the repository,
phase, workflow run, and run attempt with a maximum lifetime of ten minutes.
The Portal publisher and final GitHub publisher validate the exact one-file
handoff, hash, complete binding, and expiry immediately before every external
mutation, including provenance attestation. Use
**Re-run all jobs** after a downstream failure; partial or single-job reruns
deliberately reject a lease from a prior workflow attempt.

The five privileged secret names listed above must exist only in their named
environments. Never define one as a repository secret or as an organization
secret visible to this repository: GitHub secret lookup otherwise falls through
to that broader scope if an environment secret is missing. The central
release-control reconciler rejects that configuration using secret names and
visibility only; it never reads secret values.

Repository administrators must also install an active ruleset for
`refs/tags/v*` before release: tag creation is restricted to the GitHub Actions
integration used by the release workflow, while tag update, deletion, and
non-fast-forward changes are denied. Operators and administrators must not
manually create, move, or delete a release tag. This server-side rule is an
external release prerequisite; repository documentation and workflow checks do
not substitute for it.

`LATCHWAY_SIGNING_KEY` is the ASCII-armored private key, not a key-ring path.
Gradle user-home properties remain supported only for controlled local signing
operations:

```text
latchway.signing.key
latchway.signing.password
```

Never add those properties to the repository's `gradle.properties`. Direct
Gradle uploads are disabled: the task fails with instructions to use the
deployment-recording release script. The build also rejects signing while the
configuration cache is active, before it reads private-key values, so secret
material is not persisted there.

## Stage a release

The protected `repository_dispatch` workflow is the supported final-release
entry point because it coordinates a fixed-asset draft with a recoverable,
deterministically named Portal deployment. For a controlled local rehearsal,
first build the reviewed repository, export the reviewed public key, build the
signed Portal ZIP in a signing-only process, and create the intent:

```shell
scripts/build-release-artifacts.sh 1.0.0
LATCHWAY_SIGNING_KEY=... LATCHWAY_SIGNING_PASSWORD=... \
LATCHWAY_CENTRAL_SIGNING_PUBLIC_KEY=build/release/latchway-maven-signing-public-key.asc \
scripts/build-central-portal-bundle.sh 1.0.0 \
  build/release/latchway-android-1.0.0-central-portal.zip
python3 scripts/central-deployment-record.py create-intent \
  --repository build/release/repository \
  --archive build/release/latchway-android-1.0.0-maven-repository.zip \
  --portal-bundle build/release/latchway-android-1.0.0-central-portal.zip \
  --public-key build/release/latchway-maven-signing-public-key.asc \
  --source-commit "$(git rev-parse HEAD)" \
  --tag v1.0.0 --version 1.0.0 --namespace dev.latchway \
  --publishing-type user_managed \
  --output build/release/maven-central-upload-intent.json
```

After independently retaining that intent and exact Portal ZIP, run the
recoverable upload stage with Portal credentials only:

```shell
LATCHWAY_RELEASE_VERSION=1.0.0 \
LATCHWAY_CENTRAL_UPLOAD_INTENT=build/release/maven-central-upload-intent.json \
LATCHWAY_CENTRAL_DEPLOYMENT_RECORD=build/release/maven-central-deployment.json \
LATCHWAY_CENTRAL_DEPLOYMENT_STATUS=build/release/maven-central-deployment-status.json \
LATCHWAY_CENTRAL_INTENT_FRESH=true \
LATCHWAY_CENTRAL_SIGNING_PUBLIC_KEY=build/release/latchway-maven-signing-public-key.asc \
LATCHWAY_CENTRAL_PORTAL_BUNDLE=build/release/latchway-android-1.0.0-central-portal.zip \
./scripts/publish-central.sh
```

Set `LATCHWAY_CENTRAL_INTENT_FRESH=false` on every continuation. Copy the
deployment record to durable storage immediately after the upload returns. Do
not pass signing variables to `publish-central.sh`; it rejects them.

The CI signing job accepts only the closed 120-file unsigned repository ZIP. A
fixed inline verifier rejects duplicates, links, unsafe paths, encrypted
entries, size-limit violations, missing or extra files, and any checksum
mismatch before extraction. The job never checks out candidate source, runs
Gradle, loads a Maven plugin, or executes a downloaded JAR, AAR, POM, or script.
It adds detached signatures to the 24 fixed primary artifacts using the pinned
SHA-512 digest, checks every signature against the pinned primary fingerprint,
exports only the public key, destroys the temporary keyring, and then creates
the exact 144-file Portal ZIP and immutable upload intent.

The separate Portal publisher again proves closed-set equivalence between the
unsigned and signed archives and verifies every detached signature using only
the public key. It has no checkout, signing material, GitHub administration
token, OIDC permission, Gradle, Java, or repository scripts; downloaded package
bytes are parsed only as bounded archive data and can never run while Portal
credentials exist. It uploads that pre-reviewed bundle through Sonatype's documented
[Portal Publisher API](https://central.sonatype.org/publish/publish-portal-api/).
The API returns an exact deployment UUID. That UUID is bound to the source
commit, both reviewed ZIPs, public key, expected PURLs, and immutable intent
before the workflow waits on the deployment.

All releases use `USER_MANAGED`. The publisher first queries the complete public
coordinate set and otherwise stages or adopts the deterministically named
Portal deployment before invoking only that exact UUID's publish endpoint. It
persists the normalized deployment record and final status as a short-lived
workflow artifact, then a credential-free verifier waits for Maven Central,
downloads every POM, Gradle module, AAR, sources JAR, and Javadoc JAR, compares
every primary artifact and MD5/SHA-1/SHA-256/SHA-512 sidecar byte for byte with
the reproducible repository assembled earlier in the run, and cryptographically
verifies every detached OpenPGP signature against the reviewed public key and
pinned primary fingerprint. GnuPG output is parsed fail-closed: revoked,
expired, bad, unknown, ambiguous, or wrong-primary status is rejected.

Before the first Portal request, an independent fresh no-checkout administration
job requires GitHub immutable releases to be enabled. Candidate validation
binds the exact annotated tag object, target commit, and promotion-derived
message without publication credentials. Post-registry evidence retains hashes of
every artifact and checksum sidecar, every exact armored signature, normalized
GnuPG status, the reviewed public-key hash, and the deployment record/status.
Only after those files exist does the workflow seal `SHA256SUMS` over all nine
other fixed assets. A separate fresh no-checkout OIDC job attests the exact ten
assets, creates or resumes the fixed-asset draft, and attaches them.
Immediately before that OIDC job, a second no-OIDC administration job rechecks
the immutable-release policy; the attesting job also rejects any missing, extra,
empty, non-regular, or symlinked local asset before requesting an identity token.
Only after every asset is attached does it publish the GitHub release, and it
requires the release API to report `immutable: true`. It then runs
`gh release verify TAG --format json` and `gh release verify-asset TAG PATH
--format json` for every exact local asset, with bounded retries for GitHub's
automatic attestation propagation. A rerun downloads and byte-compares the
immutable assets without mutation.

Immediately before the irreversible publish transition, the reconciler fetches
the remote annotated tag and revalidates its exact object, commit target, and
message again. After GitHub reports the release immutable, GitHub CLI
cryptographically verifies the release and every asset, and the workflow reads
the annotated tag again. The raw release and per-asset verification JSON plus a
normalized proof binding the immutable release record to that tag object,
commit, and message are retained as a 90-day workflow artifact.

The four protected environments described above must be configured before the
workflow can run. `LATCHWAY_GITHUB_RELEASE_ADMIN_TOKEN` is a short-lived,
least-privilege fine-grained token used only by the protected no-checkout
preflight for the repository immutable-release administration setting;
ordinary release mutations still use `github.token`. Keep the administration
token out of build, signing, registry, and OIDC jobs.
The release tag must be annotated,
must identify the checked-out commit, and must exactly match the source SDK
version. `contract.lock` must identify a released core contract, and the
changelog must contain the matching release section. Repository or organization
settings must enable GitHub immutable releases before the tag workflow starts.
The workflow creates GitHub build-provenance attestations for the deterministic
repository, reviewed public key, upload intent, deployment record/status, and
`maven-central-release-evidence.json`.

The public `Latchway/latchway` release asset and attestation are read with the
SDK workflow's read-only `github.token`. Do not configure a sibling-repository
token for this public-core path.

For a release-candidate rehearsal before a tag exists, an authorized release
operator may set `LATCHWAY_ALLOW_UNTAGGED_RELEASE_FOR_STAGING=true`. The clean
worktree, version, signature, and user-managed Portal validation gates still
apply. Do not use that override for the final release.

## Failure recovery

Rerunning an exact promotion is safe across pre-POST, in-POST, response-loss,
and post-POST crashes. Before any upload the script queries Sonatype's deployment
list using the full deterministic name (which includes the exact Portal ZIP
SHA-256). A rerun waits for and adopts the matching UUID; an ambiguous POST also
reconciles that list and never blindly retries during the same invocation. If a
crash occurred before the POST and no deployment appears during the bounded
recovery window, the unchanged immutable intent authorizes the exact upload.
Multiple matching UUIDs fail closed. Once any coordinate is public, the script
verifies all five coordinates and records a complete public-registry adoption
record/status bound to the recomputed public manifest instead of exiting without
durable state.

Current official references:

- [Sonatype: Gradle publishing through the Central Portal](https://central.sonatype.org/publish/publish-portal-gradle/)
- [Sonatype: Portal Publisher API](https://central.sonatype.org/publish/publish-portal-api/)
- [Gradle: Maven Publish plugin](https://docs.gradle.org/current/userguide/publishing_maven.html)
- [Gradle: Signing plugin](https://docs.gradle.org/current/userguide/signing_plugin.html)
- [Android: Configure publication variants](https://developer.android.com/build/publish-library/configure-pub-variants)
- [GitHub: Verify release integrity](https://docs.github.com/en/code-security/how-tos/secure-your-supply-chain/secure-your-dependencies/verify-release-integrity)
