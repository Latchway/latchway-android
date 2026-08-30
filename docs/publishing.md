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
   Store its uppercase 40-character fingerprint in the protected
   `LATCHWAY_MAVEN_SIGNING_FINGERPRINT` environment variable. The release
   workflow exports only the minimal public half as an attested immutable
   release asset; private signing material is never written to the repository
   or release assets.
4. Update every source and Gradle version declaration, run the repository test
   suite, commit the exact release, and create the matching `vVERSION` tag.
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

The signing-only bundle builder adds detached signatures using an explicitly
pinned SHA-512 digest and an approved RSA, ECDSA, or EdDSA signing algorithm.
It verifies every GnuPG machine-status record, including the selected-key flag,
before the network publisher can receive Portal credentials. The intent
validator proves a closed 120-file repository allowlist, every checksum's
contents, exact unsigned-ZIP equivalence, and an exact 144-file signed Portal
ZIP with no duplicates, links, unsafe entries, or extras. The publisher uploads
that pre-reviewed bundle through Sonatype's documented
[Portal Publisher API](https://central.sonatype.org/publish/publish-portal-api/).
The API returns an exact deployment UUID. That UUID is bound to the source
commit, both reviewed ZIPs, public key, expected PURLs, and immutable intent
before the workflow waits on the deployment.

All releases use `USER_MANAGED`. The first workflow phase stages or adopts the
deterministically named deployment and attaches its UUID to the GitHub draft.
Only a later phase, after that durable attachment, sets
`LATCHWAY_CENTRAL_PUBLISH_AFTER_VALIDATION=true` and invokes the exact recorded
UUID's publish endpoint. It then waits for Maven Central,
downloads every POM, Gradle module, AAR, sources JAR, and Javadoc JAR, compares
every primary artifact and MD5/SHA-1/SHA-256/SHA-512 sidecar byte for byte with
the reproducible repository assembled earlier in the run, and cryptographically
verifies every detached OpenPGP signature against the reviewed public key and
pinned primary fingerprint. GnuPG output is parsed fail-closed: revoked,
expired, bad, unknown, ambiguous, or wrong-primary status is rejected.

Before the first Portal request, the workflow requires GitHub immutable
releases to be enabled, validates the exact remote annotated tag object,
target commit, and promotion-derived message, creates or resumes a draft,
predeclares the complete fixed asset set, and attaches the intent, signed
Portal ZIP, and tag-binding proof. It then durably attaches
the deployment record before waiting. Post-registry evidence retains hashes of
every artifact and checksum sidecar, every exact armored signature, normalized
GnuPG status, the reviewed public-key hash, and the deployment record/status.
Only after those files exist does the workflow seal `SHA256SUMS` over all eight
other fixed assets, attest that manifest, and attach it to the draft.
Only after every asset is attached does it publish the GitHub release, and it
requires the release API to report `immutable: true`. It then runs
`gh release verify TAG --format json` and `gh release verify-asset TAG PATH
--format json` for every exact local asset, with bounded retries for GitHub's
automatic attestation propagation. A rerun downloads and byte-compares the
immutable assets without mutation.

Immediately before the irreversible publish transition, the reconciler fetches
the remote annotated tag and revalidates its exact object, commit target, and
message again. After GitHub reports the release immutable, a strict verifier
decodes the verified release DSSE statement and requires its release predicate
and subject digest to name that exact annotated tag object. The raw release and
per-asset verification JSON plus normalized commit-binding proof are retained
as a 90-day workflow artifact.

The `maven-central` GitHub environment must protect all five release secrets and
require an authorized reviewer. `LATCHWAY_GITHUB_RELEASE_ADMIN_TOKEN` is a
short-lived, least-privilege fine-grained token used only by the protected
preflight and read-only reconciliation checks for the repository immutable-
release administration setting; ordinary release mutations still use
`github.token`. Keep the administration token out of build and signing steps.
The release tag must be annotated,
must identify the checked-out commit, and must exactly match the source SDK
version. `contract.lock` must identify a released core contract, and the
changelog must contain the matching release section. Repository or organization
settings must enable GitHub immutable releases before the tag workflow starts.
The workflow creates GitHub build-provenance attestations for the deterministic
repository, reviewed public key, upload intent, deployment record/status, and
`maven-central-release-evidence.json`.

If the core repository is private, configure the repository secret
`LATCHWAY_SIBLING_REPOSITORIES_READ_TOKEN` as a fine-grained Contents: read
credential scoped to `Latchway/latchway`. It authenticates only the exact core
promotion asset download and attestation verification. Public core repositories
need no secret and fall back to the job token.

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
