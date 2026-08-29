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
```

`LATCHWAY_SIGNING_KEY` is the ASCII-armored private key, not a key-ring path.
Gradle user-home properties are also supported for controlled local release
environments:

```text
latchway.central.username
latchway.central.password
latchway.signing.key
latchway.signing.password
```

Never add those properties to the repository's `gradle.properties`. Release
signing uses Gradle's in-memory OpenPGP signer. Central tasks are marked
incompatible with the configuration cache, and the release script always uses
`--no-configuration-cache`. The build rejects any signing-enabled invocation
while that cache is active, before it reads credential or private-key values,
so secret material is not persisted there.

## Stage a release

Export the four secret inputs, then run:

```shell
LATCHWAY_RELEASE_VERSION=1.0.0 ./scripts/publish-central.sh
```

The script performs the local publication/consumer gate and the full Gradle
`test assemble lint` gate before it enables the remote repository. It uses
Gradle's built-in `maven-publish` plugin to upload signed artifacts to
Sonatype's Portal OSSRH staging compatibility endpoint. It then transfers the
staging repository from the same network address into the Central Publisher
Portal with `publishing_type=user_managed`.

This workflow follows Sonatype's current
[Portal OSSRH staging API guide](https://central.sonatype.org/publish/publish-portal-ossrh-staging-api/),
which explicitly lists Gradle's built-in `maven-publish` plugin as compatible
when the documented manual endpoint is used. Artifacts are uploaded to
`https://ossrh-staging-api.central.sonatype.com/service/local/staging/deploy/maven2/`,
then the script sends an authenticated same-IP `POST` to
`/manual/upload/defaultRepository/dev.latchway?publishing_type=user_managed`.
Authentication uses a Central Publisher Portal user token as the guide
requires. This is the Portal's supported compatibility service, not either of
the retired `oss.sonatype.org`/`s01.oss.sonatype.org` OSSRH endpoints; Sonatype
documents that [legacy OSSRH reached end of life on June 30,
2025](https://central.sonatype.org/pages/ossrh-eol/). Sonatype also currently
states that it offers [no official Gradle Portal
plugin](https://central.sonatype.org/publish/publish-portal-gradle/), which is
why this repository keeps the built-in publication path rather than taking a
dependency on an unsupported community plugin.

The script defaults to `user_managed`, so an operator can inspect the deployment
in the Publisher Portal and explicitly publish or drop it. The protected tag
workflow sets `LATCHWAY_CENTRAL_PUBLISHING_TYPE=automatic`; Sonatype then
publishes only after validation succeeds. The workflow waits for Maven Central,
downloads every POM, Gradle module, AAR, sources JAR, and Javadoc JAR, validates
their SHA-256 sidecars and the presence of OpenPGP signatures, and creates the
GitHub release only after that public-registry proof succeeds. Maven Central
versions are immutable.

The `maven-central` GitHub environment must protect the four publication
secrets and require an authorized reviewer. The release tag must be annotated,
must identify the checked-out commit, and must exactly match the source SDK
version. `contract.lock` must identify a released core contract, and the
changelog must contain the matching release section. The workflow also creates
a GitHub build-provenance attestation for the deterministic repository bundle.

For a release-candidate rehearsal before a tag exists, an authorized release
operator may set `LATCHWAY_ALLOW_UNTAGGED_RELEASE_FOR_STAGING=true`. The clean
worktree, version, signature, and user-managed Portal validation gates still
apply. Do not use that override for the final release.

## Failure recovery

If any upload fails, do not retry blindly: the compatibility service may retain
an incomplete repository for the uploader's account and network address. Find
the repository through the Portal OSSRH staging manual search endpoint, inspect
it, and either transfer or drop the exact repository before retrying. Never
publish a partially validated deployment.

Current official references:

- [Sonatype: Gradle publishing through the Central Portal](https://central.sonatype.org/publish/publish-portal-gradle/)
- [Sonatype: Portal OSSRH staging API](https://central.sonatype.org/publish/publish-portal-ossrh-staging-api/)
- [Gradle: Maven Publish plugin](https://docs.gradle.org/current/userguide/publishing_maven.html)
- [Gradle: Signing plugin](https://docs.gradle.org/current/userguide/signing_plugin.html)
- [Android: Configure publication variants](https://developer.android.com/build/publish-library/configure-pub-variants)
