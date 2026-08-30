# Physical Play Integrity release evidence

The v1 Android gate is a Play Integrity Standard request made by the exact
Play-distributed Release application on locked physical hardware. Emulator,
fixture, testing-response, sideloaded, Debug, test-key, unlocked-boot, and
unlicensed runs are never release evidence.

The dedicated workflow does not create a verdict. It inspects every already
installed base/split APK, verifies each signer, package and version code, and
hashes a canonical filename+SHA-256 manifest against the protected release
pin both before launch and after the accepted observation. The two manifests
must be byte-identical. It also verifies the base version name and Play App Signing certificate,
verifies Google Play as the installer, launches one
bounded suite, retrieves only a redacted observation, and applies the checked-in
schema plus semantic policy. Missing or mismatched values fail closed.

## What the run proves

One run records:

- physical, locked, green verified-boot Android hardware running a non-debug
  `user` build and the exact package/version/certificate/installed-APK-set candidate;
- a protected Play track and cloud project, with `com.android.vending` as the
  install source and the gateway configured to require `LICENSED` accounts;
- a canonical, short-lived P-256-signed deployment statement from the same
  gateway origin, binding the exact Play client policy and gateway release;
- a successful Play Integrity Standard request whose exact SDK-provided
  `requestHash` is accepted by the gateway, yielding `PLAY_RECOGNIZED`,
  `LICENSED`, and device/strong-device trust rather than a testing verdict;
- a hardware-backed Android Keystore DPoP key and active session;
- one authorized request, exact replay rejected as HTTP 401 `dpop_replayed`,
  and a bit-tampered proof rejected as HTTP 401 `dpop_invalid`;
- typed `LatchwayException` mapping of HTTP 404 `feature_not_found`, an explicit
  refresh whose redacted pre/post access-credential hashes differ while the
  installation hash stays fixed, rejection of protocol version `0` as HTTP 426
  `protocol_version_unsupported`, and post-revocation enforcement as HTTP 403
  `installation_revoked`; and
- a bounded streamed AI request and quota response.

The first session challenge consumes one short-lived external identity JWT for
the candidate's configured identity provider. This is not a Latchway access,
refresh, session, component, administration, or provider credential, and it is
not a Firebase custom token. For `identityProvider=firebase`, the protected
provisioner supplies a Firebase ID token that the gateway verifies through the
pinned Firebase provider configuration. The app does not create or retain a
`FirebaseAuth.currentUser` session.

The normalized app-recognition and licensing fields are accepted only when the
pinned production gateway configuration requires Play licensing and returns
Play Integrity device trust. Core validation rejects any non-recognized app,
certificate/package/request-hash mismatch, insufficient device verdict,
unlicensed account under that policy, or testing response before issuing that
trust. The device never exports the integrity token or request hash.

Evidence contains safe request IDs, public app/build pins, device model/OS,
toolchain metadata and SHA-256 hashes. It excludes Firebase identity tokens,
Latchway access/refresh tokens, DPoP JWTs, integrity tokens, private keys,
provider credentials, prompts, and response bodies. The validator rejects
unknown fields and secret-shaped values.

## Installation Family addendum scope

The current protected observation proves the directly attested Android root
component. It does not yet prove a delegated Wear, companion-package,
automotive, or isolated-process component on physical hardware. Such a claim
requires a reviewed server Component Definition and an expanded signed evidence
schema that records only safe hashes/status for: distinct root/child public-key
thumbprints, child provisioning, independent refresh rotation, child-only
revocation with a still-live root, and family-wide revocation. Until that
protected workflow and a real Play-distributed run exist, the generic component
runtime is locally tested but delegated Android physical-device conformance and
release promotion remain blocked. Do not reuse fixture, emulator, sideloaded,
or root-only evidence to satisfy that gate.

The same restriction applies to framework compatibility: local CI tests the
adapter against OkHttp 4.9.2 and runs the full suite with the pinned OkHttp
5.3.0 runtime, but hosted common-framework/server conformance is separate
immutable evidence and cannot be inferred from this physical Play run.

## Protected environment

Create a reviewed GitHub environment named `play-integrity-production` and a
newly booted repository-scoped JIT runner registered with `--ephemeral`. Its
labels are `self-hosted`, `Linux`, `latchway-physical-android`, and
`latchway-ephemeral-jit`; its one-run name is exactly
`latchway-android-<run-id>-<run-attempt>`. A reusable runner, a runner that can
accept a second job, or a host with a surviving workspace is ineligible.
Connect exactly one locked physical device whose exact candidate is installed
from the pinned Play track.

Configure protected variables:

```text
LATCHWAY_ADB_VERSION
LATCHWAY_APKSIGNER_VERSION
LATCHWAY_ANDROID_PACKAGE_NAME
LATCHWAY_ANDROID_APP_VERSION
LATCHWAY_ANDROID_VERSION_CODE
LATCHWAY_ANDROID_SIGNING_CERTIFICATE_SHA256
LATCHWAY_ANDROID_INSTALLED_APK_SET_SHA256
LATCHWAY_ANDROID_PLAY_TRACK             # internal, closed, open, production
LATCHWAY_ANDROID_CLOUD_PROJECT_NUMBER
LATCHWAY_ANDROID_SDK_VERSION
LATCHWAY_SOURCE_COMMIT             # exact 40-character candidate commit
LATCHWAY_CORE_COMMIT
LATCHWAY_CONTRACT_VERSION
LATCHWAY_CONTRACT_BUNDLE_SHA256
LATCHWAY_GATEWAY_IMAGE_DIGEST
LATCHWAY_GATEWAY_CONFIGURATION_SHA256
LATCHWAY_GATEWAY_ORIGIN
LATCHWAY_GATEWAY_DEPLOYMENT_KEY_ID
LATCHWAY_GATEWAY_DEPLOYMENT_STATEMENT_SHA256
LATCHWAY_GATEWAY_DEPLOYMENT_PUBLIC_KEY_PATH
LATCHWAY_GATEWAY_DEPLOYMENT_PUBLIC_KEY_SHA256
LATCHWAY_GATEWAY_MINIMUM_TRUST_LEVEL # device_verified or strong_device_verified
LATCHWAY_APPLICATION_ID
LATCHWAY_ENVIRONMENT
LATCHWAY_IDENTITY_PROVIDER
LATCHWAY_ERROR_MAPPING_FEATURE        # canonical feature ID guaranteed absent
LATCHWAY_COLLECTOR_TRUST_ROOT_PEM
LATCHWAY_COLLECTOR_TRUST_ROOT_SHA256
LATCHWAY_ANDROID_DEVICE_GRANT_SHA256
```

Configure `LATCHWAY_ANDROID_DEVICE_SERIAL` and
`LATCHWAY_ONE_TIME_DEVICE_GRANT` as protected secrets. The serial is used only
to select adb transport and is not written to evidence. The grant is a compact
identity JWT for the configured provider; it is not a Firebase custom token or
a Latchway session/admin grant.

The device must not retain a reusable identity or Latchway session from an
earlier run. After the GitHub run ID and attempt exist, the external issuer and
supervisor authorize one identity JWT for this collection. The signed collector
lease v2 binds its exact compact-token digest to audience
`latchway-physical-evidence/android-play-integrity`, source commit, workflow run
ID, run attempt, Latchway application ID, Android package, identity-provider
name, issuance, and a maximum five-minute staging window. These are mandatory
`grant.application_id`, `grant.package_name`, and `grant.identity_provider`
fields, not inferred documentation claims. The configured identity verifier
enforces the JWT's own signature, issuer, audience, and expiration. After that
verification and before issuing a Latchway session, the trusted issuer/gateway
atomically reserves and consumes the exact SHA-256 digest under a uniqueness
constraint bound to the lease/run/application/package/provider coordinates.
The spent digest, never the raw token, remains reserved through token expiry;
a second consume fails. The app's terminal provider submits the token to the
first session challenge only once. This provider-agnostic rule supports
standard Firebase ID tokens, which are not required to carry a `jti` claim.

The protected workflow receives the JWT only as
`LATCHWAY_ONE_TIME_DEVICE_GRANT`; the public `LATCHWAY_ANDROID_DEVICE_GRANT_SHA256`
must equal the digest in the signed lease. Immediately before staging, the
collector rechecks the lease audience/source/run/attempt/hash/issuance/
expiry and all three application/package/provider bindings, clears all app data,
and confirms the process is absent. It then streams
the JWT over stdin to `adb shell content write`. The exported endpoint requires
the privileged Android `DUMP` permission, checks the safe coordinates and
embedded source/application/package/provider coordinates, reads a maximum of
65,536 ASCII bytes through a pipe,
and holds exactly one compact JWT in one process-memory slot. The activity
atomically consumes that slot once; a second stage or consume, bad digest,
wrong coordinates, non-JWT body, or oversized body leaves the process slot
terminal. Only run ID, attempt, and grant SHA-256 travel as activity arguments.
The JWT is never an argv value, file, manifest/resource, preference, log, or
evidence field, and the shell clears its logical variable immediately after the
pipe closes. Neither Bash nor the managed runtime promises physical RAM
zeroization, so the JIT host is destroyed after the one job.

The collector limits the token to 65,536 ASCII bytes, requires compact JWT
shape, recomputes SHA-256 over the exact raw bytes immediately before staging,
and compares it with the signed lease/public pin. It does not invent a
provider-specific replay claim or parse an unverified payload. The signed lease
requires `identity_grant_digest_one_use_enforced=true`. The signed teardown v2
requires `identity_grant_digest_consumed_once=true` and
`gateway_run_receipt_binds_identity_grant_digest=true`; the independently
verified gateway receipt commits to the digest and lease coordinates, and the
teardown observation repeats that exact digest as `identity_grant_sha256`. A signed
boolean without an atomic server ledger and that receipt is not eligible
physical evidence.

An organization token, PAT, registry/cloud credential, reusable account
credential, or OIDC authority is prohibited on the collector. If the
identity-issuer/supervisor provisioning path cannot enforce this one-use
contract, the physical gate cannot run.

## Ephemeral collector and supervisor contract

The GitHub-hosted `authorize-source` job checks out candidate source only as
data, executes no repository code, records the exact commit and Git tree for
this run/attempt/audience, and attests it with GitHub Sigstore. The collector
verifies the retained bundle with `--deny-self-hosted-runners` before checking
out or executing candidate code.

The JIT image exposes root-owned, non-writable
`/etc/latchway/physical-collector/lease.json` and `lease.sig`, plus
`/usr/local/libexec/latchway-physical-collector-finalize`. The externally
signed ECDSA/SHA-256 lease binds repository, commit, source-authorization hash,
run/attempt/job/audience, runner name/image/boot identity, one-job/fresh/JIT
flags, installed APK-set digest, one-use grant hash/issuance/expiry, and
the exact Latchway application ID, Android package, and identity provider.
It states that no long-lived, organization, administration, registry, or OIDC
credential exists in the collector.

The finalizer is only a one-use client for an authenticated privileged supervisor; its
private key and gateway observer capability remain outside the candidate VM.
It accepts paths rather than caller-provided digest claims, independently
hashes and validates the source/evidence/wipe files, observes the Android
device and Play/gateway server-side run receipt, verifies that receipt binds the
spent identity-grant digest and lease coordinates, permits one finalizer invocation for the
lease, deregisters the JIT runner, refuses another job, and schedules VM
destruction within ten minutes. Candidate code can cause failure but cannot
obtain a signature over chosen hashes or a synthetic physical/provider result.

An out-of-band supervisor watchdog handles cancellation, timeout, runner
crash, network loss, or a missing finalizer receipt by revoking registration,
invalidating the grant, clearing/resetting the device, and destroying the VM;
it never depends on a final workflow step running.

Android `pm clear` plus process absence and supervisor finalization are
separate unconditional `if: always()` steps. Finalization runs even when lease,
source, toolchain, grant, collection, or wipe validation fails. Evidence can
reach the signer only when the signed teardown has
`evidence_eligible=true`, independent device/provider and gateway-receipt
verification, successful app-data wipe, JIT deregistration, no further jobs,
and bounded destruction scheduling.

Also create a reviewed `physical-evidence-signing` environment. It contains
only the public collector trust root and non-secret expected hashes—no device,
Play, application, runner, provider, or supervisor credentials. The protected JIT
collector uploads a one-day
`play-integrity-physical-unsigned-<run>-<attempt>` handoff with only
repository-scoped `actions: read` and `contents: read`; candidate checkout, device collection, and validation have no
OIDC, attestation, or artifact-metadata authority. A fresh GitHub-hosted Ubuntu
job behind the signing environment downloads that handoff without checking out
source, validates the exact file set, size bounds, `SHA256SUMS`, candidate
commit, run/attempt, platform, physical-device, production-provider,
passing-test, and redaction coordinates using fixed inline shell and `jq`, and
only then requests OIDC and creates the attestation. Require independent
reviewers and restrict deployments to `main`.

The signer also validates the source attestation, trust-root signatures on the
lease and teardown, exact grant/artifact/run coordinates, wipe receipt,
evidence-manifest binding, independent supervisor verdict, and destruction
deadline. It attests `collector-isolation-validation.json` and retains a
separate `play-integrity-collector-isolation-<run>-<attempt>` artifact for 30
days without changing the observer-compatible physical artifact file set.

Build the Play candidate with the matching non-secret Gradle properties,
including the exact source/core/contract/gateway pins, `playTrack`, package,
version, signing-certificate digest, `errorMappingFeature`, and
`identityProvider`, and `requireLicensed=true`. The live app
compares embedded expected pins with its runtime package and signer before any
report can pass.

Embed the matching `gatewayOrigin`, `gatewayDeploymentKeyId`,
`gatewayDeploymentStatementSha256`, and
`gatewayDeploymentPublicKeySha256` Gradle properties as well. The gateway
publishes canonical `/.well-known/latchway/deployment-statement-v1.json` and a
detached DER ECDSA/SHA-256 `.sig`. Its maximum 24-hour policy requires
request-hash binding, Play recognition/licensing, device trust, and denies
testing/debug clients. The runner pins the P-256 SPKI digest, verifies before
and after the run without redirects, and rejects any change.

## Produce the Play candidate

Run `scripts/stage-play-conformance-candidate.sh` from a clean exact source
commit. Set `LATCHWAY_CANDIDATE_OUTPUT_DIR` to an empty directory outside this
repository and inject all non-secret candidate values through the corresponding
`LATCHWAY_*` environment variables: package/version, expected installed Play
App Signing certificate SHA-256, track/cloud project, SDK/source/core/contract,
gateway/deployment, application/environment/feature/model, and identity
provider. `LATCHWAY_IDENTITY_PROVIDER=firebase` pins the Firebase verifier
preset used by the gateway; no Firebase API key, service-account file, refresh
token, or `google-services.json` enters this proof host.

The producer checks `HEAD`, the clean Git tree, `contract.lock`, runtime SDK
version, every bounded pin, and the Gradle wrapper digest. It builds only
`:sample-conformance:bundleRelease` with a commit-derived
`SOURCE_DATE_EPOCH`, no persistent Gradle daemon, and no configuration cache.
The repository producer is unsigned-only. It also emits the canonical
`play-conformance-presign-payload.manifest`, sorted by unsigned raw-name bytes.
Each row records the strict decoded path and raw name, uncompressed content
SHA-256 and size, required ZIP version, flags, compression method, DOS
timestamp, creator platform/version, internal and external attributes, and the
exact allowlisted extra field. The closed staging directory contains exactly
that manifest, the AAB,
`play-conformance-candidate.json`, and `SHA256SUMS`.

`LATCHWAY_PLAY_SIGNING_MODE=unsigned` may be set explicitly, but any other mode
is rejected. The producer disables shell tracing before reading its environment
and rejects canonical upload-keystore, alias, password, signer-password, and
upload-certificate inputs before Gradle starts. `sample-conformance/build.gradle.kts`
contains no signing configuration and never reads signing environment variables.
The resulting AAB is intentionally **non-publishable**.

For the enforceable hosted path, dispatch `Build and isolate the Play
conformance candidate`. The first job checks out and runs candidate code without
any key material, then uploads only the exact four-file unsigned set. A fresh
`play-upload-signing` environment job has no checkout and no Gradle. Before its
secret-bearing step, fixed inline validation checks the complete staged set,
manifest bindings, hashes, ZIP safety, and absence of signing metadata. It also
hash-pins and compiles the separately carried Java verifier, re-runs its strict
unsigned/raw-ZIP validation, and requires its newly emitted payload manifest to
equal the carried manifest byte-for-byte. The
secret-bearing step invokes only system `keytool` and `jarsigner`, pins the
exported upload certificate, uses environment-backed passwords rather than
arguments, signs with the fixed `LATCHWY` signature-file name, and removes the
keystore before the step exits. It never executes the AAB or repository files.

The signer emits a five-file unverified handoff: signed AAB, carried pre-sign
payload manifest, original unsigned candidate manifest, signed-candidate
manifest, and `SHA256SUMS`. A second fresh
no-checkout job uses the no-secret `play-candidate-verification` environment and
requires the verifier source to match reviewed
`LATCHWAY_PLAY_AAB_VERIFIER_SHA256` and the signed-candidate certificate to
match reviewed `LATCHWAY_PLAY_UPLOAD_CERTIFICATE_SHA256` before compiling
`scripts/VerifyPlayAabSignature.java` from the separately retained source
artifact. Before enabling Jar cryptographic verification, that verifier parses
the raw ZIP records and recomputes the carried payload manifest. Local and
central names, required versions, flags, methods, timestamps, extra fields,
CRCs, sizes, offsets, and signed data descriptors must match one-to-one. Only
contiguous, non-overlapping regular-file entries, an exact trailing central
directory/EOCD, ZIP 2.0 stored/deflated methods, unambiguous strict
UTF-8-or-ASCII names, and at most one canonical mtime-only extended-timestamp
field are accepted. Alternate-name/Unicode-path fields, ZIP64, encryption,
directory/symlink/device or special modes, nonzero internal attributes,
prefixes, gaps, comments, trailing/polyglot bytes, and ambiguous descriptors
are rejected. It then enumerates physical JAR
entries, requires one canonical manifest and one matching signature-file/block
pair, fully reads every payload entry, requires exactly one signer on every
payload, pins the leaf X.509 certificate SHA-256, and requires the physical
payload-name set to equal the signed manifest sections. Therefore local-header
traversal aliases, external-mode mutations, appended unsigned entries, deleted
signed entries, extra signers, and partial signing fail even though plain
`jarsigner -verify` can accept several of those cases. Only the final
`play-conformance-signed-<run>-<attempt>` artifact has passed that independent gate.

The protected signing environment supplies
`LATCHWAY_PLAY_UPLOAD_KEYSTORE_BASE64`, the two upload-key passwords and alias as
secrets, and lowercase `LATCHWAY_PLAY_UPLOAD_CERTIFICATE_SHA256` as a reviewed
variable shared with the no-secret verification environment. Set reviewed
`LATCHWAY_PLAY_UPLOAD_SIGNATURE_ALGORITHM` to
`SHA256withRSA` or `SHA256withECDSA` to match that key. No key material belongs
in repository, candidate, Gradle, artifact, or verifier inputs.

The upload certificate and the installed Play App Signing certificate are
separate pins. The upload key authenticates the AAB sent to Play; Google Play
normally re-signs generated APKs with the Play App Signing key. The candidate
embeds the latter digest, while the physical collector verifies that digest on
every installed base/split APK before launch and again after observation, with
an identical canonical manifest required. The producer stages bytes only: it never calls a
Play API, uploads an AAB, changes a track, or publishes a release.

## Run and verify

Dispatch `Physical Play Integrity evidence` with the full SDK source commit.
The retained artifact contains:

```text
device-inventory.json
gateway-client-policy.json
gateway-deployment-public-key.pem
gateway-deployment-statement.json
gateway-deployment-statement.sig
gateway-deployment-verification.json
installed-apk-set.sha256
play-integrity-evidence.json
play-integrity-junit.xml
play-integrity-observation.json
play-integrity-profile.json
play-integrity-validation.json
SHA256SUMS
github-attestation.sigstore.json
```

The final `play-integrity-physical-<run>-<attempt>` artifact is produced only by
the isolated signing job. It attests the accepted profile, evidence, and
checksum manifest with GitHub Sigstore and retains the bundle at exactly
`github-attestation.sigstore.json`, as required by the core observer. The
dispatch must run from `main`, and its commit must equal the protected commit,
the dispatch input, and `GITHUB_SHA`.

Revalidate an extracted artifact offline:

```bash
python3 scripts/device-evidence.py verify \
  --schema Conformance/physical-device-evidence.schema.json \
  --profile /path/to/play-integrity-profile.json \
  --evidence /path/to/play-integrity-evidence.json \
  --junit /tmp/play-integrity-junit.xml \
  --summary /tmp/play-integrity-validation.json

python3 scripts/test-verify-gateway-deployment.py
python3 scripts/test-physical-evidence-workflow.py
python3 scripts/test-play-conformance-candidate.py
bash -n scripts/stage-play-conformance-candidate.sh
```

Repository code enforces the signed lease/receipt contract, but it neither
provisions hardware nor proves that the hypervisor destroyed the VM after the
job returned. Operators must supply and independently audit the JIT service,
root supervisor, isolated signing key and gateway observer capability,
one-use grant bootstrap, USB/device reset, protected environments, Play app,
licensed account, live gateway, physical device, and post-job destruction log.
The final artifact and external destruction log must bind the same lease/run.
None of that infrastructure exists merely because this workflow is checked in;
local schema tests and debug assembly are not physical attestation.
