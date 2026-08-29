# Physical Play Integrity release evidence

The v1 Android gate is a Play Integrity Standard request made by the exact
Play-distributed Release application on locked physical hardware. Emulator,
fixture, testing-response, sideloaded, Debug, test-key, unlocked-boot, and
unlicensed runs are never release evidence.

The dedicated workflow does not create a verdict. It inspects every already
installed base/split APK, verifies each signer, package and version code, and
hashes a canonical filename+SHA-256 manifest against the protected release
pin. It also verifies the base version name and Play App Signing certificate,
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

## Protected environment

Create a reviewed GitHub environment named `play-integrity-production` and a
self-hosted runner labeled `self-hosted`, `Linux`, and
`latchway-physical-android`. Connect exactly one locked physical device whose
exact candidate is already installed from the pinned Play track. Sign the
dedicated Firebase conformance user in before dispatch; no identity credential
is passed through Actions.

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
LATCHWAY_ENVIRONMENT
LATCHWAY_ERROR_MAPPING_FEATURE        # canonical feature ID guaranteed absent
```

Configure `LATCHWAY_ANDROID_DEVICE_SERIAL` as a protected secret. The serial is
used only to select adb transport and is not written to evidence.

Build the Play candidate with the matching non-secret Gradle properties,
including the exact source/core/contract/gateway pins, `playTrack`, package,
version, signing-certificate digest, `errorMappingFeature`, and
`requireLicensed=true`. The live app
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
```

The workflow attests the accepted profile, evidence, and checksum manifest
with GitHub Sigstore and retains the bundle. The dispatch commit must equal the
protected commit and `GITHUB_SHA`.

Revalidate an extracted artifact offline:

```bash
python3 scripts/device-evidence.py verify \
  --schema Conformance/physical-device-evidence.schema.json \
  --profile /path/to/play-integrity-profile.json \
  --evidence /path/to/play-integrity-evidence.json \
  --junit /tmp/play-integrity-junit.xml \
  --summary /tmp/play-integrity-validation.json

python3 scripts/test-verify-gateway-deployment.py
```

Until the protected Play app, account, gateway, runner, and physical device
exist, this remains an external release gate. Local schema tests and debug
assembly demonstrate only fail-closed tooling, never physical attestation.
