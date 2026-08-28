# Latchway Android SDK

Latchway lets an untrusted Android application call AI infrastructure through a
self-hosted gateway without embedding an upstream provider key. This repository
provides the Kotlin transport and platform-security integration for that
client boundary.

> **Project status:** Unreleased `0.1.0-SNAPSHOT`. The module graph and security
> implementation are available for review and conformance, but no supported
> Maven release has been published.

## Modules

- `latchway-core`: handwritten API, Android Keystore P-256 signer, encrypted
  state, RFC 9449 DPoP, and single-flight session lifecycle
- `latchway-okhttp`: bounded control transport, origin-pinned authorization,
  interceptor, and replay-safe authenticator
- `latchway-play-integrity`: Play Integrity Standard provider lifecycle and
  server `client_data_hash`/Play `requestHash` binding
- `latchway-firebase-auth`: optional Firebase ID-token adapter
- `latchway-bom`: aligned Latchway module versions
- `test-support`: explicit debug evidence, memory state, scripted transport,
  and software signer doubles for tests only
- `sample-basic`, `sample-firebase`, and `sample-conformance`: integration and
  Play-track validation applications

All Android libraries require API 23 or newer. The build uses AGP 9.3.2,
Gradle 9.5.0, Kotlin 2.3.21, Java 17 bytecode, OkHttp 5.3.0, Play Integrity
1.6.0, and the Firebase 34.18.0 BOM.

## Usage

The public API keeps the application's existing identity provider and HTTP
stack:

```kotlin
val latchway = LatchwayClient(
    configuration = LatchwayConfiguration(
        baseUrl = "https://gateway.example.com/".toHttpUrl(),
        applicationId = "habitify",
        environment = "production",
        defaultFeature = "habit-assistant",
    ),
    identityTokenProvider = FirebaseIdentityTokenProvider(),
    attestationProvider = PlayIntegrityAttestationProvider(
        context = applicationContext,
        cloudProjectNumber = cloudProjectNumber,
    ),
    context = applicationContext,
)

val http = OkHttpClient.Builder()
    .addInterceptor(latchway.interceptor())
    .authenticator(latchway.authenticator())
    .build()
```

For per-request routing, use `request.newBuilder().latchwayFeature("feature")`
or call `latchway.authorize(request, feature)` directly. Credentials are only
attached when the request origin exactly matches the configured gateway.
Any supplied control-client template is isolated onto its own dispatcher and
connection pool; interceptors, authenticators, cookies, and redirects are
removed before identity or session traffic is sent.

React Native uses the same native key, attestation, and session implementation.
Its bridge must set
`clientPlatform = LatchwayClientPlatform.REACT_NATIVE_ANDROID` and pass the
React Native package semver as `sdkVersion`; this emits the contract-owned
`react_native_android` platform and `react-native` SDK header while keeping
protocol credentials out of JavaScript.

`KeyPolicy` requires hardware backing by default. Set
`allowSoftwareBacked = true` only for an explicit environment policy such as a
development emulator. Diagnostics distinguish StrongBox, TEE, software, and
older-platform secure hardware whose exact class Android cannot report.

## Security behavior

- Use a non-exportable P-256 installation key from Android Keystore, preferring
  StrongBox when policy and hardware permit
- Report whether a key is StrongBox-, TEE-, or software-backed
- Produce RFC 9449 DPoP proofs
- Pass the server-provided 43-character `client_data_hash` directly to Play
  Integrity as `requestHash`; it is never reconstructed or hashed again
- Exchange an existing application identity token for short-lived,
  device-bound Latchway sessions
- Provide direct request authorization plus safe OkHttp interceptor and
  authenticator integrations
- Encrypt persisted refresh state and prevent refresh stampedes
- Expose quota, installation-revocation, and redacted diagnostic APIs
- Keep Firebase and Play Integrity dependencies outside the core module

The authenticator only handles a bounded set of pre-dispatch Latchway failures,
permits one nonce/session follow-up, and rejects one-shot or duplex bodies.
Application streaming responses are not buffered by the SDK.

## Protocol ownership

The Latchway core repository owns the client OpenAPI description, error
registry, protocol manifest, canonical attestation binding, DPoP vectors, and
compatibility rules. This SDK consumes a signed and checksummed contract bundle;
it does not define an independent wire protocol.

[`contract.lock`](contract.lock) pins contract `0.2.0`, wire protocol `1`, and
the exact core bundle checksum. Authoritative DPoP and attestation-binding
fixtures are vendored as test resources. See
[Architecture](docs/architecture.md) for the dependency and trust boundaries.

## Security model

The SDK holds an installation private key and short-lived Latchway session
state. It never receives an upstream AI-provider credential and does not replace
the application's identity provider. Hardware capability and fallback behavior
remain visible to policy and diagnostics.

Review [Security Policy](SECURITY.md) before reporting a vulnerability.

## Build and tests

Install Android SDK Platform 37.0 and SDK Build Tools 36, accept Google's SDK
license locally, then run:

```shell
./gradlew test assemble lint
```

The unit suites exercise the authoritative DPoP vectors, AES-GCM state codec,
session/refresh concurrency, expiry and revocation, OkHttp replay policy, Play
request-hash forwarding and bounded retry lifecycle, Firebase error mapping,
and credential redaction.

Real Play Integrity success cannot be simulated. Configure the non-secret
Gradle properties below, supply a real Firebase app configuration and signed-in
test user, install the exact signed application from a Google Play test track,
and run the on-device gate:

```properties
latchway.gatewayUrl=https://gateway.example.com/
latchway.applicationId=app_example
latchway.environment=production
latchway.feature=assistant
latchway.cloudProjectNumber=123456789012
```

Keep signing keys, credentials, and local property files out of source control;
manage the app's public Firebase configuration under its normal repository
policy. A sideloaded debug APK is not valid release evidence. The conformance
activity uses real Play evidence only and cancellation closes an in-flight
streamed call.

See [Contributing](CONTRIBUTING.md) and [Agent Instructions](AGENTS.md).

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
