# Android OkHttp request-time reuse spike

Status: locally verified source spike on 2026-08-30. This document is not a
Maven release, hosted conformance, or physical Play Integrity claim.

## Decision

Latchway can reuse OkHttp at the request-time seam without introducing an AI
framework or copying a provider request model. Applications keep their existing
OkHttp-based library and install three native hooks:

```kotlin
val http = OkHttpClient.Builder()
    .addInterceptor(latchway.interceptor())
    .addNetworkInterceptor(latchway.originGuard())
    .authenticator(latchway.authenticator())
    .build()
```

The application interceptor selects the feature, validates the exact gateway
origin/base path and contract route, rejects caller provider credentials, and
obtains DPoP-bound Latchway authorization. The network interceptor is the final
dispatch boundary. It revalidates the destination and route after application
hooks and redirects, removes no caller-selected security decision, and creates
a new proof for each permitted network attempt. The authenticator handles only
an exact, request-correlated `application/problem+json` response proving a
pre-upstream rejection: one validated DPoP nonce challenge or one expired
session refresh. One-shot and duplex bodies are never replayed.

An uncorrelated response, cross-origin redirect, same-origin redirect to an
unowned path, or internal connection retry after an attempt may have reached
the gateway fails closed. The SDK reports
`transport_destination_not_allowed` or `transport_request_not_replayable`
instead of silently replaying. Explicit safe nonce/session follow-ups receive a
new proof and a new bounded attempt. Response bodies are not read or buffered
by these hooks, so OkHttp streaming and call cancellation remain intact.

The allowlist is deliberately smaller than arbitrary same-origin HTTP:

- `POST /v1/responses`
- `POST /v1/chat/completions`
- `POST /v1/embeddings`
- `POST /v1/messages`
- `GET`, `POST`, `PUT`, `PATCH`, or `DELETE`
  `/proxy/{exact-feature}/{remainingPath}`

Opaque routes reject query strings, empty/repeated path segments, paths over
the contract's 2,048-character bound, dot traversal, encoded slash/backslash
traversal, and absolute destination forms. All paths are resolved beneath the
configured gateway base path. Storage namespaces bind
the exact base path, application, environment, identity provider, platform,
and key identity so two path-mounted deployments cannot reuse native session
state.

## Framework and native component boundary

The adapter emits the pair `android-okhttp` and `okhttp3.OkHttp.VERSION`; it
does not accept an arbitrary caller-reported OkHttp version. React Native uses
the separate contract identity `react-native-fetch` and keeps signing,
attestation, access/refresh tokens, and component provisioning grants in the
native SDK. Each configured component has a different Android Keystore P-256
alias and AES-GCM wrapping key. Refresh rotation is process-wide single-flight
even when the same component is opened by multiple client objects. Component
or family retirement deletes ciphertext, the wrapping key, and the exact
still-matching DPoP key in a non-cancellable cleanup path.

`interceptor(component)` uses the same request-time seam for a delegated
component. Only an in-memory native component reference is carried as an
OkHttp tag; the network interceptor and authenticator use it to create fresh
component proofs and rotate or clear only that component session. No component
token, grant, wrapping key, or private signing material crosses into a provider
request model.

## Versions and gates actually exercised

The dependency seam is `-Platchway.okhttp.version=<version>` in
`latchway-okhttp`; ordinary builds use the catalog-pinned version.

| OkHttp | Local evidence | Result |
| --- | --- | --- |
| 4.9.2 | `:latchway-okhttp:testDebugUnitTest -Platchway.okhttp.version=4.9.2` | Passed |
| 5.3.0 | Full `test assemble lint`, including route, authenticator, streaming, cancellation, and replay tests | Passed |

The transport tests use a dependency-neutral loopback HTTP/1.1 fixture. The
test server therefore cannot upgrade or replace the OkHttp artifact selected by
the compatibility property, and both rows execute the same redirect,
credential-boundary, streaming, cancellation, and control-body assertions.

The publication gate also produced all five `dev.latchway` Maven coordinates
and compiled independent offline Android consumers using Gradle module metadata
and POM-only resolution. This establishes source and binary dependency reuse
for the tested seam; it does not establish compatibility with Retrofit,
OpenAI's Kotlin client, LangChain4j, Koog, or every OkHttp version between the
two tested endpoints. Those integrations require their own hosted fixture and
server-conformance evidence before being added to a support matrix.

## Remaining external proof

The repository's physical workflow and validators fail closed, but source tests
cannot create Play-distributed evidence. Production proof still requires the
reviewed Play track, matching package/signing certificate and cloud project, a
real supported locked device, a live pinned gateway/core deployment, the
protected ephemeral collector/supervisor, and an accepted signed evidence
artifact. The current root-component workflow does not prove a delegated Wear,
companion-package, automotive, or isolated-process component. No fixture,
emulator, sideloaded APK, connected-device state, or local test result may be
used to close either physical gate.

Until those hosted and physical artifacts exist, keep the cross-repository
compatibility/release locks at their truthful pre-release state.
