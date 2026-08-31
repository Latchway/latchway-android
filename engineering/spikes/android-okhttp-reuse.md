# Android OkHttp request-time reuse spike

Status: locally verified source/runtime spike on 2026-08-31. This document is not a
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

## Framework fixtures actually exercised

The fixtures use each library's real HTTP integration and the same internal
OkHttp hook implementation as `LatchwayClient`. They do not duplicate DPoP,
session refresh, route checks, credential rejection, or replay policy in a
framework-specific adapter. The only synthetic boundary is the repository
test harness that supplies a real core session without requiring Android
Keystore or a production control plane. Challenge, session, and refresh calls
still traverse the production `OkHttpLatchwayTransport`; the loopback fixture
records those separately from framework data-plane calls.

| Fixture | Exact local versions | What the fixture proves |
| --- | --- | --- |
| Raw OkHttp | 4.9.2 and 5.3.0 | Request authorization, redirects, route policy, streaming, cancellation, credential rejection, and bounded replay |
| Retrofit | 2.11.0 and 3.0.0 | A real Retrofit `Call` uses the configured client; `@Streaming` is incremental, `Call.cancel()` reaches OkHttp, a one-shot body is not replayed, a replayable body receives only the correlated safe refresh, and a 429 problem remains intact for caller-owned mapping |
| Aallam OpenAI Kotlin | 4.0.1 and 4.1.0 with Ktor OkHttp 3.3.3 | Chat completion and SSE use a preconfigured Latchway OkHttp engine; Flow cancellation cancels the call; retries are explicitly disabled; HTTP 429 maps to the client's `RateLimitException` |
| LangChain4j OpenAI | 1.19.0 with OkHttp SPI 1.19.0-beta29 | Synchronous and incremental streaming chat use the injected Latchway builder; model retries are explicitly disabled; HTTP 429 maps to LangChain4j's `RateLimitException` |
| Koog OpenAI | 1.1.1 with OkHttp/okhttp-sse 5.3.0 | Its public `fromOkHttpClient` seam uses the production hooks with an absolute chat path; chat, tools, JSON schema, incremental SSE, final usage, Flow cancellation, timeout, request-ID/error preservation, and native retry proof freshness pass |

Ordinary builds use the catalog-pinned endpoints. CI also exercises Retrofit
2.11.0 and Aallam OpenAI Kotlin 4.0.1 through Gradle compatibility properties.
LangChain4j's OkHttp SPI is a separately versioned beta artifact, so the local
claim is limited to the exact pair above; this repository does not infer a
stable or contiguous compatibility range.

The framework dependencies exclude their transitive OkHttp artifacts in the
fixture configuration, which strictly reuses the adapter-selected version.
This prevents a newer Ktor, LangChain4j, or Koog dependency from silently
upgrading a supposed 4.9.2 run. The complete Koog fixture passes on 5.3.0. Its
four non-streaming cases also pass on 4.9.2, while the two SSE cases are
deliberately skipped there because Koog 1.1.1 links the OkHttp 5
`EventSources.createFactory(Call.Factory)` descriptor. All non-Koog adapter
tests continue to run on both Latchway OkHttp endpoints; the lower Retrofit and
Aallam framework endpoints run on pinned OkHttp 5.3.0.

All four libraries ultimately dispatch through OkHttp, so the wire contract
truthfully reports `android-okhttp` and `okhttp3.OkHttp.VERSION`. It does not
pretend that a generic transport seam is a contract-owned Retrofit, Aallam, or
LangChain4j/Koog adapter. Every recorded request contains DPoP authorization,
feature, protocol, SDK/framework, version, and request-ID headers, while the
library's non-secret placeholder Authorization is gone and no API-key header
is present.

Retrofit deliberately leaves HTTP error interpretation to the application;
its response exposes the original status and problem body. Aallam and
LangChain4j classify the tested 429 by HTTP status, but neither preserves the
Latchway problem `code` as a typed field. Applications that need canonical
Latchway error metadata should use direct OkHttp/Retrofit response handling
until a first-party framework error adapter exists. LangChain4j 1.19.0's
streaming chat surface does not return a cancellation handle, so this fixture
proves incremental delivery but does not claim framework-level cancellation.
Koog retains the canonical request ID and problem body in its
`LLMClientException` text but does not expose a typed Latchway error. OpenAI
Java remains untested here.

Koog's generic seam is sufficient and no public Latchway framework module is
needed, but the exact upstream release has two dependency constraints that an
Android application must make explicit. `http-client-okhttp` 1.1.1 may select
Koog's Android `utils` variant even though it references the JVM
`SuitableForIO` actual, so the verified graph includes
`ai.koog:utils-jvm:1.1.1`. The public wrapper also exposes `KLogger` while the
dependency is not on its compile API, so the verified graph explicitly adds
`io.github.oshai:kotlin-logging:8.0.01`. Full SSE requires OkHttp/okhttp-sse
5.3.0; 4.9.2 does not have the method descriptor linked by Koog 1.1.1. The
spike is based on the official Koog `1.1.1` tag at
`1bdbc29c89485a13aef85600a6f90945a07eb8ef`; it does not infer support for
another Koog or OkHttp version.

The transport tests use a dependency-neutral loopback HTTP/1.1 fixture. The
test server therefore cannot upgrade or replace the OkHttp artifact selected by
the compatibility property, and both OkHttp endpoints execute the same redirect,
credential-boundary, streaming, cancellation, and control-body assertions.

The publication gate also produced all five `dev.latchway` Maven coordinates
and compiled independent offline Android consumers using Gradle module metadata
and POM-only resolution. The third-party libraries above are
`testImplementation` dependencies and do not appear in a Latchway publication
or force an application to select an AI framework. These local fixtures do not
establish hosted server conformance, a published support matrix, or compatibility
with untested versions between the named endpoints.

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
