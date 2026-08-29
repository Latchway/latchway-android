# Android SDK Architecture

## Status

This document describes the intended `1.0.0` source candidate locked
to contract `0.5.1` and wire protocol `1`. Public APIs remain handwritten; the
internal JSON boundary is validated directly against the core schemas and
shared fixtures.

## System boundary

The customer application supplies an identity token from its existing identity
provider and an HTTP request intended for its configured Latchway gateway. The
SDK proves possession of an installation key, obtains a short-lived Latchway
session, and adds transport authorization. The gateway authenticates,
authorizes, meters, and injects the upstream provider credential.

The SDK never receives the upstream credential and never decides server-owned
facts such as user ID, plan, attestation level, organization, route, upstream,
price, or usage.

## Contract ownership

The Latchway core repository exclusively owns:

- Client session OpenAPI
- Error-code registry and retry guidance
- Protocol-version and compatibility manifest
- Canonical attestation-binding encoding
- DPoP and attestation test vectors
- Canonical request examples
- The checksummed contract release bundle

This repository consumes those artifacts. A contract update must verify the
bundle checksum, update contract.lock, regenerate internal wire DTOs
reproducibly, run shared vectors, and pass conformance against the exact core
image. Generated wire DTOs must not become the public Kotlin API.

## Module boundaries

~~~text
Customer application
    |
    +-- latchway-core
    |     Public API, session coordination, DPoP, secure state abstraction,
    |     direct request authorization, quota, diagnostics, revocation
    |
    +-- latchway-okhttp
    |     Interceptor, authenticator, and replay-safety integration
    |
    +-- latchway-play-integrity
    |     Optional standard-token provider and requestHash binding
    |
    +-- latchway-firebase-auth
    |     Optional identity-token provider adapter
    |
    +-- test-support
    |     Deterministic test signers, storage, clocks, transports, and fixtures
    |
    +-- latchway-bom
          Dependency alignment only
~~~

Integration modules depend inward on stable core interfaces. Core must not
require OkHttp, Firebase, or Play Integrity. React Native depends on these
modules for all Android security behavior. It selects the explicit
`react_native_android` client platform and `react-native` SDK identity; keys and
encrypted state are namespaced by that platform so a host app cannot
accidentally reuse an Android-native session under a different wire identity.

## Key and state boundary

The installation signer owns a non-exportable P-256 Android Keystore key.
StrongBox is preferred when supported and configured; otherwise hardware-backed
Keystore is preferred. Any software fallback is policy-controlled and visible
to diagnostics. Only a public JWK and its RFC thumbprint leave the device.

Refresh state is serialized, bound to application/environment state with AES
additional authenticated data, and encrypted with a distinct Android Keystore
AES-256-GCM key. Coroutine-safe coordination protects both first exchange and
refresh single flight.

The server constructs the canonical attestation binding because it owns the
resolved principal. Its challenge includes `client_data_hash`, the 43-character
base64url SHA-256 output. The Play adapter validates that value and passes the
same string directly to the Standard API as `requestHash`; the SDK never tries
to recreate principal-bound JSON or hash the hash. Provider preparation and
renewal are synchronized, and only documented transient platform codes receive
bounded exponential retries.

## Transport boundary

Direct authorization and OkHttp integrations preserve existing HTTP and AI
libraries. The interceptor and authenticator must recognize one-shot and
non-replayable bodies. A request is retried only when Latchway proves rejection
before upstream dispatch; uncertain or partially consumed requests are returned
to the caller without automatic replay.

Control-plane calls use a dedicated OkHttp dispatcher and connection pool.
Application interceptors, network interceptors, authenticators, cookies, and
redirects are removed, preventing recursive session establishment and
cross-origin control credential forwarding.
Credential attachment is pinned to the configured scheme, host, and effective
port. Control responses and problem bodies have strict byte limits.

Cancellation and streaming flow end to end. Process-wide installation gates
serialize refresh rotation and grant persistence across SDK client instances;
cleanup is bound to the exact access-token generation so a delayed old-session
response cannot erase a newer grant. The OkHttp network origin guard blocks
Latchway headers before a cross-origin redirect is dispatched. Errors expose
stable safe fields, request identifiers, and the required operation ID for
indeterminate outcomes, never tokens or raw integrity evidence.

## Verification boundary

Unit tests own deterministic cryptographic, storage, coroutine, cancellation,
and replay cases. Shared vectors prove wire-level agreement. Fixture tests cover
Play Integrity verdict handling without credentials. Cross-repository tests run
the SDK against PostgreSQL and the exact core container. A Play-distributed
application provides the final production verdict evidence without displaying
secrets.

## Non-goals

This repository does not own server policy, provider routing, quota
enforcement, user-authentication UI, upstream secrets, AI request modeling, or
React Native bridge behavior.
