# Android SDK Architecture

## Status

This document fixes the ownership and dependency boundaries for the planned
Kotlin SDK. It does not describe an existing implementation. Gradle manifests,
production modules, generated models, and contract.lock will be introduced only
after the core repository publishes an authoritative contract bundle.

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

## Planned module boundaries

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
          Published dependency alignment only
~~~

Integration modules depend inward on stable core interfaces. Core must not
require OkHttp, Firebase, or Play Integrity. React Native depends on these
published modules for all Android security behavior.

## Key and state boundary

The installation signer owns a non-exportable P-256 Android Keystore key.
StrongBox is preferred when supported and configured; otherwise hardware-backed
Keystore is preferred. Any software fallback is policy-controlled and visible
to diagnostics. Only a public JWK and its RFC thumbprint leave the device.

Refresh state is encrypted using Android Keystore material. Coroutine-safe
coordination protects refresh single flight. Play Integrity has a separate
provider lifecycle; its requestHash binds the core-defined canonical challenge
bytes. Retries are bounded to documented transient platform errors.

## Transport boundary

Direct authorization and OkHttp integrations preserve existing HTTP and AI
libraries. The interceptor and authenticator must recognize one-shot and
non-replayable bodies. A request is retried only when Latchway proves rejection
before upstream dispatch; uncertain or partially consumed requests are returned
to the caller without automatic replay.

Cancellation and streaming flow end to end. Errors expose stable safe fields
and request identifiers, never tokens or raw integrity evidence.

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
