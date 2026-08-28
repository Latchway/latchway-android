# Changelog

All notable changes to this project will be documented in this file.

The format follows Keep a Changelog, and releases will follow Semantic
Versioning once package publication begins.

## [Unreleased]

### Changed

- Synchronized the SDK with core contract `0.3.0` while retaining wire
  protocol `1`; compatibility is declared for server `0.3.0` through the
  tested `0.3.x` series, and indeterminate-operation errors preserve their
  required operation ID.
- Server-confirmed installation revocation is terminal for that client,
  performs retryable non-cancellable state and DPoP-key cleanup, and prevents
  transport or reprovisioning with the revoked JKT; cleanup can fail over to a
  peer coordinator after a local key-reset failure.
- Cross-client refresh and persistence are coordinated by installation and
  session generation, stale responses cannot clear replacement grants, and a
  network origin guard blocks Latchway headers before cross-origin redirects.
- Android Keystore create, sign, and reset operations are coordinated per
  process-wide alias, and stale signer instances reject replacement keys.
- The conformance sample uses the supported OpenAI Chat route and requires an
  explicit non-secret model value.
- OkHttp runtime helpers remain compatible with API 23 and avoid retaining a
  strong static Android context.

### Added

- Initial governance, contribution, security, and architecture documentation.
- Gradle 9.5/AGP 9.3 multi-module project for API 23 and newer.
- Android Keystore P-256 installation signer with StrongBox preference,
  hardware-backing policy, and redacted diagnostics.
- RFC 9449 DPoP proofs, RFC 7638 thumbprints, encrypted session persistence,
  and challenge/session/rotating-refresh single-flight coordination.
- Origin-pinned OkHttp authorization, bounded control transport, replay-safe
  authenticator, quota, revocation, and diagnostics APIs.
- Play Integrity Standard adapter using the server challenge hash directly as
  `requestHash`, with synchronized provider renewal and bounded retries.
- Optional Firebase Authentication adapter, BOM, test-support doubles, shared
  contract vectors, integration samples, and real Play-track conformance app.
- Explicit React Native Android wire identity that reuses native security while
  isolating its key and encrypted state namespace.
