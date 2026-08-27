# Changelog

All notable changes to this project will be documented in this file.

The format follows Keep a Changelog, and releases will follow Semantic
Versioning once package publication begins.

## [Unreleased]

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
