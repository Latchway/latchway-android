# Latchway Android SDK

Latchway lets an untrusted Android application call AI infrastructure through a
self-hosted gateway without embedding an upstream provider key. This repository
will provide the Kotlin transport and platform-security integration for that
client boundary.

> **Project status:** Governance foundation only. No Gradle project or supported
> release exists yet. Do not add this repository as a dependency.

## Planned scope

The SDK will:

- Use a non-exportable P-256 installation key from Android Keystore, preferring
  StrongBox when policy and hardware permit
- Report whether a key is StrongBox-, TEE-, or software-backed
- Produce RFC 9449 DPoP proofs
- Integrate Play Integrity standard requests bound to the server challenge
- Exchange an existing application identity token for short-lived,
  device-bound Latchway sessions
- Provide direct request authorization plus safe OkHttp interceptor and
  authenticator integrations
- Encrypt persisted refresh state and prevent refresh stampedes
- Expose quota, installation-revocation, and redacted diagnostic APIs
- Keep Firebase and Play Integrity dependencies outside the core module

The planned minimum Android API level is 23. Planned Maven coordinates are under
**dev.latchway**, including core, OkHttp, Play Integrity, Firebase Auth, and BOM
artifacts.

## Protocol ownership

The Latchway core repository owns the client OpenAPI description, error
registry, protocol manifest, canonical attestation binding, DPoP vectors, and
compatibility rules. This SDK consumes a signed and checksummed contract bundle;
it does not define an independent wire protocol.

A contract lock is intentionally absent until the core repository publishes the
first bundle. See [Architecture](docs/architecture.md) for the dependency and
trust boundaries.

## Security model

The SDK holds an installation private key and short-lived Latchway session
state. It never receives an upstream AI-provider credential and does not replace
the application's identity provider. Hardware capability and fallback behavior
remain visible to policy and diagnostics.

Review [Security Policy](SECURITY.md) before reporting a vulnerability.

## Development

Build and test commands will be added with the checked-in Gradle wrapper and
module graph. Until then, changes in this repository are limited to reviewed
governance, architecture, and contract-consumption foundations.

See [Contributing](CONTRIBUTING.md) and [Agent Instructions](AGENTS.md).

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
