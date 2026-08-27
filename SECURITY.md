# Security Policy

## Release status

Latchway Android SDK is pre-release and does not yet have a supported production
version. Do not use this repository as a security boundary until a release is
published and its compatibility entry is recorded.

Security fixes will target supported releases once the support matrix is
established. The unreleased branch may change without compatibility guarantees.

## Reporting a vulnerability

Use GitHub private vulnerability reporting for this repository. If that feature
is unavailable, contact the Latchway organization maintainers privately before
sharing details. Do not open a public issue for a suspected vulnerability.

Do not include live identity tokens, refresh tokens, DPoP proofs, Play Integrity
tokens or verdicts, private keys, signing assets, provider credentials, or user
data in a report. Revoke exposed credentials before continuing.

A useful report includes:

- The affected revision or released version
- The device, Android version, and security-hardware capabilities
- Reproduction steps using synthetic or redacted data
- The expected and observed security behavior
- Impact, prerequisites, and any known mitigations

## Security-sensitive scope

Treat changes to Android Keystore and StrongBox selection, key non-exportability,
encrypted persistence, P-256 signing, JWK thumbprints, DPoP proofs, Play
Integrity request binding, OkHttp retry/replay behavior, token redaction, and
installation revocation as security-sensitive. They require focused tests and
cross-repository conformance.

The SDK must never accept an upstream AI-provider secret. Latchway server
vulnerabilities should be reported against the core repository, with a
cross-reference here when client behavior is involved.

## Disclosure

Allow maintainers a reasonable opportunity to investigate and coordinate a fix
before public disclosure. Good-faith research that avoids privacy violations,
service disruption, and access beyond what is necessary is welcome.
