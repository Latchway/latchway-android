# AGENTS.md

These instructions apply to the entire Latchway Android SDK repository.

## Mission and current phase

Build the Kotlin SDK that lets Android applications authenticate to Latchway,
establish device-bound sessions, and authorize ordinary HTTP requests without
holding an upstream provider credential.

The version 1 Android implementation is locked to the draft contract 1.0.0
checkpoint and current wire protocol 2. The gateway may continue accepting
wire protocol 1 from legacy clients, but this SDK emits protocol 2. Keep
`contract.lock`, vendored vectors, runtime
behavior, and documentation aligned to the authoritative core contract bundle.
The artifacts remain unpublished until protected Play-device, Maven Central,
provenance, and immutable-release evidence gates pass. Never invent a temporary
wire contract, fake production behavior, or describe unpublished artifacts as
released.

## Authority and dependency boundaries

- The Latchway core repository is the sole owner of the client OpenAPI,
  protocol manifest, error codes, canonical attestation binding, DPoP vectors,
  and compatibility policy.
- Consume checksummed contract releases. Generated DTOs may be internal; public
  Kotlin APIs must remain handwritten and idiomatic.
- Modules are latchway-core, latchway-okhttp,
  latchway-play-integrity, latchway-firebase-auth, latchway-bom, and
  test-support.
- Firebase and Play Integrity must not become dependencies of the core module.
- React Native must consume this SDK for Android key and integrity behavior
  rather than reimplementing it.

## Security invariants

- Generate a non-exportable P-256 Android Keystore key.
- Prefer StrongBox when available and configured, then hardware-backed
  Keystore. Any software fallback must be policy-controlled and accurately
  reported.
- Follow RFC 9449 for DPoP. Validate the challenge `client_data_hash` and pass
  it directly to Play Integrity as `requestHash`; never hash it again or
  reconstruct server principal-bound canonical JSON.
- Encrypt persisted refresh state with an Android Keystore key and prevent
  refresh stampedes.
- OkHttp integration must detect one-shot and non-replayable bodies. Never
  replay a request whose dispatch outcome is uncertain.
- Retry only documented transient Play Integrity errors, with bounded attempts.
- Never log identity tokens, session tokens, refresh tokens, DPoP proofs,
  integrity tokens or verdicts, private keys, or provider credentials.
- The SDK must never accept an upstream AI-provider secret.

## Kotlin and Android implementation rules

- Minimum API level is 23 unless a lower secure baseline is proven and
  documented.
- Pin the Gradle wrapper, Android Gradle Plugin, Kotlin, and JDK compatibility
  deliberately; do not rely on a developer's globally installed Gradle.
- Prefer structured coroutine scopes and cancellation-safe synchronization.
- Keep public APIs transport-oriented; do not add an AI framework.
- Keep test doubles in test-support, never in a production path.
- No production TODO, FIXME, empty handler, hard-coded success, or placeholder
  response is acceptable.

## Testing and validation

Every change must keep wrapper builds and tests passing. Security/protocol work
requires shared vectors and core-container conformance. Test StrongBox
selection, TEE and policy fallback, refresh
concurrency, cancellation, streaming, encrypted persistence, redaction,
installation revocation, and non-replayable bodies.

Real Play Integrity completion requires a Play-distributed build. Missing Google
credentials do not block fixture tests or unrelated work; record the exact
remaining Play-validation command.

## Repository hygiene

- Do not commit secrets, signing assets, service-account files, local
  environments, build output, or machine-specific absolute paths.
- Preserve unrelated user changes and keep generated output reproducible.
- Update documentation with public behavior.
- Use focused conventional commits when explicitly asked to commit.
- Optional .agents, .claude/skills, and skills-lock.json installations are
  local developer tooling, never build or release inputs.
