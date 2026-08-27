# Contributing to Latchway Android SDK

Thank you for helping build Latchway. This repository is currently establishing
its governance and protocol boundary. It intentionally has no Gradle project or
contract lock until the core repository publishes the first authoritative
contract bundle.

## Before making a change

1. Read AGENTS.md and docs/architecture.md.
2. Confirm which repository owns the behavior. Wire protocol changes begin in
   the Latchway core repository.
3. Keep the change to one reviewable concern and explain its security impact.
4. Never commit credentials, signing material, identity tokens, integrity
   tokens or verdicts, device data, or local environment files.

## Design and implementation rules

- Public Kotlin APIs are handwritten and idiomatic; generated wire models,
  when introduced, remain internal.
- Keep core, OkHttp, Play Integrity, Firebase, BOM, and test-support
  responsibilities in separate modules.
- The core module must not require Firebase or Play Integrity.
- Private keys are non-exportable. StrongBox preference and fallback are
  policy-visible, not silently assumed.
- OkHttp integration must detect one-shot and non-replayable bodies.
- Do not create a local wire format or contract.lock without a published core
  contract bundle.
- Do not leave production-path placeholders or hard-coded success behavior.

## Tests

Every functional change must include proportionate unit tests. Security or
protocol work also requires shared-vector, device-capability, and conformance
coverage. Refresh concurrency, cancellation, redaction, encrypted persistence,
and retry safety must be tested explicitly.

Canonical wrapper commands will be documented when the Gradle project and CI
are introduced. A contribution is not ready while its documented checks fail.

## Pull requests

Use focused commits with conventional subjects such as feat(android),
fix(session), test(conformance), or docs(security). Describe compatibility
impact, tests run, and any external Play-distributed validation still required.
Generated changes must be reproducible and reviewed with their source contract.

By contributing, you agree that your contribution is licensed under the
Apache License, Version 2.0.
