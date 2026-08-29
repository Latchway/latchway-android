package dev.latchway.core

import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.cancel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.json.JSONObject
import java.net.URI
import java.nio.charset.StandardCharsets
import kotlin.coroutines.Continuation
import kotlin.coroutines.resume
import kotlin.coroutines.suspendCoroutine
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.atomic.AtomicInteger

class SessionCoordinatorTest {
    private val now = 1_700_000_000L
    private val clock = LatchwayClock { now }
    private val signer = FakeSigner()

    @Test
    fun configurationRejectsNoncanonicalApplicationIdsLocally() {
        listOf(
            "habitify",
            "app_habitify",
            "app_81J00000000000000000000000",
            "app_01j00000000000000000000000",
            "app_01J0000000000000000000000",
        ).forEach { applicationId ->
            assertThrows(IllegalArgumentException::class.java) {
                CoreConfiguration(
                    baseUrl = URI("https://gateway.example.test/"),
                    applicationId = applicationId,
                    environment = "production",
                    identityProvider = "firebase",
                )
            }
        }
        CoreConfiguration(
            baseUrl = URI("https://gateway.example.test/"),
            applicationId = "app_01J00000000000000000000000",
            environment = "production",
            identityProvider = "firebase",
        )
    }

    @Test
    fun initialSessionExchangeIsSingleFlightAcrossConcurrentCallers() = runBlocking {
        val responses = ConcurrentLinkedQueue(
            listOf(
                response(201, challenge()),
                response(201, grant("a".repeat(64), "r".repeat(32))),
            ),
        )
        val calls = AtomicInteger()
        val transport = LatchwayTransport { request ->
            calls.incrementAndGet()
            if (request.uri.path.endsWith("session-challenges")) delay(75)
            checkNotNull(responses.poll())
        }
        val identityCalls = AtomicInteger()
        val attestationCalls = AtomicInteger()
        val client = client(
            stateStore = MemoryStateStore(),
            transport = transport,
            identityProvider = IdentityTokenProvider {
                identityCalls.incrementAndGet()
                "i".repeat(32)
            },
            attestationProvider = debugAttestation(attestationCalls),
        )

        coroutineScope {
            List(32) {
                async {
                    client.authorize(
                        "POST",
                        URI("https://gateway.example.test/v1/responses"),
                        "assistant",
                    )
                }
            }.awaitAll()
        }

        assertEquals(2, calls.get())
        assertEquals(1, identityCalls.get())
        assertEquals(1, attestationCalls.get())
        client.close()
    }

    @Test
    fun refreshIsSingleFlightAndRotatesStoredCredentials() = runBlocking {
        val state = MemoryStateStore(
            snapshot(
                accessToken = "a".repeat(64),
                refreshToken = "r".repeat(32),
                accessExpiresAt = now - 1,
                refreshExpiresAt = now + 3_600,
            ),
        )
        val calls = AtomicInteger()
        val transport = LatchwayTransport { request ->
            calls.incrementAndGet()
            assertTrue(request.uri.path.endsWith("sessions/refresh"))
            delay(75)
            response(200, grant("b".repeat(64), "s".repeat(32)))
        }
        val client = client(state, transport)

        coroutineScope {
            List(32) {
                async { client.authorize("GET", URI("https://gateway.example.test/v1/diagnostics"), "assistant") }
            }.awaitAll()
        }

        assertEquals(1, calls.get())
        assertEquals("b".repeat(64), state.load()?.accessToken?.reveal())
        assertEquals("s".repeat(32), state.load()?.refreshToken?.reveal())
        client.close()
    }

    @Test
    fun refreshIsSingleFlightAcrossSeparateClientsSharingOneInstallation() = runBlocking {
        val sharedSigner = FakeSigner()
        val state = MemoryStateStore(
            snapshot("a".repeat(64), "r".repeat(32), now - 1, now + 3_600, sharedSigner),
        )
        val refreshEntered = CompletableDeferred<Unit>()
        val releaseRefresh = CompletableDeferred<Unit>()
        val calls = AtomicInteger()
        val transport = LatchwayTransport {
            check(calls.incrementAndGet() == 1) { "a second client must reuse the rotated session" }
            refreshEntered.complete(Unit)
            releaseRefresh.await()
            response(
                200,
                grant("b".repeat(64), "s".repeat(32), installationSigner = sharedSigner),
            )
        }
        val first = client(state, transport, installationSigner = sharedSigner)
        val second = client(state, transport, installationSigner = sharedSigner)

        val authorizations = listOf(
            async { first.authorize("GET", URI("https://gateway.example.test/v1/one"), "assistant") },
            async {
                refreshEntered.await()
                second.authorize("GET", URI("https://gateway.example.test/v1/two"), "assistant")
            },
        )
        refreshEntered.await()
        delay(75)
        assertEquals(1, calls.get())
        releaseRefresh.complete(Unit)
        authorizations.awaitAll()

        assertEquals(1, calls.get())
        assertEquals("b".repeat(64), state.load()?.accessToken?.reveal())
        first.close()
        second.close()
    }

    @Test
    fun refreshReuseClearsStateAndIsNeverSilentlyReprovisioned() = runBlocking {
        val state = MemoryStateStore(
            snapshot("a".repeat(64), "r".repeat(32), now - 1, now + 3_600),
        )
        val identityCalls = AtomicInteger()
        val client = client(
            stateStore = state,
            transport = LatchwayTransport {
                response(401, problem("refresh_token_reused"))
            },
            identityProvider = IdentityTokenProvider {
                identityCalls.incrementAndGet()
                "i".repeat(32)
            },
        )

        val error = assertThrows(LatchwayException::class.java) {
            runBlocking {
                client.authorize("GET", URI("https://gateway.example.test/v1/diagnostics"), "assistant")
            }
        }
        assertEquals(LatchwayErrorCode.REFRESH_TOKEN_REUSED, error.code)
        assertNull(state.load())
        assertEquals(0, identityCalls.get())
        client.close()
    }

    @Test
    fun sessionRevocationClearsOnlyTheSessionAndAllowsFreshEstablishment() = runBlocking {
        val state = MemoryStateStore(
            snapshot("a".repeat(64), "r".repeat(32), now + 600, now + 3_600),
        )
        val responses = ArrayDeque(
            listOf(
                response(401, problem("session_revoked")),
                response(201, challenge()),
                response(201, grant("b".repeat(64), "s".repeat(32))),
            ),
        )
        val calls = AtomicInteger()
        val client = client(
            stateStore = state,
            transport = LatchwayTransport {
                calls.incrementAndGet()
                responses.removeFirst()
            },
        )

        val revoked = assertThrows(LatchwayException::class.java) {
            runBlocking { client.quota("assistant") }
        }
        assertEquals(LatchwayErrorCode.SESSION_REVOKED, revoked.code)
        assertNull(state.load())
        assertEquals(0, signer.resetCount)

        client.authorize("GET", URI("https://gateway.example.test/v1/diagnostics"), "assistant")
        assertEquals(3, calls.get())
        assertEquals(0, signer.resetCount)
        client.close()
    }

    @Test
    fun delayedOldSessionRevocationCannotClearANewerGrantForTheSameKey() = runBlocking {
        val sharedSigner = FakeSigner()
        val state = MemoryStateStore(
            snapshot("a".repeat(64), "r".repeat(32), now + 600, now + 3_600, sharedSigner),
        )
        val oldResponse = CompletableDeferred<Continuation<LatchwayTransportResponse>>()
        val oldClient = client(
            stateStore = state,
            transport = LatchwayTransport {
                suspendCoroutine { continuation -> oldResponse.complete(continuation) }
            },
            installationSigner = sharedSigner,
        )
        val oldRequest = async {
            runCatching { oldClient.quota("assistant") }
        }
        val continuation = oldResponse.await()
        val refreshingClient = client(
            stateStore = state,
            transport = LatchwayTransport {
                response(
                    200,
                    grant("b".repeat(64), "s".repeat(32), installationSigner = sharedSigner),
                )
            },
            installationSigner = sharedSigner,
        )

        refreshingClient.refresh()
        continuation.resume(response(401, problem("session_revoked")))
        val staleError = withTimeout(2_000) { oldRequest.await().exceptionOrNull() }

        assertTrue(staleError is LatchwayException && staleError.code == LatchwayErrorCode.SESSION_REVOKED)
        assertEquals("b".repeat(64), state.load()?.accessToken?.reveal())
        assertEquals("s".repeat(32), state.load()?.refreshToken?.reveal())
        oldClient.close()
        refreshingClient.close()
    }

    @Test
    fun authorizationBoundCleanupCannotClearANewerGrantForTheSameKey() = runBlocking {
        val sharedSigner = FakeSigner()
        val state = MemoryStateStore(
            snapshot("a".repeat(64), "r".repeat(32), now + 600, now + 3_600, sharedSigner),
        )
        val client = client(
            stateStore = state,
            transport = LatchwayTransport { error("a current session must not use transport") },
            installationSigner = sharedSigner,
        )
        val oldAuthorization = client.authorize(
            "GET",
            URI("https://gateway.example.test/v1/old"),
            "assistant",
        )
        state.save(
            snapshot("b".repeat(64), "s".repeat(32), now + 600, now + 3_600, sharedSigner),
        )

        client.clearSessionIfCurrent(oldAuthorization)

        assertEquals("b".repeat(64), state.load()?.accessToken?.reveal())
        assertEquals("s".repeat(32), state.load()?.refreshToken?.reveal())
        client.close()
    }

    @Test
    fun protectedRevocationResponseTerminalizesAndPreventsTransportReuse() = runBlocking {
        val state = MemoryStateStore(
            snapshot("a".repeat(64), "r".repeat(32), now + 600, now + 3_600),
        )
        val calls = AtomicInteger()
        val client = client(
            stateStore = state,
            transport = LatchwayTransport {
                calls.incrementAndGet()
                response(403, problem("installation_revoked"))
            },
        )
        val error = assertThrows(LatchwayException::class.java) {
            runBlocking { client.quota("assistant") }
        }
        assertEquals(LatchwayErrorCode.INSTALLATION_REVOKED, error.code)
        assertNull(state.load())
        assertEquals(1, signer.resetCount)
        val reuseError = assertThrows(LatchwayException::class.java) {
            runBlocking { client.refresh() }
        }
        assertEquals(LatchwayErrorCode.INSTALLATION_REVOKED, reuseError.code)
        assertEquals(1, calls.get())
        client.close()
    }

    @Test
    fun installationRevocationRequiresItsCanonical403StatusBeforeKeyCleanup() = runBlocking {
        val state = MemoryStateStore(
            snapshot("a".repeat(64), "r".repeat(32), now + 600, now + 3_600),
        )
        val client = client(
            stateStore = state,
            transport = LatchwayTransport {
                response(401, problem("installation_revoked", status = 401))
            },
        )

        val error = assertThrows(LatchwayException::class.java) {
            runBlocking { client.quota("assistant") }
        }

        assertEquals(LatchwayErrorCode.RESPONSE_INVALID, error.code)
        assertEquals(signer.publicJwk.thumbprint(), state.load()?.installation?.dpopJkt)
        assertEquals(0, signer.resetCount)
        client.close()
    }

    @Test
    fun malformedInstallationRevocationProblemCannotTriggerKeyCleanup() = runBlocking {
        val malformed = JSONObject(problem("installation_revoked")).apply {
            remove("request_id")
        }.toString()
        val cases = listOf(
            problem("installation_revoked") to mapOf(
                "Content-Type" to listOf("application/json"),
                "X-Latchway-Request-ID" to listOf("req_12345678"),
            ),
            malformed to canonicalProblemHeaders(),
            problem("installation_revoked") to mapOf(
                "Content-Type" to listOf("application/problem+json"),
                "X-Latchway-Request-ID" to listOf("req_different"),
            ),
        )
        cases.forEach { (body, headers) ->
            val localSigner = FakeSigner()
            val state = MemoryStateStore(
                snapshot("a".repeat(64), "r".repeat(32), now + 600, now + 3_600, localSigner),
            )
            val client = client(
                stateStore = state,
                transport = LatchwayTransport { response(403, body, headers) },
                installationSigner = localSigner,
            )

            val error = assertThrows(LatchwayException::class.java) {
                runBlocking { client.quota("assistant") }
            }

            assertEquals(LatchwayErrorCode.RESPONSE_INVALID, error.code)
            assertEquals(localSigner.publicJwk.thumbprint(), state.load()?.installation?.dpopJkt)
            assertEquals(0, localSigner.resetCount)
            client.close()
        }
    }

    @Test
    fun operationIndeterminatePreservesItsRequiredOperationId() = runBlocking {
        val operationId = "arq_0${"1".repeat(25)}"
        val state = MemoryStateStore(
            snapshot("a".repeat(64), "r".repeat(32), now + 600, now + 3_600),
        )
        val client = client(
            stateStore = state,
            transport = LatchwayTransport {
                response(
                    503,
                    problem("operation_indeterminate", status = 503, operationId = operationId),
                )
            },
        )

        val error = assertThrows(LatchwayException::class.java) {
            runBlocking { client.quota("assistant") }
        }

        assertEquals(LatchwayErrorCode.OPERATION_INDETERMINATE, error.code)
        assertEquals(operationId, error.operationId)
        assertTrue(error.retryable)
        client.close()
    }

    @Test
    fun operationIndeterminateWithoutCanonicalOperationIdIsRejected() = runBlocking {
        val state = MemoryStateStore(
            snapshot("a".repeat(64), "r".repeat(32), now + 600, now + 3_600),
        )
        val client = client(
            stateStore = state,
            transport = LatchwayTransport {
                response(503, problem("operation_indeterminate", status = 503))
            },
        )

        val error = assertThrows(LatchwayException::class.java) {
            runBlocking { client.quota("assistant") }
        }

        assertEquals(LatchwayErrorCode.RESPONSE_INVALID, error.code)
        assertNull(error.operationId)
        client.close()
    }

    @Test
    fun operationIndeterminateRequiresItsRegistryStatusAndRetryability() = runBlocking {
        val operationId = "arq_0${"1".repeat(25)}"
        val wrongStatusClient = client(
            stateStore = MemoryStateStore(
                snapshot("a".repeat(64), "r".repeat(32), now + 600, now + 3_600),
            ),
            transport = LatchwayTransport {
                response(
                    500,
                    problem("operation_indeterminate", status = 500, operationId = operationId),
                )
            },
        )
        val wrongStatus = assertThrows(LatchwayException::class.java) {
            runBlocking { wrongStatusClient.quota("assistant") }
        }
        assertEquals(LatchwayErrorCode.RESPONSE_INVALID, wrongStatus.code)
        wrongStatusClient.close()

        val wrongRetryabilityClient = client(
            stateStore = MemoryStateStore(
                snapshot("b".repeat(64), "s".repeat(32), now + 600, now + 3_600),
            ),
            transport = LatchwayTransport {
                response(
                    503,
                    problem(
                        "operation_indeterminate",
                        status = 503,
                        operationId = operationId,
                        retryable = false,
                    ),
                )
            },
        )
        val wrongRetryability = assertThrows(LatchwayException::class.java) {
            runBlocking { wrongRetryabilityClient.quota("assistant") }
        }
        assertEquals(LatchwayErrorCode.RESPONSE_INVALID, wrongRetryability.code)
        wrongRetryabilityClient.close()
    }

    @Test
    fun refreshRevocationDoesNotDeadlockItsOwnInFlightSession() = runBlocking {
        val state = MemoryStateStore(
            snapshot("a".repeat(64), "r".repeat(32), now - 1, now + 3_600),
        )
        val calls = AtomicInteger()
        val client = client(
            stateStore = state,
            transport = LatchwayTransport {
                calls.incrementAndGet()
                response(403, problem("installation_revoked"))
            },
        )

        val error = assertThrows(LatchwayException::class.java) {
            runBlocking {
                withTimeout(2_000) {
                    client.authorize("GET", URI("https://gateway.example.test/v1/diagnostics"), "assistant")
                }
            }
        }

        assertEquals(LatchwayErrorCode.INSTALLATION_REVOKED, error.code)
        assertNull(state.load())
        assertEquals(1, signer.resetCount)
        assertEquals(1, calls.get())
        client.close()
    }

    @Test
    fun successfulRevocationClearsStateResetsKeyAndPreventsClientReuse() = runBlocking {
        val state = MemoryStateStore(
            snapshot("a".repeat(64), "r".repeat(32), now + 600, now + 3_600),
        )
        val calls = AtomicInteger()
        val client = client(
            stateStore = state,
            transport = LatchwayTransport { request ->
                calls.incrementAndGet()
                assertEquals("DELETE", request.method)
                assertTrue(request.uri.path.endsWith("installations/current"))
                response(204, "")
            },
        )

        client.revokeCurrentInstallation()

        assertNull(state.load())
        assertEquals(1, signer.resetCount)
        val error = assertThrows(LatchwayException::class.java) {
            runBlocking {
                client.authorize("POST", URI("https://gateway.example.test/v1/chat/completions"), "assistant")
            }
        }
        assertEquals(LatchwayErrorCode.INSTALLATION_REVOKED, error.code)
        assertEquals(1, calls.get())
        client.close()
    }

    @Test
    fun cancellationAfterServerRevocationCannotSkipLocalCleanup() {
        val state = MemoryStateStore(
            snapshot("a".repeat(64), "r".repeat(32), now + 600, now + 3_600),
        )
        val calls = AtomicInteger()
        val client = client(
            stateStore = state,
            transport = LatchwayTransport {
                calls.incrementAndGet()
                currentCoroutineContext().cancel()
                response(204, "")
            },
        )

        assertThrows(CancellationException::class.java) {
            runBlocking { client.revokeCurrentInstallation() }
        }

        runBlocking { assertNull(state.load()) }
        assertEquals(1, signer.resetCount)
        assertEquals(1, calls.get())
        client.close()
    }

    @Test
    fun successfulRevocationStillResetsKeyWhenStateCleanupFails() = runBlocking {
        val state = MemoryStateStore(
            initial = snapshot("a".repeat(64), "r".repeat(32), now + 600, now + 3_600),
            clearFailure = LatchwayException(
                code = LatchwayErrorCode.SECURE_STATE_UNAVAILABLE,
                safeMessage = "Test state cleanup failure",
            ),
        )
        val client = client(
            stateStore = state,
            transport = LatchwayTransport { response(204, "") },
        )

        val error = assertThrows(LatchwayException::class.java) {
            runBlocking { client.revokeCurrentInstallation() }
        }

        assertEquals(LatchwayErrorCode.SECURE_STATE_UNAVAILABLE, error.code)
        assertEquals(1, signer.resetCount)
        val reuseError = assertThrows(LatchwayException::class.java) {
            runBlocking { client.refresh() }
        }
        assertEquals(LatchwayErrorCode.INSTALLATION_REVOKED, reuseError.code)
        assertEquals(1, signer.resetCount)
        client.close()
    }

    @Test
    fun restartRejectsOldJktStateWhenFirstCleanupDidNotClearIt() = runBlocking {
        val oldSigner = FakeSigner()
        val oldSnapshot = snapshot(
            "a".repeat(64),
            "r".repeat(32),
            now + 600,
            now + 3_600,
            oldSigner,
        )
        val state = MemoryStateStore(
            initial = oldSnapshot,
            clearFailure = LatchwayException(
                code = LatchwayErrorCode.SECURE_STATE_UNAVAILABLE,
                safeMessage = "Test state cleanup failure",
            ),
        )
        val firstClient = client(
            stateStore = state,
            transport = LatchwayTransport { error("revocation marker must not use transport") },
            installationSigner = oldSigner,
        )

        val cleanupError = assertThrows(LatchwayException::class.java) {
            runBlocking { firstClient.markCurrentInstallationRevoked() }
        }
        assertEquals(LatchwayErrorCode.SECURE_STATE_UNAVAILABLE, cleanupError.code)
        assertEquals(oldSigner.publicJwk.thumbprint(), state.load()?.installation?.dpopJkt)
        assertEquals(1, oldSigner.resetCount)
        firstClient.close()

        val replacementSigner = FakeSigner()
        val responses = ArrayDeque(
            listOf(
                response(201, challenge()),
                response(
                    201,
                    grant("b".repeat(64), "s".repeat(32), installationSigner = replacementSigner),
                ),
            ),
        )
        val calls = AtomicInteger()
        val restartedClient = client(
            stateStore = state,
            transport = LatchwayTransport {
                calls.incrementAndGet()
                responses.removeFirst()
            },
            installationSigner = replacementSigner,
        )

        restartedClient.authorize(
            "POST",
            URI("https://gateway.example.test/v1/chat/completions"),
            "assistant",
        )

        assertEquals(2, calls.get())
        assertEquals(replacementSigner.publicJwk.thumbprint(), state.load()?.installation?.dpopJkt)
        restartedClient.close()
    }

    @Test
    fun peerRevocationDoesNotWaitForOrPersistAStalledOldKeyGrant() = runBlocking {
        val sharedSigner = FakeSigner()
        val state = MemoryStateStore(
            snapshot("a".repeat(64), "r".repeat(32), now - 1, now + 3_600, sharedSigner),
        )
        val stalledResponse = CompletableDeferred<Continuation<LatchwayTransportResponse>>()
        val stalledClient = client(
            stateStore = state,
            transport = LatchwayTransport {
                suspendCoroutine { continuation -> stalledResponse.complete(continuation) }
            },
            installationSigner = sharedSigner,
        )
        val authorizing = async {
            runCatching {
                stalledClient.authorize(
                    "GET",
                    URI("https://gateway.example.test/v1/diagnostics"),
                    "assistant",
                )
            }
        }
        val responseContinuation = stalledResponse.await()
        val revokingClient = client(
            stateStore = state,
            transport = LatchwayTransport { error("local revocation marker must not use transport") },
            installationSigner = sharedSigner,
        )

        withTimeout(2_000) { revokingClient.markCurrentInstallationRevoked() }

        assertNull(state.load())
        assertEquals(1, sharedSigner.resetCount)

        val replacementSigner = FakeSigner()
        val replacementResponses = ArrayDeque(
            listOf(
                response(201, challenge()),
                response(
                    201,
                    grant("c".repeat(64), "t".repeat(32), installationSigner = replacementSigner),
                ),
            ),
        )
        val replacementClient = client(
            stateStore = state,
            transport = LatchwayTransport { replacementResponses.removeFirst() },
            installationSigner = replacementSigner,
        )
        replacementClient.authorize(
            "GET",
            URI("https://gateway.example.test/v1/diagnostics"),
            "assistant",
        )

        responseContinuation.resume(
            response(
                200,
                grant("b".repeat(64), "s".repeat(32), installationSigner = sharedSigner),
            ),
        )
        withTimeout(2_000) { authorizing.await() }
        assertEquals(replacementSigner.publicJwk.thumbprint(), state.load()?.installation?.dpopJkt)
        assertEquals(1, state.saveCount.get())
        assertEquals(1, sharedSigner.resetCount)
        stalledClient.clearSession()
        assertEquals(replacementSigner.publicJwk.thumbprint(), state.load()?.installation?.dpopJkt)

        stalledClient.close()
        revokingClient.close()
        replacementClient.close()
    }

    @Test
    fun retirementSerializesWithAnOldGrantAlreadyCommittingBeforeReplacementProvisioning() = runBlocking {
        val oldSigner = FakeSigner()
        val state = BlockingSaveStateStore(
            snapshot("a".repeat(64), "r".repeat(32), now - 1, now + 3_600, oldSigner),
        )
        val oldClient = client(
            stateStore = state,
            transport = LatchwayTransport {
                response(
                    200,
                    grant("b".repeat(64), "s".repeat(32), installationSigner = oldSigner),
                )
            },
            installationSigner = oldSigner,
        )
        val oldAuthorization = async {
            runCatching {
                oldClient.authorize(
                    "GET",
                    URI("https://gateway.example.test/v1/old"),
                    "assistant",
                )
            }
        }
        state.saveEntered.await()
        val revokingClient = client(
            stateStore = state,
            transport = LatchwayTransport { error("local retirement must not use transport") },
            installationSigner = oldSigner,
        )
        val retirement = async { revokingClient.markCurrentInstallationRevoked() }
        delay(75)

        assertFalse(retirement.isCompleted)
        state.releaseSave.complete(Unit)
        val oldError = withTimeout(2_000) { oldAuthorization.await().exceptionOrNull() }
        withTimeout(2_000) { retirement.await() }
        assertTrue(oldError is LatchwayException && oldError.code == LatchwayErrorCode.INSTALLATION_REVOKED)
        assertNull(state.load())

        val replacementSigner = FakeSigner()
        val responses = ArrayDeque(
            listOf(
                response(201, challenge()),
                response(
                    201,
                    grant("c".repeat(64), "t".repeat(32), installationSigner = replacementSigner),
                ),
            ),
        )
        val replacementClient = client(
            stateStore = state,
            transport = LatchwayTransport { responses.removeFirst() },
            installationSigner = replacementSigner,
        )
        replacementClient.authorize(
            "GET",
            URI("https://gateway.example.test/v1/replacement"),
            "assistant",
        )

        assertEquals(replacementSigner.publicJwk.thumbprint(), state.load()?.installation?.dpopJkt)
        oldClient.close()
        revokingClient.close()
        replacementClient.close()
    }

    @Test
    fun replacedSignerCannotPersistAnAlreadyDispatchedGrant() = runBlocking {
        val replacedSigner = FakeSigner()
        val state = MemoryStateStore(
            snapshot("a".repeat(64), "r".repeat(32), now - 1, now + 3_600, replacedSigner),
        )
        val stalledResponse = CompletableDeferred<Continuation<LatchwayTransportResponse>>()
        val client = client(
            stateStore = state,
            transport = LatchwayTransport {
                suspendCoroutine { continuation -> stalledResponse.complete(continuation) }
            },
            installationSigner = replacedSigner,
        )
        val authorizing = async {
            runCatching {
                client.authorize(
                    "GET",
                    URI("https://gateway.example.test/v1/diagnostics"),
                    "assistant",
                )
            }
        }
        val responseContinuation = stalledResponse.await()

        replacedSigner.replaceForTest()
        responseContinuation.resume(
            response(
                200,
                grant("b".repeat(64), "s".repeat(32), installationSigner = replacedSigner),
            ),
        )

        val error = withTimeout(2_000) { authorizing.await().exceptionOrNull() }
        assertTrue(error is LatchwayException && error.code == LatchwayErrorCode.KEY_UNAVAILABLE)
        assertEquals(0, state.saveCount.get())
        assertEquals("a".repeat(64), state.load()?.accessToken?.reveal())
        client.close()
    }

    @Test
    fun legacySignerRemainsCompatibleAndIsRetiredProcessWide() = runBlocking {
        val delegate = FakeSigner()
        val legacySigner = object : InstallationSigner {
            override val publicJwk: PublicJwk = delegate.publicJwk
            override val diagnostics: KeyDiagnostics = delegate.diagnostics
            override suspend fun sign(signingInput: ByteArray): ByteArray = delegate.sign(signingInput)
        }
        val state = MemoryStateStore(
            snapshot("a".repeat(64), "r".repeat(32), now + 600, now + 3_600, legacySigner),
        )
        val firstClient = client(
            stateStore = state,
            transport = LatchwayTransport { error("local revocation marker must not use transport") },
            installationSigner = legacySigner,
        )

        firstClient.markCurrentInstallationRevoked()

        assertNull(state.load())
        assertEquals(0, delegate.resetCount)
        val peerCalls = AtomicInteger()
        val peerClient = client(
            stateStore = state,
            transport = LatchwayTransport {
                peerCalls.incrementAndGet()
                error("retired legacy signer must not use transport")
            },
            installationSigner = legacySigner,
        )
        val error = assertThrows(LatchwayException::class.java) {
            runBlocking {
                peerClient.authorize(
                    "GET",
                    URI("https://gateway.example.test/v1/diagnostics"),
                    "assistant",
                )
            }
        }
        assertEquals(LatchwayErrorCode.INSTALLATION_REVOKED, error.code)
        assertEquals(0, peerCalls.get())
        firstClient.close()
        peerClient.close()
    }

    @Test
    fun failedKeyCleanupRetriesLocallyWithoutAnotherTransportRequest() = runBlocking {
        val retrySigner = FakeSigner(resetFailures = 1)
        val state = MemoryStateStore(
            snapshot("a".repeat(64), "r".repeat(32), now + 600, now + 3_600, retrySigner),
        )
        val calls = AtomicInteger()
        val client = client(
            stateStore = state,
            transport = LatchwayTransport {
                calls.incrementAndGet()
                response(204, "")
            },
            installationSigner = retrySigner,
        )

        val cleanupError = assertThrows(LatchwayException::class.java) {
            runBlocking { client.revokeCurrentInstallation() }
        }
        assertEquals(LatchwayErrorCode.KEY_UNAVAILABLE, cleanupError.code)
        assertEquals(1, retrySigner.resetCount)

        val terminalError = assertThrows(LatchwayException::class.java) {
            runBlocking { client.refresh() }
        }
        assertEquals(LatchwayErrorCode.INSTALLATION_REVOKED, terminalError.code)
        assertEquals(2, retrySigner.resetCount)
        assertEquals(1, calls.get())
        client.close()
    }

    @Test
    fun failedKeyCleanupCanFailOverToAPeerCoordinator() = runBlocking {
        val failingSigner = FakeSigner(resetFailures = 1)
        val peerSigner = FakeSigner(publicJwk = failingSigner.publicJwk)
        val firstState = MemoryStateStore(
            snapshot("a".repeat(64), "r".repeat(32), now + 600, now + 3_600, failingSigner),
        )
        val peerState = MemoryStateStore(
            snapshot("b".repeat(64), "s".repeat(32), now + 600, now + 3_600, peerSigner),
        )
        val firstClient = client(
            stateStore = firstState,
            transport = LatchwayTransport { response(204, "") },
            installationSigner = failingSigner,
        )

        val cleanupError = assertThrows(LatchwayException::class.java) {
            runBlocking { firstClient.revokeCurrentInstallation() }
        }
        assertEquals(LatchwayErrorCode.KEY_UNAVAILABLE, cleanupError.code)
        assertNull(firstState.load())

        val peerTransportCalls = AtomicInteger()
        val peerClient = client(
            stateStore = peerState,
            transport = LatchwayTransport {
                peerTransportCalls.incrementAndGet()
                error("retired peer must finish cleanup without transport")
            },
            installationSigner = peerSigner,
        )
        val terminalError = assertThrows(LatchwayException::class.java) {
            runBlocking { peerClient.refresh() }
        }

        assertEquals(LatchwayErrorCode.INSTALLATION_REVOKED, terminalError.code)
        assertNull(peerState.load())
        assertEquals(1, failingSigner.resetCount)
        assertEquals(1, peerSigner.resetCount)
        assertEquals(0, peerTransportCalls.get())
        firstClient.close()
        peerClient.close()
    }

    @Test
    fun restartCanRecoverCleanupWhenServerReportsRevokedAgain() = runBlocking {
        val firstSigner = FakeSigner(resetFailures = 1)
        val firstClient = client(
            stateStore = MemoryStateStore(
                snapshot("a".repeat(64), "r".repeat(32), now + 600, now + 3_600, firstSigner),
            ),
            transport = LatchwayTransport { response(403, problem("installation_revoked")) },
            installationSigner = firstSigner,
        )
        val firstError = assertThrows(LatchwayException::class.java) {
            runBlocking { firstClient.quota("assistant") }
        }
        assertEquals(LatchwayErrorCode.KEY_UNAVAILABLE, firstError.code)
        assertEquals(1, firstSigner.resetCount)
        firstClient.close()

        val restartedSigner = FakeSigner()
        val responses = ArrayDeque(
            listOf(
                response(201, challenge()),
                response(403, problem("installation_revoked")),
            ),
        )
        val restartedCalls = AtomicInteger()
        val restartedClient = client(
            stateStore = MemoryStateStore(),
            transport = LatchwayTransport {
                restartedCalls.incrementAndGet()
                responses.removeFirst()
            },
            installationSigner = restartedSigner,
        )

        val restartedError = assertThrows(LatchwayException::class.java) {
            runBlocking {
                withTimeout(2_000) {
                    restartedClient.authorize(
                        "POST",
                        URI("https://gateway.example.test/v1/chat/completions"),
                        "assistant",
                    )
                }
            }
        }
        assertEquals(LatchwayErrorCode.INSTALLATION_REVOKED, restartedError.code)
        assertEquals(1, restartedSigner.resetCount)
        assertEquals(2, restartedCalls.get())

        val localError = assertThrows(LatchwayException::class.java) {
            runBlocking { restartedClient.refresh() }
        }
        assertEquals(LatchwayErrorCode.INSTALLATION_REVOKED, localError.code)
        assertEquals(2, restartedCalls.get())
        restartedClient.close()
    }

    @Test
    fun expiredChallengeIsRejectedBeforeAttestation() = runBlocking {
        val attestationCalls = AtomicInteger()
        val client = client(
            stateStore = MemoryStateStore(),
            transport = LatchwayTransport {
                response(
                    201,
                    challenge(
                        issuedAt = now - 1_000,
                        expiresAt = "2023-11-14T22:12:00Z",
                    ),
                )
            },
            attestationProvider = debugAttestation(attestationCalls),
            maximumClockSkewSeconds = 0,
        )

        val error = assertThrows(LatchwayException::class.java) {
            runBlocking {
                client.authorize("GET", URI("https://gateway.example.test/v1/diagnostics"), "assistant")
            }
        }
        assertEquals(LatchwayErrorCode.ATTESTATION_STALE, error.code)
        assertEquals(0, attestationCalls.get())
        client.close()
    }

    @Test
    fun providerCancellationIsNeverConvertedIntoAProtocolFailure() {
        val client = client(
            stateStore = MemoryStateStore(),
            transport = LatchwayTransport { error("transport must not run") },
            identityProvider = IdentityTokenProvider { throw CancellationException("cancelled") },
        )

        assertThrows(CancellationException::class.java) {
            runBlocking {
                client.authorize("GET", URI("https://gateway.example.test/v1/diagnostics"), "assistant")
            }
        }
        client.close()
    }

    @Test
    fun reactNativeUsesNativeSecurityWithDistinctWirePlatformAndSdkHeader() = runBlocking {
        val requests = ArrayList<LatchwayTransportRequest>()
        val responses = ArrayDeque(
            listOf(
                response(201, challenge()),
                response(
                    201,
                    grant("a".repeat(64), "r".repeat(32), platform = "react_native_android"),
                ),
            ),
        )
        val client = client(
            stateStore = MemoryStateStore(),
            transport = LatchwayTransport { request ->
                requests += request
                responses.removeFirst()
            },
            clientPlatform = LatchwayClientPlatform.REACT_NATIVE_ANDROID,
        )

        client.authorize("POST", URI("https://gateway.example.test/v1/responses"), "assistant")

        assertEquals(
            "react_native_android",
            JSONObject(String(checkNotNull(requests.first().body), StandardCharsets.UTF_8))
                .getString("platform"),
        )
        assertTrue(requests.all { it.headers["X-Latchway-SDK"] == "react-native" })
        client.close()
    }

    @Test
    fun oversizedAttestationEvidenceIsRejectedBeforeTransport() {
        val calls = AtomicInteger()
        val client = client(
            stateStore = MemoryStateStore(),
            transport = LatchwayTransport {
                check(calls.getAndIncrement() == 0) { "oversized exchange must not be sent" }
                response(201, challenge())
            },
            attestationProvider = object : AttestationProvider {
                override suspend fun warmUp() = Unit
                override suspend fun attest(challenge: AttestationChallenge): AttestationEvidence =
                    AttestationEvidence(
                        "debug",
                        mapOf("first" to "a".repeat(262_144), "second" to "b".repeat(262_144)),
                    )
            },
        )

        val error = assertThrows(LatchwayException::class.java) {
            runBlocking {
                client.authorize("GET", URI("https://gateway.example.test/v1/diagnostics"), "assistant")
            }
        }
        assertEquals(LatchwayErrorCode.REQUEST_INVALID, error.code)
        assertEquals(1, calls.get())
        client.close()
    }

    private fun client(
        stateStore: SessionStateStore,
        transport: LatchwayTransport,
        identityProvider: IdentityTokenProvider = IdentityTokenProvider { "i".repeat(32) },
        attestationProvider: AttestationProvider = debugAttestation(AtomicInteger()),
        maximumClockSkewSeconds: Long = 60,
        clientPlatform: LatchwayClientPlatform = LatchwayClientPlatform.ANDROID,
        installationSigner: InstallationSigner = signer,
    ): LatchwayCoreClient = LatchwayCoreClient.create(
        configuration = CoreConfiguration(
            baseUrl = URI("https://gateway.example.test/"),
            applicationId = "app_01J00000000000000000000000",
            environment = "production",
            identityProvider = "firebase",
            clientPlatform = clientPlatform,
            maximumClockSkewSeconds = maximumClockSkewSeconds,
        ),
        identityTokenProvider = identityProvider,
        attestationProvider = attestationProvider,
        signer = installationSigner,
        stateStore = stateStore,
        transport = transport,
        installationMetadata = InstallationMetadata("1.2.3", "16", "test device"),
        clock = clock,
    )

    private fun debugAttestation(counter: AtomicInteger): AttestationProvider = object : AttestationProvider {
        override suspend fun warmUp() = Unit
        override suspend fun attest(challenge: AttestationChallenge): AttestationEvidence {
            counter.incrementAndGet()
            return AttestationEvidence("debug", mapOf("debug_evidence" to "local-test"))
        }
    }

    private fun challenge(
        issuedAt: Long = now,
        expiresAt: String = "2023-11-14T22:23:20Z",
    ): String = """
        {
          "challenge_id":"chl_01J00000000000000000000001",
          "challenge_nonce":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
          "binding_version":1,
          "issued_at":$issuedAt,
          "expires_at":"$expiresAt",
          "attestation":{
            "provider":"debug",
            "mode":"required",
            "client_data_hash":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
          }
        }
    """.trimIndent()

    private fun grant(
        accessToken: String,
        refreshToken: String,
        platform: String = "android",
        installationSigner: InstallationSigner = signer,
    ): String = """
        {
          "access_token":"$accessToken",
          "token_type":"DPoP",
          "expires_in":600,
          "refresh_token":"$refreshToken",
          "refresh_expires_in":3600,
          "installation":{
            "id":"ins_01J00000000000000000000001",
            "platform":"$platform",
            "dpop_jkt":"${installationSigner.publicJwk.thumbprint()}",
            "status":"active"
          },
          "trust":{
            "provider":"debug",
            "level":"debug",
            "verified_at":"2023-11-14T22:13:20Z",
            "expires_at":"2023-11-14T23:13:20Z"
          }
        }
    """.trimIndent()

    private fun problem(
        code: String,
        status: Int = if (code == "installation_revoked") 403 else 401,
        operationId: String? = null,
        retryable: Boolean = code == "operation_indeterminate",
    ): String = JSONObject()
        .put("type", "https://latchway.dev/problems/$code")
        .put("title", "Request rejected")
        .put("status", status)
        .put("detail", "The request was rejected")
        .put("code", code)
        .put("request_id", "req_12345678")
        .put("retryable", retryable)
        .apply { operationId?.let { put("operation_id", it) } }
        .toString()

    private fun response(
        status: Int,
        body: String,
        headers: Map<String, List<String>> = if (status >= 400) {
            canonicalProblemHeaders()
        } else {
            emptyMap()
        },
    ): LatchwayTransportResponse = LatchwayTransportResponse(
        statusCode = status,
        headers = headers,
        body = body.toByteArray(StandardCharsets.UTF_8),
    )

    private fun canonicalProblemHeaders(): Map<String, List<String>> = mapOf(
        "Content-Type" to listOf("application/problem+json"),
        "X-Latchway-Request-ID" to listOf("req_12345678"),
    )

    private fun snapshot(
        accessToken: String,
        refreshToken: String,
        accessExpiresAt: Long,
        refreshExpiresAt: Long,
        installationSigner: InstallationSigner = signer,
    ): SessionSnapshot = SessionSnapshot(
        accessToken = SecretValue.of(accessToken),
        refreshToken = SecretValue.of(refreshToken),
        accessExpiresAtEpochSeconds = accessExpiresAt,
        refreshExpiresAtEpochSeconds = refreshExpiresAt,
        installation = InstallationSummary(
            id = "ins_01J00000000000000000000001",
            platform = "android",
            dpopJkt = installationSigner.publicJwk.thumbprint(),
            status = "active",
        ),
        trust = TrustSummary(
            provider = "debug",
            level = "debug",
            verifiedAt = "2023-11-14T22:13:20Z",
            expiresAt = "2023-11-14T23:13:20Z",
        ),
    )

    private class MemoryStateStore(
        initial: SessionSnapshot? = null,
        private val clearFailure: LatchwayException? = null,
    ) : SessionStateStore {
        @Volatile private var value = initial
        private val clearFailuresRemaining = AtomicInteger(if (clearFailure == null) 0 else 1)
        val saveCount = AtomicInteger()
        override suspend fun load(): SessionSnapshot? = value
        override suspend fun save(snapshot: SessionSnapshot) {
            saveCount.incrementAndGet()
            value = snapshot
        }
        override suspend fun clear() {
            if (clearFailuresRemaining.getAndUpdate { count -> (count - 1).coerceAtLeast(0) } > 0) {
                throw checkNotNull(clearFailure)
            }
            value = null
        }
    }

    private class BlockingSaveStateStore(initial: SessionSnapshot) : SessionStateStore {
        @Volatile private var value: SessionSnapshot? = initial
        private val blockNextSave = AtomicInteger(1)
        val saveEntered = CompletableDeferred<Unit>()
        val releaseSave = CompletableDeferred<Unit>()

        override suspend fun load(): SessionSnapshot? = value

        override suspend fun save(snapshot: SessionSnapshot) {
            if (blockNextSave.getAndSet(0) == 1) {
                saveEntered.complete(Unit)
                releaseSave.await()
            }
            value = snapshot
        }

        override suspend fun clear() {
            value = null
        }
    }

    private class FakeSigner(
        resetFailures: Int = 0,
        override val publicJwk: PublicJwk = uniqueJwk(),
    ) : ResettableInstallationSigner {
        @Volatile private var invalidated = false
        private val resetFailuresRemaining = AtomicInteger(resetFailures)
        var resetCount: Int = 0
            private set

        override val diagnostics = KeyDiagnostics(
            KeyBacking.SOFTWARE,
            strongBoxRequested = false,
            strongBoxUnavailable = false,
            publicJwkThumbprint = publicJwk.thumbprint(),
        )
        override suspend fun sign(signingInput: ByteArray): ByteArray {
            check(!invalidated) { "Installation key was reset" }
            return ByteArray(64) { 1 }
        }

        override suspend fun isCurrent(): Boolean = !invalidated

        fun replaceForTest() {
            invalidated = true
        }

        override suspend fun reset() {
            resetCount++
            if (resetFailuresRemaining.getAndUpdate { count -> (count - 1).coerceAtLeast(0) } > 0) {
                throw LatchwayException(
                    code = LatchwayErrorCode.KEY_UNAVAILABLE,
                    safeMessage = "Test key cleanup failure",
                )
            }
            invalidated = true
        }

        private companion object {
            val nextIdentity = AtomicInteger()

            fun uniqueJwk(): PublicJwk {
                val coordinate = ByteArray(32)
                val identity = nextIdentity.incrementAndGet()
                coordinate[28] = (identity ushr 24).toByte()
                coordinate[29] = (identity ushr 16).toByte()
                coordinate[30] = (identity ushr 8).toByte()
                coordinate[31] = identity.toByte()
                return PublicJwk(
                    x = Base64Url.encode(coordinate),
                    y = "N5wrFgi5unJsGvU57MC-o4Iv5VHL-V6Sl9_2AcOS6cI",
                )
            }
        }
    }
}
