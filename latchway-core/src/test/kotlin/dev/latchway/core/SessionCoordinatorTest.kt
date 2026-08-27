package dev.latchway.core

import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.json.JSONObject
import java.net.URI
import java.nio.charset.StandardCharsets
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.atomic.AtomicInteger

class SessionCoordinatorTest {
    private val now = 1_700_000_000L
    private val clock = LatchwayClock { now }
    private val signer = FakeSigner()

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
    fun protectedRevocationResponseClearsState() = runBlocking {
        val state = MemoryStateStore(
            snapshot("a".repeat(64), "r".repeat(32), now + 600, now + 3_600),
        )
        val client = client(
            stateStore = state,
            transport = LatchwayTransport { response(401, problem("installation_revoked")) },
        )
        val error = assertThrows(LatchwayException::class.java) {
            runBlocking { client.quota("assistant") }
        }
        assertEquals(LatchwayErrorCode.INSTALLATION_REVOKED, error.code)
        assertNull(state.load())
        client.close()
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
    ): LatchwayCoreClient = LatchwayCoreClient.create(
        configuration = CoreConfiguration(
            baseUrl = URI("https://gateway.example.test/"),
            applicationId = "app_habitify",
            environment = "production",
            identityProvider = "firebase",
            clientPlatform = clientPlatform,
            maximumClockSkewSeconds = maximumClockSkewSeconds,
        ),
        identityTokenProvider = identityProvider,
        attestationProvider = attestationProvider,
        signer = signer,
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
            "dpop_jkt":"${signer.publicJwk.thumbprint()}",
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

    private fun problem(code: String): String = """
        {
          "type":"https://latchway.dev/problems/$code",
          "title":"Request rejected",
          "status":401,
          "detail":"The request was rejected",
          "code":"$code",
          "request_id":"req_12345678",
          "retryable":false
        }
    """.trimIndent()

    private fun response(status: Int, body: String): LatchwayTransportResponse = LatchwayTransportResponse(
        statusCode = status,
        headers = emptyMap(),
        body = body.toByteArray(StandardCharsets.UTF_8),
    )

    private fun snapshot(
        accessToken: String,
        refreshToken: String,
        accessExpiresAt: Long,
        refreshExpiresAt: Long,
    ): SessionSnapshot = SessionSnapshot(
        accessToken = SecretValue.of(accessToken),
        refreshToken = SecretValue.of(refreshToken),
        accessExpiresAtEpochSeconds = accessExpiresAt,
        refreshExpiresAtEpochSeconds = refreshExpiresAt,
        installation = InstallationSummary(
            id = "ins_01J00000000000000000000001",
            platform = "android",
            dpopJkt = signer.publicJwk.thumbprint(),
            status = "active",
        ),
        trust = TrustSummary(
            provider = "debug",
            level = "debug",
            verifiedAt = "2023-11-14T22:13:20Z",
            expiresAt = "2023-11-14T23:13:20Z",
        ),
    )

    private class MemoryStateStore(initial: SessionSnapshot? = null) : SessionStateStore {
        @Volatile private var value = initial
        override suspend fun load(): SessionSnapshot? = value
        override suspend fun save(snapshot: SessionSnapshot) { value = snapshot }
        override suspend fun clear() { value = null }
    }

    private class FakeSigner : InstallationSigner {
        override val publicJwk = PublicJwk(
            x = "Cq0dYDxoGL4oLYM_cwDclqKoVgkU5OeuoXo_L4Z418s",
            y = "N5wrFgi5unJsGvU57MC-o4Iv5VHL-V6Sl9_2AcOS6cI",
        )
        override val diagnostics = KeyDiagnostics(
            KeyBacking.SOFTWARE,
            strongBoxRequested = false,
            strongBoxUnavailable = false,
            publicJwkThumbprint = publicJwk.thumbprint(),
        )
        override suspend fun sign(signingInput: ByteArray): ByteArray = ByteArray(64) { 1 }
    }
}
