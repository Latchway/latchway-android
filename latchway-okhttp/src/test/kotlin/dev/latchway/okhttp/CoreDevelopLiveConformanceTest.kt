package dev.latchway.okhttp

import dev.latchway.core.AttestationChallenge
import dev.latchway.core.AttestationEvidence
import dev.latchway.core.AttestationProvider
import dev.latchway.core.Base64Url
import dev.latchway.core.CoreConfiguration
import dev.latchway.core.IdentityTokenProvider
import dev.latchway.core.InstallationMetadata
import dev.latchway.core.KeyBacking
import dev.latchway.core.LATCHWAY_PROTOCOL_VERSION
import dev.latchway.core.LatchwayClientPlatform
import dev.latchway.core.LatchwayCoreClient
import dev.latchway.core.LatchwayTransportRequest
import dev.latchway.testsupport.InMemorySessionStateStore
import dev.latchway.testsupport.SoftwareTestInstallationSigner
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import okhttp3.Call
import okhttp3.EventListener
import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.net.Proxy
import java.net.URI
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.PosixFilePermissions
import java.util.Locale
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference

/**
 * Opt-in CI proof against the foreground `latchway develop` helper.
 *
 * The environment gate keeps ordinary JVM tests hermetic. Coordinates are
 * intentionally limited to a canonical IPv4 loopback origin and public values
 * from the develop ready document; this driver never accepts a credential.
 */
class CoreDevelopLiveConformanceTest {
    @Test
    fun controlTransportPreservesTheCanonicalJsonMediaType() = runBlocking {
        val server = LoopbackHttpServer()
        val client = loopbackClient()
        server.enqueue(LoopbackResponse().setResponseCode(200).setBody("{}"))
        server.start()
        try {
            OkHttpLatchwayTransport(client).execute(
                LatchwayTransportRequest(
                    method = "POST",
                    uri = server.url("/client/v1/session-challenges").toUri(),
                    headers = mapOf("Content-Type" to "application/json"),
                    body = "{}".toByteArray(StandardCharsets.UTF_8),
                ),
            )

            assertEquals("application/json", server.takeRequest().headers["Content-Type"])
        } finally {
            shutdown(client)
            server.shutdown()
        }
    }

    @Test
    fun androidSdkIssuesOneBoundRequestAndReadsSessionState() {
        assumeTrue(
            "$ENABLE_ENV=1 is required for the live develop conformance test",
            System.getenv(ENABLE_ENV) == "1",
        )
        assertEquals("The live develop driver is CI-only", "true", System.getenv("CI")?.lowercase(Locale.US))
        val coordinates = DevelopCoordinates.fromEnvironment()

        runBlocking {
            withTimeout(60_000) {
                runConformance(coordinates)
            }
        }
    }

    private suspend fun runConformance(coordinates: DevelopCoordinates) {
        val signer = SoftwareTestInstallationSigner.generate()
        val stateStore = InMemorySessionStateStore()
        val controlHttp = loopbackClient()
        val developProvider = DevelopProvider(
            client = controlHttp,
            coordinates = coordinates,
            dpopJkt = signer.publicJwk.thumbprint(),
        )
        val configuration = LatchwayConfiguration(
            baseUrl = coordinates.gatewayUrl,
            applicationId = coordinates.applicationId,
            environment = DEVELOP_ENVIRONMENT,
            identityProvider = DEVELOP_IDENTITY_PROVIDER,
            clientPlatform = LatchwayClientPlatform.ANDROID,
            defaultFeature = coordinates.feature,
            allowInsecureLoopback = true,
        )
        val core = LatchwayCoreClient.create(
            configuration = CoreConfiguration(
                baseUrl = coordinates.gatewayUrl.toUri(),
                applicationId = coordinates.applicationId,
                environment = DEVELOP_ENVIRONMENT,
                identityProvider = DEVELOP_IDENTITY_PROVIDER,
                clientPlatform = LatchwayClientPlatform.ANDROID,
                sdkVersion = configuration.sdkVersion,
                framework = configuration.framework,
                allowInsecureLoopback = true,
            ),
            identityTokenProvider = developProvider,
            attestationProvider = developProvider,
            signer = signer,
            stateStore = stateStore,
            transport = OkHttpLatchwayTransport(controlHttp),
            installationMetadata = InstallationMetadata(
                appVersion = "1.0.0-ci",
                osVersion = "jvm",
                deviceModel = "latchway-develop-conformance",
            ),
        )
        val proxyDispatches = AtomicInteger()
        val dispatchedRequest = AtomicReference<NetworkRequest>()
        val hooks = LatchwayOkHttpHooks(
            configuration = configuration,
            authorizer = { _, request, feature, nonce ->
                core.authorize(request.method, request.url.toUri(), feature, nonce)
            },
            refresher = { core.refresh() },
            clearer = { _, authorization -> core.clearSessionIfCurrent(authorization) },
            terminalResponseObserver = { _, _ -> Unit },
        )
        val dataHttp = loopbackClient().newBuilder()
            .eventListener(object : EventListener() {
                override fun requestHeadersEnd(call: Call, request: Request) {
                    if (request.url.encodedPath != "/v1/responses") return
                    proxyDispatches.incrementAndGet()
                    val authorization = request.header("Authorization")
                    dispatchedRequest.set(
                        NetworkRequest(
                            requestId = request.header("X-Latchway-Request-ID"),
                            feature = request.header("X-Latchway-Feature"),
                            sdk = request.header("X-Latchway-SDK"),
                            protocolVersion = request.header("X-Latchway-Protocol-Version"),
                            framework = request.header("X-Latchway-Framework"),
                            usesDpopAuthorization = authorization?.startsWith("DPoP ") == true,
                            hasDpopProof = request.header("DPoP")?.count { it == '.' } == 2,
                            hasUpstreamCredential =
                                request.header("Api-Key") != null || request.header("X-Api-Key") != null,
                        ),
                    )
                }
            })
            .addInterceptor(hooks.interceptor())
            .addNetworkInterceptor(hooks.originGuard())
            .authenticator(hooks.authenticator())
            .build()

        try {
            // Establish the SDK-owned session before observing the exact quota
            // delta caused by the single data-plane request below.
            val quotaBefore = core.quota(coordinates.feature)
            val requestLimitBefore = quotaBefore.limits.single { it.metric == "logical_requests" }
            val proxyRequest = Request.Builder()
                .url(coordinates.gatewayUrl.resolve("/v1/responses")!!)
                .post(
                    JSONObject()
                        .put("model", "client-placeholder")
                        .put("input", "Android SDK develop conformance")
                        .put("max_output_tokens", 16)
                        .put("stream", false)
                        .toString()
                        .toByteArray(StandardCharsets.UTF_8)
                        .toRequestBody(JSON),
                )
                .latchwayFeature(coordinates.feature)
                .build()
            val proxy = withContext(Dispatchers.IO) {
                dataHttp.newCall(proxyRequest).execute().use(::readProxyResponse)
            }

            assertEquals(1, proxyDispatches.get())
            val networkRequest = checkNotNull(dispatchedRequest.get()) { "No proxy request was dispatched" }
            assertEquals(coordinates.feature, networkRequest.feature)
            assertEquals("android", networkRequest.sdk)
            assertEquals(LATCHWAY_PROTOCOL_VERSION.toString(), networkRequest.protocolVersion)
            assertEquals("android-okhttp", networkRequest.framework)
            assertTrue(networkRequest.usesDpopAuthorization)
            assertTrue(networkRequest.hasDpopProof)
            assertFalse(networkRequest.hasUpstreamCredential)
            assertEquals(networkRequest.requestId, proxy.responseRequestId)
            assertEquals("response", proxy.document.getString("object"))
            assertEquals("completed", proxy.document.getString("status"))
            assertEquals("resp_mock_0001", proxy.document.getString("id"))
            assertEquals("latchway-mock-model", proxy.document.getString("model"))
            val outputText = proxy.document.getJSONArray("output")
                .getJSONObject(0)
                .getJSONArray("content")
                .getJSONObject(0)
            assertEquals("output_text", outputText.getString("type"))
            assertEquals("Deterministic mock response.", outputText.getString("text"))
            val usage = proxy.document.getJSONObject("usage")
            assertEquals(11L, usage.getLong("input_tokens"))
            assertEquals(7L, usage.getLong("output_tokens"))
            assertEquals(18L, usage.getLong("total_tokens"))

            val stored = checkNotNull(stateStore.load()) { "SDK did not persist the issued session" }
            assertEquals("android", stored.installation.platform)
            assertEquals("active", stored.installation.status)
            assertEquals(signer.publicJwk.thumbprint(), stored.installation.dpopJkt)
            assertEquals("debug", stored.trust.provider)
            assertEquals("debug", stored.trust.level)

            val quota = core.quota(coordinates.feature)
            assertEquals(coordinates.feature, quota.feature)
            val requestLimit = quota.limits.single { it.metric == "logical_requests" }
            assertTrue(requestLimit.hard)
            assertEquals(100L, requestLimit.maximum)
            assertEquals(checkNotNull(requestLimitBefore.used) + 1, requestLimit.used)
            assertEquals(0L, requestLimit.reserved)
            assertEquals(checkNotNull(requestLimitBefore.remaining) - 1, requestLimit.remaining)

            core.refresh()
            val refreshed = checkNotNull(stateStore.load()) { "SDK did not persist the refreshed session" }
            assertEquals(stored.installation.id, refreshed.installation.id)
            assertEquals(stored.installation.dpopJkt, refreshed.installation.dpopJkt)

            val diagnostics = core.diagnostics()
            assertEquals(stored.installation.id, diagnostics.installationId)
            assertEquals("active", diagnostics.installationStatus)
            assertEquals(KeyBacking.SOFTWARE, diagnostics.key.backing)
            assertEquals(signer.publicJwk.thumbprint(), diagnostics.key.publicJwkThumbprint)
            assertEquals("debug", diagnostics.trustProvider)
            assertEquals("debug", diagnostics.trustLevel)
            assertTrue(diagnostics.refreshAvailable)
            assertTrue(diagnostics.requestId.isNotBlank())

            assertEquals(1, developProvider.identityRequests.get())
            assertEquals(1, developProvider.attestationRequests.get())
            assertEquals(1, developProvider.warmUps.get())
            assertEquals(developProvider.lastChallengeId, developProvider.authorizedChallengeId)
            assertEquals(developProvider.lastBindingHash, developProvider.authorizedBindingHash)

            writeReport(
                output = requiredEnvironment(OUTPUT_ENV),
                requestId = checkNotNull(proxy.responseRequestId) { "Proxy response omitted its request identifier" },
                contractVersion = diagnostics.contractVersion,
                protocolVersion = diagnostics.protocolVersion,
                quotaLimitCount = quota.limits.size,
            )
        } finally {
            core.close()
            shutdown(dataHttp)
            shutdown(controlHttp)
        }
    }

    private class DevelopProvider(
        private val client: OkHttpClient,
        private val coordinates: DevelopCoordinates,
        private val dpopJkt: String,
    ) : IdentityTokenProvider, AttestationProvider {
        val warmUps = AtomicInteger()
        val identityRequests = AtomicInteger()
        val attestationRequests = AtomicInteger()
        var lastChallengeId: String? = null
            private set
        var lastBindingHash: String? = null
            private set
        var authorizedChallengeId: String? = null
            private set
        var authorizedBindingHash: String? = null
            private set

        override suspend fun warmUp() {
            warmUps.incrementAndGet()
        }

        override suspend fun identityToken(): String = withContext(Dispatchers.IO) {
            identityRequests.incrementAndGet()
            client.newCall(Request.Builder().url(coordinates.identityTokenUrl).get().build())
                .execute()
                .use { response ->
                    val document = readHelperResponse(response)
                    requireExactKeys(document, "identity_token")
                    document.getString("identity_token").also {
                        check(it.length in 64..65_536) { "Develop identity helper returned an invalid token" }
                    }
                }
        }

        override suspend fun attest(challenge: AttestationChallenge): AttestationEvidence =
            withContext(Dispatchers.IO) {
                check(challenge.provider == "debug") { "Develop challenge did not select debug attestation" }
                lastChallengeId = challenge.challengeId
                lastBindingHash = challenge.clientDataHash
                attestationRequests.incrementAndGet()
                val requestBody = JSONObject()
                    .put("challenge_id", challenge.challengeId)
                    .put("binding_hash", challenge.clientDataHash)
                    .put("application_id", coordinates.applicationId)
                    .put("environment", DEVELOP_ENVIRONMENT)
                    .put("dpop_jkt", dpopJkt)
                    .put("platform", "android")
                    .toString()
                    .toByteArray(StandardCharsets.UTF_8)
                    .toRequestBody(JSON)
                val document = client.newCall(
                    Request.Builder()
                        .url(coordinates.attestationEvidenceUrl)
                        .post(requestBody)
                        .build(),
                ).execute().use(::readHelperResponse)
                requireExactKeys(document, "key_id", "binding_hash", "expires_at", "signature")
                val bindingHash = document.getString("binding_hash")
                val signature = document.getString("signature")
                check(bindingHash == challenge.clientDataHash) {
                    "Develop evidence was not bound to the SDK challenge"
                }
                check(Base64Url.decode(bindingHash).size == 32) { "Develop evidence binding is invalid" }
                check(Base64Url.decode(signature).size == 64) { "Develop evidence signature is invalid" }
                check(document.getLong("expires_at") > System.currentTimeMillis() / 1_000) {
                    "Develop evidence is already expired"
                }
                authorizedChallengeId = challenge.challengeId
                authorizedBindingHash = bindingHash
                AttestationEvidence(
                    provider = "debug",
                    evidence = linkedMapOf(
                        "key_id" to document.getString("key_id"),
                        "binding_hash" to bindingHash,
                        "expires_at" to document.getLong("expires_at"),
                        "signature" to signature,
                    ),
                )
            }
    }

    private data class DevelopCoordinates(
        val gatewayUrl: HttpUrl,
        val applicationId: String,
        val feature: String,
    ) {
        val identityTokenUrl: HttpUrl = gatewayUrl.resolve("/development/v1/identity-token")!!
        val attestationEvidenceUrl: HttpUrl = gatewayUrl.resolve("/development/v1/attestation-evidence")!!

        companion object {
            fun fromEnvironment(): DevelopCoordinates {
                val rawGateway = requiredEnvironment(GATEWAY_ENV)
                val parsed = URI(rawGateway)
                check(parsed.scheme == "http" && parsed.host == "127.0.0.1") {
                    "$GATEWAY_ENV must be an exact IPv4 loopback HTTP origin"
                }
                check(
                    parsed.port in 1..65_535 && parsed.userInfo == null && parsed.query == null &&
                        parsed.fragment == null && parsed.rawPath.isNullOrEmpty() &&
                        rawGateway == "http://127.0.0.1:${parsed.port}",
                ) { "$GATEWAY_ENV must not contain credentials, a path, a query, or a fragment" }
                return DevelopCoordinates(
                    gatewayUrl = "$rawGateway/".toHttpUrl(),
                    applicationId = requiredEnvironment(APPLICATION_ID_ENV),
                    feature = requiredEnvironment(FEATURE_ENV).also {
                        check(IDENTIFIER.matches(it)) { "$FEATURE_ENV is not a canonical identifier" }
                    },
                )
            }
        }
    }

    private data class ProxyResponse(
        val responseRequestId: String?,
        val document: JSONObject,
    )

    private data class NetworkRequest(
        val requestId: String?,
        val feature: String?,
        val sdk: String?,
        val protocolVersion: String?,
        val framework: String?,
        val usesDpopAuthorization: Boolean,
        val hasDpopProof: Boolean,
        val hasUpstreamCredential: Boolean,
    )

    private companion object {
        const val ENABLE_ENV = "LATCHWAY_ANDROID_DEVELOP_CONFORMANCE"
        const val GATEWAY_ENV = "LATCHWAY_DEVELOP_BASE_URL"
        const val APPLICATION_ID_ENV = "LATCHWAY_DEVELOP_APPLICATION_ID"
        const val FEATURE_ENV = "LATCHWAY_DEVELOP_FEATURE"
        const val OUTPUT_ENV = "LATCHWAY_SDK_CONFORMANCE_OUTPUT"
        const val DEVELOP_ENVIRONMENT = "development"
        const val DEVELOP_IDENTITY_PROVIDER = "mock_oidc"
        const val MAX_RESPONSE_BYTES = 512 * 1024
        val IDENTIFIER = Regex("^[a-z][a-z0-9_-]{0,62}$")
        val JSON = "application/json".toMediaType()

        fun loopbackClient(): OkHttpClient = OkHttpClient.Builder()
            .proxy(Proxy.NO_PROXY)
            .followRedirects(false)
            .followSslRedirects(false)
            .connectTimeout(5, TimeUnit.SECONDS)
            .readTimeout(15, TimeUnit.SECONDS)
            .writeTimeout(5, TimeUnit.SECONDS)
            .callTimeout(20, TimeUnit.SECONDS)
            .build()

        fun readHelperResponse(response: Response): JSONObject {
            assertEquals("Develop helper HTTP status", 200, response.code)
            assertEquals("Develop helper cache policy", "no-store", response.header("Cache-Control"))
            return readJson(response)
        }

        fun readProxyResponse(response: Response): ProxyResponse {
            check(response.code == 200) { "Develop proxy returned HTTP ${response.code}" }
            return ProxyResponse(
                responseRequestId = response.header("X-Latchway-Request-ID"),
                document = readJson(response),
            )
        }

        @Suppress("UNNECESSARY_SAFE_CALL") // Response.body is nullable in supported OkHttp 4.x.
        fun readJson(response: Response): JSONObject {
            check(
                response.header("Content-Type")?.substringBefore(';')
                    ?.equals("application/json", ignoreCase = true) == true,
            ) { "Develop endpoint returned a non-JSON response" }
            val encoded = response.body?.byteStream()?.use { it.readNBytes(MAX_RESPONSE_BYTES + 1) }
                ?: ByteArray(0)
            check(encoded.isNotEmpty() && encoded.size <= MAX_RESPONSE_BYTES) {
                "Develop endpoint returned an empty or oversized response"
            }
            return JSONObject(String(encoded, StandardCharsets.UTF_8))
        }

        fun requireExactKeys(document: JSONObject, vararg expected: String) {
            check(document.keys().asSequence().toSet() == expected.toSet()) {
                "Develop helper response shape changed"
            }
        }

        fun requiredEnvironment(name: String): String =
            checkNotNull(System.getenv(name)?.takeIf { it.isNotBlank() && it == it.trim() }) {
                "$name is required and must not contain surrounding whitespace"
            }

        fun writeReport(
            output: String,
            requestId: String,
            contractVersion: String,
            protocolVersion: Int,
            quotaLimitCount: Int,
        ) {
            val path = Path.of(output)
            check(path.isAbsolute && Files.isDirectory(path.parent)) {
                "$OUTPUT_ENV must name a file in an existing absolute evidence directory"
            }
            val report = JSONObject()
                .put("schema_version", 1)
                .put("kind", "latchway_sdk_live_debug_conformance")
                .put("sdk_kind", "android")
                .put("status", "passed")
                .put("physical_attestation_claimed", false)
                .put("checks", JSONObject()
                    .put("debug_attestation", true)
                    .put("dpop_session", true)
                    .put("proxied_mock_request", true)
                    .put("quota", true)
                    .put("session_refresh", true))
                .put("observations", JSONObject()
                    .put("platform", "android")
                    .put("trust_provider", "debug")
                    .put("contract_version", contractVersion)
                    .put("protocol_version", protocolVersion)
                    .put("response_request_id", requestId)
                    .put("quota_limit_count", quotaLimitCount)
                    .put("logical_requests_delta", 1))
            Files.writeString(
                path,
                report.toString(2) + "\n",
                StandardCharsets.UTF_8,
                StandardOpenOption.CREATE_NEW,
                StandardOpenOption.WRITE,
            )
            Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-------"))
        }

        fun shutdown(client: OkHttpClient) {
            client.dispatcher.cancelAll()
            client.connectionPool.evictAll()
            client.dispatcher.executorService.shutdown()
        }
    }
}
