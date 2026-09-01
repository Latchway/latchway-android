package dev.latchway.okhttp

import dev.latchway.core.LatchwayClientPlatform
import kotlinx.coroutines.runBlocking
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttp
import okhttp3.Request
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.RequestBody.Companion.toRequestBody
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class RoutePolicyTest {
    private val gateway = "https://gateway.example.test/base/".toHttpUrl()

    @Test
    fun dataPlaneRouteAuthorizationIsExactAndFeatureBound() {
        assertTrue(allowed("POST", "/base/v1/responses"))
        assertTrue(allowed("POST", "/base/v1/chat/completions"))
        assertTrue(allowed("POST", "/base/v1/embeddings"))
        assertTrue(allowed("POST", "/base/v1/messages"))
        assertFalse(allowed("GET", "/base/v1/responses"))
        assertFalse(allowed("POST", "/base/v1/responses/"))
        assertFalse(allowed("POST", "/v1/responses"))
        assertFalse(allowed("POST", "/base/client/v1/diagnostics"))
        assertFalse(allowed("POST", "/base/v1/files"))

        assertTrue(allowed("GET", "/base/proxy/assistant/models"))
        assertTrue(allowed("POST", "/base/proxy/assistant/generate"))
        assertTrue(allowed("PUT", "/base/proxy/assistant/files/current"))
        assertTrue(allowed("PATCH", "/base/proxy/assistant/files/current"))
        assertTrue(allowed("DELETE", "/base/proxy/assistant/files/current"))
        assertFalse(allowed("GET", "/base/proxy/other/models"))
        assertFalse(allowed("HEAD", "/base/proxy/assistant/models"))
        assertFalse(allowed("OPTIONS", "/base/proxy/assistant/models"))
        assertFalse(allowed("GET", "/base/proxy/assistant/models?cursor=secret"))
        assertFalse(allowed("GET", "/base/proxy/assistant/http:%2F%2Fevil.example"))
        assertFalse(allowed("GET", "/base/proxy/assistant/%2e%2e/admin"))
        assertFalse(allowed("GET", "/base/proxy/assistant/models//latest"))
        assertFalse(allowed("GET", "/base/proxy/assistant/models/"))
        assertFalse(allowed("GET", "/base/proxy/assistant/${"a".repeat(2_049)}"))

        val otherOrigin = Request.Builder()
            .url("https://secondary.example.test/base/v1/responses")
            .post(ByteArray(0).toRequestBody())
            .build()
        assertFalse(isAllowedDataPlaneRequest(gateway, otherOrigin, "assistant"))

        val fragmented = Request.Builder()
            .url("https://gateway.example.test/base/v1/responses#local")
            .post(ByteArray(0).toRequestBody())
            .build()
        assertFalse(isAllowedDataPlaneRequest(gateway, fragmented, "assistant"))

        val userInfo = Request.Builder()
            .url("https://user:password@gateway.example.test/base/v1/responses")
            .post(ByteArray(0).toRequestBody())
            .build()
        assertFalse(isAllowedDataPlaneRequest(gateway, userInfo, "assistant"))
    }

    @Test
    fun publishedOkHttpFrameworkDeclarationMatchesThePinnedRuntime() {
        assertEquals(LATCHWAY_OKHTTP_FRAMEWORK_VERSION, OkHttp.VERSION)
        val android = LatchwayConfiguration(
            baseUrl = "https://gateway.example.test/".toHttpUrl(),
            applicationId = "app_01J00000000000000000000000",
            environment = "production",
        )
        assertEquals("android-okhttp", android.framework.id)
        assertEquals(OkHttp.VERSION, android.framework.version)

        val koog = android.copy(frameworkIntegration = LatchwayFrameworkIntegration.KOOG)
        assertEquals("koog-android", koog.framework.id)
        assertEquals(LATCHWAY_KOOG_FRAMEWORK_VERSION, koog.framework.version)
        assertEquals("1.1.1", koog.framework.version)

        val reactNative = android.copy(
            clientPlatform = LatchwayClientPlatform.REACT_NATIVE_ANDROID,
            sdkVersion = "1.2.3",
        )
        assertEquals(LATCHWAY_REACT_NATIVE_FRAMEWORK_ID, reactNative.framework.id)
        assertEquals(LATCHWAY_REACT_NATIVE_FRAMEWORK_VERSION, reactNative.framework.version)
        assertEquals("0.82.0", reactNative.framework.version)
        assertThrows(IllegalArgumentException::class.java) {
            reactNative.copy(frameworkIntegration = LatchwayFrameworkIntegration.KOOG)
        }

        val androidWithDifferentSdkVersion = android.copy(sdkVersion = "9.8.7")
        assertEquals(OkHttp.VERSION, androidWithDifferentSdkVersion.framework.version)

        val reactNativeWithDifferentSdkVersion = reactNative.copy(sdkVersion = "9.8.7")
        assertEquals(LATCHWAY_REACT_NATIVE_FRAMEWORK_VERSION, reactNativeWithDifferentSdkVersion.framework.version)
    }

    @Test
    fun defaultOkHttpIntegrationPreservesEveryRegisteredAiRouteAndStructuredBody() = runBlocking {
        val server = LoopbackHttpServer()
        repeat(3) {
            server.enqueue(
                LoopbackResponse()
                    .setResponseCode(200)
                    .addHeader("Content-Type", "application/json")
                    .setBody("{\"accepted\":true}"),
            )
        }
        server.start()
        val harness = FrameworkConformanceHarness(server)
        val client = harness.okHttpBuilder().build()
        val json = "application/json".toMediaType()
        val requests = listOf(
            "/v1/responses" to "{\"input\":\"hello\"}",
            "/v1/chat/completions" to "{\"messages\":[],\"tools\":[{\"type\":\"function\"}],\"response_format\":{\"type\":\"json_schema\"}}",
            "/v1/embeddings" to "{\"input\":\"hello\"}",
        )

        try {
            for ((path, body) in requests) {
                val request = Request.Builder()
                    .url(server.url(path))
                    .post(body.toRequestBody(json))
                    .latchwayFeature(FRAMEWORK_FEATURE)
                    .build()
                client.newCall(request).execute().use { response ->
                    assertTrue(response.isSuccessful)
                    assertEquals("{\"accepted\":true}", checkNotNull(response.body).string())
                }
                val recorded = server.takeDataRequest()
                assertEquals("POST $path HTTP/1.1", recorded.requestLine)
                assertEquals(body, recorded.body.readUtf8())
                assertFrameworkAuthorization(recorded)
            }
        } finally {
            client.dispatcher.cancelAll()
            client.connectionPool.evictAll()
            client.dispatcher.executorService.shutdown()
            harness.close()
            server.shutdown()
        }
    }

    @Test
    fun secureStorageNamespacesIncludeTheExactGatewayBasePath() {
        fun configuration(baseUrl: String) = LatchwayConfiguration(
            baseUrl = baseUrl.toHttpUrl(),
            applicationId = "app_01J00000000000000000000000",
            environment = "production",
        )

        assertFalse(
            storageNamespace(configuration("https://gateway.example.test/")) ==
                storageNamespace(configuration("https://gateway.example.test/tenant-a/")),
        )
        assertFalse(
            storageNamespace(configuration("https://gateway.example.test/tenant-a/")) ==
                storageNamespace(configuration("https://gateway.example.test/tenant-b/")),
        )
        assertFalse(
            storageNamespace(configuration("https://gateway.example.test/tenant-a/")) ==
                storageNamespace(
                    configuration("https://gateway.example.test/tenant-a/").copy(identityProvider = "auth0"),
                ),
        )
    }

    @Test
    fun anInternalSecondNetworkAttemptIsRejectedAsIndeterminate() {
        val budget = LatchwayNetworkAttemptBudget("android:attempt-one")
        val request = Request.Builder()
            .url("https://gateway.example.test/base/v1/responses")
            .post(ByteArray(0).toRequestBody())
            .tag(LatchwayNetworkAttemptBudget::class.java, budget)
            .build()

        claimNetworkAttempt(request)
        val error = assertThrows(dev.latchway.core.LatchwayException::class.java) {
            claimNetworkAttempt(request)
        }

        assertEquals(dev.latchway.core.LatchwayErrorCode.TRANSPORT_REQUEST_NOT_REPLAYABLE, error.code)
    }

    @Test
    fun validatedAuthenticatorNonceSurvivesFinalNetworkResigning() {
        val nonce = "nonce-0123456789abcdef"
        val challenged = Request.Builder()
            .url("https://gateway.example.test/base/v1/responses")
            .post(ByteArray(0).toRequestBody())
            .latchwayRetryNonce(nonce)
            .build()

        assertEquals(nonce, challenged.latchwayRetryNonce())
        assertEquals(
            null,
            challenged.newBuilder().latchwayRetryNonce(null).build().latchwayRetryNonce(),
        )
        assertThrows(IllegalArgumentException::class.java) {
            challenged.newBuilder().latchwayRetryNonce("short")
        }
    }

    private fun allowed(method: String, path: String): Boolean {
        val builder = Request.Builder().url("https://gateway.example.test$path")
        val request = when (method) {
            "GET" -> builder.get().build()
            "POST" -> builder.post(ByteArray(0).toRequestBody()).build()
            "PUT" -> builder.put(ByteArray(0).toRequestBody()).build()
            "PATCH" -> builder.patch(ByteArray(0).toRequestBody()).build()
            "DELETE" -> builder.delete(ByteArray(0).toRequestBody()).build()
            "HEAD" -> builder.head().build()
            "OPTIONS" -> builder.method("OPTIONS", null).build()
            else -> error("unsupported test method")
        }
        return isAllowedDataPlaneRequest(gateway, request, "assistant")
    }
}
