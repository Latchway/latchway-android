package dev.latchway.okhttp

import dev.latchway.core.LatchwayClientPlatform
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

        val reactNative = android.copy(
            clientPlatform = LatchwayClientPlatform.REACT_NATIVE_ANDROID,
            sdkVersion = "1.2.3",
        )
        assertEquals("react-native-fetch", reactNative.framework.id)
        assertEquals("1.2.3", reactNative.framework.version)

        val androidWithDifferentSdkVersion = android.copy(sdkVersion = "9.8.7")
        assertEquals(OkHttp.VERSION, androidWithDifferentSdkVersion.framework.version)
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
