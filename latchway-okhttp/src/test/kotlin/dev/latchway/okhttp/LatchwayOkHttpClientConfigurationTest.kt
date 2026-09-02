package dev.latchway.okhttp

import dev.latchway.core.LatchwayComponentClient
import dev.latchway.core.LatchwayErrorCode
import dev.latchway.core.LatchwayException
import okhttp3.Authenticator
import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.Interceptor
import okhttp3.OkHttpClient
import okhttp3.Protocol
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import okhttp3.ResponseBody.Companion.toResponseBody
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.atomic.AtomicInteger

class LatchwayOkHttpClientConfigurationTest {
    @Test
    fun atomicBuilderHasRootAndComponentJavaOverloads() {
        val signatures = LatchwayClient::class.java.methods
            .filter { it.name == "buildOkHttpClient" }
            .map { method -> method.parameterTypes.toList() }
            .toSet()

        assertTrue(emptyList<Class<*>>() in signatures)
        assertTrue(listOf(OkHttpClient.Builder::class.java) in signatures)
        assertTrue(listOf(LatchwayComponentClient::class.java) in signatures)
        assertTrue(
            listOf(
                LatchwayComponentClient::class.java,
                OkHttpClient.Builder::class.java,
            ) in signatures,
        )
    }

    @Test
    fun completeBuilderPreservesConfigurationAndInstallsEveryHookLast() {
        val gateway = "https://gateway.example.test/".toHttpUrl()
        val hooks = hooks(gateway)
        val applicationInterceptor = Interceptor { chain -> chain.proceed(chain.request()) }
        val networkInterceptor = Interceptor { chain -> chain.proceed(chain.request()) }
        val fallbackCalls = AtomicInteger()
        val fallbackRequest = Request.Builder().url("https://service.example.test/retry").build()
        val fallback = Authenticator { _, _ ->
            fallbackCalls.incrementAndGet()
            fallbackRequest
        }
        val builder = OkHttpClient.Builder()
            .followRedirects(false)
            .retryOnConnectionFailure(false)
            .addInterceptor(applicationInterceptor)
            .addNetworkInterceptor(networkInterceptor)
            .authenticator(fallback)

        val configured = buildLatchwayOkHttpClient(builder, hooks, component = null)
        try {
            assertEquals(2, configured.interceptors.size)
            assertSame(applicationInterceptor, configured.interceptors.first())
            assertTrue(configured.interceptors.last() is LatchwayOkHttpInstallationPart)
            assertEquals(2, configured.networkInterceptors.size)
            assertSame(networkInterceptor, configured.networkInterceptors.first())
            assertTrue(configured.networkInterceptors.last() is LatchwayOkHttpInstallationPart)
            assertTrue(configured.authenticator is LatchwayOkHttpInstallationPart)
            assertFalse(configured.followRedirects)
            assertFalse(configured.retryOnConnectionFailure)

            // Installation snapshots instead of mutating the caller's builder.
            assertEquals(listOf(applicationInterceptor), builder.interceptors())
            assertEquals(listOf(networkInterceptor), builder.networkInterceptors())
            assertSame(fallback, builder.build().authenticator)

            assertSame(
                fallbackRequest,
                configured.authenticator.authenticate(
                    null,
                    response("https://service.example.test/private"),
                ),
            )
            assertEquals(1, fallbackCalls.get())
            assertNull(configured.authenticator.authenticate(null, response(gateway.toString())))
            assertEquals(1, fallbackCalls.get())
        } finally {
            shutdown(configured)
        }
    }

    @Test
    fun partialOrDuplicateLatchwayInstallationFailsBeforeMutatingTheBuilder() {
        val hooks = hooks("https://gateway.example.test/".toHttpUrl())
        val partiallyConfigured = listOf(
            OkHttpClient.Builder().addInterceptor(hooks.interceptor()),
            OkHttpClient.Builder().addNetworkInterceptor(hooks.originGuard()),
            OkHttpClient.Builder().authenticator(hooks.authenticator()),
        )

        for (builder in partiallyConfigured) {
            val interceptors = builder.interceptors().toList()
            val networkInterceptors = builder.networkInterceptors().toList()
            val authenticator = builder.build().authenticator

            val error = assertThrows(LatchwayException::class.java) {
                buildLatchwayOkHttpClient(builder, hooks, component = null)
            }

            assertEquals(LatchwayErrorCode.CONFIGURATION_INVALID, error.code)
            assertEquals(interceptors, builder.interceptors())
            assertEquals(networkInterceptors, builder.networkInterceptors())
            assertSame(authenticator, builder.build().authenticator)
        }

        val configured = buildLatchwayOkHttpClient(OkHttpClient.Builder(), hooks, component = null)
        try {
            val duplicate = assertThrows(LatchwayException::class.java) {
                buildLatchwayOkHttpClient(configured.newBuilder(), hooks, component = null)
            }
            assertEquals(LatchwayErrorCode.CONFIGURATION_INVALID, duplicate.code)
        } finally {
            shutdown(configured)
        }
    }

    @Test
    fun completeBuilderStillBlocksCredentialsBeforeCrossOriginRedirectDispatch() {
        val gateway = LoopbackHttpServer()
        val redirectTarget = LoopbackHttpServer()
        gateway.start()
        redirectTarget.start()
        gateway.enqueue(
            LoopbackResponse()
                .setResponseCode(302)
                .addHeader("Location", redirectTarget.url("/credential-target").toString()),
        )
        redirectTarget.enqueue(LoopbackResponse().setResponseCode(200).setBody("must not arrive"))
        val harness = FrameworkConformanceHarness(gateway)
        val configured = harness.okHttpClient()

        try {
            val error = assertThrows(LatchwayException::class.java) {
                configured.newCall(
                    Request.Builder()
                        .url(gateway.url("/v1/responses"))
                        .post("{}".toRequestBody())
                        .latchwayFeature(FRAMEWORK_FEATURE)
                        .build(),
                ).execute().use { }
            }

            assertEquals(LatchwayErrorCode.TRANSPORT_DESTINATION_NOT_ALLOWED, error.code)
            assertEquals(1, gateway.dataRequestCount)
            assertEquals(0, redirectTarget.requestCount)
        } finally {
            shutdown(configured)
            harness.close()
            gateway.shutdown()
            redirectTarget.shutdown()
        }
    }

    private fun hooks(gateway: HttpUrl): LatchwayOkHttpHooks = LatchwayOkHttpHooks(
        configuration = LatchwayConfiguration(
            baseUrl = gateway,
            applicationId = "app_01J00000000000000000000000",
            environment = "production",
            defaultFeature = FRAMEWORK_FEATURE,
            allowInsecureLoopback = gateway.scheme == "http",
        ),
        authorizer = { _, _, _, _ -> error("authorization is not used by configuration tests") },
        refresher = { },
        clearer = { _, _ -> },
        terminalResponseObserver = { _, _ -> },
    )

    private fun response(url: String): Response = Response.Builder()
        .request(Request.Builder().url(url).build())
        .protocol(Protocol.HTTP_1_1)
        .code(500)
        .message("Test response")
        .body(ByteArray(0).toResponseBody())
        .build()

    private fun shutdown(client: OkHttpClient) {
        client.dispatcher.cancelAll()
        client.connectionPool.evictAll()
        client.dispatcher.executorService.shutdown()
    }
}
