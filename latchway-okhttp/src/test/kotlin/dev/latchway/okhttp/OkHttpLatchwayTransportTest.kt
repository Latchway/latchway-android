package dev.latchway.okhttp

import dev.latchway.core.LatchwayTransportRequest
import dev.latchway.core.LatchwayErrorCode
import dev.latchway.core.LatchwayException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import mockwebserver3.MockResponse
import mockwebserver3.MockWebServer
import okhttp3.Call
import okhttp3.Cookie
import okhttp3.CookieJar
import okhttp3.EventListener
import okhttp3.HttpUrl
import okhttp3.OkHttpClient
import okhttp3.Response
import okhttp3.Request
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.nio.charset.StandardCharsets
import java.util.concurrent.TimeUnit

class OkHttpLatchwayTransportTest {
    @Test
    fun originGuardBlocksLatchwayHeadersBeforeACrossOriginRedirectIsDispatched() {
        val gateway = MockWebServer()
        val redirectTarget = MockWebServer()
        gateway.start()
        redirectTarget.start()
        gateway.enqueue(
            MockResponse.Builder()
                .code(302)
                .addHeader("Location", redirectTarget.url("/credential-target"))
                .build(),
        )
        redirectTarget.enqueue(MockResponse.Builder().code(200).body("must not arrive").build())
        val client = OkHttpClient.Builder()
            .addNetworkInterceptor(gatewayOriginGuard(gateway.url("/")))
            .build()

        try {
            val error = assertThrows(LatchwayException::class.java) {
                client.newCall(
                    Request.Builder()
                        .url(gateway.url("/start"))
                        .header("Authorization", "DPoP access-token")
                        .header("DPoP", "signed-proof")
                        .header("X-Latchway-Request-ID", "req_12345678")
                        .build(),
                ).execute().use { }
            }

            assertEquals(LatchwayErrorCode.CONFIGURATION_INVALID, error.code)
            assertEquals(0, redirectTarget.requestCount)
        } finally {
            client.dispatcher.cancelAll()
            client.connectionPool.evictAll()
            client.dispatcher.executorService.shutdown()
            gateway.close()
            redirectTarget.close()
        }
    }

    @Test
    fun originGuardRejectsCookieJarCredentialsBeforeGatewayDispatch() {
        val gateway = MockWebServer()
        gateway.start()
        val client = OkHttpClient.Builder()
            .cookieJar(object : CookieJar {
                override fun saveFromResponse(url: HttpUrl, cookies: List<Cookie>) = Unit

                override fun loadForRequest(url: HttpUrl): List<Cookie> = listOf(
                    Cookie.Builder()
                        .hostOnlyDomain(url.host)
                        .name("api_key")
                        .value("provider-secret")
                        .build(),
                )
            })
            .addNetworkInterceptor(gatewayOriginGuard(gateway.url("/")))
            .build()

        try {
            val error = assertThrows(LatchwayException::class.java) {
                client.newCall(
                    Request.Builder()
                        .url(gateway.url("/v1/responses"))
                        .header("Authorization", "DPoP access-token")
                        .header("DPoP", "signed-proof")
                        .build(),
                ).execute().use { }
            }

            assertEquals(LatchwayErrorCode.REQUEST_INVALID, error.code)
            assertEquals(0, gateway.requestCount)
        } finally {
            client.dispatcher.cancelAll()
            client.connectionPool.evictAll()
            client.dispatcher.executorService.shutdown()
            gateway.close()
        }
    }

    @Test
    fun originGuardRejectsProxyCredentialAddedByALaterInterceptorBeforeDispatch() {
        val gateway = MockWebServer()
        gateway.start()
        val client = OkHttpClient.Builder()
            .addInterceptor { chain ->
                chain.proceed(
                    chain.request().newBuilder()
                        .header("Proxy-Authorization", "Basic provider-secret")
                        .build(),
                )
            }
            .addNetworkInterceptor(gatewayOriginGuard(gateway.url("/")))
            .build()

        try {
            val error = assertThrows(LatchwayException::class.java) {
                client.newCall(Request.Builder().url(gateway.url("/v1/responses")).build())
                    .execute()
                    .use { }
            }

            assertEquals(LatchwayErrorCode.REQUEST_INVALID, error.code)
            assertEquals(0, gateway.requestCount)
        } finally {
            client.dispatcher.cancelAll()
            client.connectionPool.evictAll()
            client.dispatcher.executorService.shutdown()
            gateway.close()
        }
    }

    @Test
    fun originGuardRejectsCredentialQueryBeforeGatewayDispatch() {
        val gateway = MockWebServer()
        gateway.start()
        val client = OkHttpClient.Builder()
            .addNetworkInterceptor(gatewayOriginGuard(gateway.url("/")))
            .build()

        try {
            val error = assertThrows(LatchwayException::class.java) {
                client.newCall(
                    Request.Builder()
                        .url(gateway.url("/v1/responses?Api_Key=provider-secret"))
                        .header("Authorization", "DPoP access-token")
                        .header("DPoP", "signed-proof")
                        .build(),
                ).execute().use { }
            }

            assertEquals(LatchwayErrorCode.REQUEST_INVALID, error.code)
            assertEquals(0, gateway.requestCount)
        } finally {
            client.dispatcher.cancelAll()
            client.connectionPool.evictAll()
            client.dispatcher.executorService.shutdown()
            gateway.close()
        }
    }

    @Test
    fun forwardsEveryControlHeaderAndBody() = runBlocking {
        val server = MockWebServer()
        val client = OkHttpClient()
        server.enqueue(
            MockResponse.Builder()
                .code(201)
                .addHeader("X-Latchway-Request-ID", "req_12345678")
                .body("accepted")
                .build(),
        )
        server.start()

        try {
            val response = OkHttpLatchwayTransport(client).execute(
                LatchwayTransportRequest(
                    method = "POST",
                    uri = server.url("/client/v1/sessions").toUri(),
                    headers = linkedMapOf(
                        "X-Latchway-Protocol-Version" to "1",
                        "X-Latchway-SDK" to "android",
                    ),
                    body = "request".toByteArray(StandardCharsets.UTF_8),
                ),
            )
            val recorded = server.takeRequest()

            assertEquals("1", recorded.headers["X-Latchway-Protocol-Version"])
            assertEquals("android", recorded.headers["X-Latchway-SDK"])
            assertEquals("request", recorded.body?.utf8())
            assertEquals(201, response.statusCode)
            assertEquals("accepted", String(response.body, StandardCharsets.UTF_8))
        } finally {
            client.dispatcher.cancelAll()
            client.connectionPool.evictAll()
            client.dispatcher.executorService.shutdown()
            server.close()
        }
    }

    @Test
    fun cancellationAfterHeadersClosesAStalledBodyDrain() = runBlocking {
        val server = MockWebServer()
        val headersReceived = CompletableDeferred<Unit>()
        val client = OkHttpClient.Builder()
            .readTimeout(0, TimeUnit.MILLISECONDS)
            .eventListener(object : EventListener() {
                override fun responseHeadersEnd(call: Call, response: Response) {
                    headersReceived.complete(Unit)
                }
            })
            .build()
        server.enqueue(
            MockResponse.Builder()
                .code(200)
                .body("body that must not finish draining")
                .bodyDelay(1, TimeUnit.DAYS)
                .build(),
        )
        server.start()

        try {
            val executing = async(Dispatchers.IO) {
                OkHttpLatchwayTransport(client).execute(
                    LatchwayTransportRequest(
                        method = "GET",
                        uri = server.url("/client/v1/diagnostics").toUri(),
                        headers = emptyMap(),
                        body = null,
                    ),
                )
            }
            headersReceived.await()
            delay(100)

            withTimeout(2_000) { executing.cancelAndJoin() }

            assertTrue(executing.isCancelled)
        } finally {
            client.dispatcher.cancelAll()
            client.connectionPool.evictAll()
            client.dispatcher.executorService.shutdown()
            server.close()
        }
    }
}
