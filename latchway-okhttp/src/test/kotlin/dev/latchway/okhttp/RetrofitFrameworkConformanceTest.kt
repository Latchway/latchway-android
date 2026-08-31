package dev.latchway.okhttp

import dev.latchway.core.LatchwayErrorCode
import dev.latchway.core.LatchwayException
import okhttp3.EventListener
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.RequestBody
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.ResponseBody
import okio.BufferedSink
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import retrofit2.Call
import retrofit2.Retrofit
import retrofit2.http.Body
import retrofit2.http.Header
import retrofit2.http.POST
import retrofit2.http.Streaming
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

class RetrofitFrameworkConformanceTest {
    @Test
    fun retrofitUsesTheProductionHooksAndReplacesItsPlaceholderAuthorization() {
        val server = LoopbackHttpServer()
        server.enqueue(
            LoopbackResponse()
                .setResponseCode(200)
                .addHeader("Content-Type", "application/json")
                .setBody("{\"id\":\"resp_retrofit\",\"status\":\"completed\"}"),
        )
        server.start()
        val harness = FrameworkConformanceHarness(server)
        val http = harness.okHttpBuilder().build()

        try {
            val response = retrofit(server, http).response(
                authorization = "Bearer $PROVIDER_PLACEHOLDER",
                body = "{\"model\":\"feature-selected-server-side\"}"
                    .toRequestBody(JSON),
            ).execute()
            val request = server.takeDataRequest()

            assertTrue(response.isSuccessful)
            assertEquals(2, server.controlRequestCount)
            assertFrameworkAuthorization(request)
            assertEquals("POST /v1/responses HTTP/1.1", request.requestLine)
            assertTrue(request.body.readUtf8().contains("feature-selected-server-side"))
        } finally {
            close(http, harness, server)
        }
    }

    @Test
    fun retrofitStreamingIsIncrementalAndCallCancellationReachesOkHttp() {
        val server = LoopbackHttpServer()
        server.enqueue(
            LoopbackResponse()
                .setResponseCode(200)
                .addHeader("Content-Type", "text/event-stream")
                .setChunkedBody(
                    chunks = listOf("data: first\n", "data: second\n"),
                    delay = 2,
                    unit = TimeUnit.SECONDS,
                ),
        )
        server.start()
        val canceled = CountDownLatch(1)
        val listener = object : EventListener() {
            override fun canceled(call: okhttp3.Call) {
                canceled.countDown()
            }
        }
        val harness = FrameworkConformanceHarness(server)
        val http = harness.okHttpBuilder(listener).build()

        try {
            val call = retrofit(server, http).stream(
                authorization = "Bearer $PROVIDER_PLACEHOLDER",
                body = "{}".toRequestBody(JSON),
            )
            val started = System.nanoTime()
            val response = call.execute()
            val first = checkNotNull(response.body()).source().readUtf8LineStrict()
            val elapsedMillis = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started)

            assertEquals("data: first", first)
            assertTrue("first frame must arrive before the delayed second frame", elapsedMillis < 1_500)
            call.cancel()
            assertTrue(call.isCanceled)
            assertTrue("Retrofit cancellation must cancel the underlying OkHttp call", canceled.await(2, TimeUnit.SECONDS))
            assertEquals(2, server.controlRequestCount)
            assertFrameworkAuthorization(server.takeDataRequest())
        } finally {
            close(http, harness, server)
        }
    }

    @Test
    fun retrofitOneShotBodyIsNotReplayedForASessionChallenge() {
        val server = LoopbackHttpServer()
        server.enqueue(
            LoopbackResponse().setLatchwayProblem(
                code = "session_expired",
                status = 401,
                retryable = true,
            ),
        )
        server.start()
        val harness = FrameworkConformanceHarness(server, includeRefreshGrant = true)
        val http = harness.okHttpBuilder().build()

        try {
            val response = retrofit(server, http).response(
                authorization = "Bearer $PROVIDER_PLACEHOLDER",
                body = OneShotBody("one dispatch only"),
            ).execute()

            assertEquals(401, response.code())
            assertEquals(1, server.dataRequestCount)
            assertEquals(2, server.controlRequestCount)
            assertFrameworkAuthorization(server.takeDataRequest())
        } finally {
            close(http, harness, server)
        }
    }

    @Test
    fun retrofitReplayableBodyUsesOnlyTheCorrelatedPreDispatchRefresh() {
        val server = LoopbackHttpServer()
        server.enqueue(
            LoopbackResponse().setLatchwayProblem(
                code = "session_expired",
                status = 401,
                retryable = true,
            ),
        )
        server.enqueue(
            LoopbackResponse()
                .setResponseCode(200)
                .addHeader("Content-Type", "application/json")
                .setBody("{\"id\":\"resp_after_refresh\",\"status\":\"completed\"}"),
        )
        server.start()
        val harness = FrameworkConformanceHarness(server, includeRefreshGrant = true)
        val http = harness.okHttpBuilder().build()

        try {
            val response = retrofit(server, http).response(
                authorization = "Bearer $PROVIDER_PLACEHOLDER",
                body = "{}".toRequestBody(JSON),
            ).execute()
            val first = server.takeDataRequest()
            val second = server.takeDataRequest()

            assertTrue(response.isSuccessful)
            assertEquals(2, server.dataRequestCount)
            assertEquals(3, server.controlRequestCount)
            assertFrameworkAuthorization(first)
            assertFrameworkAuthorization(second)
            assertNotEquals(first.headers["DPoP"], second.headers["DPoP"])
            assertNotEquals(first.headers["Authorization"], second.headers["Authorization"])
        } finally {
            close(http, harness, server)
        }
    }

    @Test
    fun retrofitProviderCredentialHeadersFailBeforeDispatchAndRemainRedacted() {
        val server = LoopbackHttpServer()
        server.start()
        val harness = FrameworkConformanceHarness(server)
        val http = harness.okHttpBuilder().build()
        val secret = "upstream-provider-secret-that-must-never-leave-the-app"

        try {
            val error = assertThrows(LatchwayException::class.java) {
                retrofit(server, http).forbiddenCredential(
                    apiKey = secret,
                    body = "{}".toRequestBody(JSON),
                ).execute()
            }

            assertEquals(LatchwayErrorCode.REQUEST_INVALID, error.code)
            assertFalse(error.toString().contains(secret))
            assertFalse(error.message.orEmpty().contains(secret))
            assertEquals(0, server.dataRequestCount)
            assertEquals(0, server.controlRequestCount)
        } finally {
            close(http, harness, server)
        }
    }

    @Test
    fun retrofitPreservesLatchwayProblemForCallerOwnedErrorMappingWithoutRetries() {
        val server = LoopbackHttpServer()
        server.enqueue(
            LoopbackResponse().setLatchwayProblem(
                code = "quota_exceeded",
                status = 429,
                retryable = false,
            ),
        )
        server.start()
        val harness = FrameworkConformanceHarness(server)
        val http = harness.okHttpBuilder().build()

        try {
            val response = retrofit(server, http).response(
                authorization = "Bearer $PROVIDER_PLACEHOLDER",
                body = "{}".toRequestBody(JSON),
            ).execute()
            val recorded = server.takeDataRequest()
            val problem = JSONObject(checkNotNull(response.errorBody()).string())

            assertEquals(429, response.code())
            assertEquals(1, server.dataRequestCount)
            assertEquals(2, server.controlRequestCount)
            assertFrameworkAuthorization(recorded)
            assertEquals("quota_exceeded", problem.getString("code"))
            assertEquals(recorded.headers["X-Latchway-Request-ID"], problem.getString("request_id"))
            assertFalse(problem.toString().contains(PROVIDER_PLACEHOLDER))
            assertFalse(problem.toString().contains(FRAMEWORK_ACCESS_TOKEN))
            assertFalse(problem.toString().contains(checkNotNull(recorded.headers["DPoP"])))
        } finally {
            close(http, harness, server)
        }
    }

    private fun retrofit(server: LoopbackHttpServer, client: OkHttpClient): RetrofitService =
        Retrofit.Builder()
            .baseUrl(server.url("/"))
            .client(client)
            .build()
            .create(RetrofitService::class.java)

    private fun close(
        client: OkHttpClient,
        harness: FrameworkConformanceHarness,
        server: LoopbackHttpServer,
    ) {
        client.dispatcher.cancelAll()
        client.connectionPool.evictAll()
        client.dispatcher.executorService.shutdown()
        harness.close()
        server.shutdown()
    }

    private interface RetrofitService {
        @POST("v1/responses")
        fun response(
            @Header("Authorization") authorization: String,
            @Body body: RequestBody,
        ): Call<ResponseBody>

        @Streaming
        @POST("v1/responses")
        fun stream(
            @Header("Authorization") authorization: String,
            @Body body: RequestBody,
        ): Call<ResponseBody>

        @POST("v1/responses")
        fun forbiddenCredential(
            @Header("X-Api-Key") apiKey: String,
            @Body body: RequestBody,
        ): Call<ResponseBody>
    }

    private class OneShotBody(private val value: String) : RequestBody() {
        override fun contentType() = JSON
        override fun contentLength(): Long = value.toByteArray().size.toLong()
        override fun isOneShot(): Boolean = true
        override fun writeTo(sink: BufferedSink) {
            sink.writeUtf8(value)
        }
    }

    private companion object {
        val JSON = "application/json; charset=utf-8".toMediaType()
    }
}
