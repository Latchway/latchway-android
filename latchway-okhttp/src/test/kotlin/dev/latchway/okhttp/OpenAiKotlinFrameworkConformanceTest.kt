package dev.latchway.okhttp

import com.aallam.openai.api.chat.ChatCompletionRequest
import com.aallam.openai.api.chat.StreamOptions
import com.aallam.openai.api.chat.chatCompletionRequest
import com.aallam.openai.api.exception.RateLimitException
import com.aallam.openai.api.model.ModelId
import com.aallam.openai.client.OpenAI
import com.aallam.openai.client.OpenAIConfig
import com.aallam.openai.client.OpenAIHost
import com.aallam.openai.client.RetryStrategy
import io.ktor.client.engine.okhttp.OkHttp
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.runBlocking
import okhttp3.EventListener
import okhttp3.OkHttpClient
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

class OpenAiKotlinFrameworkConformanceTest {
    @Test
    fun aallamOpenAiKotlinUsesThePreconfiguredLatchwayOkHttpEngine() = runBlocking {
        val server = LoopbackHttpServer()
        server.enqueue(
            LoopbackResponse()
                .setResponseCode(200)
                .addHeader("Content-Type", "application/json")
                .setBody(CHAT_COMPLETION),
        )
        server.start()
        val harness = FrameworkConformanceHarness(server)
        val http = harness.okHttpBuilder().build()
        val openAI = openAI(server, http)

        try {
            val completion = openAI.chatCompletion(request())
            val recorded = server.takeDataRequest()

            assertEquals("chatcmpl_latchway", completion.id)
            assertEquals(2, server.controlRequestCount)
            assertTrue(completion.choices.isNotEmpty())
            assertEquals("POST /v1/chat/completions HTTP/1.1", recorded.requestLine)
            assertFrameworkAuthorization(recorded)
            assertTrue(recorded.body.readUtf8().contains("framework-fixture"))
        } finally {
            close(openAI, http, harness, server)
        }
    }

    @Test
    fun aallamStreamingDeliversIncrementallyAndCoroutineCancellationCancelsOkHttp() = runBlocking {
        val server = LoopbackHttpServer()
        server.enqueue(
            LoopbackResponse()
                .setResponseCode(200)
                .addHeader("Content-Type", "text/event-stream")
                .setChunkedBody(
                    chunks = listOf(CHAT_STREAM_FIRST, "data: [DONE]\n\n"),
                    delay = 3,
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
        val openAI = openAI(server, http)

        try {
            val first = CompletableDeferred<String>()
            val started = System.nanoTime()
            val collecting = async(Dispatchers.IO) {
                openAI.chatCompletions(request()).collect { chunk ->
                    first.complete(chunk.id)
                }
            }
            assertEquals("chatcmpl_stream", first.await())
            val elapsedMillis = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started)
            assertTrue("first SSE frame must precede the delayed terminal frame", elapsedMillis < 2_000)

            collecting.cancelAndJoin()
            assertTrue("cancelling the Flow must cancel the Ktor/OkHttp call", canceled.await(2, TimeUnit.SECONDS))
            assertEquals(2, server.controlRequestCount)
            assertFrameworkAuthorization(server.takeDataRequest())
        } finally {
            close(openAI, http, harness, server)
        }
    }

    @Test
    fun fwReq109AallamStreamReturnsTerminalUsageThroughConfiguredLatchwayOkHttpEngine() = runBlocking {
        val server = LoopbackHttpServer()
        server.enqueue(
            LoopbackResponse()
                .setResponseCode(200)
                .addHeader("Content-Type", "text/event-stream")
                .setBody(CHAT_STREAM_WITH_USAGE),
        )
        server.start()
        val harness = FrameworkConformanceHarness(server)
        val http = harness.okHttpBuilder().build()
        val openAI = openAI(server, http)

        try {
            val chunks = openAI.chatCompletions(request(includeUsage = true)).toList()
            val recorded = server.takeDataRequest()
            val usage = checkNotNull(chunks.last().usage)

            assertEquals("chatcmpl_stream", chunks.first().id)
            assertEquals(7, usage.promptTokens)
            assertEquals(2, usage.completionTokens)
            assertEquals(9, usage.totalTokens)
            assertFrameworkAuthorization(recorded)
            assertTrue(recorded.body.readUtf8().contains("\"include_usage\":true"))
        } finally {
            close(openAI, http, harness, server)
        }
    }

    @Test
    fun aallamQuotaFailureMapsToItsSafeApiExceptionWithoutFrameworkRetries() {
        val server = LoopbackHttpServer()
        server.enqueue(
            LoopbackResponse()
                .setResponseCode(429)
                .addHeader("Content-Type", "application/problem+json")
                .setBody(
                    """
                    {"type":"https://docs.latchway.dev/errors/quota-exceeded",
                     "documentation_url":"https://docs.latchway.dev/errors/quota-exceeded",
                     "title":"Quota exceeded","status":429,
                     "detail":"The feature quota is exhausted","code":"quota_exceeded",
                     "request_id":"req_framework_quota","retryable":false}
                    """.trimIndent(),
                ),
        )
        server.start()
        val harness = FrameworkConformanceHarness(server)
        val http = harness.okHttpBuilder().build()
        val openAI = openAI(server, http)

        try {
            val error = assertThrows(RateLimitException::class.java) {
                runBlocking { openAI.chatCompletion(request()) }
            }
            val recorded = server.takeDataRequest()

            assertEquals(1, server.dataRequestCount)
            assertEquals(2, server.controlRequestCount)
            assertFrameworkAuthorization(recorded)
            assertFalse(error.toString().contains(PROVIDER_PLACEHOLDER))
            assertFalse(error.message.orEmpty().contains(PROVIDER_PLACEHOLDER))
            assertFalse(error.toString().contains(FRAMEWORK_ACCESS_TOKEN))
            assertFalse(error.toString().contains(checkNotNull(recorded.headers["DPoP"])))
            assertEquals(429, error.statusCode)
        } finally {
            close(openAI, http, harness, server)
        }
    }

    private fun openAI(server: LoopbackHttpServer, http: OkHttpClient): OpenAI {
        val engine = OkHttp.create { preconfigured = http }
        return OpenAI(
            OpenAIConfig(
                token = PROVIDER_PLACEHOLDER,
                host = OpenAIHost(baseUrl = server.url("/v1/").toString()),
                retry = RetryStrategy(maxRetries = 0),
                engine = engine,
            ),
        )
    }

    private fun request(includeUsage: Boolean = false): ChatCompletionRequest = chatCompletionRequest {
        model = ModelId("framework-fixture")
        messages {
            user { content = "Say fixture" }
        }
        if (includeUsage) {
            streamOptions = StreamOptions(includeUsage = true)
        }
    }

    private fun close(
        openAI: OpenAI,
        http: OkHttpClient,
        harness: FrameworkConformanceHarness,
        server: LoopbackHttpServer,
    ) {
        openAI.close()
        http.dispatcher.cancelAll()
        http.connectionPool.evictAll()
        http.dispatcher.executorService.shutdown()
        harness.close()
        server.shutdown()
    }

    private companion object {
        val CHAT_COMPLETION = """
            {
              "id":"chatcmpl_latchway",
              "object":"chat.completion",
              "created":1700000000,
              "model":"framework-fixture",
              "choices":[{
                "index":0,
                "message":{"role":"assistant","content":"fixture accepted"},
                "finish_reason":"stop"
              }],
              "usage":{"prompt_tokens":3,"completion_tokens":2,"total_tokens":5}
            }
        """.trimIndent()

        val CHAT_STREAM_FIRST = """
            data: {"id":"chatcmpl_stream","object":"chat.completion.chunk","created":1700000000,"model":"framework-fixture","choices":[{"index":0,"delta":{"role":"assistant","content":"first"},"finish_reason":null}]}

        """.trimIndent() + "\n"

        val CHAT_STREAM_WITH_USAGE = """
            data: {"id":"chatcmpl_stream","object":"chat.completion.chunk","created":1700000000,"model":"framework-fixture","choices":[{"index":0,"delta":{"role":"assistant","content":"first"},"finish_reason":null}]}

            data: {"id":"chatcmpl_stream","object":"chat.completion.chunk","created":1700000000,"model":"framework-fixture","choices":[],"usage":{"prompt_tokens":7,"completion_tokens":2,"total_tokens":9}}

            data: [DONE]

        """.trimIndent() + "\n"
    }
}
