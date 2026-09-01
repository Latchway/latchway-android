package dev.latchway.okhttp

import dev.langchain4j.exception.RateLimitException
import dev.langchain4j.http.client.okhttp.OkHttpClient as LangChainOkHttpClient
import dev.langchain4j.model.chat.response.ChatResponse
import dev.langchain4j.model.chat.response.StreamingChatResponseHandler
import dev.langchain4j.model.openai.OpenAiChatModel
import dev.langchain4j.model.openai.OpenAiStreamingChatModel
import okhttp3.ConnectionPool
import okhttp3.Dispatcher
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

class LangChain4jFrameworkConformanceTest {
    @Test
    fun langChain4jUsesItsOkHttpSpiWithTheLatchwayHooks() {
        val server = LoopbackHttpServer()
        server.enqueue(
            LoopbackResponse()
                .setResponseCode(200)
                .addHeader("Content-Type", "application/json")
                .setBody(CHAT_COMPLETION),
        )
        server.start()
        val harness = FrameworkConformanceHarness(server)
        val resources = ClientResources()
        val model = OpenAiChatModel.builder()
            .baseUrl(server.url("/v1").toString())
            .apiKey(PROVIDER_PLACEHOLDER)
            .modelName("framework-fixture")
            .maxRetries(0)
            .httpClientBuilder(resources.langChainBuilder(harness))
            .build()

        try {
            val answer = model.chat("Say fixture")
            val recorded = server.takeDataRequest()

            assertEquals("fixture accepted", answer)
            assertEquals(2, server.controlRequestCount)
            assertEquals("POST /v1/chat/completions HTTP/1.1", recorded.requestLine)
            assertFrameworkAuthorization(recorded)
            assertTrue(recorded.body.readUtf8().contains("framework-fixture"))
        } finally {
            resources.close()
            harness.close()
            server.shutdown()
        }
    }

    @Test
    fun langChain4jStreamingRemainsIncrementalThroughItsOkHttpSpi() {
        val server = LoopbackHttpServer()
        server.enqueue(
            LoopbackResponse()
                .setResponseCode(200)
                .addHeader("Content-Type", "text/event-stream")
                .setChunkedBody(
                    chunks = listOf(CHAT_STREAM_FIRST, CHAT_STREAM_SECOND_AND_DONE),
                    delay = 1_500,
                    unit = TimeUnit.MILLISECONDS,
                ),
        )
        server.start()
        val harness = FrameworkConformanceHarness(server)
        val resources = ClientResources()
        val model = OpenAiStreamingChatModel.builder()
            .baseUrl(server.url("/v1").toString())
            .apiKey(PROVIDER_PLACEHOLDER)
            .modelName("framework-fixture")
            .httpClientBuilder(resources.langChainBuilder(harness))
            .build()

        try {
            val first = CountDownLatch(1)
            val complete = CountDownLatch(1)
            val partial = StringBuilder()
            val error = AtomicReference<Throwable>()
            val response = AtomicReference<ChatResponse>()
            val started = System.nanoTime()
            model.chat("Say fixture", object : StreamingChatResponseHandler {
                override fun onPartialResponse(value: String) {
                    partial.append(value)
                    first.countDown()
                }

                override fun onCompleteResponse(value: ChatResponse) {
                    response.set(value)
                    complete.countDown()
                }

                override fun onError(cause: Throwable) {
                    error.set(cause)
                    complete.countDown()
                }
            })

            assertTrue("first streaming callback did not arrive", first.await(1, TimeUnit.SECONDS))
            val firstElapsed = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started)
            assertTrue("first callback must precede the delayed terminal frame", firstElapsed < 1_200)
            assertTrue("stream did not complete", complete.await(4, TimeUnit.SECONDS))
            assertEquals(null, error.get())
            assertEquals("firstsecond", partial.toString())
            assertNotNull(response.get())
            assertEquals(2, server.controlRequestCount)
            assertFrameworkAuthorization(server.takeDataRequest())
        } finally {
            resources.close()
            harness.close()
            server.shutdown()
        }
    }

    @Test
    fun langChain4jErrorMappingIsBoundedAndRetriesStayDisabled() {
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
                     "request_id":"req_langchain_quota","retryable":false}
                    """.trimIndent(),
                ),
        )
        server.start()
        val harness = FrameworkConformanceHarness(server)
        val resources = ClientResources()
        val model = OpenAiChatModel.builder()
            .baseUrl(server.url("/v1").toString())
            .apiKey(PROVIDER_PLACEHOLDER)
            .modelName("framework-fixture")
            .maxRetries(0)
            .httpClientBuilder(resources.langChainBuilder(harness))
            .build()

        try {
            val error = assertThrows(RateLimitException::class.java) {
                model.chat("Say fixture")
            }
            val recorded = server.takeDataRequest()

            assertEquals(1, server.dataRequestCount)
            assertEquals(2, server.controlRequestCount)
            assertFrameworkAuthorization(recorded)
            assertFalse(error.toString().contains(PROVIDER_PLACEHOLDER))
            assertFalse(error.message.orEmpty().contains(PROVIDER_PLACEHOLDER))
            assertFalse(error.toString().contains(FRAMEWORK_ACCESS_TOKEN))
            assertFalse(error.toString().contains(checkNotNull(recorded.headers["DPoP"])))
        } finally {
            resources.close()
            harness.close()
            server.shutdown()
        }
    }

    private class ClientResources {
        private val dispatcher = Dispatcher()
        private val connectionPool = ConnectionPool()

        fun langChainBuilder(harness: FrameworkConformanceHarness) =
            LangChainOkHttpClient.builder()
                .okHttpClientBuilder(
                    harness.okHttpBuilder()
                        .dispatcher(dispatcher)
                        .connectionPool(connectionPool),
                )

        fun close() {
            dispatcher.cancelAll()
            connectionPool.evictAll()
            dispatcher.executorService.shutdown()
        }
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

        val CHAT_STREAM_SECOND_AND_DONE = """
            data: {"id":"chatcmpl_stream","object":"chat.completion.chunk","created":1700000000,"model":"framework-fixture","choices":[{"index":0,"delta":{"content":"second"},"finish_reason":"stop"}]}

            data: [DONE]

        """.trimIndent() + "\n"
    }
}
