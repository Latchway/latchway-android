package dev.latchway.okhttp

import ai.koog.agents.core.tools.ToolDescriptor
import ai.koog.http.client.KoogHttpClient
import ai.koog.http.client.okhttp.fromOkHttpClient
import ai.koog.prompt.dsl.prompt
import ai.koog.prompt.executor.clients.LLMClientException
import ai.koog.prompt.executor.clients.openai.OpenAIChatParams
import ai.koog.prompt.executor.clients.openai.OpenAIClientSettings
import ai.koog.prompt.executor.clients.openai.OpenAILLMClient
import ai.koog.prompt.executor.clients.openai.OpenAIModels
import ai.koog.prompt.executor.clients.retry.RetryConfig
import ai.koog.prompt.executor.clients.retry.RetryingLLMClient
import ai.koog.prompt.params.LLMParams
import ai.koog.prompt.streaming.StreamFrame
import io.github.oshai.kotlinlogging.KotlinLogging
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import okhttp3.EventListener
import okhttp3.OkHttp
import okhttp3.OkHttpClient
import org.json.JSONObject
import org.junit.Assume.assumeTrue
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.time.Duration.Companion.milliseconds

/** Exact Koog 1.1.1 compatibility spike through its public preconfigured-OkHttp seam. */
class KoogFrameworkConformanceTest {
    @Test
    fun koogPreservesChatToolsAndStructuredOutputThroughLatchwayOkHttp() = runBlocking {
        val server = LoopbackHttpServer()
        server.enqueue(
            LoopbackResponse()
                .setResponseCode(200)
                .addHeader("Content-Type", "application/json")
                .setBody(CHAT_COMPLETION),
        )
        server.start()
        val harness = FrameworkConformanceHarness(server)
        val fixture = koog(server, harness)
        val schema = buildJsonObject {
            put("type", "object")
            put("x-latchway-fixture", "structured-output")
        }
        val request = prompt(
            id = "koog-structured-fixture",
            params = OpenAIChatParams(
                schema = LLMParams.Schema.JSON.Basic("fixture_answer", schema),
            ),
        ) {
            user("Say fixture")
        }
        val tools = listOf(
            ToolDescriptor(
                name = "fixture_lookup",
                description = "Return deterministic fixture data",
            ),
        )

        try {
            val answer = fixture.client.execute(request, OpenAIModels.Chat.GPT4o, tools)
            val recorded = server.takeDataRequest()
            val body = JSONObject(recorded.body.readUtf8())

            assertEquals("fixture accepted", answer.textContent())
            assertEquals("POST /v1/chat/completions HTTP/1.1", recorded.requestLine)
            assertFrameworkAuthorization(recorded)
            assertEquals("fixture_lookup", body.getJSONArray("tools").getJSONObject(0)
                .getJSONObject("function").getString("name"))
            assertTrue(body.getJSONObject("response_format").toString().contains("structured-output"))
            assertFalse(body.toString().contains(PROVIDER_PLACEHOLDER))
        } finally {
            close(fixture, harness, server)
        }
    }

    @Test
    fun koogStreamingIsIncrementalAndPreservesFinalUsage() = runBlocking {
        requireKoogStreamingRuntime()
        val server = LoopbackHttpServer()
        server.enqueue(
            LoopbackResponse()
                .setResponseCode(200)
                .addHeader("Content-Type", "text/event-stream")
                .setChunkedBody(
                    chunks = listOf(CHAT_STREAM_FIRST, CHAT_STREAM_USAGE_AND_DONE),
                    delay = 750,
                    unit = TimeUnit.MILLISECONDS,
                ),
        )
        server.start()
        val harness = FrameworkConformanceHarness(server)
        val fixture = koog(server, harness)

        try {
            val first = CompletableDeferred<Long>()
            val started = System.nanoTime()
            val frames = mutableListOf<StreamFrame>()
            fixture.client.executeStreaming(prompt(), OpenAIModels.Chat.GPT4o, emptyList())
                .collect { frame ->
                    frames += frame
                    if (frame is StreamFrame.TextDelta) {
                        first.complete(TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started))
                    }
                }

            assertTrue("first SSE frame must precede the delayed terminal frame", first.await() < 600)
            assertEquals("first", frames.filterIsInstance<StreamFrame.TextDelta>().joinToString("") { it.text })
            val end = frames.filterIsInstance<StreamFrame.End>().single()
            assertEquals(5, end.metaInfo.totalTokensCount)
            assertFrameworkAuthorization(server.takeDataRequest())
        } finally {
            close(fixture, harness, server)
        }
    }

    @Test
    fun koogCoroutineCancellationCancelsTheUnderlyingOkHttpEventSource() = runBlocking {
        requireKoogStreamingRuntime()
        val server = LoopbackHttpServer()
        server.enqueue(
            LoopbackResponse()
                .setResponseCode(200)
                .addHeader("Content-Type", "text/event-stream")
                .setChunkedBody(
                    chunks = listOf(CHAT_STREAM_FIRST, CHAT_STREAM_USAGE_AND_DONE),
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
        val fixture = koog(server, harness, eventListener = listener)

        try {
            val first = CompletableDeferred<Unit>()
            val collecting = async(Dispatchers.IO) {
                fixture.client.executeStreaming(prompt(), OpenAIModels.Chat.GPT4o, emptyList())
                    .collect { frame ->
                        if (frame is StreamFrame.TextDelta) first.complete(Unit)
                    }
            }
            first.await()
            collecting.cancelAndJoin()

            assertTrue("cancelling Koog's Flow must cancel its OkHttp EventSource", canceled.await(2, TimeUnit.SECONDS))
            assertFrameworkAuthorization(server.takeDataRequest())
        } finally {
            close(fixture, harness, server)
        }
    }

    @Test
    fun koogTimeoutPropagatesWithoutLeakingCredentials() {
        val server = LoopbackHttpServer()
        server.enqueue(
            LoopbackResponse()
                .setResponseCode(200)
                .addHeader("Content-Type", "application/json")
                .setBody(CHAT_COMPLETION)
                .setBodyDelay(2, TimeUnit.SECONDS),
        )
        server.start()
        val harness = FrameworkConformanceHarness(server)
        val fixture = koog(server, harness, callTimeoutMillis = 250)

        try {
            val started = System.nanoTime()
            val error = assertThrows(LLMClientException::class.java) {
                runBlocking { fixture.client.execute(prompt(), OpenAIModels.Chat.GPT4o, emptyList()) }
            }
            val elapsed = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started)
            val recorded = server.takeDataRequest()

            assertTrue("Koog must preserve the configured OkHttp timeout", elapsed < 1_500)
            assertFrameworkAuthorization(recorded)
            assertSafeError(error, recorded)
        } finally {
            close(fixture, harness, server)
        }
    }

    @Test
    fun koogNativeRetryCreatesANewDpopProofForEveryFrameworkAttempt() = runBlocking {
        val server = LoopbackHttpServer()
        server.enqueue(
            LoopbackResponse()
                .setResponseCode(503)
                .addHeader("Content-Type", "text/plain")
                .setBody("service unavailable"),
        )
        server.enqueue(
            LoopbackResponse()
                .setResponseCode(200)
                .addHeader("Content-Type", "application/json")
                .setBody(CHAT_COMPLETION),
        )
        server.start()
        val harness = FrameworkConformanceHarness(server)
        val fixture = koog(server, harness)
        val retrying = RetryingLLMClient(
            fixture.client,
            RetryConfig(
                maxAttempts = 2,
                // Koog 1.1.1 calls Random.nextDouble even for zero jitter,
                // so retain its smallest valid non-empty jitter range.
                initialDelay = 1.milliseconds,
                maxDelay = 1.milliseconds,
                jitterFactor = 0.1,
            ),
        )

        try {
            val answer = retrying.execute(prompt(), OpenAIModels.Chat.GPT4o, emptyList())
            val first = server.takeDataRequest()
            val second = server.takeDataRequest()

            assertEquals("fixture accepted", answer.textContent())
            assertEquals(2, server.dataRequestCount)
            assertFrameworkAuthorization(first)
            assertFrameworkAuthorization(second)
            assertNotEquals(first.headers["DPoP"], second.headers["DPoP"])
            assertNotEquals(first.headers["X-Latchway-Request-ID"], second.headers["X-Latchway-Request-ID"])
        } finally {
            close(fixture, harness, server)
        }
    }

    @Test
    fun koogQuotaErrorPreservesTheLatchwayRequestIdAndNoCredentialMaterial() {
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
        val fixture = koog(server, harness)

        try {
            val error = assertThrows(LLMClientException::class.java) {
                runBlocking { fixture.client.execute(prompt(), OpenAIModels.Chat.GPT4o, emptyList()) }
            }
            val recorded = server.takeDataRequest()
            val requestId = checkNotNull(recorded.headers["X-Latchway-Request-ID"])

            assertEquals(1, server.dataRequestCount)
            assertFrameworkAuthorization(recorded)
            assertTrue(error.toString().contains(requestId))
            assertTrue(error.toString().contains("quota_exceeded"))
            assertSafeError(error, recorded)
        } finally {
            close(fixture, harness, server)
        }
    }

    private fun koog(
        server: LoopbackHttpServer,
        harness: FrameworkConformanceHarness,
        eventListener: EventListener? = null,
        callTimeoutMillis: Long? = null,
    ): KoogFixture {
        val builder = harness.okHttpBuilder(eventListener)
        if (callTimeoutMillis != null) builder.callTimeout(callTimeoutMillis, TimeUnit.MILLISECONDS)
        val http = builder.build()
        val koogHttp = KoogHttpClient.fromOkHttpClient(
            clientName = "LatchwayKoogConformance",
            logger = KotlinLogging.logger { },
            okHttpClient = http,
        )
        // Koog 1.1.1's preconfigured-OkHttp helper intentionally has no base-URL
        // argument. Its public primary OpenAI constructor supports the same client
        // when the provider path is absolute, so no framework-specific module is needed.
        val settings = OpenAIClientSettings(
            baseUrl = server.url("/").toString(),
            chatCompletionsPath = server.url("/v1/chat/completions").toString(),
        )
        return KoogFixture(OpenAILLMClient(settings = settings, httpClient = koogHttp), http)
    }

    private fun prompt() = prompt("koog-fixture") {
        user("Say fixture")
    }

    private fun requireKoogStreamingRuntime() {
        // Koog 1.1.1 calls the OkHttp 5 EventSources.createFactory(Call.Factory)
        // descriptor. Its non-streaming path works on 4.9.2, but the full
        // integration is supportable only on the tested OkHttp 5 endpoint.
        assumeTrue(
            "Koog 1.1.1 streaming requires OkHttp 5.x",
            OkHttp.VERSION.substringBefore('.').toInt() >= 5,
        )
    }

    private fun assertSafeError(error: Throwable, recorded: LoopbackRecordedRequest) {
        val rendered = error.toString()
        assertFalse(rendered.contains(PROVIDER_PLACEHOLDER))
        assertFalse(rendered.contains(FRAMEWORK_ACCESS_TOKEN))
        assertFalse(rendered.contains(checkNotNull(recorded.headers["DPoP"])))
        assertFalse(rendered.contains("i".repeat(32)))
        assertFalse(rendered.contains("r".repeat(32)))
    }

    private fun close(
        fixture: KoogFixture,
        harness: FrameworkConformanceHarness,
        server: LoopbackHttpServer,
    ) {
        fixture.client.close()
        fixture.http.dispatcher.cancelAll()
        fixture.http.connectionPool.evictAll()
        fixture.http.dispatcher.executorService.shutdown()
        harness.close()
        server.shutdown()
    }

    private data class KoogFixture(
        val client: OpenAILLMClient,
        val http: OkHttpClient,
    )

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

        val CHAT_STREAM_USAGE_AND_DONE = """
            data: {"id":"chatcmpl_stream","object":"chat.completion.chunk","created":1700000000,"model":"framework-fixture","choices":[],"usage":{"prompt_tokens":3,"completion_tokens":2,"total_tokens":5}}

            data: [DONE]

        """.trimIndent() + "\n"
    }
}
