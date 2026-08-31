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
import okhttp3.Call
import okhttp3.Cookie
import okhttp3.CookieJar
import okhttp3.EventListener
import okhttp3.HttpUrl
import okhttp3.OkHttpClient
import okhttp3.Response
import okhttp3.Request
import okhttp3.HttpUrl.Companion.toHttpUrl
import okio.Buffer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.EOFException
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketException
import java.nio.charset.StandardCharsets
import java.util.Collections
import java.util.concurrent.Executors
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

class OkHttpLatchwayTransportTest {
    @Test
    fun originGuardBlocksLatchwayHeadersBeforeACrossOriginRedirectIsDispatched() {
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

            assertEquals(LatchwayErrorCode.TRANSPORT_DESTINATION_NOT_ALLOWED, error.code)
            assertEquals(0, redirectTarget.requestCount)
        } finally {
            client.dispatcher.cancelAll()
            client.connectionPool.evictAll()
            client.dispatcher.executorService.shutdown()
            gateway.shutdown()
            redirectTarget.shutdown()
        }
    }

    @Test
    fun originGuardRejectsCookieJarCredentialsBeforeGatewayDispatch() {
        val gateway = LoopbackHttpServer()
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
            gateway.shutdown()
        }
    }

    @Test
    fun originGuardRejectsProxyCredentialAddedByALaterInterceptorBeforeDispatch() {
        val gateway = LoopbackHttpServer()
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
            gateway.shutdown()
        }
    }

    @Test
    fun originGuardRejectsCredentialQueryBeforeGatewayDispatch() {
        val gateway = LoopbackHttpServer()
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
            gateway.shutdown()
        }
    }

    @Test
    fun forwardsEveryControlHeaderAndBody() = runBlocking {
        val server = LoopbackHttpServer()
        val client = OkHttpClient()
        server.enqueue(
            LoopbackResponse()
                .setResponseCode(201)
                .addHeader("X-Latchway-Request-ID", "req_12345678")
                .setBody("accepted"),
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
            assertEquals("request", recorded.body.readUtf8())
            assertEquals(201, response.statusCode)
            assertEquals("accepted", String(response.body, StandardCharsets.UTF_8))
        } finally {
            client.dispatcher.cancelAll()
            client.connectionPool.evictAll()
            client.dispatcher.executorService.shutdown()
            server.shutdown()
        }
    }

    @Test
    fun cancellationAfterHeadersClosesAStalledBodyDrain() = runBlocking {
        val server = LoopbackHttpServer()
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
            LoopbackResponse()
                .setResponseCode(200)
                .setBody("body that must not finish draining")
                // Stay beyond the cancellation assertion's timeout while still
                // allowing MockWebServer 4.x to retire its response task.
                .setBodyDelay(3, TimeUnit.SECONDS),
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
            server.shutdown()
        }
    }
}

/** A dependency-neutral HTTP/1.1 fixture so the same tests run on OkHttp 4.x and 5.x. */
internal class LoopbackHttpServer {
    private val socket = ServerSocket(0, 50, InetAddress.getByName("127.0.0.1"))
    private val responses = LinkedBlockingQueue<LoopbackResponse>()
    private val controlResponses = LinkedBlockingQueue<LoopbackResponse>()
    private val requests = LinkedBlockingQueue<LoopbackRecordedRequest>()
    private val dataRequests = LinkedBlockingQueue<LoopbackRecordedRequest>()
    private val responseWorkers = Executors.newCachedThreadPool { task ->
        Thread(task, "latchway-loopback-response").apply { isDaemon = true }
    }
    private val started = AtomicBoolean(false)
    private val closed = AtomicBoolean(false)
    private val count = AtomicInteger(0)
    private val dataCount = AtomicInteger(0)
    private val controlCount = AtomicInteger(0)
    private var acceptThread: Thread? = null

    val requestCount: Int get() = count.get()
    val dataRequestCount: Int get() = dataCount.get()
    val controlRequestCount: Int get() = controlCount.get()

    fun start() {
        check(started.compareAndSet(false, true)) { "Loopback server already started" }
        acceptThread = Thread(::acceptRequests, "latchway-loopback-accept").apply {
            isDaemon = true
            start()
        }
    }

    fun enqueue(response: LoopbackResponse) {
        responses.add(response)
    }

    fun enqueueControl(response: LoopbackResponse) {
        controlResponses.add(response)
    }

    fun url(path: String): HttpUrl {
        val normalized = if (path.startsWith('/')) path else "/$path"
        return "http://127.0.0.1:${socket.localPort}$normalized".toHttpUrl()
    }

    fun takeRequest(): LoopbackRecordedRequest =
        checkNotNull(requests.poll(5, TimeUnit.SECONDS)) { "No loopback request arrived" }

    fun takeDataRequest(): LoopbackRecordedRequest =
        checkNotNull(dataRequests.poll(5, TimeUnit.SECONDS)) { "No loopback data-plane request arrived" }

    fun shutdown() {
        if (!closed.compareAndSet(false, true)) return
        socket.close()
        responseWorkers.shutdownNow()
        acceptThread?.join(1_000)
        check(responseWorkers.awaitTermination(2, TimeUnit.SECONDS)) {
            "Loopback response workers did not stop"
        }
    }

    private fun acceptRequests() {
        while (!closed.get()) {
            try {
                val accepted = socket.accept()
                responseWorkers.execute {
                    try {
                        serve(accepted)
                    } catch (_: SocketException) {
                        // Streaming fixtures intentionally let clients close
                        // the socket before the delayed terminal chunk.
                    } catch (_: InterruptedException) {
                        Thread.currentThread().interrupt()
                    }
                }
            } catch (_: SocketException) {
                if (!closed.get()) throw IllegalStateException("Loopback accept failed")
            }
        }
    }

    private fun serve(client: Socket) {
        client.use { connected ->
            val input = BufferedInputStream(connected.getInputStream())
            val requestLine = input.readAsciiLine() ?: return
            val headers = linkedMapOf<String, String>()
            while (true) {
                val line = input.readAsciiLine() ?: throw EOFException("Headers ended unexpectedly")
                if (line.isEmpty()) break
                val separator = line.indexOf(':')
                check(separator > 0) { "Invalid HTTP header" }
                headers[line.substring(0, separator)] = line.substring(separator + 1).trim()
            }
            val contentLength = headers.entries
                .firstOrNull { it.key.equals("Content-Length", ignoreCase = true) }
                ?.value
                ?.toIntOrNull()
                ?: 0
            val body = ByteArray(contentLength)
            var offset = 0
            while (offset < body.size) {
                val read = input.read(body, offset, body.size - offset)
                if (read == -1) throw EOFException("Request body ended unexpectedly")
                offset += read
            }
            val recorded = LoopbackRecordedRequest(
                requestLine = requestLine,
                headers = CaseInsensitiveHeaders(headers),
                body = Buffer().write(body),
            )
            requests.put(recorded)
            count.incrementAndGet()

            val requestTarget = requestLine.substringAfter(' ').substringBefore(' ')
            val isControlRequest = requestTarget.startsWith("/client/")
            if (isControlRequest) {
                controlCount.incrementAndGet()
            } else {
                dataRequests.put(recorded)
                dataCount.incrementAndGet()
            }

            // Dedicated control responses let the framework fixtures share a
            // server with data traffic. Existing transport tests that enqueue
            // a generic `/client/...` response retain their original behavior.
            val responseQueue = if (isControlRequest && controlResponses.isNotEmpty()) {
                controlResponses
            } else {
                responses
            }
            val response = responseQueue.poll(5, TimeUnit.SECONDS)
                ?: LoopbackResponse().setResponseCode(500).setBody("No response enqueued")
            val output = BufferedOutputStream(connected.getOutputStream())
            val requestId = headers.entries
                .firstOrNull { it.key.equals("X-Latchway-Request-ID", ignoreCase = true) }
                ?.value
            val responseBody = response.renderBody(requestId)
            val responseHeaders = response.renderHeaders(requestId)
            val statusText = when (response.code) {
                200 -> "OK"
                201 -> "Created"
                302 -> "Found"
                else -> "Test response"
            }
            output.write("HTTP/1.1 ${response.code} $statusText\r\n".toByteArray(StandardCharsets.US_ASCII))
            for ((name, value) in responseHeaders) {
                output.write("$name: $value\r\n".toByteArray(StandardCharsets.US_ASCII))
            }
            if (response.chunks == null) {
                output.write("Content-Length: ${responseBody.size}\r\n".toByteArray(StandardCharsets.US_ASCII))
            } else {
                output.write("Transfer-Encoding: chunked\r\n".toByteArray(StandardCharsets.US_ASCII))
            }
            output.write("Connection: close\r\n\r\n".toByteArray(StandardCharsets.US_ASCII))
            output.flush()
            val chunks = response.chunks
            if (chunks == null) {
                if (response.bodyDelayMillis > 0) Thread.sleep(response.bodyDelayMillis)
                output.write(responseBody)
                output.flush()
            } else {
                chunks.forEachIndexed { index, chunk ->
                    output.write("${chunk.size.toString(16)}\r\n".toByteArray(StandardCharsets.US_ASCII))
                    output.write(chunk)
                    output.write("\r\n".toByteArray(StandardCharsets.US_ASCII))
                    output.flush()
                    if (index != chunks.lastIndex && response.chunkDelayMillis > 0) {
                        Thread.sleep(response.chunkDelayMillis)
                    }
                }
                output.write("0\r\n\r\n".toByteArray(StandardCharsets.US_ASCII))
                output.flush()
            }
        }
    }
}

internal class LoopbackResponse {
    var code: Int = 200
        private set
    val headers: MutableList<Pair<String, String>> = mutableListOf()
    var body: ByteArray = ByteArray(0)
        private set
    var bodyDelayMillis: Long = 0
        private set
    var chunks: List<ByteArray>? = null
        private set
    var chunkDelayMillis: Long = 0
        private set
    private var latchwayProblem: LatchwayProblem? = null

    fun setResponseCode(value: Int): LoopbackResponse = apply { code = value }

    fun addHeader(name: String, value: String): LoopbackResponse = apply {
        headers += name to value
    }

    fun setBody(value: String): LoopbackResponse = apply {
        body = value.toByteArray(StandardCharsets.UTF_8)
    }

    fun setBodyDelay(value: Long, unit: TimeUnit): LoopbackResponse = apply {
        bodyDelayMillis = unit.toMillis(value)
    }

    fun setChunkedBody(
        chunks: List<String>,
        delay: Long,
        unit: TimeUnit,
    ): LoopbackResponse = apply {
        require(chunks.isNotEmpty())
        this.chunks = chunks.map { it.toByteArray(StandardCharsets.UTF_8) }
        chunkDelayMillis = unit.toMillis(delay)
    }

    fun setLatchwayProblem(
        code: String,
        status: Int,
        retryable: Boolean,
    ): LoopbackResponse = apply {
        latchwayProblem = LatchwayProblem(code, status, retryable)
        this.code = status
    }

    internal fun renderBody(requestId: String?): ByteArray {
        val problem = latchwayProblem ?: return body
        val correlated = requireNotNull(requestId) { "A Latchway problem requires a request ID" }
        return org.json.JSONObject()
            .put("type", "https://latchway.dev/problems/${problem.code}")
            .put("title", "Request rejected")
            .put("status", problem.status)
            .put("detail", "The request was rejected before upstream dispatch")
            .put("code", problem.code)
            .put("request_id", correlated)
            .put("retryable", problem.retryable)
            .toString()
            .toByteArray(StandardCharsets.UTF_8)
    }

    internal fun renderHeaders(requestId: String?): List<Pair<String, String>> = buildList {
        addAll(headers)
        if (latchwayProblem != null) {
            add("Content-Type" to "application/problem+json")
            add("X-Latchway-Request-ID" to requireNotNull(requestId))
        }
    }

    private data class LatchwayProblem(
        val code: String,
        val status: Int,
        val retryable: Boolean,
    )
}

internal data class LoopbackRecordedRequest(
    val requestLine: String,
    val headers: CaseInsensitiveHeaders,
    val body: Buffer,
)

internal class CaseInsensitiveHeaders(values: Map<String, String>) {
    private val values = Collections.unmodifiableMap(values.toMap())

    operator fun get(name: String): String? =
        values.entries.firstOrNull { it.key.equals(name, ignoreCase = true) }?.value
}

private fun BufferedInputStream.readAsciiLine(): String? {
    val output = Buffer()
    while (true) {
        when (val next = read()) {
            -1 -> return if (output.size == 0L) null else output.readUtf8()
            '\n'.code -> return output.readUtf8().removeSuffix("\r")
            else -> output.writeByte(next)
        }
    }
}
