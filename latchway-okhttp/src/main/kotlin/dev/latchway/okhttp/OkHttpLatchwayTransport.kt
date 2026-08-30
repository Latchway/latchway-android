package dev.latchway.okhttp

import dev.latchway.core.LatchwayErrorCode
import dev.latchway.core.LatchwayException
import dev.latchway.core.LatchwayTransport
import dev.latchway.core.LatchwayTransportRequest
import dev.latchway.core.LatchwayTransportResponse
import kotlinx.coroutines.suspendCancellableCoroutine
import okhttp3.Call
import okhttp3.Callback
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import java.io.ByteArrayOutputStream
import java.io.IOException
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

public class OkHttpLatchwayTransport(
    private val client: OkHttpClient,
) : LatchwayTransport {
    override suspend fun execute(request: LatchwayTransportRequest): LatchwayTransportResponse {
        val builder = Request.Builder().url(request.uri.toURL())
        for ((name, value) in request.headers) builder.header(name, value)
        val body = request.body?.toRequestBody(JSON)
        builder.method(request.method, body)
        return try {
            client.newCall(builder.build()).awaitBoundedResponse()
        } catch (error: LatchwayException) {
            throw error
        } catch (error: IOException) {
            throw LatchwayException(
                code = LatchwayErrorCode.NETWORK_UNAVAILABLE,
                retryable = true,
                safeMessage = "The Latchway control endpoint could not be reached",
                cause = error,
            )
        }
    }

    /**
     * Keep the cancellable continuation attached until the response body has
     * been drained. Cancelling the coroutine therefore closes a stalled call
     * even after response headers have arrived.
     */
    private suspend fun Call.awaitBoundedResponse(): LatchwayTransportResponse =
        suspendCancellableCoroutine { continuation ->
            continuation.invokeOnCancellation { cancel() }
            enqueue(object : Callback {
                override fun onFailure(call: Call, e: IOException) {
                    if (continuation.isActive) continuation.resumeWithException(e)
                }

                @Suppress("UNNECESSARY_SAFE_CALL") // Response.body is nullable in supported OkHttp 4.x.
                override fun onResponse(call: Call, response: Response) {
                    try {
                        val result = response.use {
                            LatchwayTransportResponse(
                                statusCode = it.code,
                                headers = it.headers.toMultimap(),
                                body = it.body?.byteStream()?.use(::readBounded) ?: ByteArray(0),
                            )
                        }
                        if (continuation.isActive) continuation.resume(result)
                    } catch (error: Exception) {
                        if (continuation.isActive) continuation.resumeWithException(error)
                    }
                }
            })
        }

    private companion object {
        const val MAX_RESPONSE_BYTES = 512 * 1024
        val JSON = "application/json; charset=utf-8".toMediaType()

        fun readBounded(input: java.io.InputStream): ByteArray {
            val output = ByteArrayOutputStream()
            val buffer = ByteArray(8 * 1024)
            var total = 0
            while (true) {
                val read = input.read(buffer)
                if (read == -1) break
                total += read
                if (total > MAX_RESPONSE_BYTES) {
                    throw LatchwayException(
                        code = LatchwayErrorCode.RESPONSE_INVALID,
                        safeMessage = "Latchway control response exceeded the safe limit",
                    )
                }
                output.write(buffer, 0, read)
            }
            return output.toByteArray()
        }
    }
}
