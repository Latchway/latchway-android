package dev.latchway.core

import java.net.URI
import java.nio.charset.StandardCharsets

public class LatchwayTransportRequest(
    public val method: String,
    public val uri: URI,
    public val headers: Map<String, String>,
    public val body: ByteArray?,
) {
    init {
        require(Regex("^[A-Z]{3,16}$").matches(method))
        require(uri.isAbsolute)
        require(body == null || body.size <= MAX_REQUEST_BYTES)
    }

    override fun toString(): String =
        "LatchwayTransportRequest(method=$method, uri=$uri, headers=[REDACTED], bodyBytes=${body?.size ?: 0})"

    private companion object {
        const val MAX_REQUEST_BYTES = 512 * 1024
    }
}

public class LatchwayTransportResponse(
    public val statusCode: Int,
    public val headers: Map<String, List<String>>,
    public val body: ByteArray,
) {
    init {
        require(statusCode in 100..599)
        require(body.size <= MAX_RESPONSE_BYTES) { "Latchway control response exceeds the safe limit" }
    }

    public fun header(name: String): String? = headers.entries
        .firstOrNull { it.key.equals(name, ignoreCase = true) }
        ?.value
        ?.firstOrNull()

    internal fun utf8Body(): String = String(body, StandardCharsets.UTF_8)

    override fun toString(): String =
        "LatchwayTransportResponse(statusCode=$statusCode, headers=${headers.keys}, body=[REDACTED])"

    private companion object {
        const val MAX_RESPONSE_BYTES = 512 * 1024
    }
}

public fun interface LatchwayTransport {
    public suspend fun execute(request: LatchwayTransportRequest): LatchwayTransportResponse
}
