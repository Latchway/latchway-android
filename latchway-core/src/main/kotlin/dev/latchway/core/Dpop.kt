package dev.latchway.core

import java.net.URI
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.Locale
import java.util.UUID

public class SecretValue private constructor(private val value: String) {
    public fun reveal(): String = value
    override fun toString(): String = "[REDACTED]"

    public companion object {
        public fun of(value: String): SecretValue {
            require(value.isNotEmpty()) { "secret value must not be empty" }
            return SecretValue(value)
        }
    }
}

public data class PublicJwk(
    val x: String,
    val y: String,
) {
    public val kty: String = "EC"
    public val crv: String = "P-256"

    init {
        require(
            BASE64_SHA256.matches(x) && BASE64_SHA256.matches(y) &&
                Base64Url.decode(x).size == 32 && Base64Url.decode(y).size == 32,
        ) {
            "P-256 coordinates must be 32-byte base64url values"
        }
    }

    public fun thumbprint(): String {
        val canonical = "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":${jsonString(x)},\"y\":${jsonString(y)}}"
        return Base64Url.encode(sha256(canonical.toByteArray(StandardCharsets.UTF_8)))
    }

    internal fun headerJson(): String =
        "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":${jsonString(x)},\"y\":${jsonString(y)}}"

    private companion object {
        val BASE64_SHA256 = Regex("^[A-Za-z0-9_-]{43}$")
    }
}

public interface InstallationSigner {
    public val publicJwk: PublicJwk
    public val diagnostics: KeyDiagnostics

    /** Returns the 64-byte JOSE ECDSA signature (R || S), never DER. */
    public suspend fun sign(signingInput: ByteArray): ByteArray
}

public data class DpopProofRequest(
    val method: String,
    val uri: URI,
    val accessToken: SecretValue? = null,
    val nonce: String? = null,
) {
    init {
        require(METHOD.matches(method)) { "DPoP HTTP method is invalid" }
        require(uri.isAbsolute && (uri.scheme == "https" || uri.scheme == "http")) {
            "DPoP URI must be absolute HTTP(S)"
        }
        require(uri.userInfo == null) { "DPoP URI must not contain user information" }
        require(nonce == null || nonce.length in 16..512 && nonce.none { it.isISOControl() }) {
            "DPoP nonce is invalid"
        }
    }

    private companion object {
        val METHOD = Regex("^[A-Z]{3,16}$")
    }
}

public class DpopProofFactory(
    private val signer: InstallationSigner,
    private val clock: LatchwayClock = SystemLatchwayClock,
    private val jtiFactory: () -> String = { UUID.randomUUID().toString() },
) {
    public suspend fun create(request: DpopProofRequest): SecretValue {
        val header = "{\"typ\":\"dpop+jwt\",\"alg\":\"ES256\",\"jwk\":${signer.publicJwk.headerJson()}}"
        val claims = ArrayList<String>(6)
        claims += "\"htm\":${jsonString(request.method)}"
        claims += "\"htu\":${jsonString(canonicalHtu(request.uri))}"
        claims += "\"iat\":${clock.epochSeconds()}"
        claims += "\"jti\":${jsonString(jtiFactory())}"
        request.accessToken?.let {
            val ath = Base64Url.encode(sha256(it.reveal().toByteArray(StandardCharsets.US_ASCII)))
            claims += "\"ath\":${jsonString(ath)}"
        }
        request.nonce?.let { claims += "\"nonce\":${jsonString(it)}" }
        val payload = claims.joinToString(prefix = "{", postfix = "}", separator = ",")

        val encodedHeader = Base64Url.encode(header.toByteArray(StandardCharsets.UTF_8))
        val encodedPayload = Base64Url.encode(payload.toByteArray(StandardCharsets.UTF_8))
        val signingInput = "$encodedHeader.$encodedPayload"
        val signature = signer.sign(signingInput.toByteArray(StandardCharsets.US_ASCII))
        if (signature.size != 64) {
            throw LatchwayException(
                code = LatchwayErrorCode.KEY_UNAVAILABLE,
                safeMessage = "Installation signer returned an invalid ES256 signature",
            )
        }
        return SecretValue.of("$signingInput.${Base64Url.encode(signature)}")
    }
}

public object Base64Url {
    private const val ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

    public fun encode(input: ByteArray): String {
        if (input.isEmpty()) return ""
        val output = StringBuilder((input.size * 4 + 2) / 3)
        var index = 0
        while (index + 3 <= input.size) {
            val value = ((input[index].toInt() and 0xff) shl 16) or
                ((input[index + 1].toInt() and 0xff) shl 8) or
                (input[index + 2].toInt() and 0xff)
            output.append(ALPHABET[value ushr 18 and 63])
            output.append(ALPHABET[value ushr 12 and 63])
            output.append(ALPHABET[value ushr 6 and 63])
            output.append(ALPHABET[value and 63])
            index += 3
        }
        val remaining = input.size - index
        if (remaining == 1) {
            val value = input[index].toInt() and 0xff
            output.append(ALPHABET[value ushr 2])
            output.append(ALPHABET[value shl 4 and 63])
        } else if (remaining == 2) {
            val value = ((input[index].toInt() and 0xff) shl 8) or (input[index + 1].toInt() and 0xff)
            output.append(ALPHABET[value ushr 10 and 63])
            output.append(ALPHABET[value ushr 4 and 63])
            output.append(ALPHABET[value shl 2 and 63])
        }
        return output.toString()
    }

    public fun decode(input: String): ByteArray {
        require(input.none { it == '=' || it.isWhitespace() }) { "base64url must be unpadded" }
        require(input.length % 4 != 1) { "invalid base64url length" }
        val output = ByteArray(input.length * 6 / 8)
        var accumulator = 0
        var bits = 0
        var outputIndex = 0
        for (character in input) {
            val value = ALPHABET.indexOf(character)
            require(value >= 0) { "invalid base64url character" }
            accumulator = accumulator shl 6 or value
            bits += 6
            if (bits >= 8) {
                bits -= 8
                output[outputIndex++] = (accumulator ushr bits and 0xff).toByte()
            }
        }
        require(bits == 0 || accumulator and ((1 shl bits) - 1) == 0) { "non-canonical base64url" }
        return output
    }
}

internal fun canonicalHtu(uri: URI): String {
    val scheme = uri.scheme.lowercase(Locale.US)
    val host = uri.host?.lowercase(Locale.US)
        ?: throw IllegalArgumentException("DPoP URI must have a host")
    val authorityHost = if (':' in host && !host.startsWith('[')) "[$host]" else host
    val port = when {
        uri.port == -1 -> ""
        scheme == "https" && uri.port == 443 -> ""
        scheme == "http" && uri.port == 80 -> ""
        else -> ":${uri.port}"
    }
    val path = uri.rawPath.takeUnless { it.isNullOrEmpty() } ?: "/"
    return "$scheme://$authorityHost$port$path"
}

internal fun sha256(input: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(input)

internal fun jsonString(value: String): String = buildString(value.length + 2) {
    append('"')
    value.forEach { character ->
        when (character) {
            '"' -> append("\\\"")
            '\\' -> append("\\\\")
            '\b' -> append("\\b")
            '\u000c' -> append("\\f")
            '\n' -> append("\\n")
            '\r' -> append("\\r")
            '\t' -> append("\\t")
            else -> if (character.code < 0x20) {
                append("\\u")
                append(character.code.toString(16).padStart(4, '0'))
            } else {
                append(character)
            }
        }
    }
    append('"')
}

internal object EcdsaSignatureCodec {
    fun derToJose(der: ByteArray): ByteArray {
        var index = 0
        fun readByte(): Int {
            if (index >= der.size) throw IllegalArgumentException("truncated DER signature")
            return der[index++].toInt() and 0xff
        }
        fun readLength(): Int {
            val first = readByte()
            if (first and 0x80 == 0) return first
            val count = first and 0x7f
            require(count in 1..2) { "unsupported DER length" }
            var length = 0
            repeat(count) { length = length shl 8 or readByte() }
            require(length >= 128) { "non-canonical DER length" }
            return length
        }
        require(readByte() == 0x30) { "ES256 signature is not a DER sequence" }
        val sequenceLength = readLength()
        require(sequenceLength == der.size - index) { "invalid DER sequence length" }

        fun readInteger(): ByteArray {
            require(readByte() == 0x02) { "ES256 signature member is not an integer" }
            val length = readLength()
            require(length in 1..33 && index + length <= der.size) { "invalid DER integer length" }
            val value = der.copyOfRange(index, index + length)
            index += length
            require(value[0].toInt() and 0x80 == 0) { "negative DER integer" }
            require(value.size == 1 || value[0].toInt() != 0 || value[1].toInt() and 0x80 != 0) {
                "non-canonical DER integer"
            }
            return if (value.size == 33) {
                require(value[0].toInt() == 0) { "oversized DER integer" }
                value.copyOfRange(1, 33)
            } else {
                value
            }
        }

        val r = readInteger()
        val s = readInteger()
        require(index == der.size) { "trailing DER signature data" }
        val jose = ByteArray(64)
        r.copyInto(jose, 32 - r.size)
        s.copyInto(jose, 64 - s.size)
        return jose
    }

    fun joseToDer(jose: ByteArray): ByteArray {
        require(jose.size == 64) { "ES256 JOSE signature must be 64 bytes" }
        fun integer(bytes: ByteArray): ByteArray {
            var first = 0
            while (first < bytes.lastIndex && bytes[first].toInt() == 0) first++
            val unsigned = bytes.copyOfRange(first, bytes.size)
            val needsZero = unsigned[0].toInt() and 0x80 != 0
            val value = if (needsZero) byteArrayOf(0) + unsigned else unsigned
            return byteArrayOf(0x02, value.size.toByte()) + value
        }
        val r = integer(jose.copyOfRange(0, 32))
        val s = integer(jose.copyOfRange(32, 64))
        val payload = r + s
        return byteArrayOf(0x30, payload.size.toByte()) + payload
    }
}
