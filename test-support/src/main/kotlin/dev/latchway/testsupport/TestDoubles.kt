package dev.latchway.testsupport

import dev.latchway.core.AttestationChallenge
import dev.latchway.core.AttestationEvidence
import dev.latchway.core.AttestationProvider
import dev.latchway.core.Base64Url
import dev.latchway.core.IdentityTokenProvider
import dev.latchway.core.InstallationSigner
import dev.latchway.core.KeyBacking
import dev.latchway.core.KeyDiagnostics
import dev.latchway.core.LatchwayTransport
import dev.latchway.core.LatchwayTransportRequest
import dev.latchway.core.LatchwayTransportResponse
import dev.latchway.core.PublicJwk
import dev.latchway.core.SessionSnapshot
import dev.latchway.core.SessionStateStore
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec

public class StaticIdentityTokenProvider(
    private val token: String,
) : IdentityTokenProvider {
    override suspend fun identityToken(): String = token
    override fun toString(): String = "StaticIdentityTokenProvider(token=[REDACTED])"
}

/** Explicit debug-only evidence provider for local and server debug-policy tests. */
public class DebugAttestationProvider(
    private val evidenceValue: String = "test-support-debug-evidence",
) : AttestationProvider {
    public var warmUpCount: Int = 0
        private set
    public var attestCount: Int = 0
        private set
    public var lastClientDataHash: String? = null
        private set

    override suspend fun warmUp() {
        warmUpCount++
    }

    override suspend fun attest(challenge: AttestationChallenge): AttestationEvidence {
        require(challenge.provider == "debug")
        attestCount++
        lastClientDataHash = challenge.clientDataHash
        return AttestationEvidence("debug", mapOf("debug_evidence" to evidenceValue))
    }

    override fun toString(): String = "DebugAttestationProvider(evidence=[REDACTED])"
}

public class InMemorySessionStateStore(
    initial: SessionSnapshot? = null,
) : SessionStateStore {
    private val mutex = Mutex()
    private var snapshot: SessionSnapshot? = initial

    override suspend fun load(): SessionSnapshot? = mutex.withLock { snapshot }
    override suspend fun save(snapshot: SessionSnapshot) { mutex.withLock { this.snapshot = snapshot } }
    override suspend fun clear() { mutex.withLock { snapshot = null } }
}

public class ScriptedLatchwayTransport(
    responses: Iterable<LatchwayTransportResponse>,
) : LatchwayTransport {
    private val mutex = Mutex()
    private val pending = ArrayDeque(responses.toList())
    private val mutableRequests = ArrayList<LatchwayTransportRequest>()

    public val requests: List<LatchwayTransportRequest>
        get() = synchronized(mutableRequests) { mutableRequests.toList() }

    override suspend fun execute(request: LatchwayTransportRequest): LatchwayTransportResponse = mutex.withLock {
        synchronized(mutableRequests) { mutableRequests += request }
        check(pending.isNotEmpty()) { "No scripted transport response remains" }
        pending.removeFirst()
    }
}

public class SoftwareTestInstallationSigner private constructor(
    private val keyPair: KeyPair,
    override val publicJwk: PublicJwk,
) : InstallationSigner {
    override val diagnostics: KeyDiagnostics = KeyDiagnostics(
        backing = KeyBacking.SOFTWARE,
        strongBoxRequested = false,
        strongBoxUnavailable = false,
        publicJwkThumbprint = publicJwk.thumbprint(),
    )

    override suspend fun sign(signingInput: ByteArray): ByteArray {
        val signature = Signature.getInstance("SHA256withECDSA")
        signature.initSign(keyPair.private)
        signature.update(signingInput)
        return derToJose(signature.sign())
    }

    public companion object {
        public fun generate(): SoftwareTestInstallationSigner {
            val generator = KeyPairGenerator.getInstance("EC")
            generator.initialize(ECGenParameterSpec("secp256r1"))
            val keyPair = generator.generateKeyPair()
            val publicKey = keyPair.public as ECPublicKey
            val jwk = PublicJwk(
                x = Base64Url.encode(coordinate(publicKey.w.affineX)),
                y = Base64Url.encode(coordinate(publicKey.w.affineY)),
            )
            return SoftwareTestInstallationSigner(keyPair, jwk)
        }

        private fun coordinate(value: BigInteger): ByteArray {
            val raw = value.toByteArray()
            val unsigned = if (raw.size == 33 && raw[0].toInt() == 0) raw.copyOfRange(1, 33) else raw
            return ByteArray(32).also { unsigned.copyInto(it, 32 - unsigned.size) }
        }

        private fun derToJose(der: ByteArray): ByteArray {
            var index = 0
            fun byte(): Int = der[index++].toInt() and 0xff
            fun length(): Int {
                val first = byte()
                if (first < 128) return first
                var value = 0
                repeat(first and 0x7f) { value = value shl 8 or byte() }
                return value
            }
            require(byte() == 0x30)
            require(length() == der.size - index)
            fun integer(): ByteArray {
                require(byte() == 0x02)
                val integerLength = length()
                val value = der.copyOfRange(index, index + integerLength)
                index += integerLength
                return if (value.size == 33 && value[0].toInt() == 0) value.copyOfRange(1, 33) else value
            }
            val r = integer()
            val s = integer()
            return ByteArray(64).also {
                r.copyInto(it, 32 - r.size)
                s.copyInto(it, 64 - s.size)
            }
        }
    }
}
