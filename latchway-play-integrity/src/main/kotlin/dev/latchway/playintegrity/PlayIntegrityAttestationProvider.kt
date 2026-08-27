package dev.latchway.playintegrity

import android.content.Context
import com.google.android.play.core.integrity.IntegrityManagerFactory
import com.google.android.play.core.integrity.StandardIntegrityException
import com.google.android.play.core.integrity.StandardIntegrityManager
import com.google.android.play.core.integrity.model.StandardIntegrityErrorCode
import dev.latchway.core.AttestationChallenge
import dev.latchway.core.AttestationEvidence
import dev.latchway.core.AttestationProvider
import dev.latchway.core.Base64Url
import dev.latchway.core.LatchwayErrorCode
import dev.latchway.core.LatchwayException
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.delay
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.tasks.await

public data class PlayIntegrityRetryPolicy(
    val maximumAttempts: Int = 3,
    val initialDelayMillis: Long = 250,
    val maximumDelayMillis: Long = 2_000,
) {
    init {
        require(maximumAttempts in 1..5)
        require(initialDelayMillis in 50..5_000)
        require(maximumDelayMillis in initialDelayMillis..10_000)
    }
}

/**
 * Google Play Integrity Standard provider. The 43-character server hash is passed to
 * Play as requestHash verbatim; hashing it again would break the protocol binding.
 */
public class PlayIntegrityAttestationProvider private constructor(
    private val gateway: StandardIntegrityGateway,
    private val retryPolicy: PlayIntegrityRetryPolicy,
    private val sleeper: suspend (Long) -> Unit,
) : AttestationProvider {
    public constructor(
        context: Context,
        cloudProjectNumber: Long,
        retryPolicy: PlayIntegrityRetryPolicy = PlayIntegrityRetryPolicy(),
    ) : this(
        gateway = GoogleStandardIntegrityGateway(context.applicationContext, cloudProjectNumber),
        retryPolicy = retryPolicy,
        sleeper = { delay(it) },
    ) {
        require(cloudProjectNumber > 0) { "cloudProjectNumber must be positive" }
    }

    override suspend fun warmUp() {
        runWithRetry(allowProviderRenewal = false) { gateway.prepare() }
    }

    override suspend fun attest(challenge: AttestationChallenge): AttestationEvidence {
        if (challenge.provider != PROVIDER) {
            throw LatchwayException(
                code = LatchwayErrorCode.ATTESTATION_UNSUPPORTED,
                safeMessage = "Play Integrity cannot answer a ${challenge.provider} challenge",
            )
        }
        if (!CLIENT_DATA_HASH.matches(challenge.clientDataHash) ||
            runCatching { Base64Url.decode(challenge.clientDataHash).size }.getOrNull() != 32
        ) {
            throw LatchwayException(
                code = LatchwayErrorCode.ATTESTATION_INVALID,
                safeMessage = "The server supplied an invalid Play Integrity request hash",
            )
        }
        warmUp()
        val token = runWithRetry(allowProviderRenewal = true) {
            gateway.request(challenge.clientDataHash)
        }
        if (token.length !in 16..262_144) {
            throw LatchwayException(
                code = LatchwayErrorCode.ATTESTATION_INVALID,
                safeMessage = "Google Play returned an invalid integrity token",
            )
        }
        return AttestationEvidence(
            provider = PROVIDER,
            evidence = mapOf("integrity_token" to token),
        )
    }

    private suspend fun <T> runWithRetry(
        allowProviderRenewal: Boolean,
        action: suspend () -> T,
    ): T {
        var delayMillis = retryPolicy.initialDelayMillis
        repeat(retryPolicy.maximumAttempts) { attempt ->
            try {
                return action()
            } catch (failure: IntegrityGatewayException) {
                if (allowProviderRenewal &&
                    failure.errorCode == StandardIntegrityErrorCode.INTEGRITY_TOKEN_PROVIDER_INVALID
                ) {
                    gateway.invalidate()
                    runWithRetry(allowProviderRenewal = false) { gateway.prepare() }
                    return runWithRetry(allowProviderRenewal = false, action = action)
                } else if (failure.errorCode.isDocumentedTransient() &&
                    attempt + 1 < retryPolicy.maximumAttempts
                ) {
                    sleeper(delayMillis)
                    delayMillis = (delayMillis * 2).coerceAtMost(retryPolicy.maximumDelayMillis)
                } else {
                    throw failure.toLatchwayException()
                }
            } catch (failure: CancellationException) {
                throw failure
            } catch (failure: LatchwayException) {
                throw failure
            } catch (failure: Exception) {
                throw LatchwayException(
                    code = LatchwayErrorCode.ATTESTATION_INVALID,
                    safeMessage = "Play Integrity failed unexpectedly",
                    cause = failure,
                )
            }
        }
        throw LatchwayException(
            code = LatchwayErrorCode.ATTESTATION_INVALID,
            safeMessage = "Play Integrity retry policy was exhausted",
        )
    }

    internal companion object {
        const val PROVIDER = "play_integrity"
        val CLIENT_DATA_HASH = Regex("^[A-Za-z0-9_-]{43}$")

        fun forTesting(
            gateway: StandardIntegrityGateway,
            retryPolicy: PlayIntegrityRetryPolicy = PlayIntegrityRetryPolicy(),
            sleeper: suspend (Long) -> Unit = {},
        ): PlayIntegrityAttestationProvider = PlayIntegrityAttestationProvider(gateway, retryPolicy, sleeper)
    }
}

internal interface StandardIntegrityGateway {
    suspend fun prepare()
    suspend fun request(requestHash: String): String
    suspend fun invalidate()
}

private class GoogleStandardIntegrityGateway(
    context: Context,
    private val cloudProjectNumber: Long,
) : StandardIntegrityGateway {
    private val manager = IntegrityManagerFactory.createStandard(context)
    private val mutex = Mutex()
    private var provider: StandardIntegrityManager.StandardIntegrityTokenProvider? = null

    override suspend fun prepare(): Unit = mutex.withLock {
        if (provider != null) return@withLock
        try {
            provider = manager.prepareIntegrityToken(
                StandardIntegrityManager.PrepareIntegrityTokenRequest.builder()
                    .setCloudProjectNumber(cloudProjectNumber)
                    .build(),
            ).await()
        } catch (error: StandardIntegrityException) {
            throw IntegrityGatewayException(error.errorCode, error)
        }
    }

    override suspend fun request(requestHash: String): String {
        val readyProvider = mutex.withLock { provider }
            ?: throw IntegrityGatewayException(StandardIntegrityErrorCode.INTEGRITY_TOKEN_PROVIDER_INVALID)
        return try {
            readyProvider.request(
                StandardIntegrityManager.StandardIntegrityTokenRequest.builder()
                    .setRequestHash(requestHash)
                    .build(),
            ).await().token()
        } catch (error: StandardIntegrityException) {
            throw IntegrityGatewayException(error.errorCode, error)
        }
    }

    override suspend fun invalidate() {
        mutex.withLock { provider = null }
    }
}

internal class IntegrityGatewayException(
    val errorCode: Int,
    cause: Throwable? = null,
) : Exception("Play Integrity operation failed with code $errorCode", cause)

private fun Int.isDocumentedTransient(): Boolean = this in setOf(
    StandardIntegrityErrorCode.NETWORK_ERROR,
    StandardIntegrityErrorCode.TOO_MANY_REQUESTS,
    StandardIntegrityErrorCode.CANNOT_BIND_TO_SERVICE,
    StandardIntegrityErrorCode.GOOGLE_SERVER_UNAVAILABLE,
    StandardIntegrityErrorCode.CLIENT_TRANSIENT_ERROR,
    StandardIntegrityErrorCode.INTERNAL_ERROR,
)

private fun IntegrityGatewayException.toLatchwayException(): LatchwayException = LatchwayException(
    code = if (errorCode == StandardIntegrityErrorCode.NETWORK_ERROR) {
        LatchwayErrorCode.NETWORK_UNAVAILABLE
    } else {
        LatchwayErrorCode.ATTESTATION_INVALID
    },
    retryable = errorCode.isDocumentedTransient(),
    safeMessage = if (errorCode.isDocumentedTransient()) {
        "Play Integrity was temporarily unavailable after bounded retries"
    } else {
        "Play Integrity could not produce acceptable attestation evidence"
    },
    cause = this,
)
