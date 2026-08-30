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
 * Play as requestHash verbatim; hashing it again would break the protocol binding. The
 * server cloud project option must exactly match the project configured by the caller.
 */
public class PlayIntegrityAttestationProvider private constructor(
    private val gateway: StandardIntegrityGateway,
    private val cloudProjectNumber: Long,
    private val retryPolicy: PlayIntegrityRetryPolicy,
    private val sleeper: suspend (Long) -> Unit,
) : AttestationProvider {
    private val warmUpMutex = Mutex()
    private var prepared = false
    private var providerGeneration = 0L

    private enum class ProviderInvalidDisposition {
        STALE_OBSERVATION,
        RENEWED,
        EXHAUSTED,
    }

    private data class ProviderInvalidResolution(
        val disposition: ProviderInvalidDisposition,
        val generation: Long,
    )

    public constructor(
        context: Context,
        cloudProjectNumber: Long,
        retryPolicy: PlayIntegrityRetryPolicy = PlayIntegrityRetryPolicy(),
    ) : this(
        gateway = GoogleStandardIntegrityGateway(context.applicationContext, cloudProjectNumber),
        cloudProjectNumber = cloudProjectNumber,
        retryPolicy = retryPolicy,
        sleeper = { delay(it) },
    )

    init {
        require(cloudProjectNumber > 0) { "cloudProjectNumber must be positive" }
    }

    override suspend fun warmUp(): Unit = warmUpMutex.withLock { prepareLocked() }

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
        requireMatchingCloudProjectNumber(challenge.providerOptions)
        warmUp()
        val token = requestToken(challenge.clientDataHash)
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

    private fun requireMatchingCloudProjectNumber(providerOptions: Map<String, Any?>) {
        val rawProjectNumber = providerOptions["cloud_project_number"] as? String
        val parsedProjectNumber = rawProjectNumber
            ?.takeIf(CLOUD_PROJECT_NUMBER::matches)
            ?.toLongOrNull()
        if (parsedProjectNumber == null ||
            parsedProjectNumber != cloudProjectNumber ||
            rawProjectNumber != parsedProjectNumber.toString()
        ) {
            throw LatchwayException(
                code = LatchwayErrorCode.ATTESTATION_INVALID,
                safeMessage = "The server supplied an invalid Play Integrity cloud project",
            )
        }
    }

    private suspend fun <T> runWithRetry(
        propagateInvalidProvider: Boolean = false,
        action: suspend () -> T,
    ): T {
        var delayMillis = retryPolicy.initialDelayMillis
        repeat(retryPolicy.maximumAttempts) { attempt ->
            try {
                return action()
            } catch (failure: IntegrityGatewayException) {
                if (propagateInvalidProvider &&
                    failure.errorCode == StandardIntegrityErrorCode.INTEGRITY_TOKEN_PROVIDER_INVALID
                ) {
                    throw failure
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

    private suspend fun requestToken(requestHash: String): String {
        var observedGeneration = warmUpMutex.withLock { providerGeneration }
        // A stale observation does not spend this request's one real provider renewal. Both
        // the stale-generation transitions and the actual renewal are independently bounded.
        var providerRenewalAvailable = true
        var staleRetriesRemaining = retryPolicy.maximumAttempts
        while (true) {
            try {
                return runWithRetry(propagateInvalidProvider = true) {
                    gateway.request(requestHash)
                }
            } catch (failure: IntegrityGatewayException) {
                if (failure.errorCode != StandardIntegrityErrorCode.INTEGRITY_TOKEN_PROVIDER_INVALID) {
                    throw failure.toLatchwayException()
                }
                val resolution = resolveInvalidProvider(
                    observedGeneration = observedGeneration,
                    allowRenewal = providerRenewalAvailable,
                )
                when (resolution.disposition) {
                    ProviderInvalidDisposition.STALE_OBSERVATION -> {
                        if (staleRetriesRemaining == 0) throw failure.toLatchwayException()
                        staleRetriesRemaining--
                    }
                    ProviderInvalidDisposition.RENEWED -> providerRenewalAvailable = false
                    ProviderInvalidDisposition.EXHAUSTED -> throw failure.toLatchwayException()
                }
                observedGeneration = resolution.generation
            }
        }
    }

    private suspend fun prepareLocked() {
        if (prepared) return
        runWithRetry { gateway.prepare() }
        prepared = true
        providerGeneration++
    }

    private suspend fun resolveInvalidProvider(
        observedGeneration: Long,
        allowRenewal: Boolean,
    ): ProviderInvalidResolution = warmUpMutex.withLock {
        if (!prepared) {
            prepareLocked()
            return@withLock ProviderInvalidResolution(
                ProviderInvalidDisposition.STALE_OBSERVATION,
                providerGeneration,
            )
        }
        if (providerGeneration != observedGeneration) {
            return@withLock ProviderInvalidResolution(
                ProviderInvalidDisposition.STALE_OBSERVATION,
                providerGeneration,
            )
        }
        if (!allowRenewal) {
            return@withLock ProviderInvalidResolution(
                ProviderInvalidDisposition.EXHAUSTED,
                providerGeneration,
            )
        }
        gateway.invalidate()
        prepared = false
        prepareLocked()
        ProviderInvalidResolution(
            ProviderInvalidDisposition.RENEWED,
            providerGeneration,
        )
    }

    internal companion object {
        const val PROVIDER = "play_integrity"
        val CLIENT_DATA_HASH = Regex("^[A-Za-z0-9_-]{43}$")
        val CLOUD_PROJECT_NUMBER = Regex("^[1-9][0-9]{0,18}$")

        fun forTesting(
            gateway: StandardIntegrityGateway,
            cloudProjectNumber: Long = 123_456_789L,
            retryPolicy: PlayIntegrityRetryPolicy = PlayIntegrityRetryPolicy(),
            sleeper: suspend (Long) -> Unit = {},
        ): PlayIntegrityAttestationProvider = PlayIntegrityAttestationProvider(
            gateway,
            cloudProjectNumber,
            retryPolicy,
            sleeper,
        )
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
