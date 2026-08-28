package dev.latchway.core

import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.util.concurrent.ConcurrentHashMap

/**
 * Coordinates all in-process access to one Android Keystore alias. Android
 * Keystore aliases are process-global even when callers create several SDK
 * clients, so a mutex owned by one signer instance is not sufficient.
 */
internal object InstallationKeyAliasLocks {
    private val locks = ConcurrentHashMap<String, Mutex>()

    suspend fun <T> withAlias(alias: String, operation: suspend () -> T): T =
        lock(alias).withLock { operation() }

    private fun lock(alias: String): Mutex {
        locks[alias]?.let { return it }
        val candidate = Mutex()
        return locks.putIfAbsent(alias, candidate) ?: candidate
    }
}

/**
 * A server-revoked JKT stays retired for the life of this process. This also
 * terminalizes peer coordinators that were created with the same installation
 * key before one of them observed revocation.
 */
internal object InstallationKeyRetirements {
    private class Retirement {
        val keyResetMutex = Mutex()
        val stateMutex = Mutex()

        @Volatile
        var keyResetComplete: Boolean = false

        @Volatile
        var retired: Boolean = false
    }

    private val identities = ConcurrentHashMap<String, Retirement>()

    fun retire(identity: String) {
        retirement(identity).retired = true
    }

    fun isRetired(identity: String): Boolean = identities[identity]?.retired == true

    /**
     * Serializes persistence for one installation identity with retirement.
     * Retirement is marked before cleanup waits for this gate, so a late grant
     * can never commit after replacement provisioning has completed.
     */
    suspend fun <T> persistIfActive(
        identity: String,
        inactive: () -> Throwable,
        operation: suspend () -> T,
    ): T {
        val retirement = retirement(identity)
        return retirement.stateMutex.withLock {
            if (retirement.retired) throw inactive()
            val result = operation()
            if (retirement.retired) throw inactive()
            result
        }
    }

    /** Serializes conditional state cleanup with grants for this identity. */
    suspend fun <T> withState(identity: String, operation: suspend () -> T): T =
        retirement(identity).stateMutex.withLock { operation() }

    /**
     * Runs key destruction at most once after a successful reset. A failed
     * owner does not strand cleanup: another coordinator can acquire the
     * identity-scoped mutex and retry with its own signer instance.
     */
    suspend fun resetKey(identity: String, reset: suspend () -> Unit) {
        val retirement = retirement(identity)
        retirement.keyResetMutex.withLock {
            if (retirement.keyResetComplete) return@withLock
            reset()
            retirement.keyResetComplete = true
        }
    }

    private fun retirement(identity: String): Retirement {
        identities[identity]?.let { return it }
        val candidate = Retirement()
        return identities.putIfAbsent(identity, candidate) ?: candidate
    }
}

internal data class SessionCoordinationKey(
    val baseUrl: String,
    val applicationId: String,
    val environment: String,
    val identityProvider: String,
    val platform: String,
    val signerIdentity: String,
)

/** Prevents separate clients from rotating the same refresh token concurrently. */
internal object SessionCoordinationLocks {
    private val locks = ConcurrentHashMap<SessionCoordinationKey, Mutex>()

    suspend fun <T> withSession(key: SessionCoordinationKey, operation: suspend () -> T): T =
        lock(key).withLock { operation() }

    private fun lock(key: SessionCoordinationKey): Mutex {
        locks[key]?.let { return it }
        val candidate = Mutex()
        return locks.putIfAbsent(key, candidate) ?: candidate
    }
}

/**
 * Binds a signer instance to the exact public key it observed at creation.
 * A stale instance may neither sign with nor delete a replacement key that
 * was subsequently created under the same alias.
 */
internal class AliasBoundInstallationKey(
    private val alias: String,
    private val expectedIdentity: String,
) {
    @Volatile private var invalidated = false

    suspend fun <T> sign(
        currentIdentity: suspend () -> String?,
        unavailable: () -> Throwable,
        operation: suspend () -> T,
    ): T = InstallationKeyAliasLocks.withAlias(alias) {
        if (invalidated || currentIdentity() != expectedIdentity) throw unavailable()
        operation()
    }

    suspend fun isCurrent(currentIdentity: suspend () -> String?): Boolean =
        InstallationKeyAliasLocks.withAlias(alias) {
            !invalidated && currentIdentity() == expectedIdentity
        }

    suspend fun reset(
        currentIdentity: suspend () -> String?,
        delete: suspend () -> Unit,
    ): Unit = InstallationKeyAliasLocks.withAlias(alias) {
        invalidated = true
        when (currentIdentity()) {
            null -> Unit
            expectedIdentity -> delete()
            else -> Unit
        }
    }
}
