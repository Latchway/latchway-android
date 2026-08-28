package dev.latchway.core

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.yield
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.atomic.AtomicReference

class InstallationKeyLifecycleTest {
    @Test
    fun sameAliasCreationWaitsForActiveSigning() = runBlocking {
        val alias = "test.creation.alias"
        val identity = AtomicReference<String?>("key-a")
        val key = AliasBoundInstallationKey(alias, "key-a")
        val signEntered = CompletableDeferred<Unit>()
        val releaseSign = CompletableDeferred<Unit>()
        val creationStarted = CompletableDeferred<Unit>()
        val replacementInstalled = CompletableDeferred<Unit>()

        val signing = async(Dispatchers.Default) {
            key.sign(
                currentIdentity = { identity.get() },
                unavailable = { IllegalStateException("stale") },
            ) {
                signEntered.complete(Unit)
                releaseSign.await()
            }
        }
        signEntered.await()
        val creating = async(Dispatchers.Default) {
            creationStarted.complete(Unit)
            InstallationKeyAliasLocks.withAlias(alias) {
                identity.set("key-b")
                replacementInstalled.complete(Unit)
            }
        }
        creationStarted.await()
        yield()

        assertFalse(replacementInstalled.isCompleted)
        releaseSign.complete(Unit)
        signing.await()
        creating.await()
        assertEquals("key-b", identity.get())
    }

    @Test
    fun sameAliasSignAndResetAreSerialized() = runBlocking {
        val identity = AtomicReference<String?>("key-a")
        val key = AliasBoundInstallationKey("test.serialized.alias", "key-a")
        val signEntered = CompletableDeferred<Unit>()
        val releaseSign = CompletableDeferred<Unit>()
        val resetStarted = CompletableDeferred<Unit>()
        val deleted = CompletableDeferred<Unit>()

        val signing = async(Dispatchers.Default) {
            key.sign(
                currentIdentity = { identity.get() },
                unavailable = { IllegalStateException("stale") },
            ) {
                signEntered.complete(Unit)
                releaseSign.await()
                "signature"
            }
        }
        signEntered.await()
        val resetting = async(Dispatchers.Default) {
            resetStarted.complete(Unit)
            key.reset(currentIdentity = { identity.get() }) {
                identity.set(null)
                deleted.complete(Unit)
            }
        }
        resetStarted.await()
        yield()

        assertFalse(deleted.isCompleted)
        releaseSign.complete(Unit)
        assertEquals("signature", signing.await())
        resetting.await()
        assertTrue(deleted.isCompleted)
    }

    @Test
    fun staleInstanceCannotSignWithOrDeleteReplacementKey() = runBlocking {
        val identity = AtomicReference<String?>("key-a")
        val retiring = AliasBoundInstallationKey("test.replacement.alias", "key-a")
        val stalePeer = AliasBoundInstallationKey("test.replacement.alias", "key-a")

        retiring.reset(currentIdentity = { identity.get() }) { identity.set(null) }
        identity.set("key-b")
        val replacement = AliasBoundInstallationKey("test.replacement.alias", "key-b")

        val staleError = assertThrows(IllegalStateException::class.java) {
            runBlocking {
                stalePeer.sign(
                    currentIdentity = { identity.get() },
                    unavailable = { IllegalStateException("stale") },
                ) { "must-not-sign" }
            }
        }
        assertEquals("stale", staleError.message)

        var staleDeletionRan = false
        stalePeer.reset(currentIdentity = { identity.get() }) {
            staleDeletionRan = true
            identity.set(null)
        }
        assertFalse(staleDeletionRan)
        assertEquals("key-b", identity.get())
        assertFalse(stalePeer.isCurrent { identity.get() })
        assertTrue(replacement.isCurrent { identity.get() })
        assertEquals(
            "replacement-signature",
            replacement.sign(
                currentIdentity = { identity.get() },
                unavailable = { IllegalStateException("stale") },
            ) { "replacement-signature" },
        )
    }
}
