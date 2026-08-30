package dev.latchway.sample.conformance

import android.content.ContentProvider
import android.content.ContentValues
import android.content.Context
import android.content.pm.PackageManager
import android.database.Cursor
import android.net.Uri
import android.os.Binder
import android.os.ParcelFileDescriptor
import dev.latchway.core.IdentityTokenProvider
import dev.latchway.core.LatchwayErrorCode
import dev.latchway.core.LatchwayException
import kotlinx.coroutines.delay
import kotlinx.coroutines.withTimeoutOrNull
import java.io.InputStream
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.Locale
import java.util.concurrent.atomic.AtomicReference

internal const val PHYSICAL_GRANT_AUDIENCE: String =
    "latchway-physical-evidence/android-play-integrity"

/**
 * Shell-only, write-only bootstrap endpoint for the protected physical runner.
 *
 * The grant body arrives over a pipe (`adb shell content write` stdin), never
 * through an Intent, command argument, manifest value, file, preference, log,
 * or evidence document. The provider keeps one bounded grant in process memory
 * until the matching activity atomically takes it.
 */
public class OneTimeIdentityGrantProvider : ContentProvider() {
    override fun onCreate(): Boolean = true

    override fun openFile(uri: Uri, mode: String): ParcelFileDescriptor {
        requireShellCaller()
        require(mode == "w" || mode == "wt") { "bootstrap endpoint is write-only" }
        val coordinates = BootstrapCoordinates.from(contextOrThrow(), uri)
        val pipe = ParcelFileDescriptor.createReliablePipe()
        val readEnd = pipe[0]
        val writeEnd = pipe[1]
        Thread(
            {
                val input = ParcelFileDescriptor.AutoCloseInputStream(readEnd)
                try {
                    val bytes = readBoundedGrant(input)
                    OneTimeIdentityGrantSlot.offer(coordinates, bytes)
                } catch (_: Exception) {
                    OneTimeIdentityGrantSlot.clear()
                    runCatching { readEnd.closeWithError("identity grant rejected") }
                } finally {
                    runCatching { input.close() }
                }
            },
            "latchway-one-time-grant",
        ).apply {
            isDaemon = true
            start()
        }
        return writeEnd
    }

    override fun query(
        uri: Uri,
        projection: Array<out String>?,
        selection: String?,
        selectionArgs: Array<out String>?,
        sortOrder: String?,
    ): Cursor? = null

    override fun getType(uri: Uri): String = "application/octet-stream"

    override fun insert(uri: Uri, values: ContentValues?): Uri? = null

    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<out String>?): Int = 0

    override fun update(
        uri: Uri,
        values: ContentValues?,
        selection: String?,
        selectionArgs: Array<out String>?,
    ): Int = 0

    private fun requireShellCaller() {
        val caller = Binder.getCallingUid()
        require(caller == ANDROID_SHELL_UID || caller == ANDROID_ROOT_UID) {
            "bootstrap caller is not permitted"
        }
    }

    private fun contextOrThrow(): Context = requireNotNull(context)

    private companion object {
        const val ANDROID_ROOT_UID = 0
        const val ANDROID_SHELL_UID = 2_000
    }
}

internal data class BootstrapCoordinates(
    val audience: String,
    val sourceCommit: String,
    val applicationId: String,
    val packageName: String,
    val identityProvider: String,
    val runId: String,
    val workflowRunId: String,
    val runAttempt: String,
    val grantSha256: String,
) {
    init {
        require(audience == PHYSICAL_GRANT_AUDIENCE)
        require(COMMIT.matches(sourceCommit))
        require(APPLICATION_ID.matches(applicationId))
        require(PACKAGE_NAME.matches(packageName) && packageName.length <= 255)
        require(IDENTIFIER.matches(identityProvider))
        require(RUN_ID.matches(runId))
        require(WORKFLOW_RUN_ID.matches(workflowRunId))
        require(RUN_ATTEMPT.matches(runAttempt))
        require(SHA256.matches(grantSha256))
        require(runId == "play-integrity-$workflowRunId-$runAttempt")
    }

    companion object {
        private val COMMIT = Regex("^[0-9a-f]{40}$")
        private val APPLICATION_ID = Regex("^app_[0-7][0-9A-HJKMNP-TV-Z]{25}$")
        private val PACKAGE_NAME = Regex("^[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z][A-Za-z0-9_]*)+$")
        private val IDENTIFIER = Regex("^[a-z][a-z0-9_-]{0,62}$")
        private val RUN_ID = Regex("^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")
        private val RUN_ATTEMPT = Regex("^[1-9][0-9]{0,8}$")
        private val WORKFLOW_RUN_ID = Regex("^[1-9][0-9]{0,19}$")
        private val SHA256 = Regex("^[0-9a-f]{64}$")

        fun from(context: Context, uri: Uri): BootstrapCoordinates {
            require(uri.path == "/v1/one-time-identity-grant") { "invalid bootstrap path" }
            require(uri.queryParameterNames == EXPECTED_QUERY_KEYS) { "invalid bootstrap coordinates" }
            fun one(name: String): String = requireNotNull(uri.getQueryParameter(name)).also {
                require(uri.getQueryParameters(name).size == 1)
            }
            val audience = one("audience")
            val sourceCommit = one("source_commit")
            val applicationId = one("application_id")
            val packageName = one("package_name")
            val identityProvider = one("identity_provider")
            val runId = one("run_id")
            val workflowRunId = one("workflow_run_id")
            val runAttempt = one("run_attempt")
            val grantSha256 = one("grant_sha256")
            require(sourceCommit == embeddedMetadata(context, "dev.latchway.SOURCE_COMMIT")) {
                "source commit mismatch"
            }
            require(applicationId == embeddedMetadata(context, "dev.latchway.APPLICATION_ID")) {
                "application ID mismatch"
            }
            require(packageName == context.packageName) { "package name mismatch" }
            require(identityProvider == embeddedMetadata(context, "dev.latchway.IDENTITY_PROVIDER")) {
                "identity provider mismatch"
            }
            return BootstrapCoordinates(
                audience,
                sourceCommit,
                applicationId,
                packageName,
                identityProvider,
                runId,
                workflowRunId,
                runAttempt,
                grantSha256,
            )
        }

        private val EXPECTED_QUERY_KEYS = setOf(
            "audience",
            "source_commit",
            "application_id",
            "package_name",
            "identity_provider",
            "run_id",
            "workflow_run_id",
            "run_attempt",
            "grant_sha256",
        )
    }
}

internal data class OneTimeIdentityGrant(
    val coordinates: BootstrapCoordinates,
    val token: String,
) {
    override fun toString(): String =
        "OneTimeIdentityGrant(coordinates=$coordinates, token=[REDACTED])"
}

internal object OneTimeIdentityGrantSlot {
    private val processState = OneTimeIdentityGrantSlotState()

    fun offer(coordinates: BootstrapCoordinates, bytes: ByteArray) =
        processState.offer(coordinates, bytes)

    suspend fun takeProvider(expected: BootstrapCoordinates): OneUseIdentityTokenProvider? =
        processState.take(expected)?.let { OneUseIdentityTokenProvider(it.token) }

    fun clear() = processState.clear()
}

internal class OneTimeIdentityGrantSlotState(
    private val grantWaitMillis: Long = DEFAULT_GRANT_WAIT_MILLIS,
) {
    init {
        require(grantWaitMillis > 0)
    }

    private sealed interface State {
        data object Empty : State
        data object Staging : State
        data class Pending(val grant: OneTimeIdentityGrant) : State
        data object Terminal : State
    }

    private val state = AtomicReference<State>(State.Empty)

    fun offer(coordinates: BootstrapCoordinates, bytes: ByteArray) {
        try {
            require(state.compareAndSet(State.Empty, State.Staging)) {
                "the process bootstrap slot was already staged or consumed"
            }
            require(bytes.size in MINIMUM_GRANT_BYTES..MAXIMUM_GRANT_BYTES)
            val actualHash = sha256(bytes)
            require(constantTimeEquals(actualHash, coordinates.grantSha256))
            val token = String(bytes, StandardCharsets.US_ASCII)
            require(token.toByteArray(StandardCharsets.US_ASCII).contentEquals(bytes))
            require(isValidIdentityJwt(token))
            require(state.compareAndSet(
                State.Staging,
                State.Pending(OneTimeIdentityGrant(coordinates, token)),
            ))
        } catch (error: Exception) {
            state.set(State.Terminal)
            throw error
        } finally {
            bytes.fill(0)
        }
    }

    suspend fun take(expected: BootstrapCoordinates): OneTimeIdentityGrant? {
        val grant = withTimeoutOrNull(grantWaitMillis) {
            while (true) {
                when (val current = state.get()) {
                    is State.Pending -> {
                        if (!state.compareAndSet(current, State.Terminal)) continue
                        return@withTimeoutOrNull current.grant.takeIf { it.coordinates == expected }
                    }
                    State.Terminal -> return@withTimeoutOrNull null
                    State.Empty, State.Staging -> delay(25)
                }
            }
            @Suppress("UNREACHABLE_CODE")
            null
        }
        // A consume attempt is terminal even when the writer never arrives or
        // is still staging at the deadline. A late pipe cannot revive the slot.
        state.set(State.Terminal)
        return grant
    }

    fun clear() {
        state.set(State.Terminal)
    }

    private companion object {
        const val MINIMUM_GRANT_BYTES = 16
        const val MAXIMUM_GRANT_BYTES = 65_536
        const val DEFAULT_GRANT_WAIT_MILLIS = 10_000L
    }
}

internal class OneUseIdentityTokenProvider(token: String) : IdentityTokenProvider {
    private val pending = AtomicReference<String?>(token)

    override suspend fun identityToken(): String = pending.getAndSet(null)
        ?: throw LatchwayException(
            code = LatchwayErrorCode.IDENTITY_TOKEN_MISSING,
            safeMessage = "The one-use physical identity grant was already consumed",
        )

    fun clear() {
        pending.set(null)
    }

    override fun toString(): String = "OneUseIdentityTokenProvider(token=[REDACTED])"
}

internal fun isValidIdentityJwt(value: String): Boolean {
    if (value.length !in 16..65_536 || value.any(Char::isWhitespace)) return false
    val segments = value.split('.')
    return segments.size == 3 && segments.all {
        it.isNotEmpty() && it.length <= 32_768 && it.all { character ->
            character in 'a'..'z' || character in 'A'..'Z' || character in '0'..'9' ||
                character == '-' || character == '_'
        }
    }
}

private fun embeddedMetadata(context: Context, name: String): String {
    val metadata = context.packageManager
        .getApplicationInfo(context.packageName, PackageManager.GET_META_DATA).metaData
    return requireNotNull(metadata.getString(name))
}

private fun readBoundedGrant(input: InputStream): ByteArray {
    val buffer = ByteArray(65_537)
    var count = 0
    try {
        while (count < buffer.size) {
            val read = input.read(buffer, count, buffer.size - count)
            if (read == -1) break
            count += read
        }
        require(count <= 65_536) { "identity grant exceeded the size limit" }
        return buffer.copyOf(count)
    } finally {
        buffer.fill(0)
    }
}

private fun sha256(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256")
    .digest(bytes)
    .joinToString("") { "%02x".format(Locale.US, it.toInt() and 0xff) }

private fun constantTimeEquals(left: String, right: String): Boolean =
    MessageDigest.isEqual(
        left.toByteArray(StandardCharsets.US_ASCII),
        right.toByteArray(StandardCharsets.US_ASCII),
    )
