package dev.latchway.core

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.nio.charset.StandardCharsets
import java.security.KeyStore
import java.util.concurrent.ConcurrentHashMap
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

public data class InstallationSummary(
    val id: String,
    val platform: String,
    val dpopJkt: String,
    val status: String,
)

public data class TrustSummary(
    val provider: String,
    val level: String,
    val verifiedAt: String,
    val expiresAt: String,
)

public class SessionSnapshot(
    public val accessToken: SecretValue,
    public val refreshToken: SecretValue,
    public val accessExpiresAtEpochSeconds: Long,
    public val refreshExpiresAtEpochSeconds: Long,
    public val installation: InstallationSummary,
    public val trust: TrustSummary,
) {
    init {
        require(accessExpiresAtEpochSeconds > 0)
        require(refreshExpiresAtEpochSeconds > accessExpiresAtEpochSeconds)
        require(INSTALLATION_ID.matches(installation.id))
        require(installation.platform in ANDROID_PLATFORMS)
        require(Base64Url.decode(installation.dpopJkt).size == 32)
    }

    override fun toString(): String =
        "SessionSnapshot(installation=${installation.id}, accessExpiresAt=$accessExpiresAtEpochSeconds, " +
            "refreshExpiresAt=$refreshExpiresAtEpochSeconds, credentials=[REDACTED])"

    private companion object {
        val INSTALLATION_ID = Regex("^ins_[A-Za-z0-9_-]{16,128}$")
        val ANDROID_PLATFORMS = LatchwayClientPlatform.entries.mapTo(HashSet()) { it.wireValue }
    }
}

public interface SessionStateStore {
    public suspend fun load(): SessionSnapshot?
    public suspend fun save(snapshot: SessionSnapshot)
    public suspend fun clear()
}

internal interface InstallationBoundSessionStateStore {
    suspend fun clearIfInstallation(expectedDpopJkt: String)
    suspend fun clearIfSession(expectedDpopJkt: String, expectedAccessTokenFingerprint: String)
}

internal object SessionStateNamespaceLocks {
    private val locks = ConcurrentHashMap<String, Mutex>()

    fun lock(namespace: String): Mutex {
        locks[namespace]?.let { return it }
        val candidate = Mutex()
        return locks.putIfAbsent(namespace, candidate) ?: candidate
    }
}

/** AES-256-GCM state whose encryption key remains in Android Keystore. */
public class AndroidEncryptedSessionStateStore(
    context: Context,
    namespace: String,
) : SessionStateStore, InstallationBoundSessionStateStore {
    private val preferences = context.applicationContext.getSharedPreferences(
        "dev.latchway.session.$namespace",
        Context.MODE_PRIVATE,
    )
    private val keyAlias = "dev.latchway.session.$namespace.aes.v1"
    private val aad = "latchway-session-v1:$namespace".toByteArray(StandardCharsets.UTF_8)
    private val mutex = SessionStateNamespaceLocks.lock(namespace)

    init {
        require(NAMESPACE.matches(namespace)) { "Session state namespace is invalid" }
    }

    override suspend fun load(): SessionSnapshot? = mutex.withLock { loadLocked() }

    override suspend fun save(snapshot: SessionSnapshot): Unit = mutex.withLock {
        withContext(Dispatchers.IO) {
            try {
                val encrypted = SessionStateEncryption.encrypt(
                    key = encryptionKey(),
                    aad = aad,
                    plaintext = encodeSnapshot(snapshot).toByteArray(StandardCharsets.UTF_8),
                )
                if (!preferences.edit()
                        .putString(VERSION, "1")
                        .putString(IV, Base64Url.encode(encrypted.iv))
                        .putString(CIPHERTEXT, Base64Url.encode(encrypted.ciphertext))
                        .commit()
                ) {
                    throw IllegalStateException("Encrypted state could not be persisted")
                }
            } catch (error: LatchwayException) {
                throw error
            } catch (error: CancellationException) {
                throw error
            } catch (error: Exception) {
                throw LatchwayException(
                    code = LatchwayErrorCode.SECURE_STATE_UNAVAILABLE,
                    safeMessage = "Encrypted session state could not be saved",
                    cause = error,
                )
            }
        }
    }

    override suspend fun clear(): Unit = mutex.withLock { clearLocked() }

    override suspend fun clearIfInstallation(expectedDpopJkt: String): Unit = mutex.withLock {
        val stored = loadLocked() ?: return@withLock
        if (stored.installation.dpopJkt == expectedDpopJkt) clearLocked()
    }

    override suspend fun clearIfSession(
        expectedDpopJkt: String,
        expectedAccessTokenFingerprint: String,
    ): Unit = mutex.withLock {
        val stored = loadLocked() ?: return@withLock
        if (stored.installation.dpopJkt == expectedDpopJkt &&
            stored.accessTokenFingerprint() == expectedAccessTokenFingerprint
        ) {
            clearLocked()
        }
    }

    private suspend fun loadLocked(): SessionSnapshot? = withContext(Dispatchers.IO) {
        val encodedCiphertext = preferences.getString(CIPHERTEXT, null) ?: return@withContext null
        val encodedIv = preferences.getString(IV, null) ?: return@withContext corruptState()
        if (preferences.getString(VERSION, null) != "1") return@withContext corruptState()
        try {
            val plaintext = SessionStateEncryption.decrypt(
                key = encryptionKey(),
                aad = aad,
                blob = EncryptedSessionBlob(
                    iv = Base64Url.decode(encodedIv),
                    ciphertext = Base64Url.decode(encodedCiphertext),
                ),
            )
            decodeSnapshot(String(plaintext, StandardCharsets.UTF_8))
        } catch (error: LatchwayException) {
            throw error
        } catch (error: CancellationException) {
            throw error
        } catch (error: Exception) {
            corruptState(error)
        }
    }

    private suspend fun clearLocked(): Unit = withContext(Dispatchers.IO) {
        if (!preferences.edit().clear().commit()) {
            throw LatchwayException(
                code = LatchwayErrorCode.SECURE_STATE_UNAVAILABLE,
                safeMessage = "Encrypted session state could not be cleared",
            )
        }
    }

    private fun encryptionKey(): SecretKey {
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (keyStore.getKey(keyAlias, null) as? SecretKey)?.let { return it }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        generator.init(
            KeyGenParameterSpec.Builder(
                keyAlias,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
            ).setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setRandomizedEncryptionRequired(true)
                .build(),
        )
        return generator.generateKey()
    }

    private fun corruptState(cause: Throwable? = null): Nothing {
        preferences.edit().clear().commit()
        throw LatchwayException(
            code = LatchwayErrorCode.SECURE_STATE_UNAVAILABLE,
            safeMessage = "Encrypted session state was invalid and has been cleared",
            cause = cause,
        )
    }

    private companion object {
        const val VERSION = "version"
        const val IV = "iv"
        const val CIPHERTEXT = "ciphertext"
        val NAMESPACE = Regex("^[A-Za-z0-9._-]{1,96}$")
    }
}

internal data class EncryptedSessionBlob(val iv: ByteArray, val ciphertext: ByteArray)

internal object SessionStateEncryption {
    private const val TRANSFORMATION = "AES/GCM/NoPadding"

    fun encrypt(key: SecretKey, aad: ByteArray, plaintext: ByteArray): EncryptedSessionBlob {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, key)
        cipher.updateAAD(aad)
        return EncryptedSessionBlob(cipher.iv, cipher.doFinal(plaintext))
    }

    fun decrypt(key: SecretKey, aad: ByteArray, blob: EncryptedSessionBlob): ByteArray {
        require(blob.iv.size == 12) { "AES-GCM IV must be 96 bits" }
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, blob.iv))
        cipher.updateAAD(aad)
        return cipher.doFinal(blob.ciphertext)
    }
}

internal fun encodeSnapshot(value: SessionSnapshot): String = JSONObject()
    .put("version", 1)
    .put("access_token", value.accessToken.reveal())
    .put("refresh_token", value.refreshToken.reveal())
    .put("access_expires_at", value.accessExpiresAtEpochSeconds)
    .put("refresh_expires_at", value.refreshExpiresAtEpochSeconds)
    .put("installation", JSONObject()
        .put("id", value.installation.id)
        .put("platform", value.installation.platform)
        .put("dpop_jkt", value.installation.dpopJkt)
        .put("status", value.installation.status))
    .put("trust", JSONObject()
        .put("provider", value.trust.provider)
        .put("level", value.trust.level)
        .put("verified_at", value.trust.verifiedAt)
        .put("expires_at", value.trust.expiresAt))
    .toString()

internal fun decodeSnapshot(encoded: String): SessionSnapshot {
    val json = JSONObject(encoded)
    require(json.getInt("version") == 1)
    val installation = json.getJSONObject("installation")
    val trust = json.getJSONObject("trust")
    return SessionSnapshot(
        accessToken = SecretValue.of(json.getString("access_token")),
        refreshToken = SecretValue.of(json.getString("refresh_token")),
        accessExpiresAtEpochSeconds = json.getLong("access_expires_at"),
        refreshExpiresAtEpochSeconds = json.getLong("refresh_expires_at"),
        installation = InstallationSummary(
            id = installation.getString("id"),
            platform = installation.getString("platform"),
            dpopJkt = installation.getString("dpop_jkt"),
            status = installation.getString("status"),
        ),
        trust = TrustSummary(
            provider = trust.getString("provider"),
            level = trust.getString("level"),
            verifiedAt = trust.getString("verified_at"),
            expiresAt = trust.getString("expires_at"),
        ),
    )
}
