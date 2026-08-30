package dev.latchway.core

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.io.Closeable
import java.nio.charset.StandardCharsets
import java.security.KeyStore
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

public data class InstallationFamilySummary(
    val id: String,
    val status: String,
) {
    init {
        require(FAMILY_ID.matches(id)) { "Installation Family ID is not canonical" }
        require(status == "active" || status == "revoked") { "Installation Family status is invalid" }
    }
}

public data class ClientComponentSummary(
    val id: String,
    val definitionId: String,
    val kind: String,
    val platform: String,
    val isRoot: Boolean,
    val status: String,
    val dpopJkt: String,
    val grantedFeatures: Set<String>,
) {
    init {
        require(COMPONENT_ID.matches(id)) { "Component ID is not canonical" }
        requireIdentifier(definitionId, "definitionId")
        require(kind in COMPONENT_KINDS) { "Component kind is invalid" }
        require(platform in COMPONENT_PLATFORMS) { "Component platform is invalid" }
        require(status == "active" || status == "revoked") { "Component status is invalid" }
        require(Base64Url.decode(dpopJkt).size == 32) { "Component DPoP thumbprint is invalid" }
        require(grantedFeatures.isNotEmpty() && grantedFeatures.size <= 256)
        grantedFeatures.forEach { requireIdentifier(it, "grantedFeatures") }
    }
}

public data class ComponentTrustSummary(
    val provider: String,
    val level: String,
    val source: String,
    val parentComponentId: String,
    val parentAttestationProvider: String?,
    val delegationId: String,
    val verifiedAt: String,
    val expiresAt: String,
) {
    init {
        require(provider in ATTESTATION_PROVIDERS) { "Component trust provider is invalid" }
        require(level in COMPONENT_TRUST_LEVELS) { "Component trust level is invalid" }
        require(source in COMPONENT_SESSION_TRUST_SOURCES) { "Component trust source is invalid" }
        require(COMPONENT_ID.matches(parentComponentId)) { "Parent component ID is not canonical" }
        require(parentAttestationProvider == null || parentAttestationProvider in ATTESTATION_PROVIDERS) {
            "Parent attestation provider is invalid"
        }
        require(DELEGATION_ID.matches(delegationId)) { "Component delegation ID is not canonical" }
        val verified = parseRfc3339EpochSeconds(verifiedAt)
        val expires = parseRfc3339EpochSeconds(expiresAt)
        require(expires > verified) { "Component trust lifetime is invalid" }
    }
}

/** Native-only rotating credentials for one independently keyed client component. */
public class ComponentSessionSnapshot(
    public val accessToken: SecretValue,
    public val refreshToken: SecretValue,
    public val accessExpiresAtEpochSeconds: Long,
    public val refreshExpiresAtEpochSeconds: Long,
    public val installation: InstallationSummary,
    public val installationFamily: InstallationFamilySummary,
    public val component: ClientComponentSummary,
    public val trust: ComponentTrustSummary,
) {
    init {
        require(accessExpiresAtEpochSeconds > 0)
        require(refreshExpiresAtEpochSeconds > accessExpiresAtEpochSeconds)
        require(INSTALLATION_ID.matches(installation.id))
        require(installation.status == "active")
        require(installation.platform == component.platform)
        require(installation.dpopJkt == component.dpopJkt)
        require(installationFamily.status == "active")
        require(component.status == "active" && !component.isRoot)
    }

    override fun toString(): String =
        "ComponentSessionSnapshot(component=${component.id}, family=${installationFamily.id}, " +
            "accessExpiresAt=$accessExpiresAtEpochSeconds, refreshExpiresAt=$refreshExpiresAtEpochSeconds, " +
            "credentials=[REDACTED])"
}

public interface ComponentSessionStateStore {
    public suspend fun load(): ComponentSessionSnapshot?
    public suspend fun save(snapshot: ComponentSessionSnapshot)
    public suspend fun clear()

    /** Permanently retires this component's encrypted state namespace. */
    public suspend fun destroy(): Unit = clear()
}

/** AES-256-GCM component state whose wrapping key remains in Android Keystore. */
public class AndroidEncryptedComponentSessionStateStore(
    context: Context,
    namespace: String,
) : ComponentSessionStateStore {
    private val preferences = context.applicationContext.getSharedPreferences(
        "dev.latchway.component.$namespace",
        Context.MODE_PRIVATE,
    )
    private val keyAlias = "dev.latchway.component.$namespace.aes.v1"
    private val aad = "latchway-component-session-v1:$namespace".toByteArray(StandardCharsets.UTF_8)
    private val mutex = SessionStateNamespaceLocks.lock("component:$namespace")

    init {
        require(NAMESPACE.matches(namespace)) { "Component state namespace is invalid" }
    }

    override suspend fun load(): ComponentSessionSnapshot? = mutex.withLock { loadLocked() }

    override suspend fun save(snapshot: ComponentSessionSnapshot): Unit = mutex.withLock {
        withContext(Dispatchers.IO) {
            try {
                val encrypted = SessionStateEncryption.encrypt(
                    key = encryptionKey(),
                    aad = aad,
                    plaintext = encodeComponentSnapshot(snapshot).toByteArray(StandardCharsets.UTF_8),
                )
                if (!preferences.edit()
                        .putString(VERSION, "1")
                        .putString(IV, Base64Url.encode(encrypted.iv))
                        .putString(CIPHERTEXT, Base64Url.encode(encrypted.ciphertext))
                        .commit()
                ) {
                    throw IllegalStateException("Encrypted component state could not be persisted")
                }
            } catch (error: LatchwayException) {
                throw error
            } catch (error: CancellationException) {
                throw error
            } catch (error: Exception) {
                throw LatchwayException(
                    code = LatchwayErrorCode.SECURE_STATE_UNAVAILABLE,
                    safeMessage = "Encrypted component state could not be saved",
                    cause = error,
                )
            }
        }
    }

    override suspend fun clear(): Unit = mutex.withLock {
        withContext(Dispatchers.IO) {
            if (!preferences.edit().clear().commit()) {
                throw LatchwayException(
                    code = LatchwayErrorCode.SECURE_STATE_UNAVAILABLE,
                    safeMessage = "Encrypted component state could not be cleared",
                )
            }
        }
    }

    /** Clears ciphertext and removes the component-specific wrapping key. */
    override suspend fun destroy(): Unit = mutex.withLock {
        withContext(Dispatchers.IO) {
            if (!preferences.edit().clear().commit()) {
                throw LatchwayException(
                    code = LatchwayErrorCode.SECURE_STATE_UNAVAILABLE,
                    safeMessage = "Encrypted component state could not be cleared",
                )
            }
            val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            if (keyStore.containsAlias(keyAlias)) keyStore.deleteEntry(keyAlias)
        }
    }

    private suspend fun loadLocked(): ComponentSessionSnapshot? = withContext(Dispatchers.IO) {
        val ciphertext = preferences.getString(CIPHERTEXT, null) ?: return@withContext null
        val iv = preferences.getString(IV, null) ?: return@withContext corruptState()
        if (preferences.getString(VERSION, null) != "1") return@withContext corruptState()
        try {
            val plaintext = SessionStateEncryption.decrypt(
                key = encryptionKey(),
                aad = aad,
                blob = EncryptedSessionBlob(Base64Url.decode(iv), Base64Url.decode(ciphertext)),
            )
            decodeComponentSnapshot(String(plaintext, StandardCharsets.UTF_8))
        } catch (error: LatchwayException) {
            throw error
        } catch (error: CancellationException) {
            throw error
        } catch (error: Exception) {
            corruptState(error)
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
            safeMessage = "Encrypted component state was invalid and has been cleared",
            cause = cause,
        )
    }

    private companion object {
        const val VERSION = "version"
        const val IV = "iv"
        const val CIPHERTEXT = "ciphertext"
        val NAMESPACE = Regex("^[A-Za-z0-9._-]{1,80}$")
    }
}

public data class LatchwayComponentDiagnostics(
    val familyId: String?,
    val componentId: String?,
    val definitionId: String,
    val keyAvailable: Boolean,
    val keyBacking: KeyBacking,
    val grantAvailable: Boolean,
    val sessionAvailable: Boolean,
    val trustSource: String?,
    val trustExpiresAt: String?,
    val containingAppActionRequired: Boolean,
)

public class LatchwayComponentClient internal constructor(
    private val coordinator: ComponentSessionCoordinator,
) : Closeable {
    public suspend fun authorize(
        method: String,
        uri: java.net.URI,
        feature: String,
        nonce: String? = null,
    ): AuthorizedHeaders = coordinator.authorize(method, uri, feature, nonce)

    public suspend fun refresh(): Unit = coordinator.forceRefresh()
    public suspend fun clearSession(): Unit = coordinator.clearSession()
    /** Clears only the credential generation that produced [authorization]. */
    public suspend fun clearSessionIfCurrent(authorization: AuthorizedHeaders): Unit =
        coordinator.clearSessionIfCurrent(authorization.accessTokenFingerprint)
    public suspend fun revoke(): Unit = coordinator.revoke()
    public suspend fun diagnostics(): LatchwayComponentDiagnostics = coordinator.diagnostics()
    /** Applies a trusted terminal component problem and destroys only this component's state. */
    public suspend fun markTerminal(code: LatchwayErrorCode): Unit = coordinator.markTerminal(code)
    override fun close(): Unit = Unit
}

internal data class ComponentProvisioning(
    val componentId: String,
    val familyId: String,
    val definitionId: String,
    val publicJwk: PublicJwk,
    val trust: ComponentProvisioningTrust,
    val grantedFeatures: Set<String>,
    val refreshGrant: SecretValue,
    val refreshGrantExpiresAtEpochSeconds: Long,
)

internal data class ComponentProvisioningTrust(
    val source: String,
    val expiresAt: String,
) {
    init {
        require(source in PROVISIONING_TRUST_SOURCES)
        parseRfc3339EpochSeconds(expiresAt)
    }
}

private data class InitialComponentCredentials(
    val accessToken: SecretValue,
    val refreshToken: SecretValue,
    val accessExpiresAtEpochSeconds: Long,
    val refreshExpiresAtEpochSeconds: Long,
)

private data class ComponentSessionExpectation(
    val familyId: String,
    val componentId: String,
    val definitionId: String,
    val platform: String,
    val dpopJkt: String,
    val grantedFeatures: Set<String>,
    val trustSource: String,
    val maximumTrustExpiresAtEpochSeconds: Long,
    val installationId: String? = null,
    val componentKind: String? = null,
    val stableTrust: ComponentTrustSummary? = null,
)

internal class ComponentSessionCoordinator(
    private val configuration: CoreConfiguration,
    private val rootCoordinator: SessionCoordinator,
    private val definitionId: String,
    private val signer: InstallationSigner,
    private val stateStore: ComponentSessionStateStore,
    private val transport: LatchwayTransport,
    private val clock: LatchwayClock,
) {
    private val mutex = Mutex()
    private val proofFactory = DpopProofFactory(signer, clock)
    private val signerIdentity = signer.publicJwk.thumbprint()
    private val sessionCoordinationKey = SessionCoordinationKey(
        baseUrl = coordinationOrigin(configuration.baseUrl),
        applicationId = configuration.applicationId,
        environment = configuration.environment,
        identityProvider = configuration.identityProvider,
        platform = configuration.clientPlatform.wireValue,
        signerIdentity = signerIdentity,
    )
    private val resettableSigner = signer as? ResettableInstallationSigner
    @Volatile private var componentRevocationAccepted = false
    @Volatile private var localRetirementComplete = false

    suspend fun provision(provisioning: ComponentProvisioning): LatchwayComponentClient {
        require(provisioning.definitionId == definitionId)
        require(provisioning.publicJwk.thumbprint() == signerIdentity)
        SessionCoordinationLocks.withSession(sessionCoordinationKey) {
            val snapshot = createInitialSession(provisioning)
            saveIfCurrent(snapshot)
        }
        return LatchwayComponentClient(this)
    }

    suspend fun open(definitionId: String): LatchwayComponentClient =
        SessionCoordinationLocks.withSession(sessionCoordinationKey) {
            val state = loadCurrent() ?: throw LatchwayException(
                code = LatchwayErrorCode.COMPONENT_NOT_PROVISIONED,
                safeMessage = "The containing application must provision this component before use",
            )
            if (state.component.definitionId != definitionId) {
                throw LatchwayException(
                    code = LatchwayErrorCode.COMPONENT_NOT_PROVISIONED,
                    safeMessage = "The stored component does not match the requested definition",
                )
            }
            LatchwayComponentClient(this)
        }

    suspend fun authorize(
        method: String,
        uri: java.net.URI,
        feature: String,
        nonce: String?,
    ): AuthorizedHeaders {
        requireIdentifier(feature, "feature")
        requireComponentDataPlaneDestination(configuration.baseUrl, uri, method, feature)
        val state = currentSession(forceRefresh = false)
        if (feature !in state.component.grantedFeatures) {
            throw LatchwayException(
                code = LatchwayErrorCode.COMPONENT_FEATURE_NOT_GRANTED,
                safeMessage = "The requested feature was not delegated to this component",
            )
        }
        val proof = proofFactory.create(
            DpopProofRequest(method.uppercase(), uri, state.accessToken, nonce),
        )
        ensureSignerCurrent()
        return AuthorizedHeaders(state.accessToken, proof, newRequestId())
    }

    suspend fun forceRefresh() {
        currentSession(forceRefresh = true)
    }

    suspend fun clearSession() {
        SessionCoordinationLocks.withSession(sessionCoordinationKey) {
            stateStore.clear()
        }
    }

    suspend fun clearSessionIfCurrent(expectedAccessTokenFingerprint: String) {
        SessionCoordinationLocks.withSession(sessionCoordinationKey) {
            val current = loadCurrent() ?: return@withSession
            if (accessTokenFingerprint(current.accessToken) == expectedAccessTokenFingerprint) {
                stateStore.clear()
            }
        }
    }

    suspend fun markTerminal(code: LatchwayErrorCode) {
        require(code in COMPONENT_TERMINAL_CODES)
        SessionCoordinationLocks.withSession(sessionCoordinationKey) { retireLocal() }
    }

    suspend fun revoke(): Unit = SessionCoordinationLocks.withSession(sessionCoordinationKey) {
        if (localRetirementComplete) return@withSession
        if (!componentRevocationAccepted) {
            val state = loadCurrent()
            if (state == null) {
                retireLocal()
                return@withSession
            }
            try {
                rootCoordinator.revokeComponent(state.component.id)
                componentRevocationAccepted = true
            } catch (error: LatchwayException) {
                if (error.code in COMPONENT_TERMINAL_CODES) retireLocal()
                throw error
            }
        }
        retireLocal()
    }

    suspend fun diagnostics(): LatchwayComponentDiagnostics {
        val keyAvailable = resettableSigner?.isCurrent() ?: true
        val state = if (keyAvailable) runCatching { stateStore.load() }.getOrNull() else null
        return LatchwayComponentDiagnostics(
            familyId = state?.installationFamily?.id,
            componentId = state?.component?.id,
            definitionId = state?.component?.definitionId ?: definitionId,
            keyAvailable = keyAvailable,
            keyBacking = signer.diagnostics.backing,
            grantAvailable = false,
            sessionAvailable = state != null,
            trustSource = state?.trust?.source,
            trustExpiresAt = state?.trust?.expiresAt,
            containingAppActionRequired = state == null,
        )
    }

    private suspend fun currentSession(forceRefresh: Boolean): ComponentSessionSnapshot = mutex.withLock {
        SessionCoordinationLocks.withSession(sessionCoordinationKey) {
            if (localRetirementComplete) {
                throw LatchwayException(
                    code = LatchwayErrorCode.COMPONENT_REVOKED,
                    safeMessage = "This client component has been retired",
                )
            }
            val state = loadCurrent() ?: throw LatchwayException(
                code = LatchwayErrorCode.COMPONENT_NOT_PROVISIONED,
                safeMessage = "The containing application must provision this component before use",
            )
            val now = clock.epochSeconds()
            if (!forceRefresh && state.accessExpiresAtEpochSeconds - configuration.refreshLeewaySeconds > now) {
                return@withSession state
            }
            if (state.refreshExpiresAtEpochSeconds - configuration.refreshLeewaySeconds <= now) {
                throw LatchwayException(
                    code = LatchwayErrorCode.COMPONENT_PARENT_TRUST_EXPIRED,
                    safeMessage = "The containing application must renew component trust",
                )
            }
            try {
                refreshSession(state).also { saveIfCurrent(it) }
            } catch (error: LatchwayException) {
                when (error.code) {
                    in COMPONENT_TERMINAL_CODES -> retireLocal()
                    LatchwayErrorCode.SESSION_REVOKED,
                    LatchwayErrorCode.REFRESH_TOKEN_REUSED,
                    LatchwayErrorCode.COMPONENT_NOT_PROVISIONED,
                    LatchwayErrorCode.COMPONENT_DELEGATION_EXPIRED,
                    LatchwayErrorCode.COMPONENT_PARENT_TRUST_EXPIRED -> stateStore.clear()
                    else -> Unit
                }
                throw error
            }
        }
    }

    private suspend fun createInitialSession(provisioning: ComponentProvisioning): ComponentSessionSnapshot {
        if (provisioning.refreshGrantExpiresAtEpochSeconds <= clock.epochSeconds()) {
            throw LatchwayException(
                code = LatchwayErrorCode.COMPONENT_DELEGATION_EXPIRED,
                safeMessage = "The component provisioning grant expired",
            )
        }
        val response = executeDpopControl(
            method = "POST",
            path = "/client/v1/component-sessions",
            body = JSONObject()
                .put("component_id", provisioning.componentId)
                .put("refresh_grant", provisioning.refreshGrant.reveal()),
            accessToken = null,
        )
        requireSuccess(response, setOf(201))
        val initial = parseInitialComponentSession(
            encoded = response.utf8Body(),
            nowEpochSeconds = clock.epochSeconds(),
        )
        require(
            initial.refreshExpiresAtEpochSeconds <=
                parseRfc3339EpochSeconds(provisioning.trust.expiresAt),
        ) { "Initial component credentials exceeded the delegated trust lifetime" }
        val refreshed = executeDpopControl(
            method = "POST",
            path = "/client/v1/sessions/refresh",
            body = JSONObject().put("refresh_token", initial.refreshToken.reveal()),
            accessToken = null,
        )
        requireSuccess(refreshed)
        return parseRefreshedComponentSession(
            encoded = refreshed.utf8Body(),
            expectation = ComponentSessionExpectation(
                familyId = provisioning.familyId,
                componentId = provisioning.componentId,
                definitionId = provisioning.definitionId,
                platform = configuration.clientPlatform.wireValue,
                dpopJkt = signerIdentity,
                grantedFeatures = provisioning.grantedFeatures,
                trustSource = provisioning.trust.source,
                maximumTrustExpiresAtEpochSeconds = parseRfc3339EpochSeconds(provisioning.trust.expiresAt),
            ),
            nowEpochSeconds = clock.epochSeconds(),
            maximumClockSkewSeconds = configuration.maximumClockSkewSeconds,
        )
    }

    private suspend fun refreshSession(state: ComponentSessionSnapshot): ComponentSessionSnapshot {
        val response = executeDpopControl(
            method = "POST",
            path = "/client/v1/sessions/refresh",
            body = JSONObject().put("refresh_token", state.refreshToken.reveal()),
            accessToken = null,
        )
        requireSuccess(response)
        return parseRefreshedComponentSession(
            encoded = response.utf8Body(),
            expectation = ComponentSessionExpectation(
                familyId = state.installationFamily.id,
                componentId = state.component.id,
                definitionId = state.component.definitionId,
                platform = state.component.platform,
                dpopJkt = signerIdentity,
                grantedFeatures = state.component.grantedFeatures,
                trustSource = state.trust.source,
                maximumTrustExpiresAtEpochSeconds = parseRfc3339EpochSeconds(state.trust.expiresAt),
                installationId = state.installation.id,
                componentKind = state.component.kind,
                stableTrust = state.trust,
            ),
            nowEpochSeconds = clock.epochSeconds(),
            maximumClockSkewSeconds = configuration.maximumClockSkewSeconds,
        )
    }

    private suspend fun executeDpopControl(
        method: String,
        path: String,
        body: JSONObject,
        accessToken: SecretValue?,
    ): LatchwayTransportResponse {
        val uri = configuration.endpoint(path)
        val bytes = body.toString().toByteArray(StandardCharsets.UTF_8)
        require(bytes.size <= MAX_COMPONENT_CONTROL_BYTES)
        var nonce: String? = null
        repeat(2) { attempt ->
            ensureSignerCurrent()
            val proof = proofFactory.create(DpopProofRequest(method, uri, accessToken, nonce))
            ensureSignerCurrent()
            val response = transport.execute(
                LatchwayTransportRequest(
                    method = method,
                    uri = uri,
                    headers = protocolHeaders(configuration, newRequestId()) + mapOf(
                        "Content-Type" to "application/json",
                        "DPoP" to proof.reveal(),
                    ) + if (accessToken != null) {
                        mapOf("Authorization" to "DPoP ${accessToken.reveal()}")
                    } else {
                        emptyMap()
                    },
                    body = bytes,
                ),
            )
            if (attempt == 0 && response.statusCode == 401 && response.header("DPoP-Nonce") != null &&
                runCatching { problem(response).code == LatchwayErrorCode.DPOP_NONCE_REQUIRED }.getOrDefault(false)
            ) {
                nonce = response.header("DPoP-Nonce")?.takeIf {
                    it.length in 16..512 && it.none(Char::isISOControl)
                } ?: throw responseInvalid("The server returned an invalid DPoP nonce")
            } else {
                return response
            }
        }
        throw responseInvalid("DPoP nonce negotiation did not complete")
    }

    private suspend fun loadCurrent(): ComponentSessionSnapshot? {
        ensureSignerCurrent()
        val state = stateStore.load() ?: return null
        if (state.component.dpopJkt != signerIdentity) {
            stateStore.destroy()
            throw LatchwayException(
                code = LatchwayErrorCode.COMPONENT_KEY_REPLACED,
                safeMessage = "The component key was replaced",
            )
        }
        return state
    }

    private suspend fun saveIfCurrent(snapshot: ComponentSessionSnapshot) {
        ensureSignerCurrent()
        stateStore.save(snapshot)
        ensureSignerCurrent()
    }

    private suspend fun ensureSignerCurrent() {
        if (resettableSigner?.isCurrent() == false) {
            stateStore.destroy()
            throw LatchwayException(
                code = LatchwayErrorCode.COMPONENT_KEY_REPLACED,
                safeMessage = "The component key was reset or replaced",
            )
        }
    }

    private suspend fun retireLocal(): Unit = withContext(NonCancellable) {
        try {
            stateStore.destroy()
        } finally {
            resettableSigner?.reset()
            localRetirementComplete = true
        }
    }
}

internal fun parseComponentProvisioning(
    encoded: String,
    definitionId: String,
    publicJwk: PublicJwk,
    requestedFeatures: Set<String>,
    nowEpochSeconds: Long,
): ComponentProvisioning = try {
    val json = JSONObject(encoded)
    requireExactKeys(
        json,
        setOf(
            "component_id", "installation_family_id", "trust", "granted_features",
            "refresh_grant", "refresh_grant_expires_at",
        ),
    )
    val componentId = json.getString("component_id").also { require(COMPONENT_ID.matches(it)) }
    val familyId = json.getString("installation_family_id").also { require(FAMILY_ID.matches(it)) }
    val trustJson = json.getJSONObject("trust")
    requireExactKeys(trustJson, setOf("source", "expires_at"))
    val trust = ComponentProvisioningTrust(
        source = trustJson.getString("source"),
        expiresAt = trustJson.getString("expires_at"),
    )
    val trustExpiry = parseRfc3339EpochSeconds(trust.expiresAt)
    val refreshExpiryText = json.getString("refresh_grant_expires_at")
    val refreshExpiry = parseRfc3339EpochSeconds(refreshExpiryText)
    require(refreshExpiry == trustExpiry && refreshExpiry > nowEpochSeconds)
    val features = json.getJSONArray("granted_features").toIdentifierSet()
    require(features.isNotEmpty() && requestedFeatures.containsAll(features))
    val refreshGrant = json.getString("refresh_grant").also {
        require(it.length in 32..2_048 && it.none(Char::isISOControl) && it.trim() == it)
    }
    ComponentProvisioning(
        componentId = componentId,
        familyId = familyId,
        definitionId = definitionId,
        publicJwk = publicJwk,
        trust = trust,
        grantedFeatures = features,
        refreshGrant = SecretValue.of(refreshGrant),
        refreshGrantExpiresAtEpochSeconds = refreshExpiry,
    )
} catch (error: LatchwayException) {
    throw error
} catch (error: Exception) {
    throw responseInvalid("The server returned invalid component provisioning", error)
}

private fun parseInitialComponentSession(
    encoded: String,
    nowEpochSeconds: Long,
): InitialComponentCredentials = try {
    val json = JSONObject(encoded)
    requireExactKeys(json, setOf("access_token", "expires_in", "refresh_token", "refresh_expires_at"))
    val access = json.getString("access_token").also { require(it.length in 64..16_384) }
    val refresh = json.getString("refresh_token").also { require(it.length in 32..2_048) }
    val expiresIn = json.getLong("expires_in").also { require(it in 60..3_600) }
    val refreshExpiresAt = parseRfc3339EpochSeconds(json.getString("refresh_expires_at"))
    val accessExpiresAt = nowEpochSeconds + expiresIn
    require(refreshExpiresAt > accessExpiresAt)
    InitialComponentCredentials(
        accessToken = SecretValue.of(access),
        refreshToken = SecretValue.of(refresh),
        accessExpiresAtEpochSeconds = accessExpiresAt,
        refreshExpiresAtEpochSeconds = refreshExpiresAt,
    )
} catch (error: Exception) {
    if (error is LatchwayException) throw error
    throw responseInvalid("The server returned an invalid component session", error)
}

private fun parseRefreshedComponentSession(
    encoded: String,
    expectation: ComponentSessionExpectation,
    nowEpochSeconds: Long,
    maximumClockSkewSeconds: Long,
): ComponentSessionSnapshot = try {
    val json = JSONObject(encoded)
    requireExactKeys(
        json,
        setOf(
            "access_token", "token_type", "expires_in", "refresh_token", "refresh_expires_in",
            "installation", "installation_family", "component", "trust",
        ),
    )
    val access = json.getString("access_token").also { require(it.length in 64..16_384) }
    require(json.getString("token_type") == "DPoP")
    val refresh = json.getString("refresh_token").also { require(it.length in 32..2_048) }
    val expiresIn = json.getLong("expires_in").also { require(it in 60..3_600) }
    val refreshExpiresIn = json.getLong("refresh_expires_in").also { require(it in 300..31_536_000) }
    val familyJson = json.getJSONObject("installation_family")
    requireExactKeys(familyJson, setOf("id", "status"))
    val family = InstallationFamilySummary(familyJson.getString("id"), familyJson.getString("status"))
    require(family.id == expectation.familyId && family.status == "active")
    val componentJson = json.getJSONObject("component")
    requireExactKeys(
        componentJson,
        setOf("id", "definition_id", "kind", "platform", "is_root", "status", "dpop_jkt", "granted_features"),
    )
    val component = ClientComponentSummary(
        id = componentJson.getString("id"),
        definitionId = componentJson.getString("definition_id"),
        kind = componentJson.getString("kind"),
        platform = componentJson.getString("platform"),
        isRoot = componentJson.getBoolean("is_root"),
        status = componentJson.getString("status"),
        dpopJkt = componentJson.getString("dpop_jkt"),
        grantedFeatures = componentJson.getJSONArray("granted_features").toIdentifierSet(),
    )
    require(
        component.id == expectation.componentId &&
            component.definitionId == expectation.definitionId &&
            component.platform == expectation.platform &&
            component.dpopJkt == expectation.dpopJkt &&
            component.grantedFeatures == expectation.grantedFeatures &&
            (expectation.componentKind == null || component.kind == expectation.componentKind) &&
            !component.isRoot,
    )
    val installation = json.getJSONObject("installation")
    requireExactKeys(installation, setOf("id", "platform", "dpop_jkt", "status"))
    val installationSummary = InstallationSummary(
        id = installation.getString("id"),
        platform = installation.getString("platform"),
        dpopJkt = installation.getString("dpop_jkt"),
        status = installation.getString("status"),
    )
    require(INSTALLATION_ID.matches(installationSummary.id))
    require(expectation.installationId == null || installationSummary.id == expectation.installationId)
    require(installationSummary.dpopJkt == expectation.dpopJkt)
    require(installationSummary.platform == component.platform)
    require(installationSummary.status == "active")
    val trustJson = json.getJSONObject("trust")
    requireAllowedKeys(
        trustJson,
        required = setOf(
            "provider", "level", "source", "parent_component_id", "delegation_id",
            "verified_at", "expires_at",
        ),
        optional = setOf("parent_attestation_provider"),
    )
    val trust = ComponentTrustSummary(
        provider = trustJson.getString("provider"),
        level = trustJson.getString("level"),
        source = trustJson.getString("source"),
        parentComponentId = trustJson.getString("parent_component_id"),
        parentAttestationProvider = trustJson.optString("parent_attestation_provider")
            .takeIf(String::isNotEmpty),
        delegationId = trustJson.getString("delegation_id"),
        verifiedAt = trustJson.getString("verified_at"),
        expiresAt = trustJson.getString("expires_at"),
    )
    require(trust.source == expectation.trustSource)
    require(expectation.stableTrust == null || trust == expectation.stableTrust)
    require(parseRfc3339EpochSeconds(trust.verifiedAt) <= nowEpochSeconds + maximumClockSkewSeconds)
    val refreshExpiresAt = nowEpochSeconds + refreshExpiresIn
    val trustExpiresAt = parseRfc3339EpochSeconds(trust.expiresAt)
    require(
        trustExpiresAt >= refreshExpiresAt &&
            trustExpiresAt == expectation.maximumTrustExpiresAtEpochSeconds,
    )
    ComponentSessionSnapshot(
        accessToken = SecretValue.of(access),
        refreshToken = SecretValue.of(refresh),
        accessExpiresAtEpochSeconds = nowEpochSeconds + expiresIn,
        refreshExpiresAtEpochSeconds = refreshExpiresAt,
        installation = installationSummary,
        installationFamily = family,
        component = component,
        trust = trust,
    )
} catch (error: Exception) {
    if (error is LatchwayException) throw error
    throw responseInvalid("The server returned an invalid refreshed component session", error)
}

internal fun encodeComponentSnapshot(value: ComponentSessionSnapshot): String = JSONObject()
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
    .put("installation_family", JSONObject()
        .put("id", value.installationFamily.id)
        .put("status", value.installationFamily.status))
    .put("component", JSONObject()
        .put("id", value.component.id)
        .put("definition_id", value.component.definitionId)
        .put("kind", value.component.kind)
        .put("platform", value.component.platform)
        .put("is_root", value.component.isRoot)
        .put("status", value.component.status)
        .put("dpop_jkt", value.component.dpopJkt)
        .put("granted_features", JSONArray(value.component.grantedFeatures.sorted())))
    .put("trust", JSONObject()
        .put("provider", value.trust.provider)
        .put("level", value.trust.level)
        .put("source", value.trust.source)
        .put("parent_component_id", value.trust.parentComponentId)
        .apply {
            value.trust.parentAttestationProvider?.let { put("parent_attestation_provider", it) }
        }
        .put("delegation_id", value.trust.delegationId)
        .put("verified_at", value.trust.verifiedAt)
        .put("expires_at", value.trust.expiresAt))
    .toString()

internal fun decodeComponentSnapshot(encoded: String): ComponentSessionSnapshot {
    val json = JSONObject(encoded)
    require(json.getInt("version") == 1)
    val installation = json.getJSONObject("installation")
    val family = json.getJSONObject("installation_family")
    val component = json.getJSONObject("component")
    val trust = json.getJSONObject("trust")
    return ComponentSessionSnapshot(
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
        installationFamily = InstallationFamilySummary(family.getString("id"), family.getString("status")),
        component = ClientComponentSummary(
            id = component.getString("id"),
            definitionId = component.getString("definition_id"),
            kind = component.getString("kind"),
            platform = component.getString("platform"),
            isRoot = component.getBoolean("is_root"),
            status = component.getString("status"),
            dpopJkt = component.getString("dpop_jkt"),
            grantedFeatures = component.getJSONArray("granted_features").toIdentifierSet(),
        ),
        trust = ComponentTrustSummary(
            provider = trust.getString("provider"),
            level = trust.getString("level"),
            source = trust.getString("source"),
            parentComponentId = trust.getString("parent_component_id"),
            parentAttestationProvider = trust.optString("parent_attestation_provider").takeIf(String::isNotEmpty),
            delegationId = trust.getString("delegation_id"),
            verifiedAt = trust.getString("verified_at"),
            expiresAt = trust.getString("expires_at"),
        ),
    )
}

private fun JSONArray.toIdentifierSet(): Set<String> {
    require(length() in 1..256)
    val values = LinkedHashSet<String>(length())
    repeat(length()) { index ->
        val value = getString(index)
        requireIdentifier(value, "grantedFeatures")
        require(values.add(value))
    }
    return values
}

private fun requireExactKeys(json: JSONObject, expected: Set<String>) {
    require(json.length() == expected.size && json.keys().asSequence().toSet() == expected)
}

private fun requireAllowedKeys(json: JSONObject, required: Set<String>, optional: Set<String>) {
    val actual = json.keys().asSequence().toSet()
    require(actual.containsAll(required) && actual.all { it in required || it in optional })
}

/** Public component credentials are usable only on contract-owned, feature-bound data routes. */
internal fun requireComponentDataPlaneDestination(
    baseUrl: java.net.URI,
    target: java.net.URI,
    method: String,
    feature: String,
) {
    requireGatewayDestination(baseUrl, target)
    val basePath = baseUrl.rawPath?.ifEmpty { "/" } ?: "/"
    val targetPath = target.rawPath?.ifEmpty { "/" } ?: "/"
    val relativePath = "/" + targetPath.removePrefix(basePath)
    val normalizedMethod = method.uppercase(java.util.Locale.US)
    val structured = relativePath in COMPONENT_STRUCTURED_DATA_PATHS && normalizedMethod == "POST"
    val opaquePrefix = "/proxy/$feature/"
    val remaining = relativePath.removePrefix(opaquePrefix)
    val lowerRemaining = remaining.lowercase(java.util.Locale.US)
    val opaque = normalizedMethod in COMPONENT_OPAQUE_DATA_METHODS &&
        target.rawQuery == null && relativePath.startsWith(opaquePrefix) &&
        remaining.length in 1..2_048 &&
        remaining.split('/').all { it.isNotEmpty() && it != "." && it != ".." } &&
        "%2e" !in lowerRemaining && "%2f" !in lowerRemaining && "%5c" !in lowerRemaining &&
        '\\' !in remaining && !remaining.startsWith("http:", ignoreCase = true) &&
        !remaining.startsWith("https:", ignoreCase = true)
    if (!structured && !opaque) {
        throw LatchwayException(
            code = LatchwayErrorCode.TRANSPORT_DESTINATION_NOT_ALLOWED,
            safeMessage = "Component authorization is limited to contract-owned data-plane routes",
        )
    }
}

private const val MAX_COMPONENT_CONTROL_BYTES = 512 * 1024
private val FAMILY_ID = Regex("^fam_[A-Za-z0-9_-]{16,128}$")
private val COMPONENT_ID = Regex("^cmp_[A-Za-z0-9_-]{16,128}$")
private val INSTALLATION_ID = Regex("^ins_[A-Za-z0-9_-]{16,128}$")
private val DELEGATION_ID = Regex("^dlg_[A-Za-z0-9_-]{16,128}$")
private val PROVISIONING_TRUST_SOURCES = setOf(
    "delegated_from_attested_root",
    "delegated_identity_only",
)
private val COMPONENT_SESSION_TRUST_SOURCES = PROVISIONING_TRUST_SOURCES + "delegated_direct_attested"
private val COMPONENT_TRUST_LEVELS = setOf(
    "none", "identity_only", "web_risk_verified", "app_verified", "device_verified",
    "strong_device_verified", "debug",
)
private val COMPONENT_TERMINAL_CODES = setOf(
    LatchwayErrorCode.COMPONENT_REVOKED,
    LatchwayErrorCode.COMPONENT_KEY_INVALID,
    LatchwayErrorCode.COMPONENT_KEY_REPLACED,
    LatchwayErrorCode.INSTALLATION_FAMILY_REVOKED,
    LatchwayErrorCode.INSTALLATION_FAMILY_NOT_FOUND,
)
private val COMPONENT_PLATFORMS = setOf("ios", "android", "web", "react_native_ios", "react_native_android", "node")
private val COMPONENT_STRUCTURED_DATA_PATHS = setOf(
    "/v1/responses",
    "/v1/chat/completions",
    "/v1/embeddings",
    "/v1/messages",
)
private val COMPONENT_OPAQUE_DATA_METHODS = setOf("GET", "POST", "PUT", "PATCH", "DELETE")
private val COMPONENT_KINDS = setOf(
    "main_app", "widget", "share_extension", "app_intent_extension",
    "notification_service_extension", "action_extension", "sso_extension",
    "watch_extension", "android_app", "wear_app", "browser", "node_process",
)
