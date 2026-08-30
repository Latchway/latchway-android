package dev.latchway.core

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.cancel
import kotlinx.coroutines.joinAll
import kotlinx.coroutines.withContext
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.json.JSONArray
import org.json.JSONException
import org.json.JSONObject
import java.net.URI
import java.nio.charset.StandardCharsets
import java.util.Locale
import java.util.UUID
import java.util.concurrent.atomic.AtomicBoolean

internal class SessionCoordinator(
    private val configuration: CoreConfiguration,
    private val identityTokenProvider: IdentityTokenProvider,
    private val attestationProvider: AttestationProvider,
    private val signer: InstallationSigner,
    private val stateStore: SessionStateStore,
    private val transport: LatchwayTransport,
    private val installationMetadata: InstallationMetadata,
    private val clock: LatchwayClock,
) {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val sessionMutex = Mutex()
    private val revocationMutex = Mutex()
    private var inFlightSession: Deferred<SessionSnapshot>? = null
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
    private val installationRevoked = AtomicBoolean(false)
    @Volatile private var revocationCleanupComplete = false

    suspend fun authorize(method: String, uri: URI, feature: String, nonce: String?): AuthorizedHeaders {
        requireIdentifier(feature, "feature")
        requireGatewayDestination(configuration.baseUrl, uri)
        val state = currentSession(forceRefresh = false)
        val requestId = newRequestId()
        val proof = proofFactory.create(
            DpopProofRequest(
                method = method.uppercase(),
                uri = uri,
                accessToken = state.accessToken,
                nonce = nonce,
            ),
        )
        ensureInstallationActive()
        return AuthorizedHeaders(state.accessToken, proof, requestId)
    }

    suspend fun quota(feature: String): LatchwayQuotaSnapshot {
        requireIdentifier(feature, "feature")
        val response = executeProtected("GET", "/client/v1/features/$feature/quota")
        requireSuccess(response)
        return parseQuota(response.utf8Body())
    }

    suspend fun diagnostics(): LatchwayDiagnostics {
        val response = executeProtected("GET", "/client/v1/diagnostics")
        requireSuccess(response)
        return parseDiagnostics(
            response.utf8Body(),
            signer.diagnostics,
            configuration.clientPlatform.wireValue,
        )
    }

    suspend fun revokeCurrentInstallation() {
        val response = executeProtected("DELETE", "/client/v1/installations/current")
        if (response.statusCode == 204) {
            cleanupRevokedInstallation()
            return
        }
        throw problem(response)
    }

    suspend fun revokeCurrentInstallationFamily() {
        val response = executeProtected("DELETE", "/client/v1/installation-families/current")
        if (response.statusCode == 204) {
            cleanupRevokedInstallation()
            return
        }
        throw problem(response)
    }

    suspend fun revokeComponent(componentId: String) {
        require(COMPONENT_ID.matches(componentId)) { "componentId is not canonical" }
        val response = executeProtected(
            "DELETE",
            "/client/v1/installation-families/current/components/$componentId",
        )
        requireSuccess(response, setOf(204))
    }

    suspend fun provisionComponentClient(
        definitionId: String,
        requestedFeatures: Set<String>,
        signer: InstallationSigner,
        stateStore: ComponentSessionStateStore,
    ): LatchwayComponentClient {
        requireIdentifier(definitionId, "definitionId")
        require(requestedFeatures.isNotEmpty() && requestedFeatures.size <= 256) {
            "requestedFeatures must contain between 1 and 256 unique features"
        }
        requestedFeatures.forEach { requireIdentifier(it, "requestedFeatures") }
        val features = requestedFeatures.toList().sorted()
        val body = JSONObject()
            .put("component_definition_id", definitionId)
            .put("public_jwk", JSONObject()
                .put("kty", signer.publicJwk.kty)
                .put("crv", signer.publicJwk.crv)
                .put("x", signer.publicJwk.x)
                .put("y", signer.publicJwk.y))
            .put("requested_features", JSONArray(features))
            .put("client_metadata", JSONObject()
                .put("app_version", installationMetadata.appVersion)
                .put("sdk_version", configuration.sdkVersion))
        val response = executeProtected(
            method = "POST",
            path = "/client/v1/installation-families/current/components",
            body = body,
        )
        requireSuccess(response, setOf(201))
        val provisioning = parseComponentProvisioning(
            encoded = response.utf8Body(),
            definitionId = definitionId,
            publicJwk = signer.publicJwk,
            requestedFeatures = requestedFeatures,
            nowEpochSeconds = clock.epochSeconds(),
        )
        return ComponentSessionCoordinator(
            configuration = configuration,
            rootCoordinator = this,
            definitionId = definitionId,
            signer = signer,
            stateStore = stateStore,
            transport = transport,
            clock = clock,
        ).provision(provisioning)
    }

    suspend fun openComponentClient(
        definitionId: String,
        signer: InstallationSigner,
        stateStore: ComponentSessionStateStore,
    ): LatchwayComponentClient {
        requireIdentifier(definitionId, "definitionId")
        return ComponentSessionCoordinator(
            configuration = configuration,
            rootCoordinator = this,
            definitionId = definitionId,
            signer = signer,
            stateStore = stateStore,
            transport = transport,
            clock = clock,
        ).open(definitionId)
    }

    suspend fun markCurrentInstallationRevoked() {
        cleanupRevokedInstallation()
    }

    suspend fun forceRefresh() {
        currentSession(forceRefresh = true)
    }

    suspend fun clearSession() {
        if (installationRevoked.get() || InstallationKeyRetirements.isRetired(signerIdentity)) {
            cleanupRevokedInstallation()
            return
        }
        val pending = sessionMutex.withLock {
            inFlightSession?.also { it.cancel() }.also { inFlightSession = null }
        }
        pending?.let { joinAll(it) }
        clearPersistedState(signerIdentity)
    }

    suspend fun clearSessionIfCurrent(expectedAccessTokenFingerprint: String) {
        clearPersistedSession(expectedAccessTokenFingerprint)
    }

    fun close() {
        scope.cancel()
    }

    private suspend fun currentSession(forceRefresh: Boolean): SessionSnapshot {
        ensureInstallationActive()
        val task = try {
            sessionMutex.withLock {
                throwIfInstallationRevoked()
                inFlightSession?.takeIf { it.isActive } ?: scope.async {
                    SessionCoordinationLocks.withSession(sessionCoordinationKey) {
                        throwIfInstallationRevoked()
                        val stored = loadCurrentSignerState()
                        val now = clock.epochSeconds()
                        when {
                            !forceRefresh && stored != null &&
                                stored.accessExpiresAtEpochSeconds - configuration.refreshLeewaySeconds > now -> stored
                            stored != null &&
                                stored.refreshExpiresAtEpochSeconds - configuration.refreshLeewaySeconds > now -> {
                                try {
                                    refreshSession(stored)
                                } catch (error: LatchwayException) {
                                    if (error.code.clearsSession()) clearPersistedSession(stored)
                                    if (error.code.allowsNewSession()) {
                                        clearPersistedSession(stored)
                                        establishSession()
                                    } else {
                                        throw error
                                    }
                                }
                            }
                            else -> establishSession()
                        }
                    }
                }.also { inFlightSession = it }
            }
        } catch (error: LatchwayException) {
            if (error.code.isRootTerminal()) cleanupRevokedInstallation()
            throw error
        }
        return try {
            val result = task.await()
            ensureInstallationActive()
            result
        } catch (error: LatchwayException) {
            if (error.code.isRootTerminal()) {
                cleanupRevokedInstallation()
            }
            throw error
        } finally {
            sessionMutex.withLock {
                if (inFlightSession === task && task.isCompleted) inFlightSession = null
            }
        }
    }

    private suspend fun cleanupRevokedInstallation() {
        markInstallationRevoked()
        withContext(NonCancellable) {
            sessionMutex.withLock {
                inFlightSession?.cancel()
                inFlightSession = null
            }
            revocationMutex.withLock {
                if (revocationCleanupComplete) return@withLock
                var cleanupFailure: Exception? = null
                try {
                    clearPersistedState(signerIdentity)
                } catch (error: CancellationException) {
                    cleanupFailure = error
                } catch (error: LatchwayException) {
                    cleanupFailure = error
                } catch (error: Exception) {
                    cleanupFailure = LatchwayException(
                        code = LatchwayErrorCode.SECURE_STATE_UNAVAILABLE,
                        safeMessage = "Encrypted session state could not be cleared",
                        cause = error,
                    )
                }
                try {
                    resettableSigner?.let { currentSigner ->
                        InstallationKeyRetirements.resetKey(signerIdentity) {
                            currentSigner.reset()
                        }
                    }
                } catch (error: CancellationException) {
                    cleanupFailure = cleanupFailure ?: error
                } catch (error: LatchwayException) {
                    cleanupFailure = cleanupFailure ?: error
                } catch (error: Exception) {
                    cleanupFailure = cleanupFailure ?: LatchwayException(
                        code = LatchwayErrorCode.KEY_UNAVAILABLE,
                        safeMessage = "The installation signing key could not be reset",
                        cause = error,
                    )
                }
                revocationCleanupComplete = cleanupFailure == null
                cleanupFailure?.let { throw it }
            }
        }
    }

    private fun markInstallationRevoked() {
        InstallationKeyRetirements.retire(signerIdentity)
        installationRevoked.set(true)
    }

    private suspend fun ensureInstallationActive() {
        if (installationRevoked.get() || InstallationKeyRetirements.isRetired(signerIdentity)) {
            cleanupRevokedInstallation()
            throw installationRevokedError()
        }
        throwIfInstallationRevoked()
        ensureSignerCurrent()
    }

    private fun throwIfInstallationRevoked() {
        if (installationRevoked.get() || InstallationKeyRetirements.isRetired(signerIdentity)) {
            throw installationRevokedError()
        }
    }

    private suspend fun ensureSignerCurrent() {
        if (resettableSigner?.isCurrent() == false) {
            throw LatchwayException(
                code = LatchwayErrorCode.KEY_UNAVAILABLE,
                safeMessage = "The installation signing key was reset or replaced",
            )
        }
    }

    private suspend fun ensureInstallationMayPersist() {
        throwIfInstallationRevoked()
        ensureSignerCurrent()
    }

    private suspend fun loadCurrentSignerState(): SessionSnapshot? {
        ensureInstallationMayPersist()
        val stored = stateStore.load() ?: return null
        if (stored.installation.dpopJkt == signerIdentity) return stored
        clearPersistedState(stored.installation.dpopJkt)
        return null
    }

    private suspend fun establishSession(): SessionSnapshot {
        try {
            attestationProvider.warmUp()
        } catch (error: LatchwayException) {
            throw error
        } catch (error: CancellationException) {
            throw error
        } catch (error: Exception) {
            throw LatchwayException(
                code = LatchwayErrorCode.ATTESTATION_INVALID,
                retryable = true,
                safeMessage = "The attestation provider could not prepare",
                cause = error,
            )
        }
        val identityToken = try {
            identityTokenProvider.identityToken()
        } catch (error: LatchwayException) {
            throw error
        } catch (error: CancellationException) {
            throw error
        } catch (error: Exception) {
            throw LatchwayException(
                code = LatchwayErrorCode.IDENTITY_TOKEN_INVALID,
                retryable = true,
                safeMessage = "The identity provider could not provide a token",
                cause = error,
            )
        }.also {
            if (it.length !in 16..65_536) {
                throw LatchwayException(
                    code = LatchwayErrorCode.IDENTITY_TOKEN_INVALID,
                    safeMessage = "The identity provider returned an invalid token",
                )
            }
        }
        val challengeBody = JSONObject()
            .put("application_id", configuration.applicationId)
            .put("environment", configuration.environment)
            .put("identity_provider", configuration.identityProvider)
            .put("identity_token", identityToken)
            .put("platform", configuration.clientPlatform.wireValue)
            .put("sdk_version", configuration.sdkVersion)
        val challengeResponse = executeDpopControl(
            method = "POST",
            path = "/client/v1/session-challenges",
            body = challengeBody,
        )
        requireSuccess(challengeResponse, setOf(201))
        val challenge = parseChallenge(
            encoded = challengeResponse.utf8Body(),
            nowEpochSeconds = clock.epochSeconds(),
            maximumClockSkewSeconds = configuration.maximumClockSkewSeconds,
        )
        val evidence = try {
            attestationProvider.attest(challenge)
        } catch (error: LatchwayException) {
            throw error
        } catch (error: CancellationException) {
            throw error
        } catch (error: Exception) {
            throw LatchwayException(
                code = LatchwayErrorCode.ATTESTATION_INVALID,
                retryable = true,
                safeMessage = "The attestation provider could not produce evidence",
                cause = error,
            )
        }
        if (challenge.expiresAtEpochSeconds + configuration.maximumClockSkewSeconds <= clock.epochSeconds()) {
            throw LatchwayException(
                code = LatchwayErrorCode.ATTESTATION_STALE,
                safeMessage = "The attestation challenge expired before exchange",
            )
        }
        if (evidence.provider != challenge.provider) {
            throw LatchwayException(
                code = LatchwayErrorCode.ATTESTATION_INVALID,
                safeMessage = "The attestation provider returned mismatched evidence",
            )
        }
        val evidenceJson = try {
            mapToJson(evidence.evidence)
        } catch (error: CancellationException) {
            throw error
        } catch (error: Exception) {
            throw LatchwayException(
                code = LatchwayErrorCode.ATTESTATION_INVALID,
                safeMessage = "The attestation provider returned invalid evidence",
                cause = error,
            )
        }
        val exchangeBody = JSONObject()
            .put("challenge_id", challenge.challengeId)
            .put("attestation", JSONObject()
                .put("provider", evidence.provider)
                .put("evidence", evidenceJson))
            .put("installation", JSONObject().put("app_version", installationMetadata.appVersion).apply {
                installationMetadata.osVersion?.let { put("os_version", it) }
                installationMetadata.deviceModel?.let { put("device_model", it) }
            })
        val exchangeResponse = executeDpopControl(
            method = "POST",
            path = "/client/v1/sessions",
            body = exchangeBody,
        )
        requireSuccess(exchangeResponse, setOf(201))
        return parseAndStoreGrant(exchangeResponse.utf8Body())
    }

    private suspend fun refreshSession(stored: SessionSnapshot): SessionSnapshot {
        val body = JSONObject().put("refresh_token", stored.refreshToken.reveal())
        val response = executeDpopControl(
            method = "POST",
            path = "/client/v1/sessions/refresh",
            body = body,
        )
        requireSuccess(response)
        return parseAndStoreGrant(response.utf8Body())
    }

    private suspend fun parseAndStoreGrant(encoded: String): SessionSnapshot {
        val grant = try {
            val json = JSONObject(encoded)
            requireExactString(json, "token_type", "DPoP")
            val expiresIn = boundedLong(json, "expires_in", 60, 3_600)
            val refreshExpiresIn = boundedLong(json, "refresh_expires_in", 300, 31_536_000)
            val accessToken = boundedString(json, "access_token", 64, 16_384)
            val refreshToken = boundedString(json, "refresh_token", 32, 2_048)
            val installation = parseInstallation(
                json.getJSONObject("installation"),
                configuration.clientPlatform.wireValue,
            )
            if (installation.dpopJkt != signer.publicJwk.thumbprint()) {
                throw responseInvalid("The session was bound to an unexpected installation key")
            }
            val trust = parseTrust(json.getJSONObject("trust"))
            val now = clock.epochSeconds()
            SessionSnapshot(
                accessToken = SecretValue.of(accessToken),
                refreshToken = SecretValue.of(refreshToken),
                accessExpiresAtEpochSeconds = now + expiresIn,
                refreshExpiresAtEpochSeconds = now + refreshExpiresIn,
                installation = installation,
                trust = trust,
            )
        } catch (error: LatchwayException) {
            throw error
        } catch (error: Exception) {
            throw responseInvalid("The server returned an invalid session grant", error)
        }
        try {
            InstallationKeyRetirements.persistIfActive(
                identity = signerIdentity,
                inactive = ::installationRevokedError,
            ) {
                ensureInstallationMayPersist()
                stateStore.save(grant)
                ensureInstallationMayPersist()
            }
        } catch (error: LatchwayException) {
            if (error.code == LatchwayErrorCode.KEY_UNAVAILABLE) {
                runCatching { clearPersistedSession(grant) }
            }
            throw error
        }
        return grant
    }

    private suspend fun clearPersistedState(expectedIdentity: String) {
        InstallationKeyRetirements.withState(expectedIdentity) {
            if (stateStore is InstallationBoundSessionStateStore) {
                stateStore.clearIfInstallation(expectedIdentity)
                return@withState
            }
            val stored = stateStore.load() ?: return@withState
            if (stored.installation.dpopJkt == expectedIdentity) stateStore.clear()
        }
    }

    private suspend fun clearPersistedSession(expected: SessionSnapshot) {
        clearPersistedSession(expected.accessTokenFingerprint())
    }

    private suspend fun clearPersistedSession(expectedAccessTokenFingerprint: String) {
        InstallationKeyRetirements.withState(signerIdentity) {
            if (stateStore is InstallationBoundSessionStateStore) {
                stateStore.clearIfSession(signerIdentity, expectedAccessTokenFingerprint)
                return@withState
            }
            val stored = stateStore.load() ?: return@withState
            if (stored.installation.dpopJkt == signerIdentity &&
                stored.accessTokenFingerprint() == expectedAccessTokenFingerprint
            ) {
                stateStore.clear()
            }
        }
    }

    private suspend fun executeProtected(
        method: String,
        path: String,
        body: JSONObject? = null,
    ): LatchwayTransportResponse {
        val state = currentSession(forceRefresh = false)
        val uri = configuration.endpoint(path)
        val bodyBytes = body?.toString()?.toByteArray(StandardCharsets.UTF_8)
        if (bodyBytes != null && bodyBytes.size > MAX_CONTROL_REQUEST_BYTES) {
            throw LatchwayException(
                code = LatchwayErrorCode.REQUEST_INVALID,
                safeMessage = "The Latchway control request exceeded the safe size limit",
            )
        }
        var nonce: String? = null
        repeat(2) { attempt ->
            ensureInstallationActive()
            val proof = proofFactory.create(DpopProofRequest(method, uri, state.accessToken, nonce))
            ensureInstallationActive()
            val response = transport.execute(
                LatchwayTransportRequest(
                    method = method,
                    uri = uri,
                    headers = protocolHeaders(configuration, newRequestId()) + mapOf(
                        "Authorization" to "DPoP ${state.accessToken.reveal()}",
                        "DPoP" to proof.reveal(),
                    ) + if (bodyBytes != null) mapOf("Content-Type" to "application/json") else emptyMap(),
                    body = bodyBytes,
                ),
            )
            if (attempt == 0 && isNonceChallenge(response)) {
                nonce = validNonce(response.header("DPoP-Nonce"))
            } else {
                if (response.statusCode >= 400) {
                    runCatching { problem(response) }.getOrNull()?.code?.let { code ->
                        when {
                            code.isRootTerminal() -> cleanupRevokedInstallation()
                            code.clearsSession() -> clearPersistedSession(state)
                        }
                    }
                }
                return response
            }
        }
        throw responseInvalid("DPoP nonce negotiation did not complete")
    }

    private suspend fun executeDpopControl(
        method: String,
        path: String,
        body: JSONObject,
    ): LatchwayTransportResponse {
        val uri = configuration.endpoint(path)
        val bytes = body.toString().toByteArray(StandardCharsets.UTF_8)
        if (bytes.size > MAX_CONTROL_REQUEST_BYTES) {
            throw LatchwayException(
                code = LatchwayErrorCode.REQUEST_INVALID,
                safeMessage = "The Latchway control request exceeded the safe size limit",
            )
        }
        var nonce: String? = null
        repeat(2) { attempt ->
            throwIfInstallationRevoked()
            val proof = proofFactory.create(DpopProofRequest(method, uri, nonce = nonce))
            throwIfInstallationRevoked()
            val response = transport.execute(
                LatchwayTransportRequest(
                    method = method,
                    uri = uri,
                    headers = protocolHeaders(configuration, newRequestId()) + mapOf(
                        "Content-Type" to "application/json",
                        "DPoP" to proof.reveal(),
                    ),
                    body = bytes,
                ),
            )
            if (attempt == 0 && isNonceChallenge(response)) {
                nonce = validNonce(response.header("DPoP-Nonce"))
            } else {
                return response
            }
        }
        throw responseInvalid("DPoP nonce negotiation did not complete")
    }

}

internal fun protocolHeaders(configuration: CoreConfiguration, requestId: String): Map<String, String> = buildMap {
    putAll(mapOf(
        "Accept" to "application/json, application/problem+json",
        "X-Latchway-Protocol-Version" to LATCHWAY_PROTOCOL_VERSION.toString(),
        "X-Latchway-SDK" to configuration.clientPlatform.sdkHeaderValue,
        "X-Latchway-SDK-Version" to configuration.sdkVersion,
        "X-Latchway-Request-ID" to requestId,
    ))
    configuration.framework?.let {
        put("X-Latchway-Framework", it.id)
        put("X-Latchway-Framework-Version", it.version)
    }
}

private val COMPONENT_ID = Regex("^cmp_[A-Za-z0-9_-]{16,128}$")

private fun SessionCoordinator.isNonceChallenge(response: LatchwayTransportResponse): Boolean =
    response.statusCode == 401 && response.header("DPoP-Nonce") != null &&
        runCatching { problem(response).code == LatchwayErrorCode.DPOP_NONCE_REQUIRED }.getOrDefault(false)

private fun SessionCoordinator.validNonce(value: String?): String {
    if (value == null || value.length !in 16..512 || value.any { it.isISOControl() }) {
        throw responseInvalid("The server returned an invalid DPoP nonce")
    }
    return value
}

private const val MAX_CONTROL_REQUEST_BYTES = 512 * 1024

private fun LatchwayErrorCode.allowsNewSession(): Boolean = when (this) {
    LatchwayErrorCode.IDENTITY_TOKEN_MISSING,
    LatchwayErrorCode.IDENTITY_TOKEN_INVALID,
    LatchwayErrorCode.IDENTITY_TOKEN_EXPIRED,
    LatchwayErrorCode.IDENTITY_REAUTHENTICATION_REQUIRED,
    LatchwayErrorCode.ATTESTATION_REQUIRED,
    LatchwayErrorCode.ATTESTATION_STALE,
    LatchwayErrorCode.ATTESTATION_STEP_UP_REQUIRED,
    LatchwayErrorCode.SESSION_EXPIRED -> true
    else -> false
}

private fun LatchwayErrorCode.clearsSession(): Boolean = when (this) {
    LatchwayErrorCode.SESSION_REVOKED,
    LatchwayErrorCode.REFRESH_TOKEN_REUSED -> true
    else -> false
}

private fun LatchwayErrorCode.isRootTerminal(): Boolean =
    this == LatchwayErrorCode.INSTALLATION_REVOKED ||
        this == LatchwayErrorCode.INSTALLATION_FAMILY_REVOKED ||
        this == LatchwayErrorCode.INSTALLATION_FAMILY_NOT_FOUND

private fun installationRevokedError(): LatchwayException = LatchwayException(
    code = LatchwayErrorCode.INSTALLATION_REVOKED,
    safeMessage = "This client installation has been revoked",
)

internal fun newRequestId(): String = "android:${UUID.randomUUID()}"

internal fun requireGatewayDestination(baseUrl: URI, target: URI) {
    val baseScheme = baseUrl.scheme?.lowercase(Locale.US)
    val targetScheme = target.scheme?.lowercase(Locale.US)
    val baseHost = baseUrl.host?.lowercase(Locale.US)
    val targetHost = target.host?.lowercase(Locale.US)
    val basePath = baseUrl.rawPath?.ifEmpty { "/" } ?: "/"
    val targetPath = target.rawPath?.ifEmpty { "/" } ?: "/"
    val allowed = target.isAbsolute && target.userInfo == null && target.fragment == null &&
        baseScheme == targetScheme && baseHost == targetHost &&
        effectivePort(baseUrl, baseScheme) == effectivePort(target, targetScheme) &&
        targetPath.startsWith(basePath)
    if (!allowed) {
        throw LatchwayException(
            code = LatchwayErrorCode.TRANSPORT_DESTINATION_NOT_ALLOWED,
            safeMessage = "Latchway authorization is limited to the configured gateway destination",
        )
    }
}

private fun effectivePort(uri: URI, scheme: String?): Int = when {
    uri.port >= 0 -> uri.port
    scheme == "https" -> 443
    scheme == "http" -> 80
    else -> -1
}

internal fun coordinationOrigin(uri: URI): String {
    val scheme = uri.scheme.lowercase(Locale.US)
    val host = uri.host.lowercase(Locale.US)
    val port = when {
        uri.port >= 0 -> uri.port
        scheme == "http" -> 80
        else -> 443
    }
    val path = uri.rawPath?.ifEmpty { "/" } ?: "/"
    return "$scheme://$host:$port$path"
}

internal fun requireSuccess(
    response: LatchwayTransportResponse,
    accepted: Set<Int> = setOf(200),
) {
    if (response.statusCode !in accepted) throw problem(response)
}

internal fun problem(response: LatchwayTransportResponse): LatchwayException {
    return try {
        require(isProblemMediaType(response.header("Content-Type")))
        val json = JSONObject(response.utf8Body())
        val status = json.get("status")
        require(status is Number && status.toDouble() == response.statusCode.toDouble())
        val rawCode = boundedString(json, "code", 1, 128)
        val code = LatchwayErrorCode.fromWire(rawCode)
        require(code.wireValue == rawCode)
        require(boundedString(json, "type", 1, 2_048) == "https://latchway.dev/problems/$rawCode")
        require(boundedString(json, "title", 1, 256).isNotBlank())
        val detail = boundedString(json, "detail", 1, 2_048).also { require(it.isNotBlank()) }
        val requestId = boundedString(json, "request_id", 8, 128).also {
            require(isCanonicalRequestId(it))
            require(response.header("X-Latchway-Request-ID") == it)
        }
        val retryable = json.get("retryable").also { require(it is Boolean) } as Boolean
        when (code) {
            LatchwayErrorCode.INSTALLATION_REVOKED -> {
                require(response.statusCode == 403)
                require(!retryable)
            }
            LatchwayErrorCode.INSTALLATION_FAMILY_REVOKED -> {
                require(response.statusCode == 403)
                require(!retryable)
            }
            LatchwayErrorCode.OPERATION_INDETERMINATE -> {
                require(response.statusCode == 503)
                require(retryable)
            }
            else -> Unit
        }
        val rawOperationId = if (json.has("operation_id") && !json.isNull("operation_id")) {
            json.getString("operation_id")
        } else {
            null
        }
        val operationId = sanitizeOperationId(rawOperationId)
        if (code == LatchwayErrorCode.OPERATION_INDETERMINATE) {
            require(operationId != null)
        } else {
            require(!json.has("operation_id"))
        }
        LatchwayException(
            code = code,
            requestId = requestId,
            retryable = retryable,
            httpStatus = response.statusCode,
            safeMessage = detail,
        ).attachOperationId(operationId)
    } catch (error: Exception) {
        LatchwayException(
            code = LatchwayErrorCode.RESPONSE_INVALID,
            requestId = response.header("X-Latchway-Request-ID"),
            httpStatus = response.statusCode,
            safeMessage = "The server returned an invalid problem response",
            cause = error,
        )
    }
}

private fun isProblemMediaType(value: String?): Boolean =
    value?.substringBefore(';')?.trim()?.equals("application/problem+json", ignoreCase = true) == true

private fun isCanonicalRequestId(value: String): Boolean =
    value.length in 8..128 && Regex("^[A-Za-z0-9][A-Za-z0-9._:-]*$").matches(value)

private fun parseChallenge(
    encoded: String,
    nowEpochSeconds: Long,
    maximumClockSkewSeconds: Long,
): AttestationChallenge = try {
    val json = JSONObject(encoded)
    require(json.getInt("binding_version") == 1)
    val issuedAt = json.getLong("issued_at").also {
        require(it >= 0 && it <= nowEpochSeconds + maximumClockSkewSeconds)
    }
    boundedString(json, "challenge_nonce", 1, 2_048).also { Base64Url.decode(it) }
    val expiresAt = parseRfc3339EpochSeconds(boundedString(json, "expires_at", 20, 64))
    require(expiresAt > issuedAt)
    if (expiresAt + maximumClockSkewSeconds <= nowEpochSeconds) {
        throw LatchwayException(
            code = LatchwayErrorCode.ATTESTATION_STALE,
            safeMessage = "The server returned an expired attestation challenge",
        )
    }
    val attestation = json.getJSONObject("attestation")
    AttestationChallenge(
        challengeId = boundedString(json, "challenge_id", 20, 132),
        provider = boundedString(attestation, "provider", 1, 63).also {
            require(it in ATTESTATION_PROVIDERS)
        },
        mode = when (attestation.getString("mode")) {
            "required" -> AttestationMode.REQUIRED
            "preferred" -> AttestationMode.PREFERRED
            else -> throw JSONException("Invalid attestation mode")
        },
        clientDataHash = boundedString(attestation, "client_data_hash", 43, 43),
        providerOptions = attestation.optJSONObject("provider_options")?.toSafeMap() ?: emptyMap(),
        issuedAtEpochSeconds = issuedAt,
        expiresAtEpochSeconds = expiresAt,
    )
} catch (error: Exception) {
    if (error is LatchwayException) throw error
    throw responseInvalid("The server returned an invalid attestation challenge", error)
}

/**
 * Parses the App Attest-only component binding-v2 challenge without exposing a
 * direct component step-up operation from the Android SDK.
 */
internal fun parseComponentAttestationChallenge(
    encoded: String,
    nowEpochSeconds: Long,
    maximumClockSkewSeconds: Long,
): AttestationChallenge = try {
    val json = JSONObject(encoded)
    val expectedKeys = setOf(
        "challenge_id", "challenge_nonce", "binding_version", "issued_at", "expires_at", "attestation",
    )
    require(json.length() == expectedKeys.size && json.keys().asSequence().toSet() == expectedKeys)
    require(json.getInt("binding_version") == 2)
    val issuedAt = json.getLong("issued_at").also {
        require(it in 0..253_402_300_799 && it <= nowEpochSeconds + maximumClockSkewSeconds)
    }
    val challengeNonce = boundedString(json, "challenge_nonce", 43, 86)
    require(Base64Url.decode(challengeNonce).size in 32..64)
    val expiresAt = parseRfc3339EpochSeconds(boundedString(json, "expires_at", 20, 64))
    require(expiresAt > issuedAt)
    if (expiresAt + maximumClockSkewSeconds <= nowEpochSeconds) {
        throw LatchwayException(
            code = LatchwayErrorCode.ATTESTATION_STALE,
            safeMessage = "The server returned an expired component attestation challenge",
        )
    }
    val attestation = json.getJSONObject("attestation")
    val actualAttestationKeys = attestation.keys().asSequence().toSet()
    val requiredAttestationKeys = setOf("provider", "mode", "client_data_hash")
    require(actualAttestationKeys.containsAll(requiredAttestationKeys))
    require(actualAttestationKeys.all { it in requiredAttestationKeys || it == "provider_options" })
    require(attestation.getString("provider") == "app_attest")
    require(attestation.getString("mode") == "required")
    if (attestation.has("provider_options")) {
        require(!attestation.isNull("provider_options") && attestation.get("provider_options") is JSONObject)
    }
    AttestationChallenge(
        challengeId = boundedString(json, "challenge_id", 20, 132),
        provider = "app_attest",
        mode = AttestationMode.REQUIRED,
        clientDataHash = boundedString(attestation, "client_data_hash", 43, 43),
        providerOptions = attestation.optJSONObject("provider_options")?.toSafeMap() ?: emptyMap(),
        issuedAtEpochSeconds = issuedAt,
        expiresAtEpochSeconds = expiresAt,
    )
} catch (error: Exception) {
    if (error is LatchwayException) throw error
    throw responseInvalid("The server returned an invalid component attestation challenge", error)
}

private fun parseQuota(encoded: String): LatchwayQuotaSnapshot = try {
    val json = JSONObject(encoded)
    val limitsJson = json.getJSONArray("limits")
    require(limitsJson.length() <= 128)
    val limits = ArrayList<LatchwayQuotaLimit>(limitsJson.length())
    repeat(limitsJson.length()) { index ->
        val value = limitsJson.getJSONObject(index)
        limits += LatchwayQuotaLimit(
            metric = boundedString(value, "metric", 1, 128),
            maximum = optionalNonNegativeLong(value, "maximum"),
            used = optionalNonNegativeLong(value, "used"),
            reserved = optionalNonNegativeLong(value, "reserved"),
            remaining = optionalNonNegativeLong(value, "remaining"),
            resetsAt = if (value.has("resets_at") && !value.isNull("resets_at")) {
                boundedRfc3339(value, "resets_at")
            } else {
                null
            },
            hard = value.getBoolean("hard"),
        )
    }
    LatchwayQuotaSnapshot(
        feature = boundedString(json, "feature", 1, 63).also { requireIdentifier(it, "feature") },
        observedAt = boundedRfc3339(json, "observed_at"),
        limits = limits,
    )
} catch (error: Exception) {
    if (error is LatchwayException) throw error
    throw responseInvalid("The server returned an invalid quota response", error)
}

private fun parseDiagnostics(
    encoded: String,
    key: KeyDiagnostics,
    expectedPlatform: String,
): LatchwayDiagnostics = try {
    val json = JSONObject(encoded)
    requireExactString(json, "contract_version", LATCHWAY_CONTRACT_VERSION)
    require(json.getInt("protocol_version") == LATCHWAY_PROTOCOL_VERSION)
    val installation = parseInstallation(json.getJSONObject("installation"), expectedPlatform)
    val session = json.getJSONObject("session")
    val trust = parseTrust(json.getJSONObject("trust"))
    LatchwayDiagnostics(
        requestId = boundedString(json, "request_id", 8, 128),
        serverVersion = boundedString(json, "server_version", 1, 128),
        contractVersion = LATCHWAY_CONTRACT_VERSION,
        protocolVersion = LATCHWAY_PROTOCOL_VERSION,
        installationId = installation.id,
        installationStatus = installation.status,
        key = key,
        sessionExpiresAt = boundedRfc3339(session, "expires_at"),
        refreshAvailable = session.getBoolean("refresh_available"),
        trustProvider = trust.provider,
        trustLevel = trust.level,
        trustExpiresAt = trust.expiresAt,
    )
} catch (error: Exception) {
    if (error is LatchwayException) throw error
    throw responseInvalid("The server returned invalid diagnostics", error)
}

private fun parseInstallation(json: JSONObject, expectedPlatform: String): InstallationSummary {
    val result = InstallationSummary(
        id = boundedString(json, "id", 20, 132),
        platform = boundedString(json, "platform", 1, 32),
        dpopJkt = boundedString(json, "dpop_jkt", 1, 128),
        status = boundedString(json, "status", 1, 32),
    )
    require(Regex("^ins_[A-Za-z0-9_-]{16,128}$").matches(result.id))
    require(result.platform == expectedPlatform)
    require(result.status == "active" || result.status == "revoked")
    require(Base64Url.decode(result.dpopJkt).size == 32)
    return result
}

private fun parseTrust(json: JSONObject): TrustSummary {
    val level = boundedString(json, "level", 1, 64)
    require(level in setOf(
        "none", "identity_only", "web_risk_verified", "app_verified", "device_verified",
        "strong_device_verified", "debug",
    ))
    return TrustSummary(
        provider = boundedString(json, "provider", 1, 63).also { requireIdentifier(it, "trust provider") },
        level = level,
        verifiedAt = boundedRfc3339(json, "verified_at"),
        expiresAt = boundedRfc3339(json, "expires_at"),
    )
}

private fun boundedString(json: JSONObject, name: String, minimum: Int, maximum: Int): String =
    json.getString(name).also { require(it.length in minimum..maximum) }

private fun boundedRfc3339(json: JSONObject, name: String): String =
    boundedString(json, name, 20, 64).also { parseRfc3339EpochSeconds(it) }

private fun boundedLong(json: JSONObject, name: String, minimum: Long, maximum: Long): Long =
    json.getLong(name).also { require(it in minimum..maximum) }

private fun optionalNonNegativeLong(json: JSONObject, name: String): Long? =
    if (json.has(name) && !json.isNull(name)) json.getLong(name).also { require(it >= 0) } else null

private fun requireExactString(json: JSONObject, name: String, expected: String) {
    require(json.getString(name) == expected)
}

private fun mapToJson(values: Map<String, Any?>): JSONObject = JSONObject().also { json ->
    require(values.size <= 128)
    values.forEach { (key, value) ->
        require(key.length in 1..128)
        json.put(key, value.toJsonValue(0))
    }
}

private fun Any?.toJsonValue(depth: Int): Any {
    require(depth <= 8) { "Attestation evidence is too deeply nested" }
    return when (this) {
        null -> JSONObject.NULL
        is String -> also { require(length <= 262_144) }
        is Boolean, is Int, is Long, is Double -> this
        is Number -> toDouble()
        is Map<*, *> -> JSONObject().also { output ->
            require(size <= 128)
            entries.forEach { (key, value) ->
                require(key is String && key.length in 1..128)
                output.put(key, value.toJsonValue(depth + 1))
            }
        }
        is Iterable<*> -> JSONArray().also { output ->
            val values = take(129).toList()
            require(values.size <= 128)
            values.forEach { output.put(it.toJsonValue(depth + 1)) }
        }
        else -> throw IllegalArgumentException("Unsupported JSON evidence value")
    }
}

private fun JSONObject.toSafeMap(depth: Int = 0): Map<String, Any?> {
    require(depth <= 8)
    require(length() <= 128)
    return keys().asSequence().associateWith { key ->
        when (val value = get(key)) {
            JSONObject.NULL -> null
            is JSONObject -> value.toSafeMap(depth + 1)
            is JSONArray -> value.toSafeList(depth + 1)
            is String, is Boolean, is Number -> value
            else -> throw JSONException("Unsupported JSON value")
        }
    }
}

private fun JSONArray.toSafeList(depth: Int): List<Any?> {
    require(depth <= 8)
    require(length() <= 128)
    return (0 until length()).map { index ->
        when (val value = get(index)) {
            JSONObject.NULL -> null
            is JSONObject -> value.toSafeMap(depth + 1)
            is JSONArray -> value.toSafeList(depth + 1)
            is String, is Boolean, is Number -> value
            else -> throw JSONException("Unsupported JSON value")
        }
    }
}

internal fun responseInvalid(message: String, cause: Throwable? = null): LatchwayException = LatchwayException(
    code = LatchwayErrorCode.RESPONSE_INVALID,
    safeMessage = message,
    cause = cause,
)

internal fun parseRfc3339EpochSeconds(value: String): Long {
    val match = RFC3339.matchEntire(value) ?: throw IllegalArgumentException("Invalid RFC 3339 timestamp")
    val zone = match.groupValues[7]
    val offsetMillis = if (zone == "Z") {
        0
    } else {
        val offsetHours = zone.substring(1, 3).toInt()
        val offsetMinutes = zone.substring(4, 6).toInt()
        require(offsetHours <= 23 && offsetMinutes <= 59) { "Invalid RFC 3339 offset" }
        val absoluteOffset = (offsetHours * 60 + offsetMinutes) * 60 * 1_000
        if (zone[0] == '-') -absoluteOffset else absoluteOffset
    }
    val timeZone = java.util.SimpleTimeZone(offsetMillis, "LatchwayOffset")
    val calendar = java.util.GregorianCalendar(timeZone).apply {
        isLenient = false
        clear()
        set(java.util.Calendar.YEAR, match.groupValues[1].toInt())
        set(java.util.Calendar.MONTH, match.groupValues[2].toInt() - 1)
        set(java.util.Calendar.DAY_OF_MONTH, match.groupValues[3].toInt())
        set(java.util.Calendar.HOUR_OF_DAY, match.groupValues[4].toInt())
        set(java.util.Calendar.MINUTE, match.groupValues[5].toInt())
        set(java.util.Calendar.SECOND, match.groupValues[6].toInt())
    }
    return calendar.timeInMillis / 1_000
}

private val RFC3339 = Regex(
    "^(\\d{4})-(\\d{2})-(\\d{2})T(\\d{2}):(\\d{2}):(\\d{2})(?:\\.\\d{1,9})?(Z|[+-]\\d{2}:\\d{2})$",
)
