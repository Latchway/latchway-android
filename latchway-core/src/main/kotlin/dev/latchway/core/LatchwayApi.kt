package dev.latchway.core

import java.io.Closeable
import java.io.IOException
import java.net.URI
import java.util.Locale

public const val LATCHWAY_SDK_VERSION: String = "0.1.0"
public const val LATCHWAY_CONTRACT_VERSION: String = "0.2.0"
public const val LATCHWAY_PROTOCOL_VERSION: Int = 1

internal val ATTESTATION_PROVIDERS: Set<String> = setOf(
    "app_attest",
    "play_integrity",
    "firebase_app_check",
    "turnstile",
    "debug",
)

public enum class LatchwayClientPlatform(
    public val wireValue: String,
    public val sdkHeaderValue: String,
) {
    ANDROID("android", "android"),
    REACT_NATIVE_ANDROID("react_native_android", "react-native"),
}

public fun interface IdentityTokenProvider {
    public suspend fun identityToken(): String
}

public data class CoreConfiguration(
    val baseUrl: URI,
    val applicationId: String,
    val environment: String,
    val identityProvider: String,
    val clientPlatform: LatchwayClientPlatform = LatchwayClientPlatform.ANDROID,
    val sdkVersion: String = LATCHWAY_SDK_VERSION,
    val refreshLeewaySeconds: Long = 60,
    val maximumClockSkewSeconds: Long = 60,
    val allowInsecureLoopback: Boolean = false,
) {
    init {
        requireBaseUrl(baseUrl, allowInsecureLoopback)
        require(applicationId.isNotBlank() && applicationId.length <= 128) {
            "applicationId must contain 1 to 128 characters"
        }
        requireIdentifier(environment, "environment")
        requireIdentifier(identityProvider, "identityProvider")
        require(SEMVER.matches(sdkVersion)) { "sdkVersion must be semantic version syntax" }
        require(refreshLeewaySeconds in 5..300) { "refreshLeewaySeconds must be between 5 and 300" }
        require(maximumClockSkewSeconds in 0..300) { "maximumClockSkewSeconds must be between 0 and 300" }
    }

    internal fun endpoint(path: String): URI = baseUrl.resolve(path.removePrefix("/"))

    private companion object {
        val SEMVER = Regex("^[0-9]+\\.[0-9]+\\.[0-9]+(?:-[0-9A-Za-z.-]+)?$")
    }
}

public enum class LatchwayErrorCode(public val wireValue: String) {
    REQUEST_INVALID("request_invalid"),
    IDENTITY_TOKEN_MISSING("identity_token_missing"),
    IDENTITY_TOKEN_INVALID("identity_token_invalid"),
    IDENTITY_TOKEN_EXPIRED("identity_token_expired"),
    IDENTITY_REAUTHENTICATION_REQUIRED("identity_reauthentication_required"),
    ATTESTATION_REQUIRED("attestation_required"),
    ATTESTATION_UNSUPPORTED("attestation_unsupported"),
    ATTESTATION_INVALID("attestation_invalid"),
    ATTESTATION_STALE("attestation_stale"),
    ATTESTATION_STEP_UP_REQUIRED("attestation_step_up_required"),
    DPOP_MISSING("dpop_missing"),
    DPOP_INVALID("dpop_invalid"),
    DPOP_REPLAYED("dpop_replayed"),
    DPOP_NONCE_REQUIRED("dpop_nonce_required"),
    SESSION_EXPIRED("session_expired"),
    SESSION_REVOKED("session_revoked"),
    REFRESH_TOKEN_REUSED("refresh_token_reused"),
    INSTALLATION_REVOKED("installation_revoked"),
    FEATURE_NOT_FOUND("feature_not_found"),
    FEATURE_NOT_ALLOWED("feature_not_allowed"),
    MODEL_NOT_ALLOWED("model_not_allowed"),
    QUOTA_EXCEEDED("quota_exceeded"),
    CONCURRENCY_EXCEEDED("concurrency_exceeded"),
    OUTPUT_LIMIT_EXCEEDED("output_limit_exceeded"),
    PRICING_UNAVAILABLE("pricing_unavailable"),
    ROUTE_NOT_FOUND("route_not_found"),
    UPSTREAM_UNAVAILABLE("upstream_unavailable"),
    UPSTREAM_TIMEOUT("upstream_timeout"),
    UPSTREAM_PROTOCOL_ERROR("upstream_protocol_error"),
    CONFIGURATION_INVALID("configuration_invalid"),
    SERVER_NOT_READY("server_not_ready"),
    PROTOCOL_VERSION_UNSUPPORTED("protocol_version_unsupported"),
    AUTHENTICATION_REQUIRED("authentication_required"),
    PERMISSION_DENIED("permission_denied"),
    RESOURCE_NOT_FOUND("resource_not_found"),
    CONFLICT("conflict"),
    RATE_LIMITED("rate_limited"),
    ETAG_REQUIRED("etag_required"),
    ETAG_MISMATCH("etag_mismatch"),
    BOOTSTRAP_DISABLED("bootstrap_disabled"),
    INTERNAL_ERROR("internal_error"),
    KEY_UNAVAILABLE("key_unavailable"),
    SECURE_STATE_UNAVAILABLE("secure_state_unavailable"),
    NETWORK_UNAVAILABLE("network_unavailable"),
    RESPONSE_INVALID("response_invalid");

    public companion object {
        public fun fromWire(value: String?): LatchwayErrorCode =
            entries.firstOrNull { it.wireValue == value } ?: INTERNAL_ERROR
    }
}

public class LatchwayException(
    public val code: LatchwayErrorCode,
    requestId: String? = null,
    public val retryable: Boolean = false,
    public val httpStatus: Int? = null,
    safeMessage: String = code.wireValue,
    cause: Throwable? = null,
) : IOException(sanitizeMessage(safeMessage), cause?.let(::sanitizeCause)) {
    public val requestId: String? = sanitizeRequestId(requestId)

    override fun toString(): String = buildString {
        append("LatchwayException(code=")
        append(code.wireValue)
        requestId?.let { append(", requestId=").append(it) }
        httpStatus?.let { append(", httpStatus=").append(it) }
        append(", retryable=").append(retryable).append(')')
    }
}

public enum class AttestationMode {
    REQUIRED,
    PREFERRED,
}

public data class AttestationChallenge(
    val challengeId: String,
    val provider: String,
    val mode: AttestationMode,
    val clientDataHash: String,
    val providerOptions: Map<String, Any?>,
    val issuedAtEpochSeconds: Long = 0,
    val expiresAtEpochSeconds: Long = Long.MAX_VALUE,
) {
    init {
        require(CHALLENGE_ID.matches(challengeId)) { "challengeId is not canonical" }
        require(provider in ATTESTATION_PROVIDERS) { "provider is not supported by this contract" }
        require(BASE64_SHA256.matches(clientDataHash) && Base64Url.decode(clientDataHash).size == 32) {
            "clientDataHash must be base64url SHA-256"
        }
        require(issuedAtEpochSeconds >= 0 && expiresAtEpochSeconds > issuedAtEpochSeconds) {
            "attestation challenge lifetime is invalid"
        }
    }

    private companion object {
        val CHALLENGE_ID = Regex("^chl_[A-Za-z0-9_-]{16,128}$")
        val BASE64_SHA256 = Regex("^[A-Za-z0-9_-]{43}$")
    }
}

public data class AttestationEvidence(
    val provider: String,
    val evidence: Map<String, Any?>,
) {
    init {
        require(provider in ATTESTATION_PROVIDERS) { "provider is not supported by this contract" }
        require(evidence.isNotEmpty()) { "attestation evidence must not be empty" }
    }

    override fun toString(): String = "AttestationEvidence(provider=$provider, evidence=[REDACTED])"
}

public interface AttestationProvider {
    public suspend fun warmUp()
    public suspend fun attest(challenge: AttestationChallenge): AttestationEvidence
}

public object UnsupportedAttestationProvider : AttestationProvider {
    override suspend fun warmUp(): Unit = Unit

    override suspend fun attest(challenge: AttestationChallenge): AttestationEvidence {
        throw LatchwayException(
            code = LatchwayErrorCode.ATTESTATION_UNSUPPORTED,
            safeMessage = "No attestation provider is configured for ${challenge.provider}",
        )
    }
}

public enum class KeyBacking {
    STRONGBOX,
    TRUSTED_EXECUTION_ENVIRONMENT,
    SOFTWARE,
    UNKNOWN_SECURE_HARDWARE,
}

public data class KeyPolicy(
    val preferStrongBox: Boolean = true,
    val allowSoftwareBacked: Boolean = false,
)

public data class KeyDiagnostics(
    val backing: KeyBacking,
    val strongBoxRequested: Boolean,
    val strongBoxUnavailable: Boolean,
    val publicJwkThumbprint: String,
)

public data class LatchwayQuotaLimit(
    val metric: String,
    val maximum: Long?,
    val used: Long?,
    val reserved: Long?,
    val remaining: Long?,
    val resetsAt: String?,
    val hard: Boolean,
)

public data class LatchwayQuotaSnapshot(
    val feature: String,
    val observedAt: String,
    val limits: List<LatchwayQuotaLimit>,
)

public data class LatchwayDiagnostics(
    val requestId: String,
    val serverVersion: String,
    val contractVersion: String,
    val protocolVersion: Int,
    val installationId: String,
    val installationStatus: String,
    val key: KeyDiagnostics,
    val sessionExpiresAt: String,
    val refreshAvailable: Boolean,
    val trustProvider: String,
    val trustLevel: String,
    val trustExpiresAt: String,
)

public data class InstallationMetadata(
    val appVersion: String,
    val osVersion: String? = null,
    val deviceModel: String? = null,
) {
    init {
        require(appVersion.isNotBlank() && appVersion.length <= 128)
        require(osVersion == null || osVersion.isNotBlank() && osVersion.length <= 128)
        require(deviceModel == null || deviceModel.isNotBlank() && deviceModel.length <= 128)
    }
}

public fun interface LatchwayClock {
    public fun epochSeconds(): Long
}

public object SystemLatchwayClock : LatchwayClock {
    override fun epochSeconds(): Long = System.currentTimeMillis() / 1_000
}

public class AuthorizedHeaders internal constructor(
    private val accessToken: SecretValue,
    private val proof: SecretValue,
    public val requestId: String,
) {
    public fun authorizationHeader(): String = "DPoP ${accessToken.reveal()}"
    public fun dpopHeader(): String = proof.reveal()
    override fun toString(): String = "AuthorizedHeaders(requestId=$requestId, credentials=[REDACTED])"
}

public class LatchwayCoreClient internal constructor(
    private val coordinator: SessionCoordinator,
) : Closeable {
    public suspend fun authorize(
        method: String,
        uri: URI,
        feature: String,
        nonce: String? = null,
    ): AuthorizedHeaders = coordinator.authorize(method, uri, feature, nonce)

    public suspend fun quota(feature: String): LatchwayQuotaSnapshot = coordinator.quota(feature)
    public suspend fun revokeCurrentInstallation(): Unit = coordinator.revokeCurrentInstallation()
    public suspend fun diagnostics(): LatchwayDiagnostics = coordinator.diagnostics()
    public suspend fun refresh(): Unit = coordinator.forceRefresh()
    public suspend fun clearSession(): Unit = coordinator.clearSession()
    override fun close(): Unit = coordinator.close()

    public companion object {
        public fun create(
            configuration: CoreConfiguration,
            identityTokenProvider: IdentityTokenProvider,
            attestationProvider: AttestationProvider,
            signer: InstallationSigner,
            stateStore: SessionStateStore,
            transport: LatchwayTransport,
            installationMetadata: InstallationMetadata,
            clock: LatchwayClock = SystemLatchwayClock,
        ): LatchwayCoreClient = LatchwayCoreClient(
            SessionCoordinator(
                configuration = configuration,
                identityTokenProvider = identityTokenProvider,
                attestationProvider = attestationProvider,
                signer = signer,
                stateStore = stateStore,
                transport = transport,
                installationMetadata = installationMetadata,
                clock = clock,
            ),
        )
    }
}

internal fun requireIdentifier(value: String, name: String) {
    require(Regex("^[a-z][a-z0-9_-]{0,62}$").matches(value)) { "$name is not a canonical identifier" }
}

private fun requireBaseUrl(uri: URI, allowInsecureLoopback: Boolean) {
    require(uri.isAbsolute && uri.host != null) { "baseUrl must be an absolute HTTP origin" }
    require(uri.userInfo == null && uri.query == null && uri.fragment == null) {
        "baseUrl must not contain user information, query, or fragment"
    }
    val scheme = uri.scheme.lowercase(Locale.US)
    val loopback = uri.host.equals("localhost", true) || uri.host == "127.0.0.1" || uri.host == "::1"
    require(scheme == "https" || scheme == "http" && loopback && allowInsecureLoopback) {
        "baseUrl must use HTTPS; HTTP is limited to an explicitly enabled loopback origin"
    }
    require(uri.path.isNullOrEmpty() || uri.path.endsWith('/')) { "baseUrl path must end with '/'" }
}

private fun sanitizeMessage(value: String): String {
    val bounded = value.replace(Regex("[\\r\\n\\u0000-\\u001f]"), " ").take(512)
    val secretMarkers = listOf("eyJ", "lwa_", "lws_", "refresh_token", "identity_token", "integrity_token")
    val looksLikeCredential = Regex("[A-Za-z0-9_-]{64,}").containsMatchIn(bounded)
    return if (looksLikeCredential || secretMarkers.any { bounded.contains(it, ignoreCase = true) }) {
        "Sensitive detail redacted"
    } else {
        bounded
    }
}

private fun sanitizeRequestId(value: String?): String? = value?.takeIf {
    it.length in 8..128 && Regex("^[A-Za-z0-9][A-Za-z0-9._:-]*$").matches(it)
}

private fun sanitizeCause(original: Throwable): Throwable = Exception(
    "Underlying ${original::class.java.simpleName}",
).apply {
    stackTrace = original.stackTrace
}
