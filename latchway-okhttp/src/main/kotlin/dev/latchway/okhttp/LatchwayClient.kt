package dev.latchway.okhttp

import android.content.ContentProvider
import android.content.ContentValues
import android.content.Context
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.database.Cursor
import android.net.Uri
import android.os.Build
import dev.latchway.core.AndroidEncryptedSessionStateStore
import dev.latchway.core.AndroidKeystoreInstallationSigner
import dev.latchway.core.AttestationProvider
import dev.latchway.core.AuthorizedHeaders
import dev.latchway.core.Base64Url
import dev.latchway.core.CoreConfiguration
import dev.latchway.core.IdentityTokenProvider
import dev.latchway.core.InstallationMetadata
import dev.latchway.core.KeyPolicy
import dev.latchway.core.LATCHWAY_SDK_VERSION
import dev.latchway.core.LATCHWAY_PROTOCOL_VERSION
import dev.latchway.core.LatchwayClientPlatform
import dev.latchway.core.LatchwayCoreClient
import dev.latchway.core.LatchwayDiagnostics
import dev.latchway.core.LatchwayErrorCode
import dev.latchway.core.LatchwayException
import dev.latchway.core.LatchwayQuotaSnapshot
import dev.latchway.core.UnsupportedAttestationProvider
import kotlinx.coroutines.runBlocking
import okhttp3.Authenticator
import okhttp3.ConnectionPool
import okhttp3.CookieJar
import okhttp3.Dispatcher
import okhttp3.HttpUrl
import okhttp3.Interceptor
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.Route
import org.json.JSONObject
import java.io.Closeable
import java.lang.ref.WeakReference
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.Locale

public data class LatchwayConfiguration(
    val baseUrl: HttpUrl,
    val applicationId: String,
    val environment: String,
    val identityProvider: String = "firebase",
    val clientPlatform: LatchwayClientPlatform = LatchwayClientPlatform.ANDROID,
    val sdkVersion: String = LATCHWAY_SDK_VERSION,
    val defaultFeature: String? = null,
    val keyPolicy: KeyPolicy = KeyPolicy(),
    val allowInsecureLoopback: Boolean = false,
) {
    init {
        CoreConfiguration(
            baseUrl = baseUrl.toUri(),
            applicationId = applicationId,
            environment = environment,
            identityProvider = identityProvider,
            clientPlatform = clientPlatform,
            sdkVersion = sdkVersion,
            allowInsecureLoopback = allowInsecureLoopback,
        )
        defaultFeature?.let(::validateFeature)
    }
}

public data class LatchwayFeature(public val value: String) {
    init { validateFeature(value) }
}

public fun Request.Builder.latchwayFeature(feature: String): Request.Builder =
    tag(LatchwayFeature::class.java, LatchwayFeature(feature))

public class LatchwayClient(
    private val configuration: LatchwayConfiguration,
    private val identityTokenProvider: IdentityTokenProvider,
    private val attestationProvider: AttestationProvider = UnsupportedAttestationProvider,
    controlClient: OkHttpClient = OkHttpClient(),
    context: Context = LatchwayAndroidRuntime.requireContext(),
) : Closeable {
    private val applicationContext = context.applicationContext
    private val controlClient = isolatedControlClient(controlClient)
    private val coreDelegate = lazy(LazyThreadSafetyMode.SYNCHRONIZED) {
        runBlocking { createCore() }
    }
    private val core: LatchwayCoreClient by coreDelegate

    public fun interceptor(): Interceptor = Interceptor { chain ->
        val request = chain.request()
        if (!isGatewayOrigin(request.url)) return@Interceptor chain.proceed(request)
        val feature = request.latchwayFeature()
        val response = chain.proceed(runBlocking { authorizeInternal(request, feature, nonce = null) })
        observeInstallationRevocation(response, ::isGatewayOrigin) {
            runCatching { runBlocking { core.markCurrentInstallationRevoked() } }
        }
        response
    }

    /**
     * Install as a network interceptor. It blocks caller provider credentials
     * before gateway dispatch and Latchway credentials on cross-origin redirects.
     */
    public fun originGuard(): Interceptor = gatewayOriginGuard(configuration.baseUrl)

    public fun authenticator(): Authenticator = object : Authenticator {
        override fun authenticate(route: Route?, response: Response): Request? {
            if (!isGatewayOrigin(response.request.url)) return null
            val request = response.request
            val decision = authenticationDecision(response)
            if (decision.action == AuthenticationAction.NONE) return null
            return when (decision.action) {
                AuthenticationAction.NONCE -> {
                    val feature = runCatching { request.latchwayFeature() }.getOrNull() ?: return null
                    val nonce = decision.nonce ?: return null
                    runCatching { runBlocking { authorizeInternal(request, feature, nonce) } }.getOrNull()
                }
                AuthenticationAction.REFRESH -> runCatching {
                    val feature = request.latchwayFeature()
                    runBlocking {
                        core.refresh()
                        authorizeInternal(request, feature, nonce = null)
                    }
                }.getOrNull()
                AuthenticationAction.CLEAR -> {
                    val authorization = request.tag(AuthorizedHeaders::class.java) ?: return null
                    runCatching { runBlocking { core.clearSessionIfCurrent(authorization) } }
                    null
                }
                AuthenticationAction.NONE -> null
            }
        }
    }

    public suspend fun authorize(request: Request, feature: String): Request =
        authorizeInternal(request, feature, nonce = null)

    /** Creates exactly one replacement proof for a validated server DPoP nonce challenge. */
    public suspend fun authorize(request: Request, feature: String, nonce: String): Request =
        authorizeInternal(request, feature, nonce)

    public suspend fun quota(feature: String): LatchwayQuotaSnapshot = core.quota(feature)

    public suspend fun revokeCurrentInstallation(): Unit = core.revokeCurrentInstallation()

    public suspend fun diagnostics(): LatchwayDiagnostics = core.diagnostics()

    public suspend fun refresh(): Unit = core.refresh()

    public suspend fun clearSession(): Unit = core.clearSession()

    override fun close() {
        if (coreDelegate.isInitialized()) core.close()
        controlClient.dispatcher.cancelAll()
        controlClient.connectionPool.evictAll()
        controlClient.dispatcher.executorService.shutdown()
    }

    private suspend fun authorizeInternal(request: Request, feature: String, nonce: String?): Request {
        validateFeature(feature)
        if (!isGatewayOrigin(request.url)) {
            throw LatchwayException(
                code = LatchwayErrorCode.CONFIGURATION_INVALID,
                safeMessage = "Latchway credentials can only be attached to the configured gateway origin",
            )
        }
        rejectUpstreamCredentials(request, authorizationWillBeReplaced = true)
        val authorized = core.authorize(request.method, request.url.toUri(), feature, nonce)
        return request.newBuilder()
            .header("Authorization", authorized.authorizationHeader())
            .header("DPoP", authorized.dpopHeader())
            .header("X-Latchway-Protocol-Version", LATCHWAY_PROTOCOL_VERSION.toString())
            .header("X-Latchway-SDK", configuration.clientPlatform.sdkHeaderValue)
            .header("X-Latchway-SDK-Version", configuration.sdkVersion)
            .header("X-Latchway-Request-ID", authorized.requestId)
            .header("X-Latchway-Feature", feature)
            .tag(AuthorizedHeaders::class.java, authorized)
            .tag(LatchwayFeature::class.java, LatchwayFeature(feature))
            .build()
    }

    private suspend fun createCore(): LatchwayCoreClient {
        val namespace = storageNamespace(configuration)
        val signer = AndroidKeystoreInstallationSigner.create(
            context = applicationContext,
            alias = "dev.latchway.installation.$namespace.dpop.v1",
            policy = configuration.keyPolicy,
        )
        return LatchwayCoreClient.create(
            configuration = CoreConfiguration(
                baseUrl = configuration.baseUrl.toUri(),
                applicationId = configuration.applicationId,
                environment = configuration.environment,
                identityProvider = configuration.identityProvider,
                clientPlatform = configuration.clientPlatform,
                sdkVersion = configuration.sdkVersion,
                allowInsecureLoopback = configuration.allowInsecureLoopback,
            ),
            identityTokenProvider = identityTokenProvider,
            attestationProvider = attestationProvider,
            signer = signer,
            stateStore = AndroidEncryptedSessionStateStore(applicationContext, namespace),
            transport = OkHttpLatchwayTransport(controlClient),
            installationMetadata = applicationContext.installationMetadata(),
        )
    }

    private fun Request.latchwayFeature(): String =
        tag(LatchwayFeature::class.java)?.value
            ?: header("X-Latchway-Feature")
            ?: configuration.defaultFeature
            ?: throw LatchwayException(
                code = LatchwayErrorCode.CONFIGURATION_INVALID,
                safeMessage = "A Latchway feature is required for gateway requests",
            )

    private fun isGatewayOrigin(url: HttpUrl): Boolean =
        url.scheme == configuration.baseUrl.scheme &&
            url.host == configuration.baseUrl.host &&
            url.port == configuration.baseUrl.port
}

internal object LatchwayAndroidRuntime {
    @Volatile private var contextReference = WeakReference<Context>(null)

    fun install(context: Context) {
        contextReference = WeakReference(context.applicationContext)
    }

    fun requireContext(): Context = contextReference.get() ?: throw IllegalStateException(
        "Latchway Android context provider has not initialized",
    )
}

public class LatchwayContextProvider : ContentProvider() {
    override fun onCreate(): Boolean {
        context?.let(LatchwayAndroidRuntime::install)
        return true
    }

    override fun query(
        uri: Uri,
        projection: Array<out String>?,
        selection: String?,
        selectionArgs: Array<out String>?,
        sortOrder: String?,
    ): Cursor? = throw UnsupportedOperationException("LatchwayContextProvider does not expose data")

    override fun getType(uri: Uri): String? = null
    override fun insert(uri: Uri, values: ContentValues?): Uri? =
        throw UnsupportedOperationException("LatchwayContextProvider does not expose data")
    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<out String>?): Int =
        throw UnsupportedOperationException("LatchwayContextProvider does not expose data")
    override fun update(uri: Uri, values: ContentValues?, selection: String?, selectionArgs: Array<out String>?): Int =
        throw UnsupportedOperationException("LatchwayContextProvider does not expose data")
}

/**
 * Preserve explicit TLS/DNS/time-out choices while enforcing a separate execution pool and removing
 * application hooks that could recurse into Latchway or observe control-plane credentials.
 */
internal fun isolatedControlClient(template: OkHttpClient): OkHttpClient {
    val builder = template.newBuilder()
    builder.interceptors().clear()
    builder.networkInterceptors().clear()
    return builder
        .dispatcher(Dispatcher())
        .connectionPool(ConnectionPool())
        .authenticator(Authenticator.NONE)
        .proxyAuthenticator(Authenticator.NONE)
        .cookieJar(CookieJar.NO_COOKIES)
        .followRedirects(false)
        .followSslRedirects(false)
        .build()
}

private fun Context.installationMetadata(): InstallationMetadata {
    val packageInfo = if (Build.VERSION.SDK_INT >= 33) {
        packageManager.getPackageInfo(packageName, PackageManager.PackageInfoFlags.of(0))
    } else {
        @Suppress("DEPRECATION")
        packageManager.getPackageInfo(packageName, 0)
    }
    return InstallationMetadata(
        appVersion = packageInfo.versionName?.takeIf { it.isNotBlank() }
            ?: packageInfo.compatibleVersionCode().toString(),
        osVersion = Build.VERSION.RELEASE,
        deviceModel = listOf(Build.MANUFACTURER, Build.MODEL).filter { it.isNotBlank() }.joinToString(" ").take(128),
    )
}

private fun PackageInfo.compatibleVersionCode(): Long = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
    longVersionCode
} else {
    @Suppress("DEPRECATION")
    versionCode.toLong()
}

private fun storageNamespace(configuration: LatchwayConfiguration): String {
    val input = "${configuration.baseUrl.scheme}://${configuration.baseUrl.host}:${configuration.baseUrl.port}/" +
        "${configuration.applicationId}/${configuration.environment}"
    val platformInput = "$input/${configuration.clientPlatform.wireValue}"
    return Base64Url.encode(
        MessageDigest.getInstance("SHA-256").digest(platformInput.toByteArray(StandardCharsets.UTF_8)),
    )
        .take(32)
}

private fun validateFeature(feature: String) {
    require(Regex("^[a-z][a-z0-9_-]{0,62}$").matches(feature)) { "feature is not a canonical identifier" }
}

internal fun responseCount(response: Response): Int {
    var count = 1
    var previous = response.priorResponse
    while (previous != null) {
        count++
        previous = previous.priorResponse
    }
    return count
}

internal fun Response.problemCode(): LatchwayErrorCode? = try {
    if ((code != 401 && code != 403) || body.contentType()?.let {
            it.type != "application" || it.subtype != "problem+json"
        } != false
    ) {
        null
    } else {
        val responseRequestId = header("X-Latchway-Request-ID")?.takeIf(::isValidRequestId)
        if (responseRequestId == null) {
            null
        } else {
            val problem = JSONObject(peekBody(64 * 1024).string())
            val problemStatus = problem.get("status")
            val rawCode = problem.get("code") as? String
            val requestId = problem.get("request_id") as? String
            val type = problem.get("type") as? String
            val title = problem.get("title") as? String
            val detail = problem.get("detail") as? String
            val retryable = problem.get("retryable") as? Boolean
            if (problemStatus !is Number || problemStatus.toDouble() != code.toDouble() ||
                requestId != responseRequestId || rawCode == null ||
                type != "https://latchway.dev/problems/$rawCode" || title.isNullOrBlank() ||
                detail.isNullOrBlank() || retryable == null
            ) {
                null
            } else {
                val problemCode = LatchwayErrorCode.fromWire(rawCode).takeIf { it.wireValue == rawCode }
                when (code) {
                    401 -> problemCode?.takeIf {
                        it in AUTHENTICATOR_PROBLEM_CODES && retryable == it.canonicalRetryability()
                    }
                    403 -> problemCode?.takeIf {
                        it == LatchwayErrorCode.INSTALLATION_REVOKED && !retryable
                    }
                    else -> null
                }
            }
        }
    }
} catch (_: Exception) {
    null
}

internal fun observeInstallationRevocation(
    response: Response,
    trustedOrigin: (HttpUrl) -> Boolean,
    markRevoked: () -> Unit,
) {
    if (trustedOrigin(response.request.url) &&
        response.problemCode() == LatchwayErrorCode.INSTALLATION_REVOKED
    ) {
        markRevoked()
    }
}

internal fun gatewayOriginGuard(gatewayOrigin: HttpUrl): Interceptor = Interceptor { chain ->
    val request = chain.request()
    val isGatewayOrigin = request.url.hasSameOrigin(gatewayOrigin)
    if (!isGatewayOrigin &&
        (request.hasLatchwayCredentials() || request.tag(AuthorizedHeaders::class.java) != null)
    ) {
        throw LatchwayException(
            code = LatchwayErrorCode.CONFIGURATION_INVALID,
            safeMessage = "Latchway credentials cannot follow a redirect to another origin",
        )
    }
    if (isGatewayOrigin) {
        rejectUpstreamCredentials(request, authorizationWillBeReplaced = false)
    }
    chain.proceed(request)
}

internal val FORBIDDEN_CALLER_CREDENTIAL_NAMES: Set<String> = setOf(
    "authorization",
    "proxy-authorization",
    "api-key",
    "api_key",
    "apikey",
    "x-api-key",
    "openai-api-key",
    "openai_api_key",
    "x-openai-api-key",
    "anthropic-api-key",
    "anthropic_api_key",
    "x-goog-api-key",
    "x-goog-api_key",
    "access_token",
    "token",
    "key",
)

internal fun rejectUpstreamCredentials(
    request: Request,
    authorizationWillBeReplaced: Boolean,
) {
    val hasForbiddenHeader = request.headers.names().any { name ->
        val normalized = name.lowercase(Locale.US)
        if (normalized == "cookie") {
            true
        } else if (normalized !in FORBIDDEN_CALLER_CREDENTIAL_NAMES) {
            false
        } else if (normalized == "authorization") {
            !authorizationWillBeReplaced && !request.hasLatchwayAuthorization()
        } else {
            true
        }
    }
    if (hasForbiddenHeader) throw upstreamCredentialError()

    if (request.url.queryParameterNames.any {
            it.lowercase(Locale.US) in FORBIDDEN_CALLER_CREDENTIAL_NAMES
        }
    ) {
        throw upstreamCredentialError()
    }
}

private fun Request.hasLatchwayAuthorization(): Boolean {
    val values = headers.values("Authorization")
    if (values.size != 1) return false
    val value = values.single()
    val authorized = tag(AuthorizedHeaders::class.java)
    return if (authorized != null) {
        value == authorized.authorizationHeader()
    } else {
        value.startsWith("DPoP ") && value.length > 5
    }
}

private fun upstreamCredentialError(): LatchwayException = LatchwayException(
    code = LatchwayErrorCode.REQUEST_INVALID,
    safeMessage = "Upstream provider credentials must not be supplied to Latchway",
)

private fun Request.hasLatchwayCredentials(): Boolean =
    header("DPoP") != null || header("Authorization")?.startsWith("DPoP ") == true ||
        headers.names().any { it.startsWith("X-Latchway-", ignoreCase = true) }

private fun HttpUrl.hasSameOrigin(other: HttpUrl): Boolean =
    scheme == other.scheme && host == other.host && port == other.port

internal fun isValidNonce(value: String): Boolean =
    value.length in 16..512 && value.none { it.isISOControl() }

private fun isValidRequestId(value: String): Boolean =
    value.length in 8..128 && Regex("^[A-Za-z0-9][A-Za-z0-9._:-]*$").matches(value)

private val AUTHENTICATOR_PROBLEM_CODES: Set<LatchwayErrorCode> = setOf(
    LatchwayErrorCode.DPOP_NONCE_REQUIRED,
    LatchwayErrorCode.SESSION_EXPIRED,
    LatchwayErrorCode.SESSION_REVOKED,
    LatchwayErrorCode.REFRESH_TOKEN_REUSED,
)

private fun LatchwayErrorCode.canonicalRetryability(): Boolean = when (this) {
    LatchwayErrorCode.DPOP_NONCE_REQUIRED,
    LatchwayErrorCode.SESSION_EXPIRED -> true
    else -> false
}

internal enum class AuthenticationAction { NONE, NONCE, REFRESH, CLEAR }

internal data class AuthenticationDecision(
    val action: AuthenticationAction,
    val nonce: String? = null,
)

internal fun authenticationDecision(response: Response): AuthenticationDecision {
    if (responseCount(response) > 1) return AuthenticationDecision(AuthenticationAction.NONE)
    val body = response.request.body
    if (body != null && (body.isOneShot() || body.isDuplex())) {
        return AuthenticationDecision(AuthenticationAction.NONE)
    }
    return when (response.problemCode()) {
        LatchwayErrorCode.DPOP_NONCE_REQUIRED -> {
            val nonce = response.header("DPoP-Nonce")?.takeIf(::isValidNonce)
                ?: return AuthenticationDecision(AuthenticationAction.NONE)
            AuthenticationDecision(AuthenticationAction.NONCE, nonce)
        }
        LatchwayErrorCode.SESSION_EXPIRED -> AuthenticationDecision(AuthenticationAction.REFRESH)
        LatchwayErrorCode.SESSION_REVOKED,
        LatchwayErrorCode.REFRESH_TOKEN_REUSED -> AuthenticationDecision(AuthenticationAction.CLEAR)
        else -> AuthenticationDecision(AuthenticationAction.NONE)
    }
}
