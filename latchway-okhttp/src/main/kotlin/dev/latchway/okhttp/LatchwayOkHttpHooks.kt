package dev.latchway.okhttp

import dev.latchway.core.AuthorizedHeaders
import dev.latchway.core.LATCHWAY_PROTOCOL_VERSION
import dev.latchway.core.LatchwayComponentClient
import dev.latchway.core.LatchwayErrorCode
import dev.latchway.core.LatchwayException
import kotlinx.coroutines.runBlocking
import okhttp3.Authenticator
import okhttp3.HttpUrl
import okhttp3.Interceptor
import okhttp3.Request
import okhttp3.Route
import okhttp3.Response

/** Marker used to reject partial or duplicate manual hook installation. */
internal interface LatchwayOkHttpInstallationPart

private class LatchwayInstalledInterceptor(
    private val delegate: Interceptor,
) : Interceptor, LatchwayOkHttpInstallationPart {
    override fun intercept(chain: Interceptor.Chain): Response = delegate.intercept(chain)
}

private class LatchwayInstalledAuthenticator(
    private val delegate: Authenticator,
    private val fallback: Authenticator,
    private val isGatewayOrigin: (HttpUrl) -> Boolean,
) : Authenticator, LatchwayOkHttpInstallationPart {
    override fun authenticate(route: Route?, response: Response): Request? =
        if (isGatewayOrigin(response.request.url)) {
            delegate.authenticate(route, response)
        } else {
            fallback.authenticate(route, response)
        }
}

/**
 * Framework-neutral production OkHttp hooks used by [LatchwayClient].
 *
 * Repository conformance fixtures instantiate this internal implementation so
 * they exercise the same interceptors without adding a public test-double path
 * or a framework-specific production module.
 */
internal class LatchwayOkHttpHooks(
    private val configuration: LatchwayConfiguration,
    private val authorizer: suspend (
        component: LatchwayComponentClient?,
        request: Request,
        feature: String,
        nonce: String?,
    ) -> AuthorizedHeaders,
    private val refresher: suspend (component: LatchwayComponentClient?) -> Unit,
    private val clearer: suspend (
        component: LatchwayComponentClient?,
        authorization: AuthorizedHeaders,
    ) -> Unit,
    private val terminalResponseObserver: (Response, LatchwayComponentClient?) -> Unit,
) {
    fun interceptor(defaultComponent: LatchwayComponentClient? = null): Interceptor =
        LatchwayInstalledInterceptor(Interceptor { chain ->
            val request = chain.request()
            if (!isGatewayOrigin(request.url)) return@Interceptor chain.proceed(request)
            val component = defaultComponent ?: request.tag(LatchwayComponentClient::class.java)
            val feature = request.latchwayFeature()
            requireAllowedDataPlaneRequest(request, feature)
            val response = chain.proceed(
                runBlocking { authorize(component, request, feature, nonce = null) },
            )
            terminalResponseObserver(response, component)
            response
        })

    /** Final dispatch guard and proof renewal for every actual network attempt. */
    fun originGuard(): Interceptor = LatchwayInstalledInterceptor(Interceptor { chain ->
        val request = chain.request()
        if (!isGatewayOrigin(request.url)) {
            if (request.hasLatchwayCredentials() || request.tag(AuthorizedHeaders::class.java) != null) {
                throw LatchwayException(
                    code = LatchwayErrorCode.TRANSPORT_DESTINATION_NOT_ALLOWED,
                    safeMessage = "Latchway credentials cannot follow a redirect to another origin",
                )
            }
            return@Interceptor chain.proceed(request)
        }
        val feature = request.latchwayFeature()
        requireAllowedDataPlaneRequest(request, feature)
        rejectUpstreamCredentials(request, authorizationWillBeReplaced = true)
        claimNetworkAttempt(request)
        // A network interceptor runs once per actual network attempt. Re-sign
        // here so connection retries and same-origin follow-ups never reuse a
        // proof created by the application interceptor.
        val component = request.tag(LatchwayComponentClient::class.java)
        val authorized = runBlocking {
            authorize(component, request, feature, nonce = request.latchwayRetryNonce())
        }
        val outgoingBudget = checkNotNull(authorized.tag(LatchwayNetworkAttemptBudget::class.java))
        check(outgoingBudget.claim()) { "A fresh network-attempt budget must be unclaimed" }
        chain.proceed(authorized)
    })

    fun authenticator(fallback: Authenticator = Authenticator.NONE): Authenticator {
        val delegate = Authenticator { _, response ->
            if (!isGatewayOrigin(response.request.url)) return@Authenticator null
            val request = response.request
            val component = request.tag(LatchwayComponentClient::class.java)
            val decision = authenticationDecision(response)
            when (decision.action) {
                AuthenticationAction.NONCE -> {
                    val feature = runCatching { request.latchwayFeature() }.getOrNull()
                        ?: return@Authenticator null
                    val nonce = decision.nonce ?: return@Authenticator null
                    runCatching {
                        runBlocking { authorize(component, request, feature, nonce) }
                    }.getOrNull()
                }
                AuthenticationAction.REFRESH -> runCatching {
                    val feature = request.latchwayFeature()
                    runBlocking {
                        refresher(component)
                        authorize(component, request, feature, nonce = null)
                    }
                }.getOrNull()
                AuthenticationAction.CLEAR -> {
                    val authorization = request.tag(AuthorizedHeaders::class.java)
                        ?: return@Authenticator null
                    runCatching { runBlocking { clearer(component, authorization) } }
                    null
                }
                AuthenticationAction.NONE -> null
            }
        }
        return LatchwayInstalledAuthenticator(delegate, fallback, ::isGatewayOrigin)
    }

    suspend fun authorize(
        component: LatchwayComponentClient?,
        request: Request,
        feature: String,
        nonce: String? = null,
    ): Request {
        validateFeature(feature)
        if (!isGatewayOrigin(request.url)) {
            throw LatchwayException(
                code = LatchwayErrorCode.TRANSPORT_DESTINATION_NOT_ALLOWED,
                safeMessage = "Latchway credentials can only be attached to the configured gateway origin",
            )
        }
        requireAllowedDataPlaneRequest(request, feature)
        rejectUpstreamCredentials(request, authorizationWillBeReplaced = true)
        val authorized = authorizer(component, request, feature, nonce)
        return request.newBuilder()
            .header("Authorization", authorized.authorizationHeader())
            .header("DPoP", authorized.dpopHeader())
            .header("X-Latchway-Protocol-Version", LATCHWAY_PROTOCOL_VERSION.toString())
            .header("X-Latchway-SDK", configuration.clientPlatform.sdkHeaderValue)
            .header("X-Latchway-SDK-Version", configuration.sdkVersion)
            .header("X-Latchway-Framework", configuration.framework.id)
            .header("X-Latchway-Framework-Version", configuration.framework.version)
            .header("X-Latchway-Request-ID", authorized.requestId)
            .header("X-Latchway-Feature", feature)
            .tag(AuthorizedHeaders::class.java, authorized)
            .tag(LatchwayComponentClient::class.java, component)
            .tag(LatchwayFeature::class.java, LatchwayFeature(feature))
            // Preserve only a validated authenticator nonce so the final
            // network-bound proof remains bound after the guard re-signs it.
            .latchwayRetryNonce(nonce)
            // Safe nonce/session follow-ups receive a fresh bounded attempt;
            // internal connection retries share the already-claimed budget.
            .tag(
                LatchwayNetworkAttemptBudget::class.java,
                LatchwayNetworkAttemptBudget(authorized.requestId),
            )
            .build()
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

    private fun requireAllowedDataPlaneRequest(request: Request, feature: String) {
        if (!isAllowedDataPlaneRequest(configuration.baseUrl, request, feature)) {
            throw LatchwayException(
                code = LatchwayErrorCode.TRANSPORT_DESTINATION_NOT_ALLOWED,
                safeMessage = "The request is not an allowed Latchway data-plane route",
            )
        }
    }
}
