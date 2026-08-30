package dev.latchway.okhttp

import dev.latchway.core.LatchwayErrorCode
import dev.latchway.core.LatchwayException
import okhttp3.MediaType
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.Protocol
import okhttp3.Request
import okhttp3.RequestBody
import okhttp3.Response
import okhttp3.ResponseBody.Companion.toResponseBody
import okio.BufferedSink
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotSame
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class AuthenticatorPolicyTest {
    @Test
    fun controlClientIsIsolatedFromApplicationHooksRedirectsAndDispatcher() {
        val template = okhttp3.OkHttpClient.Builder()
            .addInterceptor { chain -> chain.proceed(chain.request()) }
            .addNetworkInterceptor { chain -> chain.proceed(chain.request()) }
            .followRedirects(true)
            .followSslRedirects(true)
            .build()

        val isolated = isolatedControlClient(template)

        assertTrue(isolated.interceptors.isEmpty())
        assertTrue(isolated.networkInterceptors.isEmpty())
        assertFalse(isolated.followRedirects)
        assertFalse(isolated.followSslRedirects)
        assertNotSame(template.dispatcher, isolated.dispatcher)
        assertNotSame(template.connectionPool, isolated.connectionPool)
    }

    @Test
    fun oneShotAndDuplexBodiesAreNeverRetried() {
        val oneShot = response("session_expired", body = PolicyBody(oneShot = true))
        val duplex = response("dpop_nonce_required", body = PolicyBody(duplex = true), nonce = VALID_NONCE)
        assertEquals(AuthenticationAction.NONE, authenticationDecision(oneShot).action)
        assertEquals(AuthenticationAction.NONE, authenticationDecision(duplex).action)
        assertEquals(
            AuthenticationAction.NONE,
            authenticationDecision(response("installation_revoked", body = PolicyBody(oneShot = true))).action,
        )
    }

    @Test
    fun nonceChallengeAllowsOneReplayWithValidatedNonce() {
        val decision = authenticationDecision(response("dpop_nonce_required", nonce = VALID_NONCE))
        assertEquals(AuthenticationAction.NONCE, decision.action)
        assertEquals(VALID_NONCE, decision.nonce)
        assertEquals(
            AuthenticationAction.NONE,
            authenticationDecision(response("dpop_nonce_required", nonce = "short")).action,
        )
    }

    @Test
    fun priorAuthenticationAttemptAndUnknownProblemAreNotRetried() {
        val first = response("session_expired")
        val repeated = first.newBuilder()
            .priorResponse(
                Response.Builder()
                    .request(first.request)
                    .protocol(first.protocol)
                    .code(first.code)
                    .message(first.message)
                    .build(),
            )
            .build()
        assertEquals(AuthenticationAction.NONE, authenticationDecision(repeated).action)
        assertEquals(AuthenticationAction.NONE, authenticationDecision(response("quota_exceeded")).action)
    }

    @Test
    fun unverifiedOrProviderOwnedErrorsNeverTriggerReplay() {
        assertEquals(
            AuthenticationAction.NONE,
            authenticationDecision(response("session_expired", mediaType = "application/json")).action,
        )
        assertEquals(
            AuthenticationAction.NONE,
            authenticationDecision(response("session_expired", requestIdHeader = null)).action,
        )
        assertEquals(
            AuthenticationAction.NONE,
            authenticationDecision(response("session_expired", problemStatus = 403)).action,
        )
    }

    @Test
    fun onlyPreDispatch401SessionFailuresReachTheAuthenticator() {
        assertEquals(
            AuthenticationAction.REFRESH,
            authenticationDecision(response("session_expired")).action,
        )
        assertEquals(
            AuthenticationAction.NONE,
            authenticationDecision(response("authentication_required")).action,
        )
        assertEquals(
            AuthenticationAction.CLEAR,
            authenticationDecision(response("refresh_token_reused")).action,
        )
        assertEquals(
            AuthenticationAction.CLEAR,
            authenticationDecision(response("session_revoked")).action,
        )
        assertEquals(
            AuthenticationAction.NONE,
            authenticationDecision(response("installation_revoked")).action,
        )
        assertEquals(
            AuthenticationAction.NONE,
            authenticationDecision(
                response("component_revoked", httpStatus = 403, problemStatus = 403),
            ).action,
        )
        assertEquals(
            LatchwayErrorCode.COMPONENT_KEY_REPLACED,
            response("component_key_replaced").problemCode(),
        )
    }

    @Test
    fun interceptorObservationTerminalizesOnlyCanonical403InstallationRevocation() {
        var revocations = 0
        val revoked = response("installation_revoked")

        observeInstallationRevocation(revoked, { it.host == "gateway.example.test" }) { revocations++ }

        assertEquals(1, revocations)

        observeInstallationRevocation(
            response("installation_family_revoked", httpStatus = 403, problemStatus = 403),
            { it.host == "gateway.example.test" },
        ) { revocations++ }
        assertEquals(2, revocations)
        assertTrue(checkNotNull(revoked.body).string().contains("installation_revoked"))

        observeInstallationRevocation(
            response("installation_revoked", httpStatus = 401, problemStatus = 401),
            { it.host == "gateway.example.test" },
        ) { revocations++ }
        assertEquals(2, revocations)

        observeInstallationRevocation(
            response("installation_revoked", url = "https://redirect.example.test/final"),
            { it.host == "gateway.example.test" },
        ) { revocations++ }
        assertEquals(2, revocations)
        assertEquals(
            null,
            response("feature_not_allowed", httpStatus = 403, problemStatus = 403).problemCode(),
        )
        assertEquals(
            null,
            response("session_expired", httpStatus = 403, problemStatus = 403).problemCode(),
        )
    }

    @Test
    fun exactCredentialHeadersAreRejectedWhileAuthorizationCanBeReplaced() {
        val target = "https://gateway.example.test/v1/responses"
        for (name in (FORBIDDEN_CALLER_CREDENTIAL_NAMES - "authorization") + "cookie") {
            val request = Request.Builder()
                .url(target)
                .header(name.uppercase(), "provider-secret")
                .build()

            val error = assertThrows(LatchwayException::class.java) {
                rejectUpstreamCredentials(request, authorizationWillBeReplaced = true)
            }

            assertEquals(LatchwayErrorCode.REQUEST_INVALID, error.code)
            assertFalse(error.message.orEmpty().contains("provider-secret"))
        }

        val placeholderAuthorization = Request.Builder()
            .url(target)
            .header("Authorization", "Bearer caller-placeholder")
            .build()
        rejectUpstreamCredentials(placeholderAuthorization, authorizationWillBeReplaced = true)

        assertThrows(LatchwayException::class.java) {
            rejectUpstreamCredentials(placeholderAuthorization, authorizationWillBeReplaced = false)
        }
    }

    @Test
    fun exactCredentialQueryNamesAreRejectedCaseInsensitivelyAfterDecoding() {
        for (name in FORBIDDEN_CALLER_CREDENTIAL_NAMES) {
            val request = Request.Builder()
                .url("https://gateway.example.test/v1/responses?${name.uppercase()}=provider-secret")
                .build()

            assertThrows(LatchwayException::class.java) {
                rejectUpstreamCredentials(request, authorizationWillBeReplaced = true)
            }
        }

        val encoded = Request.Builder()
            .url("https://gateway.example.test/v1/responses?api%5Fkey=provider-secret")
            .build()
        assertThrows(LatchwayException::class.java) {
            rejectUpstreamCredentials(encoded, authorizationWillBeReplaced = true)
        }

        val ordinary = Request.Builder()
            .url("https://gateway.example.test/v1/responses?model=gpt-5&stream=true&cookie=enabled")
            .header("X-Application-Metadata", "safe")
            .build()
        rejectUpstreamCredentials(ordinary, authorizationWillBeReplaced = true)
    }

    private fun response(
        code: String,
        body: RequestBody? = null,
        nonce: String? = null,
        mediaType: String = "application/problem+json",
        requestIdHeader: String? = "req_12345678",
        httpStatus: Int = if (code == "installation_revoked") 403 else 401,
        problemStatus: Int = httpStatus,
        url: String = "https://gateway.example.test/v1/responses",
    ): Response {
        val request = Request.Builder()
            .url(url)
            .method(if (body == null) "GET" else "POST", body)
            .build()
        return Response.Builder()
            .request(request)
            .protocol(Protocol.HTTP_1_1)
            .code(httpStatus)
            .message(if (httpStatus == 403) "Forbidden" else "Unauthorized")
            .apply { nonce?.let { header("DPoP-Nonce", it) } }
            .apply { requestIdHeader?.let { header("X-Latchway-Request-ID", it) } }
            .body(
                """{"type":"https://latchway.dev/problems/$code","title":"Request rejected","status":$problemStatus,"code":"$code","request_id":"req_12345678","detail":"Request rejected","retryable":${code == "dpop_nonce_required" || code == "session_expired"}}"""
                    .toResponseBody(mediaType.toMediaType()),
            )
            .build()
    }

    private class PolicyBody(
        private val oneShot: Boolean = false,
        private val duplex: Boolean = false,
    ) : RequestBody() {
        override fun contentType(): MediaType? = null
        override fun isOneShot(): Boolean = oneShot
        override fun isDuplex(): Boolean = duplex
        override fun writeTo(sink: BufferedSink) { sink.writeUtf8("body") }
    }

    private companion object {
        const val VALID_NONCE = "nonce-0123456789abcdef"
    }
}
