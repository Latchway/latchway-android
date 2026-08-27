package dev.latchway.okhttp

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
            .priorResponse(first.newBuilder().body(ByteArray(0).toResponseBody()).build())
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
    fun onlyPreDispatchSessionFailuresRefreshAndRevocationsClear() {
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
            authenticationDecision(response("installation_revoked")).action,
        )
    }

    private fun response(
        code: String,
        body: RequestBody? = null,
        nonce: String? = null,
        mediaType: String = "application/problem+json",
        requestIdHeader: String? = "req_12345678",
        problemStatus: Int = 401,
    ): Response {
        val request = Request.Builder()
            .url("https://gateway.example.test/v1/responses")
            .method(if (body == null) "GET" else "POST", body)
            .build()
        return Response.Builder()
            .request(request)
            .protocol(Protocol.HTTP_1_1)
            .code(401)
            .message("Unauthorized")
            .apply { nonce?.let { header("DPoP-Nonce", it) } }
            .apply { requestIdHeader?.let { header("X-Latchway-Request-ID", it) } }
            .body(
                """{"status":$problemStatus,"code":"$code","request_id":"req_12345678","detail":"Request rejected","retryable":false}"""
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
