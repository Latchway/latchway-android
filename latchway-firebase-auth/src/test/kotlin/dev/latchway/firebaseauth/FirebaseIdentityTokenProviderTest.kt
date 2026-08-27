package dev.latchway.firebaseauth

import dev.latchway.core.LatchwayErrorCode
import dev.latchway.core.LatchwayException
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Test

class FirebaseIdentityTokenProviderTest {
    @Test
    fun returnsTokenWithoutIncludingItInDiagnostics() = runBlocking {
        val token = "firebase-identity-token-value"
        val provider = FirebaseIdentityTokenProvider.forTesting(FirebaseTokenSource { token })
        assertEquals(token, provider.identityToken())
        assertFalse(provider.toString().contains(token))
    }

    @Test
    fun missingUserMapsToStableIdentityError() {
        val provider = FirebaseIdentityTokenProvider.forTesting(FirebaseTokenSource { null })
        val error = assertThrows(LatchwayException::class.java) {
            runBlocking { provider.identityToken() }
        }
        assertEquals(LatchwayErrorCode.IDENTITY_TOKEN_MISSING, error.code)
    }

    @Test
    fun sdkFailureIsSanitizedAndRetryable() {
        val provider = FirebaseIdentityTokenProvider.forTesting(
            FirebaseTokenSource { throw IllegalStateException("token=secret-value") },
        )
        val error = assertThrows(LatchwayException::class.java) {
            runBlocking { provider.identityToken() }
        }
        assertEquals(LatchwayErrorCode.IDENTITY_TOKEN_INVALID, error.code)
        assertEquals(true, error.retryable)
        assertFalse(error.toString().contains("secret-value"))
    }

    @Test
    fun coroutineCancellationIsPreserved() {
        val provider = FirebaseIdentityTokenProvider.forTesting(
            FirebaseTokenSource { throw CancellationException("cancelled") },
        )
        assertThrows(CancellationException::class.java) {
            runBlocking { provider.identityToken() }
        }
    }
}
