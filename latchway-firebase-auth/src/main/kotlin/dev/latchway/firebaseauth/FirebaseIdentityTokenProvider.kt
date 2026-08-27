package dev.latchway.firebaseauth

import com.google.firebase.auth.FirebaseAuth
import dev.latchway.core.IdentityTokenProvider
import dev.latchway.core.LatchwayErrorCode
import dev.latchway.core.LatchwayException
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.tasks.await

public class FirebaseIdentityTokenProvider private constructor(
    private val source: FirebaseTokenSource,
) : IdentityTokenProvider {
    @JvmOverloads
    public constructor(
        firebaseAuth: FirebaseAuth = FirebaseAuth.getInstance(),
        forceRefresh: Boolean = false,
    ) : this(FirebaseAuthTokenSource(firebaseAuth, forceRefresh))

    override suspend fun identityToken(): String {
        val token = try {
            source.token()
        } catch (error: LatchwayException) {
            throw error
        } catch (error: CancellationException) {
            throw error
        } catch (error: Exception) {
            throw LatchwayException(
                code = LatchwayErrorCode.IDENTITY_TOKEN_INVALID,
                retryable = true,
                safeMessage = "Firebase could not provide an identity token",
                cause = error,
            )
        }
        if (token == null) {
            throw LatchwayException(
                code = LatchwayErrorCode.IDENTITY_TOKEN_MISSING,
                safeMessage = "A signed-in Firebase user is required",
            )
        }
        if (token.length !in 16..65_536) {
            throw LatchwayException(
                code = LatchwayErrorCode.IDENTITY_TOKEN_INVALID,
                safeMessage = "Firebase returned an invalid identity token",
            )
        }
        return token
    }

    internal companion object {
        fun forTesting(source: FirebaseTokenSource): FirebaseIdentityTokenProvider =
            FirebaseIdentityTokenProvider(source)
    }
}

internal fun interface FirebaseTokenSource {
    suspend fun token(): String?
}

private class FirebaseAuthTokenSource(
    private val firebaseAuth: FirebaseAuth,
    private val forceRefresh: Boolean,
) : FirebaseTokenSource {
    override suspend fun token(): String? {
        val user = firebaseAuth.currentUser ?: return null
        return user.getIdToken(forceRefresh).await().token
    }
}
