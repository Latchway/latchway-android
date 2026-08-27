package dev.latchway.core

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.math.BigInteger
import java.net.URI
import java.nio.charset.StandardCharsets
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.PrivateKey
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPrivateKeySpec
import java.security.spec.ECPublicKeySpec

class DpopContractTest {
    private val fixture: JSONObject by lazy {
        val stream = checkNotNull(javaClass.classLoader?.getResourceAsStream("contract/dpop-v1.json"))
        JSONObject(stream.bufferedReader().use { it.readText() })
    }

    @Test
    fun authoritativeThumbprintAndAccessTokenHashMatch() {
        val public = fixture.getJSONObject("public_jwk")
        val jwk = PublicJwk(public.getString("x"), public.getString("y"))
        assertEquals(fixture.getString("jwk_thumbprint_sha256_base64url"), jwk.thumbprint())
        assertEquals(
            fixture.getString("fixture_access_token_hash"),
            Base64Url.encode(sha256(fixture.getString("fixture_access_token").toByteArray(StandardCharsets.US_ASCII))),
        )
    }

    @Test
    fun everyAuthoritativeVectorHasAValidEs256Signature() {
        val key = fixturePublicKey()
        val vectors = fixture.getJSONArray("vectors")
        repeat(vectors.length()) { index ->
            val vector = vectors.getJSONObject(index)
            val parts = vector.getString("proof").split('.')
            assertEquals(3, parts.size)
            val verifier = Signature.getInstance("SHA256withECDSA")
            verifier.initVerify(key)
            verifier.update("${parts[0]}.${parts[1]}".toByteArray(StandardCharsets.US_ASCII))
            assertTrue(
                "fixture ${vector.getString("id")} signature",
                verifier.verify(EcdsaSignatureCodec.joseToDer(Base64Url.decode(parts[2]))),
            )
        }
    }

    @Test
    fun generatedProtectedProofUsesCanonicalHtuAthAndNonce() = kotlinx.coroutines.runBlocking {
        val signer = fixtureSigner()
        val factory = DpopProofFactory(
            signer = signer,
            clock = LatchwayClock { 1_700_000_030 },
            jtiFactory = { "00000000-0000-4000-8000-000000000099" },
        )
        val proof = factory.create(
            DpopProofRequest(
                method = "POST",
                uri = URI("https://GATEWAY.example.test:443/v1/responses?untrusted=yes#fragment"),
                accessToken = SecretValue.of(fixture.getString("fixture_access_token")),
                nonce = "nonce-fixture-0123456789abcdef",
            ),
        ).reveal()
        val parts = proof.split('.')
        val header = JSONObject(String(Base64Url.decode(parts[0]), StandardCharsets.UTF_8))
        val claims = JSONObject(String(Base64Url.decode(parts[1]), StandardCharsets.UTF_8))
        assertEquals("dpop+jwt", header.getString("typ"))
        assertEquals("ES256", header.getString("alg"))
        assertFalse(header.getJSONObject("jwk").has("d"))
        assertEquals("https://gateway.example.test/v1/responses", claims.getString("htu"))
        assertEquals("POST", claims.getString("htm"))
        assertEquals(fixture.getString("fixture_access_token_hash"), claims.getString("ath"))
        assertEquals("nonce-fixture-0123456789abcdef", claims.getString("nonce"))
        assertEquals(1_700_000_030, claims.getLong("iat"))

        val verifier = Signature.getInstance("SHA256withECDSA")
        verifier.initVerify(fixturePublicKey())
        verifier.update("${parts[0]}.${parts[1]}".toByteArray(StandardCharsets.US_ASCII))
        assertTrue(verifier.verify(EcdsaSignatureCodec.joseToDer(Base64Url.decode(parts[2]))))
    }

    @Test
    fun proofsAreUniqueAndSensitiveValuesAreRedacted() = kotlinx.coroutines.runBlocking {
        var nextJti = 0
        val factory = DpopProofFactory(fixtureSigner(), LatchwayClock { 100 }) { "jti-${nextJti++}" }
        val request = DpopProofRequest("GET", URI("https://gateway.example.test/client/v1/diagnostics"))
        assertNotEquals(factory.create(request).reveal(), factory.create(request).reveal())
        assertEquals("[REDACTED]", SecretValue.of("identity-token-value").toString())
        assertEquals(
            "Sensitive detail redacted",
            LatchwayException(
                LatchwayErrorCode.INTERNAL_ERROR,
                safeMessage = "identity_token=eyJsecret",
            ).message,
        )
    }

    @Test
    fun base64UrlRejectsPaddingAndNonCanonicalTailBits() {
        assertThrows(IllegalArgumentException::class.java) { Base64Url.decode("AA==") }
        assertThrows(IllegalArgumentException::class.java) { Base64Url.decode("AB") }
        assertEquals(listOf<Byte>(0), Base64Url.decode("AA").toList())
        assertThrows(IllegalArgumentException::class.java) {
            PublicJwk("A".repeat(42) + "B", "A".repeat(43))
        }
        assertThrows(IllegalArgumentException::class.java) {
            AttestationChallenge(
                challengeId = "chl_01J00000000000000000000001",
                provider = "debug",
                mode = AttestationMode.REQUIRED,
                clientDataHash = "A".repeat(42) + "B",
                providerOptions = emptyMap(),
            )
        }
    }

    @Test
    fun unsafeRequestIdentifiersAreNeverExposedByErrors() {
        val error = LatchwayException(
            code = LatchwayErrorCode.INTERNAL_ERROR,
            requestId = "identity_token=credential",
        )
        assertEquals(null, error.requestId)
        assertFalse(error.toString().contains("credential"))
    }

    private fun fixturePublicKey(): ECPublicKey {
        val public = fixture.getJSONObject("public_jwk")
        val params = curveParameters()
        return KeyFactory.getInstance("EC").generatePublic(
            ECPublicKeySpec(
                ECPoint(
                    BigInteger(1, Base64Url.decode(public.getString("x"))),
                    BigInteger(1, Base64Url.decode(public.getString("y"))),
                ),
                params,
            ),
        ) as ECPublicKey
    }

    private fun fixtureSigner(): InstallationSigner {
        val private = fixture.getJSONObject("private_jwk_for_tests_only")
        val privateKey = KeyFactory.getInstance("EC").generatePrivate(
            ECPrivateKeySpec(BigInteger(1, Base64Url.decode(private.getString("d"))), curveParameters()),
        )
        val publicJwk = PublicJwk(private.getString("x"), private.getString("y"))
        return FixtureSigner(privateKey, publicJwk)
    }

    private fun curveParameters(): ECParameterSpec {
        val parameters = AlgorithmParameters.getInstance("EC")
        parameters.init(ECGenParameterSpec("secp256r1"))
        return parameters.getParameterSpec(ECParameterSpec::class.java)
    }

    private class FixtureSigner(
        private val privateKey: PrivateKey,
        override val publicJwk: PublicJwk,
    ) : InstallationSigner {
        override val diagnostics = KeyDiagnostics(
            KeyBacking.SOFTWARE,
            strongBoxRequested = false,
            strongBoxUnavailable = false,
            publicJwkThumbprint = publicJwk.thumbprint(),
        )

        override suspend fun sign(signingInput: ByteArray): ByteArray {
            val signer = Signature.getInstance("SHA256withECDSA")
            signer.initSign(privateKey)
            signer.update(signingInput)
            return EcdsaSignatureCodec.derToJose(signer.sign())
        }
    }
}
