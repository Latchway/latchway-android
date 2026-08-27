package dev.latchway.core

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.withContext
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.ProviderException
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec

/** A non-exportable Android Keystore P-256 installation key. */
public class AndroidKeystoreInstallationSigner private constructor(
    private val alias: String,
    override val publicJwk: PublicJwk,
    override val diagnostics: KeyDiagnostics,
) : InstallationSigner {
    override suspend fun sign(signingInput: ByteArray): ByteArray = withContext(Dispatchers.IO) {
        try {
            val keyStore = loadKeyStore()
            val privateKey = keyStore.getKey(alias, null)
                ?: throw IllegalStateException("Installation key is absent")
            val signature = Signature.getInstance("SHA256withECDSA")
            signature.initSign(privateKey as java.security.PrivateKey)
            signature.update(signingInput)
            EcdsaSignatureCodec.derToJose(signature.sign())
        } catch (error: LatchwayException) {
            throw error
        } catch (error: CancellationException) {
            throw error
        } catch (error: Exception) {
            throw LatchwayException(
                code = LatchwayErrorCode.KEY_UNAVAILABLE,
                safeMessage = "The installation signing key is unavailable",
                cause = error,
            )
        }
    }

    public companion object {
        private const val DEFAULT_ALIAS = "dev.latchway.installation.dpop.v1"

        public suspend fun create(
            context: Context,
            alias: String = DEFAULT_ALIAS,
            policy: KeyPolicy = KeyPolicy(),
        ): AndroidKeystoreInstallationSigner = withContext(Dispatchers.IO) {
            require(ALIAS.matches(alias)) { "Keystore alias is invalid" }
            val keyStore = loadKeyStore()
            val existing = keyStore.getCertificate(alias)?.publicKey as? ECPublicKey
            val strongBoxRequested = policy.preferStrongBox
            var strongBoxUnavailable = false
            val publicKey = if (existing != null) {
                existing
            } else {
                val attempts = generationAttempts(
                    policy = policy,
                    apiLevel = Build.VERSION.SDK_INT,
                    strongBoxFeaturePresent = context.packageManager.hasSystemFeature(
                        PackageManager.FEATURE_STRONGBOX_KEYSTORE,
                    ),
                )
                val mayUseStrongBox = attempts.first() == KeyGenerationAttempt.STRONGBOX
                strongBoxUnavailable = strongBoxRequested && !mayUseStrongBox
                if (mayUseStrongBox) {
                    try {
                        generate(alias, strongBox = true)
                    } catch (_: ProviderException) {
                        strongBoxUnavailable = true
                        generate(alias, strongBox = false)
                    }
                } else {
                    generate(alias, strongBox = false)
                }
                loadKeyStore().getCertificate(alias).publicKey as ECPublicKey
            }

            val privateKey = loadKeyStore().getKey(alias, null) as java.security.PrivateKey
            val backing = inspectBacking(privateKey)
            if (strongBoxRequested && backing != KeyBacking.STRONGBOX) strongBoxUnavailable = true
            if (backing == KeyBacking.SOFTWARE && !policy.allowSoftwareBacked) {
                loadKeyStore().deleteEntry(alias)
                throw LatchwayException(
                    code = LatchwayErrorCode.KEY_UNAVAILABLE,
                    safeMessage = "A hardware-backed installation key is required by policy",
                )
            }
            val jwk = PublicJwk(
                x = Base64Url.encode(unsignedCoordinate(publicKey.w.affineX)),
                y = Base64Url.encode(unsignedCoordinate(publicKey.w.affineY)),
            )
            AndroidKeystoreInstallationSigner(
                alias = alias,
                publicJwk = jwk,
                diagnostics = KeyDiagnostics(
                    backing = backing,
                    strongBoxRequested = strongBoxRequested,
                    strongBoxUnavailable = strongBoxUnavailable,
                    publicJwkThumbprint = jwk.thumbprint(),
                ),
            )
        }

        private val ALIAS = Regex("^[A-Za-z0-9._-]{1,128}$")

        internal fun generationAttempts(
            policy: KeyPolicy,
            apiLevel: Int,
            strongBoxFeaturePresent: Boolean,
        ): List<KeyGenerationAttempt> = buildList {
            if (policy.preferStrongBox && apiLevel >= 28 && strongBoxFeaturePresent) {
                add(KeyGenerationAttempt.STRONGBOX)
            }
            add(KeyGenerationAttempt.DEFAULT_KEYSTORE)
        }

        private fun generate(alias: String, strongBox: Boolean): ECPublicKey {
            val builder = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setUserAuthenticationRequired(false)
            if (Build.VERSION.SDK_INT >= 28 && strongBox) builder.setIsStrongBoxBacked(true)
            val generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
            generator.initialize(builder.build())
            return generator.generateKeyPair().public as ECPublicKey
        }

        private fun inspectBacking(privateKey: java.security.PrivateKey): KeyBacking {
            val factory = KeyFactory.getInstance(privateKey.algorithm, "AndroidKeyStore")
            val info = factory.getKeySpec(privateKey, KeyInfo::class.java)
            return if (Build.VERSION.SDK_INT >= 31) {
                when (info.securityLevel) {
                    KeyProperties.SECURITY_LEVEL_STRONGBOX -> KeyBacking.STRONGBOX
                    KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> KeyBacking.TRUSTED_EXECUTION_ENVIRONMENT
                    KeyProperties.SECURITY_LEVEL_SOFTWARE -> KeyBacking.SOFTWARE
                    else -> KeyBacking.UNKNOWN_SECURE_HARDWARE
                }
            } else if (@Suppress("DEPRECATION") info.isInsideSecureHardware) {
                KeyBacking.UNKNOWN_SECURE_HARDWARE
            } else {
                KeyBacking.SOFTWARE
            }
        }

        private fun unsignedCoordinate(value: BigInteger): ByteArray {
            val raw = value.toByteArray()
            val unsigned = if (raw.size == 33 && raw[0].toInt() == 0) raw.copyOfRange(1, 33) else raw
            require(unsigned.size <= 32) { "P-256 coordinate is oversized" }
            return ByteArray(32).also { unsigned.copyInto(it, 32 - unsigned.size) }
        }

        private fun loadKeyStore(): KeyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    }
}

internal enum class KeyGenerationAttempt { STRONGBOX, DEFAULT_KEYSTORE }
