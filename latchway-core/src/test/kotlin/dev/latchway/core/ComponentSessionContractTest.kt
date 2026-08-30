package dev.latchway.core

import java.net.URI
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class ComponentSessionContractTest {
    private val jwk = PublicJwk(
        x = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        y = "N5wrFgi5unJsGvU57MC-o4Iv5VHL-V6Sl9_2AcOS6cI",
    )

    @Test
    fun componentSnapshotRoundTripsWithoutLeakingCredentialsThroughFormatting() {
        val snapshot = ComponentSessionSnapshot(
            accessToken = SecretValue.of("a".repeat(64)),
            refreshToken = SecretValue.of("r".repeat(32)),
            accessExpiresAtEpochSeconds = 1_700_000_600,
            refreshExpiresAtEpochSeconds = 1_700_003_600,
            installation = InstallationSummary(
                id = "ins_01J00000000000000000000001",
                platform = "android",
                dpopJkt = jwk.thumbprint(),
                status = "active",
            ),
            installationFamily = InstallationFamilySummary(
                "fam_01J00000000000000000000001",
                "active",
            ),
            component = ClientComponentSummary(
                id = "cmp_01J00000000000000000000001",
                definitionId = "android-wear",
                kind = "wear_app",
                platform = "android",
                isRoot = false,
                status = "active",
                dpopJkt = jwk.thumbprint(),
                grantedFeatures = setOf("assistant"),
            ),
            trust = ComponentTrustSummary(
                provider = "debug",
                level = "debug",
                source = "delegated_from_attested_root",
                parentComponentId = "cmp_01J00000000000000000000000",
                parentAttestationProvider = "debug",
                delegationId = "dlg_01J00000000000000000000001",
                verifiedAt = "2023-11-14T22:13:20Z",
                expiresAt = "2023-11-14T23:13:20Z",
            ),
        )

        val restored = decodeComponentSnapshot(encodeComponentSnapshot(snapshot))

        assertEquals(snapshot.component, restored.component)
        assertEquals(snapshot.installationFamily, restored.installationFamily)
        assertEquals("a".repeat(64), restored.accessToken.reveal())
        assertEquals("r".repeat(32), restored.refreshToken.reveal())
        assertTrue(snapshot.toString().contains("credentials=[REDACTED]"))
        assertFalse(snapshot.toString().contains("a".repeat(64)))
        assertFalse(snapshot.toString().contains("r".repeat(32)))
    }

    @Test
    fun compositeDirectAttestedTrustRoundTripsButCannotAppearInProvisioning() {
        val snapshot = ComponentSessionSnapshot(
            accessToken = SecretValue.of("a".repeat(64)),
            refreshToken = SecretValue.of("r".repeat(32)),
            accessExpiresAtEpochSeconds = 1_700_000_600,
            refreshExpiresAtEpochSeconds = 1_700_003_600,
            installation = InstallationSummary(
                id = "ins_01J00000000000000000000001",
                platform = "android",
                dpopJkt = jwk.thumbprint(),
                status = "active",
            ),
            installationFamily = InstallationFamilySummary(
                "fam_01J00000000000000000000001",
                "active",
            ),
            component = ClientComponentSummary(
                id = "cmp_01J00000000000000000000001",
                definitionId = "android-wear",
                kind = "wear_app",
                platform = "android",
                isRoot = false,
                status = "active",
                dpopJkt = jwk.thumbprint(),
                grantedFeatures = setOf("assistant"),
            ),
            trust = ComponentTrustSummary(
                provider = "app_attest",
                level = "app_verified",
                source = "delegated_direct_attested",
                parentComponentId = "cmp_01J00000000000000000000000",
                parentAttestationProvider = "app_attest",
                delegationId = "dlg_01J00000000000000000000001",
                verifiedAt = "2023-11-14T22:13:20Z",
                expiresAt = "2023-11-14T23:13:20Z",
            ),
        )

        val restored = decodeComponentSnapshot(encodeComponentSnapshot(snapshot))

        assertEquals("delegated_direct_attested", restored.trust.source)
        assertEquals(snapshot.trust, restored.trust)

        val invalidProvisioning = componentProvisioning(
            features = "[\"assistant\"]",
            refreshExpiry = "2023-11-14T23:13:20Z",
            source = "delegated_direct_attested",
        )
        val error = assertThrows(LatchwayException::class.java) {
            parseComponentProvisioning(
                encoded = invalidProvisioning,
                definitionId = "android-wear",
                publicJwk = jwk,
                requestedFeatures = setOf("assistant"),
                nowEpochSeconds = 1_700_000_000,
            )
        }
        assertEquals(LatchwayErrorCode.RESPONSE_INVALID, error.code)
    }

    @Test
    fun provisioningResponseCannotExpandFeatureScopeOrDivergeFromTrustExpiry() {
        val expanded = componentProvisioning(
            features = "[\"assistant\",\"admin\"]",
            refreshExpiry = "2023-11-14T23:13:20Z",
        )
        val expandedError = assertThrows(LatchwayException::class.java) {
            parseComponentProvisioning(
                encoded = expanded,
                definitionId = "android-wear",
                publicJwk = jwk,
                requestedFeatures = setOf("assistant"),
                nowEpochSeconds = 1_700_000_000,
            )
        }
        assertEquals(LatchwayErrorCode.RESPONSE_INVALID, expandedError.code)

        val mismatchedLifetime = componentProvisioning(
            features = "[\"assistant\"]",
            refreshExpiry = "2023-11-14T23:12:20Z",
        )
        val lifetimeError = assertThrows(LatchwayException::class.java) {
            parseComponentProvisioning(
                encoded = mismatchedLifetime,
                definitionId = "android-wear",
                publicJwk = jwk,
                requestedFeatures = setOf("assistant"),
                nowEpochSeconds = 1_700_000_000,
            )
        }
        assertEquals(LatchwayErrorCode.RESPONSE_INVALID, lifetimeError.code)
    }

    @Test
    fun everyInstallationFamilyAndFrameworkErrorHasAnExactWireMapping() {
        val values = setOf(
            "installation_family_revoked",
            "installation_family_not_found",
            "component_definition_not_found",
            "component_not_configured",
            "component_not_provisioned",
            "component_revoked",
            "component_key_invalid",
            "component_key_replaced",
            "component_delegation_expired",
            "component_feature_not_granted",
            "component_parent_trust_expired",
            "component_direct_attestation_required",
            "containing_app_setup_required",
            "framework_integration_unsupported",
            "framework_version_unsupported",
            "transport_destination_not_allowed",
            "transport_request_not_replayable",
        )

        values.forEach { value -> assertEquals(value, LatchwayErrorCode.fromWire(value).wireValue) }
    }

    @Test
    fun componentErrorsExposeSafeRecoveryMetadata() {
        val setup = LatchwayException(LatchwayErrorCode.COMPONENT_NOT_PROVISIONED)
        assertEquals(LatchwayRecoveryAction.OPEN_CONTAINING_APP, setup.recoveryAction)
        assertTrue(setup.containingAppCanResolve)
        assertFalse(setup.userAuthenticationRequired)
        assertFalse(setup.retryingImmediatelyUseful)

        val identity = LatchwayException(LatchwayErrorCode.IDENTITY_REAUTHENTICATION_REQUIRED)
        assertEquals(LatchwayRecoveryAction.REAUTHENTICATE_USER, identity.recoveryAction)
        assertTrue(identity.userAuthenticationRequired)

        val transient = LatchwayException(
            code = LatchwayErrorCode.NETWORK_UNAVAILABLE,
            retryable = true,
        )
        assertEquals(LatchwayRecoveryAction.RETRY_LATER, transient.recoveryAction)
        assertTrue(transient.retryingImmediatelyUseful)
    }

    @Test
    fun componentAuthorizationRoutesAreExactAndFeatureBound() {
        val gateway = URI("https://gateway.example.test/base/")
        requireComponentDataPlaneDestination(
            gateway,
            URI("https://gateway.example.test/base/v1/responses"),
            "POST",
            "assistant",
        )
        requireComponentDataPlaneDestination(
            gateway,
            URI("https://gateway.example.test/base/proxy/assistant/models"),
            "GET",
            "assistant",
        )

        listOf(
            URI("https://other.example.test/base/v1/responses"),
            URI("https://gateway.example.test/v1/responses"),
            URI("https://gateway.example.test/base/client/v1/diagnostics"),
            URI("https://gateway.example.test/base/proxy/other/models"),
            URI("https://gateway.example.test/base/proxy/assistant/models?cursor=secret"),
            URI("https://gateway.example.test/base/proxy/assistant/%2e%2e/admin"),
            URI("https://gateway.example.test/base/proxy/assistant/models//latest"),
            URI("https://gateway.example.test/base/proxy/assistant/models/"),
            URI("https://gateway.example.test/base/proxy/assistant/${"a".repeat(2_049)}"),
            URI("https://gateway.example.test/base/proxy/assistant/models#fragment"),
        ).forEach { target ->
            val error = assertThrows(LatchwayException::class.java) {
                requireComponentDataPlaneDestination(gateway, target, "GET", "assistant")
            }
            assertEquals(LatchwayErrorCode.TRANSPORT_DESTINATION_NOT_ALLOWED, error.code)
        }
    }

    private fun componentProvisioning(
        features: String,
        refreshExpiry: String,
        source: String = "delegated_from_attested_root",
    ): String = """
        {
          "component_id":"cmp_01J00000000000000000000001",
          "installation_family_id":"fam_01J00000000000000000000001",
          "trust":{
            "source":"$source",
            "expires_at":"2023-11-14T23:13:20Z"
          },
          "granted_features":$features,
          "refresh_grant":"${"g".repeat(32)}",
          "refresh_grant_expires_at":"$refreshExpiry"
        }
    """.trimIndent()
}
