package dev.latchway.core

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.URI
import java.nio.charset.StandardCharsets
import java.time.Instant

class ContractManifestTest {
    private val manifest: JSONObject by lazy { resource("contract/protocol-version.json") }
    private val dpopVectors: JSONObject by lazy { resource("contract/dpop-v1.json") }
    private val attestationVectors: JSONObject by lazy { resource("contract/attestation-binding-v1.json") }
    private val componentAttestationVectors: JSONObject by lazy {
        resource("contract/component-attestation-binding-v2.json")
    }
    private val installationFamilyVectors: JSONObject by lazy {
        resource("contract/installation-family-v2.json")
    }

    @Test
    fun authoritativeManifestMatchesRuntimeContractAndWireConstants() {
        assertEquals(1, manifest.getInt("manifest_version"))
        assertEquals(LATCHWAY_CONTRACT_VERSION, manifest.getString("contract_version"))
        assertEquals("released", manifest.getString("contract_status"))

        val wire = manifest.getJSONObject("wire_protocol")
        assertEquals(LATCHWAY_PROTOCOL_VERSION, wire.getInt("current"))
        assertEquals(1, wire.getInt("minimum"))
        assertEquals(listOf(1, LATCHWAY_PROTOCOL_VERSION), wire.getJSONArray("supported").integers())

        val bundle = manifest.getJSONObject("bundle")
        assertEquals("latchway-contract-$LATCHWAY_CONTRACT_VERSION.tar.gz", bundle.getString("file_name"))
        assertEquals(
            listOf(
                "client.openapi.yaml",
                "admin.openapi.yaml",
                "config.schema.json",
                "attestation-binding.schema.json",
                "component-attestation-binding.schema.json",
                "release-evidence.schema.json",
                "error-codes.yaml",
                "protocol-version.json",
                "compatibility",
                "test-vectors",
                "SHA256SUMS",
            ),
            bundle.getJSONArray("required_entries").strings(),
        )

        val dpop = manifest.getJSONObject("dpop")
        assertEquals("RFC 9449", dpop.getString("specification"))
        assertEquals("RFC 7638", dpop.getString("jwk_thumbprint_specification"))
        assertEquals(listOf("ES256"), dpop.getJSONArray("algorithms").strings())
        assertEquals(listOf("P-256"), dpop.getJSONArray("curves").strings())
        assertEquals("dpop+jwt", dpop.getString("proof_type"))

        val headers = manifest.getJSONObject("standard_headers")
        assertEquals("X-Latchway-Feature", headers.getString("feature"))
        assertEquals("X-Latchway-SDK", headers.getString("sdk"))
        assertEquals("X-Latchway-SDK-Version", headers.getString("sdk_version"))
        assertEquals("X-Latchway-Framework", headers.getString("framework"))
        assertEquals("X-Latchway-Framework-Version", headers.getString("framework_version"))
        assertEquals("X-Latchway-Protocol-Version", headers.getString("protocol_version"))
        assertEquals("X-Latchway-Request-ID", headers.getString("request_id"))
        assertEquals(
            listOf("ios", "android", "javascript", "react-native"),
            manifest.getJSONArray("sdk_kinds").strings(),
        )
        val releaseEvidence = manifest.getJSONObject("release_evidence")
        assertEquals("release-evidence.schema.json", releaseEvidence.getString("schema_file"))
        assertEquals(1, releaseEvidence.getInt("schema_version"))
        assertEquals(604800, releaseEvidence.getInt("maximum_age_seconds"))
        assertEquals(604800, releaseEvidence.getInt("maximum_window_seconds"))
        assertEquals(
            listOf(
                "live_sdk_conformance",
                "physical_devices",
                "live_provider",
                "cloud_deployments",
                "operational_resilience",
                "supply_chain",
            ),
            releaseEvidence.getJSONArray("promotion_domains").strings(),
        )
        assertEquals(
            listOf(
                "live_sdk_conformance",
                "public_tags",
                "public_registries",
                "physical_devices",
                "live_provider",
                "cloud_deployments",
                "operational_resilience",
                "supply_chain",
            ),
            releaseEvidence.getJSONArray("release_domains").strings(),
        )
        assertEquals("2026-09-01T20:25:00Z", manifest.getString("released_at"))
    }

    @Test
    fun authoritativeVectorMetadataMatchesManifest() {
        assertEquals(LATCHWAY_CONTRACT_VERSION, dpopVectors.getString("contract_version"))
        assertEquals(1, dpopVectors.getInt("wire_protocol_version"))
        assertTrue(manifest.getJSONObject("wire_protocol").getJSONArray("supported").integers()
            .contains(dpopVectors.getInt("wire_protocol_version")))
        assertEquals(LATCHWAY_CONTRACT_VERSION, attestationVectors.getString("contract_version"))
        assertEquals(
            LATCHWAY_CONTRACT_VERSION,
            componentAttestationVectors.getString("contract_version"),
        )
        assertEquals(LATCHWAY_CONTRACT_VERSION, installationFamilyVectors.getString("contract_version"))
        assertEquals(LATCHWAY_PROTOCOL_VERSION, installationFamilyVectors.getInt("wire_protocol_version"))

        val binding = manifest.getJSONObject("attestation_binding")
        assertEquals(binding.getInt("version"), attestationVectors.getInt("binding_version"))
        assertEquals(binding.getString("canonicalization"), attestationVectors.getString("canonicalization"))
        assertEquals(binding.getString("hash"), attestationVectors.getString("hash"))

        val componentBinding = manifest.getJSONObject("component_attestation_binding")
        assertEquals(componentBinding.getInt("version"), componentAttestationVectors.getInt("binding_version"))
        assertEquals("component_attestation_step_up", componentBinding.getString("purpose"))
        assertEquals(
            componentBinding.getString("canonicalization"),
            componentAttestationVectors.getString("canonicalization"),
        )
        assertEquals(componentBinding.getString("hash"), componentAttestationVectors.getString("hash"))
    }

    @Test
    fun currentRuntimeHeadersIncludeExactFrameworkPairWhileManifestRetainsLegacyWireSupport() {
        val configuration = CoreConfiguration(
            baseUrl = URI("https://gateway.example.test/"),
            applicationId = "app_01J00000000000000000000000",
            environment = "production",
            identityProvider = "firebase",
            framework = LatchwayFramework("android-okhttp", "5.3.0"),
        )

        val headers = protocolHeaders(configuration, "request-contract-1234")

        assertEquals("2", headers["X-Latchway-Protocol-Version"])
        assertEquals("android", headers["X-Latchway-SDK"])
        assertEquals("android-okhttp", headers["X-Latchway-Framework"])
        assertEquals("5.3.0", headers["X-Latchway-Framework-Version"])
        assertEquals(listOf(1, 2), manifest.getJSONObject("wire_protocol")
            .getJSONArray("supported").integers())
    }

    @Test
    fun installationFamilyV2FixtureMatchesTypedComponentAndRevocationSemantics() {
        assertEquals(1, installationFamilyVectors.getInt("format_version"))
        val family = installationFamilyVectors.getJSONObject("family")
        val typedFamily = InstallationFamilySummary(
            family.getString("id"),
            family.getString("status"),
        )
        assertEquals("active", typedFamily.status)

        val root = installationFamilyVectors.getJSONObject("root_component")
        val typedRoot = ClientComponentSummary(
            id = root.getString("id"),
            definitionId = root.getString("definition_id"),
            kind = root.getString("kind"),
            platform = root.getString("platform"),
            isRoot = root.getBoolean("is_root"),
            status = root.getString("status"),
            dpopJkt = root.getString("dpop_jkt"),
            grantedFeatures = root.getJSONArray("granted_features").strings().toSet(),
        )
        assertTrue(typedRoot.isRoot)

        val rootClaims = installationFamilyVectors.getJSONObject("root_session_claims")
        val rootTrust = rootClaims.getJSONObject("trust")
        assertEquals(typedFamily.id, rootClaims.getString("installation_family_id"))
        assertEquals(typedRoot.id, rootClaims.getString("component_id"))
        assertEquals(typedRoot.definitionId, rootClaims.getString("component_definition_id"))
        assertEquals(typedRoot.kind, rootClaims.getString("component_kind"))
        assertTrue(rootClaims.getBoolean("component_is_root"))
        assertEquals(typedRoot.grantedFeatures, rootClaims.getJSONArray("features").strings().toSet())
        assertEquals("direct_attested", rootTrust.getString("source"))
        assertFalse(rootClaims.has("installation_id"))

        val provisioned = installationFamilyVectors.getJSONArray("provisioned_components")
        assertEquals(2, provisioned.length())
        repeat(provisioned.length()) { index ->
            val scenario = provisioned.getJSONObject(index)
            val request = scenario.getJSONObject("request")
            val publicJwk = request.getJSONObject("public_jwk")
            val requested = request.getJSONArray("requested_features").strings().toSet()
            val typedJwk = PublicJwk(
                x = publicJwk.getString("x"),
                y = publicJwk.getString("y"),
            )
            val response = scenario.getJSONObject("response")
            val trust = response.getJSONObject("trust")
            val expectedClaims = scenario.getJSONObject("expected_session_claims")
            val expectedTrust = expectedClaims.getJSONObject("trust")
            val exchange = scenario.getJSONObject("session_exchange")
            val typedChild = ClientComponentSummary(
                id = expectedClaims.getString("component_id"),
                definitionId = expectedClaims.getString("component_definition_id"),
                kind = expectedClaims.getString("component_kind"),
                platform = root.getString("platform"),
                isRoot = expectedClaims.getBoolean("component_is_root"),
                status = "active",
                dpopJkt = typedJwk.thumbprint(),
                grantedFeatures = expectedClaims.getJSONArray("features").strings().toSet(),
            )
            val typedTrust = ComponentTrustSummary(
                provider = trust.getString("provider"),
                level = trust.getString("level"),
                source = trust.getString("source"),
                parentComponentId = trust.getString("parent_component_id"),
                parentAttestationProvider = trust.getString("parent_attestation_provider"),
                delegationId = trust.getString("delegation_id"),
                verifiedAt = trust.getString("verified_at"),
                expiresAt = trust.getString("expires_at"),
            )

            assertEquals(typedFamily.id, response.getString("installation_family_id"))
            assertEquals(response.getString("component_id"), typedChild.id)
            assertEquals(request.getString("component_definition_id"), typedChild.definitionId)
            assertEquals(requested, response.getJSONArray("granted_features").strings().toSet())
            assertEquals(expectedTrust.getString("source"), typedTrust.source)
            assertEquals(typedTrust.parentComponentId, expectedTrust.getString("parent_component_id"))
            assertFalse(expectedClaims.has("installation_id"))
            assertEquals(typedRoot.id, typedTrust.parentComponentId)
            assertFalse(typedChild.isRoot)
            assertEquals(trust.getString("expires_at"), response.getString("refresh_grant_expires_at"))
            assertEquals(typedChild.id, exchange.getJSONObject("request").getString("component_id"))
            assertTrue(exchange.getJSONObject("response").getString("access_token").length >= 64)
            assertTrue(exchange.getJSONObject("response").getLong("expires_in") in 60..3_600)
        }

        val revocations = installationFamilyVectors.getJSONArray("revocations")
        val sibling = revocations.getJSONObject(0)
        assertEquals("component", sibling.getString("scope"))
        assertEquals("active", sibling.getString("expected_family_status"))
        assertEquals(listOf("active", "revoked", "active"),
            sibling.getJSONArray("expected_components").statuses())
        val familyRevocation = revocations.getJSONObject(1)
        assertEquals("family", familyRevocation.getString("scope"))
        assertEquals("revoked", familyRevocation.getString("expected_family_status"))
        assertEquals(listOf("revoked", "revoked", "revoked"),
            familyRevocation.getJSONArray("expected_components").statuses())
    }

    @Test
    fun everyAuthoritativeAttestationVectorMatchesCanonicalBytesAndHash() {
        val vectors = attestationVectors.getJSONArray("vectors")
        repeat(vectors.length()) { index ->
            val vector = vectors.getJSONObject(index)
            val canonical = vector.getString("canonical_json")
            val canonicalBytes = canonical.toByteArray(StandardCharsets.UTF_8)

            assertEquals(
                "fixture ${vector.getString("id")} canonical object",
                vector.getJSONObject("input").scalarValues(),
                JSONObject(canonical).scalarValues(),
            )
            assertEquals(vector.getString("utf8_hex"), canonicalBytes.hex())
            assertEquals(vector.getString("sha256_hex"), sha256(canonicalBytes).hex())
            assertEquals(vector.getString("sha256_base64url"), Base64Url.encode(sha256(canonicalBytes)))
        }
    }

    @Test
    fun everyComponentAttestationVectorMatchesCanonicalBytesHashAndStrictChallengeParsing() {
        val vectors = componentAttestationVectors.getJSONArray("vectors")
        repeat(vectors.length()) { index ->
            val vector = vectors.getJSONObject(index)
            val input = vector.getJSONObject("input")
            val canonical = vector.getString("canonical_json")
            val canonicalBytes = canonical.toByteArray(StandardCharsets.UTF_8)

            assertEquals(
                "fixture ${vector.getString("id")} canonical object",
                input.scalarValues(),
                JSONObject(canonical).scalarValues(),
            )
            assertEquals(vector.getString("utf8_hex"), canonicalBytes.hex())
            assertEquals(vector.getString("sha256_hex"), sha256(canonicalBytes).hex())
            assertEquals(vector.getString("sha256_base64url"), Base64Url.encode(sha256(canonicalBytes)))

            val issuedAt = input.getLong("issued_at")
            val response = JSONObject()
                .put("challenge_id", input.getString("challenge_id"))
                .put("challenge_nonce", input.getString("challenge_nonce"))
                .put("binding_version", 2)
                .put("issued_at", issuedAt)
                .put("expires_at", Instant.ofEpochSecond(issuedAt + 300).toString())
                .put("attestation", JSONObject()
                    .put("provider", "app_attest")
                    .put("mode", "required")
                    .put("client_data_hash", vector.getString("sha256_base64url"))
                    .put("provider_options", JSONObject().put("environment", "production")))
            val challenge = parseComponentAttestationChallenge(
                encoded = response.toString(),
                nowEpochSeconds = issuedAt,
                maximumClockSkewSeconds = 300,
            )

            assertEquals(input.getString("challenge_id"), challenge.challengeId)
            assertEquals("app_attest", challenge.provider)
            assertEquals(AttestationMode.REQUIRED, challenge.mode)
            assertEquals(vector.getString("sha256_base64url"), challenge.clientDataHash)
            assertEquals(issuedAt, challenge.issuedAtEpochSeconds)
            assertEquals(issuedAt + 300, challenge.expiresAtEpochSeconds)
        }
    }

    @Test
    fun componentAttestationChallengeParserRejectsNonV2AndNonAppAttestDocuments() {
        val vector = componentAttestationVectors.getJSONArray("vectors").getJSONObject(0)
        val input = vector.getJSONObject("input")
        val issuedAt = input.getLong("issued_at")
        val valid = JSONObject()
            .put("challenge_id", input.getString("challenge_id"))
            .put("challenge_nonce", input.getString("challenge_nonce"))
            .put("binding_version", 2)
            .put("issued_at", issuedAt)
            .put("expires_at", Instant.ofEpochSecond(issuedAt + 300).toString())
            .put("attestation", JSONObject()
                .put("provider", "app_attest")
                .put("mode", "required")
                .put("client_data_hash", vector.getString("sha256_base64url")))

        val invalidDocuments = listOf(
            JSONObject(valid.toString()).put("binding_version", 1),
            JSONObject(valid.toString()).put("challenge_nonce", "A".repeat(42)),
            JSONObject(valid.toString()).apply {
                getJSONObject("attestation").put("provider", "play_integrity")
            },
            JSONObject(valid.toString()).put("unexpected", true),
        )
        invalidDocuments.forEach { document ->
            val error = org.junit.Assert.assertThrows(LatchwayException::class.java) {
                parseComponentAttestationChallenge(
                    encoded = document.toString(),
                    nowEpochSeconds = issuedAt,
                    maximumClockSkewSeconds = 300,
                )
            }
            assertEquals(LatchwayErrorCode.RESPONSE_INVALID, error.code)
        }
    }

    @Test
    fun operationIndeterminateUsesTheContractRegistryValue() {
        assertEquals(
            LatchwayErrorCode.OPERATION_INDETERMINATE,
            LatchwayErrorCode.fromWire("operation_indeterminate"),
        )
    }

    @Test
    fun latchwayExceptionRetainsItsPublishedJvmConstructor() {
        LatchwayException::class.java.getConstructor(
            LatchwayErrorCode::class.java,
            String::class.java,
            Boolean::class.javaPrimitiveType,
            Int::class.javaObjectType,
            String::class.java,
            Throwable::class.java,
        )
    }

    private fun resource(path: String): JSONObject {
        val stream = checkNotNull(javaClass.classLoader?.getResourceAsStream(path))
        return JSONObject(stream.bufferedReader().use { it.readText() })
    }

    private fun JSONArray.strings(): List<String> = List(length()) { getString(it) }
    private fun JSONArray.integers(): List<Int> = List(length()) { getInt(it) }
    private fun JSONArray.statuses(): List<String> =
        List(length()) { getJSONObject(it).getString("status") }

    private fun JSONObject.scalarValues(): Map<String, Any> = keys().asSequence().associateWith { get(it) }

    private fun ByteArray.hex(): String = joinToString("") { "%02x".format(it.toInt() and 0xff) }
}
