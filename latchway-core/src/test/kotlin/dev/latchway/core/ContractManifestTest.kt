package dev.latchway.core

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.nio.charset.StandardCharsets

class ContractManifestTest {
    private val manifest: JSONObject by lazy { resource("contract/protocol-version.json") }
    private val dpopVectors: JSONObject by lazy { resource("contract/dpop-v1.json") }
    private val attestationVectors: JSONObject by lazy { resource("contract/attestation-binding-v1.json") }

    @Test
    fun authoritativeManifestMatchesRuntimeContractAndWireConstants() {
        assertEquals(1, manifest.getInt("manifest_version"))
        assertEquals(LATCHWAY_CONTRACT_VERSION, manifest.getString("contract_version"))
        assertEquals("draft", manifest.getString("contract_status"))

        val wire = manifest.getJSONObject("wire_protocol")
        assertEquals(LATCHWAY_PROTOCOL_VERSION, wire.getInt("current"))
        assertEquals(LATCHWAY_PROTOCOL_VERSION, wire.getInt("minimum"))
        assertEquals(listOf(LATCHWAY_PROTOCOL_VERSION), wire.getJSONArray("supported").integers())

        val bundle = manifest.getJSONObject("bundle")
        assertEquals("latchway-contract-$LATCHWAY_CONTRACT_VERSION.tar.gz", bundle.getString("file_name"))
        assertEquals(
            listOf(
                "client.openapi.yaml",
                "admin.openapi.yaml",
                "config.schema.json",
                "attestation-binding.schema.json",
                "error-codes.yaml",
                "protocol-version.json",
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
        assertEquals("X-Latchway-Protocol-Version", headers.getString("protocol_version"))
        assertEquals("X-Latchway-Request-ID", headers.getString("request_id"))
        assertEquals(
            listOf("ios", "android", "javascript", "react-native"),
            manifest.getJSONArray("sdk_kinds").strings(),
        )
        assertTrue(manifest.isNull("released_at"))
    }

    @Test
    fun authoritativeVectorMetadataMatchesManifest() {
        assertEquals(LATCHWAY_CONTRACT_VERSION, dpopVectors.getString("contract_version"))
        assertEquals(LATCHWAY_PROTOCOL_VERSION, dpopVectors.getInt("wire_protocol_version"))
        assertEquals(LATCHWAY_CONTRACT_VERSION, attestationVectors.getString("contract_version"))

        val binding = manifest.getJSONObject("attestation_binding")
        assertEquals(binding.getInt("version"), attestationVectors.getInt("binding_version"))
        assertEquals(binding.getString("canonicalization"), attestationVectors.getString("canonicalization"))
        assertEquals(binding.getString("hash"), attestationVectors.getString("hash"))
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

    private fun JSONObject.scalarValues(): Map<String, Any> = keys().asSequence().associateWith { get(it) }

    private fun ByteArray.hex(): String = joinToString("") { "%02x".format(it.toInt() and 0xff) }
}
