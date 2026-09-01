package dev.latchway.sample.conformance

import android.app.Activity
import android.content.pm.PackageManager
import android.os.Bundle
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import dev.latchway.core.KeyBacking
import dev.latchway.core.LatchwayErrorCode
import dev.latchway.core.LatchwayException
import dev.latchway.okhttp.LatchwayClient
import dev.latchway.okhttp.LatchwayConfiguration
import dev.latchway.playintegrity.PlayIntegrityAttestationProvider
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.suspendCancellableCoroutine
import okhttp3.Call
import okhttp3.Callback
import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import org.json.JSONArray
import org.json.JSONObject
import java.io.IOException
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.Locale
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/**
 * Physical-device conformance host. Passing evidence is produced only after a
 * Play-distributed Release build completes the live negative and positive
 * cases. The UI itself never assigns release eligibility.
 */
public class ConformanceActivity : Activity() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main)
    private lateinit var status: TextView
    private lateinit var runButton: Button

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        status = TextView(this).apply { text = readinessMessage() }
        runButton = Button(this).apply {
            text = "Run physical Play Integrity conformance"
            setOnClickListener { startRun() }
        }
        setContentView(LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(48, 48, 48, 48)
            addView(status)
            addView(runButton)
        })
        if (intent.getBooleanExtra(EXTRA_AUTORUN, false)) startRun()
    }

    override fun onDestroy() {
        OneTimeIdentityGrantSlot.clear()
        scope.cancel()
        super.onDestroy()
    }

    private fun startRun() {
        if (!runButton.isEnabled) return
        runButton.isEnabled = false
        scope.launch {
            try {
                runConformance()
            } finally {
                runButton.isEnabled = true
            }
        }
    }

    private suspend fun runConformance() {
        val values = ConformanceValues.load(
            this,
            intent.getStringExtra(EXTRA_RUN_ID),
            intent.getStringExtra(EXTRA_WORKFLOW_RUN_ID),
            intent.getStringExtra(EXTRA_RUN_ATTEMPT),
            intent.getStringExtra(EXTRA_GRANT_SHA256),
        )
        if (values == null) {
            OneTimeIdentityGrantSlot.clear()
            status.text = "FAIL: protected build pins or run-bound bootstrap coordinates are missing."
            return
        }

        val startedAt = timestamp()
        val identity = runCatching { applicationIdentity(this, values) }.getOrElse {
            OneTimeIdentityGrantSlot.clear()
            status.text = "FAIL: signed application identity could not be inspected."
            return
        }
        if (identity.pins != values.expectedPins) {
            OneTimeIdentityGrantSlot.clear()
            status.text = "FAIL: the installed application does not match its protected pins."
            return
        }
        val grantCoordinates = BootstrapCoordinates(
            audience = PHYSICAL_GRANT_AUDIENCE,
            sourceCommit = values.sourceCommit,
            applicationId = values.applicationId,
            packageName = packageName,
            identityProvider = values.identityProvider,
            runId = values.runId,
            workflowRunId = values.workflowRunId,
            runAttempt = values.runAttempt,
            grantSha256 = values.deviceGrantSha256,
        )
        val identityTokenProvider = OneTimeIdentityGrantSlot.takeProvider(grantCoordinates)
        if (identityTokenProvider == null) {
            OneTimeIdentityGrantSlot.clear()
            status.text = "FAIL: the run-bound one-use identity grant was not delivered."
            return
        }
        val tests = mutableListOf<EvidenceTest>()
        var backing: KeyBacking? = null
        var trustLevel = "none"
        var acceptedProductionPolicy = false
        var gatewayVersion = "unknown"
        status.text = "Running live Play Integrity, DPoP, stream, and quota checks…"

        val client = runCatching {
            LatchwayClient(
                configuration = LatchwayConfiguration(
                    baseUrl = values.gateway,
                    applicationId = values.applicationId,
                    environment = values.environment,
                    identityProvider = values.identityProvider,
                ),
                identityTokenProvider = identityTokenProvider,
                attestationProvider = PlayIntegrityAttestationProvider(this, values.cloudProjectNumber),
                context = this,
            )
        }.getOrElse {
            identityTokenProvider.clear()
            OneTimeIdentityGrantSlot.clear()
            status.text = "FAIL: the protected client could not be initialized."
            return
        }
        val rawClient = runCatching {
            OkHttpClient.Builder()
                .followRedirects(false)
                .followSslRedirects(false)
                .retryOnConnectionFailure(false)
                .build()
        }.getOrElse {
            identityTokenProvider.clear()
            OneTimeIdentityGrantSlot.clear()
            client.close()
            status.text = "FAIL: the bounded network client could not be initialized."
            return
        }

        try {
            // Clear only Latchway's encrypted session. The Play installation
            // and hardware key remain intact, while the next authorization must
            // consume this run's one-use identity grant and execute a fresh
            // Standard Integrity challenge for this exact candidate.
            client.clearSession()

            val initialFacts = deviceFacts(null)
            tests += EvidenceTest(
                "physical_device",
                pass(
                    initialFacts.physical && !initialFacts.emulator && !initialFacts.testing &&
                        !initialFacts.debuggerAttached && !identity.observation.debuggable &&
                        identity.observation.buildMode == "release",
                ),
            )
            tests += EvidenceTest("identifier_pins", pass(identity.pins == values.expectedPins))
            tests += EvidenceTest(
                "play_install_source",
                pass(
                    identity.observation.installerPackage == PLAY_INSTALLER &&
                        identity.observation.playTrack == values.playTrack,
                ),
            )

            val quotaRequest = Request.Builder()
                .url(values.quotaUrl())
                .get()
                .header("Accept", "application/json")
                .build()
            val authorized = client.authorize(quotaRequest, values.feature)
            val authorizedResult = rawClient.newCall(authorized).awaitBounded(MAX_CONTROL_BYTES)
            tests += authorizedResult.test("dpop_authorized_request", authorizedResult.status in 200..299)

            val replay = rawClient.newCall(authorized).awaitBounded(MAX_CONTROL_BYTES)
            tests += replay.test(
                "dpop_replay_rejected",
                replay.status == 401 && replay.problemCode == "dpop_replayed",
            )

            val fresh = client.authorize(quotaRequest, values.feature)
            val proof = requireNotNull(fresh.header("DPoP")).takeIf(String::isNotBlank)
                ?: error("authorized request omitted DPoP")
            val tampered = fresh.newBuilder()
                .header("DPoP", tamperedDpopProof(proof))
                .build()
            val tamper = rawClient.newCall(tampered).awaitBounded(MAX_CONTROL_BYTES)
            tests += tamper.test(
                "tampered_dpop_rejected",
                tamper.status == 401 && tamper.problemCode == "dpop_invalid",
            )

            try {
                client.quota(values.errorMappingFeature)
                tests += EvidenceTest.failed("canonical_error_mapping")
            } catch (error: LatchwayException) {
                tests += EvidenceTest(
                    id = "canonical_error_mapping",
                    status = pass(
                        error.code == LatchwayErrorCode.FEATURE_NOT_FOUND &&
                            error.httpStatus == 404 && error.requestId != null,
                    ),
                    httpStatus = error.httpStatus,
                    errorCode = error.code.wireValue,
                    requestId = error.requestId,
                    mappedErrorType = "kotlin_latchway_exception",
                )
            }

            val beforeRefresh = client.authorize(quotaRequest, values.feature)
            val beforeRefreshDiagnostics = client.diagnostics()
            client.refresh()
            val afterRefresh = client.authorize(quotaRequest, values.feature)
            val afterRefreshDiagnostics = client.diagnostics()
            val beforeCredential = credentialHash(beforeRefresh)
            val afterCredential = credentialHash(afterRefresh)
            val beforeInstallation = sha256(beforeRefreshDiagnostics.installationId)
            val afterInstallation = sha256(afterRefreshDiagnostics.installationId)
            tests += EvidenceTest(
                id = "session_refresh_rotation",
                status = pass(
                    beforeCredential != afterCredential && beforeInstallation == afterInstallation,
                ),
                credentialBeforeSha256 = beforeCredential,
                credentialAfterSha256 = afterCredential,
                installationBeforeSha256 = beforeInstallation,
                installationAfterSha256 = afterInstallation,
            )

            val unsupported = rawClient.newCall(
                client.authorize(quotaRequest, values.feature).newBuilder()
                    .header("X-Latchway-Protocol-Version", "0")
                    .build(),
            ).awaitBounded(MAX_CONTROL_BYTES)
            tests += EvidenceTest(
                id = "protocol_version_rejection",
                status = pass(
                    unsupported.status == 426 && unsupported.problemCode == "protocol_version_unsupported",
                ),
                httpStatus = unsupported.status,
                errorCode = unsupported.problemCode,
                requestId = unsupported.requestId,
                protocolVersionSent = 0,
            )

            val streamRequest = Request.Builder()
                .url(values.streamUrl())
                .header("Content-Type", "application/json")
                .header("Accept", "text/event-stream")
                .post(
                    JSONObject()
                        .put("model", values.model)
                        .put("stream", true)
                        .put(
                            "messages",
                            JSONArray().put(
                                JSONObject()
                                    .put("role", "user")
                                    .put("content", "Return the word conformance."),
                            ),
                        )
                        .toString()
                        .toRequestBody("application/json".toMediaType()),
                )
                .build()
            val streamed = rawClient.newCall(client.authorize(streamRequest, values.feature))
                .awaitBounded(MAX_STREAM_BYTES)
            tests += streamed.test(
                "streamed_request",
                streamed.status in 200..299 && streamed.byteCount > 0,
            )

            val quota = client.quota(values.feature)
            tests += EvidenceTest("quota", pass(quota.feature == values.feature && quota.limits.isNotEmpty()))

            val diagnostics = client.diagnostics()
            backing = diagnostics.key.backing
            trustLevel = diagnostics.trustLevel
            gatewayVersion = diagnostics.serverVersion
            acceptedProductionPolicy = diagnostics.trustProvider == "play_integrity" &&
                trustLevel in setOf("device_verified", "strong_device_verified") &&
                values.requireLicensed && identity.observation.installerPackage == PLAY_INSTALLER
            tests += EvidenceTest("play_integrity_standard_request", pass(acceptedProductionPolicy))
            tests += EvidenceTest(
                "hardware_backed_key",
                pass(backing != KeyBacking.SOFTWARE),
            )
            tests += EvidenceTest(
                "session_created",
                pass(
                    diagnostics.installationStatus.isNotBlank() &&
                        diagnostics.sessionExpiresAt.isNotBlank() && acceptedProductionPolicy,
                ),
            )

            val postRevocation = client.authorize(quotaRequest, values.feature)
            client.revokeCurrentInstallation()
            val revoked = rawClient.newCall(postRevocation).awaitBounded(MAX_CONTROL_BYTES)
            tests += revoked.test(
                "installation_revocation",
                revoked.status == 403 && revoked.problemCode == "installation_revoked",
            )
        } catch (error: CancellationException) {
            throw error
        } catch (_: Exception) {
            // The persisted observation contains fixed test IDs and safe status
            // metadata only. Tokens, proofs, evidence, and exception messages are
            // deliberately excluded.
        } finally {
            identityTokenProvider.clear()
            OneTimeIdentityGrantSlot.clear()
            client.close()
            rawClient.dispatcher.cancelAll()
            rawClient.connectionPool.evictAll()
            rawClient.dispatcher.executorService.shutdown()
        }

        val requiredTests = REQUIRED_TESTS.map { required ->
            tests.firstOrNull { it.id == required } ?: EvidenceTest.failed(required)
        }
        val finalFacts = deviceFacts(backing)
        val observation = DeviceObservation(
            runId = values.runId,
            startedAt = startedAt,
            completedAt = timestamp(),
            gatewayVersion = gatewayVersion,
            application = identity.observation,
            device = finalFacts,
            provider = ProviderObservation(trustLevel, acceptedProductionPolicy),
            observedPins = identity.pins,
            tests = requiredTests,
        )
        runCatching { writeObservation(this, observation) }
            .onFailure { status.text = "FAIL: redacted observation could not be persisted." }
            .onSuccess {
                status.text = if (requiredTests.all { it.status == "passed" }) {
                    "Device suite completed. Offline protected-run validation is still required."
                } else {
                    "FAIL: the redacted observation records one or more failed checks."
                }
            }
    }

    private fun readinessMessage(): String =
        "Install the exact Release build from Google Play and use the protected physical runner."

    private companion object {
        const val EXTRA_AUTORUN = "dev.latchway.AUTORUN"
        const val EXTRA_RUN_ID = "dev.latchway.RUN_ID"
        const val EXTRA_WORKFLOW_RUN_ID = "dev.latchway.WORKFLOW_RUN_ID"
        const val EXTRA_RUN_ATTEMPT = "dev.latchway.RUN_ATTEMPT"
        const val EXTRA_GRANT_SHA256 = "dev.latchway.IDENTITY_GRANT_SHA256"
        const val MAX_CONTROL_BYTES = 65_536L
        const val MAX_STREAM_BYTES = 1_048_576L
        val REQUIRED_TESTS = setOf(
            "physical_device",
            "identifier_pins",
            "play_install_source",
            "play_integrity_standard_request",
            "hardware_backed_key",
            "session_created",
            "dpop_authorized_request",
            "dpop_replay_rejected",
            "tampered_dpop_rejected",
            "streamed_request",
            "quota",
            "canonical_error_mapping",
            "session_refresh_rotation",
            "installation_revocation",
            "protocol_version_rejection",
        )
    }
}

internal data class ConformanceValues(
    val gateway: HttpUrl,
    val applicationId: String,
    val environment: String,
    val identityProvider: String,
    val feature: String,
    val errorMappingFeature: String,
    val model: String,
    val cloudProjectNumber: Long,
    val playTrack: String,
    val expectedPins: Map<String, String>,
    val requireLicensed: Boolean,
    val runId: String,
    val workflowRunId: String,
    val runAttempt: String,
    val deviceGrantSha256: String,
    val sourceCommit: String,
) {
    fun quotaUrl(): HttpUrl = gateway.resolve("/client/v1/features/$feature/quota")
        ?: error("invalid quota URL")

    fun streamUrl(): HttpUrl = gateway.resolve("/v1/chat/completions")
        ?: error("invalid stream URL")

    companion object {
        private val IDENTIFIER = Regex("^[a-z][a-z0-9_-]{0,62}$")
        private val APPLICATION_ID = Regex("^app_[0-7][0-9A-HJKMNP-TV-Z]{25}$")
        private val RUN_ID = Regex("^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")
        private val RUN_ATTEMPT = Regex("^[1-9][0-9]{0,8}$")
        private val WORKFLOW_RUN_ID = Regex("^[1-9][0-9]{0,19}$")
        private val SHA256 = Regex("^[0-9a-f]{64}$")
        private val COMMIT = Regex("^[0-9a-f]{40}$")
        private val IMAGE = Regex("^sha256:[0-9a-f]{64}$")
        private val TRACK = Regex("^(internal|closed|open|production)$")
        private val PACKAGE = Regex("^[A-Za-z0-9][A-Za-z0-9._-]{2,254}$")
        private val GATEWAY_ORIGIN = Regex("^https://[a-z0-9][A-Za-z0-9.-]*(?::[1-9][0-9]{0,4})?(?:/[A-Za-z0-9_~.-]+)*$")
        private val KEY_ID = Regex("^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")

        fun load(
            activity: Activity,
            runIdInput: String?,
            workflowRunIdInput: String?,
            runAttemptInput: String?,
            grantSha256Input: String?,
        ): ConformanceValues? = runCatching {
            val metadata = activity.packageManager
                .getApplicationInfo(activity.packageName, PackageManager.GET_META_DATA).metaData
            val gatewayText = metadata.required("dev.latchway.GATEWAY_URL", GATEWAY_ORIGIN)
            val gatewayOrigin = metadata.required("dev.latchway.GATEWAY_ORIGIN", GATEWAY_ORIGIN)
            require(gatewayText == gatewayOrigin)
            val gateway = requireNotNull(gatewayText.toHttpUrlOrNull())
            require(gateway.isHttps)
            val applicationId = metadata.required("dev.latchway.APPLICATION_ID", APPLICATION_ID)
            val environment = metadata.required("dev.latchway.ENVIRONMENT", IDENTIFIER)
            val identityProvider = metadata.required("dev.latchway.IDENTITY_PROVIDER", IDENTIFIER)
            val feature = metadata.required("dev.latchway.FEATURE", IDENTIFIER)
            val errorMappingFeature = metadata.required("dev.latchway.ERROR_MAPPING_FEATURE", IDENTIFIER)
            require(errorMappingFeature != feature)
            val model = metadata.getString("dev.latchway.MODEL")?.takeIf(::isValidModel)
                ?: error("model is invalid")
            val cloudProject = metadata.getString("dev.latchway.CLOUD_PROJECT_NUMBER")
                ?.toLongOrNull()?.takeIf { it > 0 } ?: error("cloud project is invalid")
            val playTrack = metadata.required("dev.latchway.PLAY_TRACK", TRACK)
            val sourceCommit = metadata.required("dev.latchway.SOURCE_COMMIT", COMMIT)
            val coreCommit = metadata.required("dev.latchway.CORE_COMMIT", COMMIT)
            val contractHash = metadata.required("dev.latchway.CONTRACT_BUNDLE_SHA256", SHA256)
            val gatewayDigest = metadata.required("dev.latchway.GATEWAY_IMAGE_DIGEST", IMAGE)
            val configurationHash = metadata.required("dev.latchway.GATEWAY_CONFIGURATION_SHA256", SHA256)
            val deploymentKeyId = metadata.required("dev.latchway.GATEWAY_DEPLOYMENT_KEY_ID", KEY_ID)
            val deploymentStatementHash = metadata.required("dev.latchway.GATEWAY_DEPLOYMENT_STATEMENT_SHA256", SHA256)
            val deploymentPublicKeyHash = metadata.required("dev.latchway.GATEWAY_DEPLOYMENT_PUBLIC_KEY_SHA256", SHA256)
            val expectedPackage = metadata.required("dev.latchway.EXPECTED_PACKAGE", PACKAGE)
            val expectedVersion = metadata.required("dev.latchway.EXPECTED_VERSION", Regex("^[^\\s]{1,64}$"))
            val expectedBuild = metadata.required("dev.latchway.EXPECTED_BUILD", Regex("^[1-9][0-9]{0,17}$"))
            val expectedCertificate = metadata.required("dev.latchway.EXPECTED_CERTIFICATE_SHA256", SHA256)
            val requireLicensed = metadata.getString("dev.latchway.REQUIRE_LICENSED") == "true"
            require(requireLicensed)
            val runId = requireNotNull(runIdInput).also { require(RUN_ID.matches(it)) }
            val workflowRunId = requireNotNull(workflowRunIdInput).also {
                require(WORKFLOW_RUN_ID.matches(it))
            }
            val runAttempt = requireNotNull(runAttemptInput).also { require(RUN_ATTEMPT.matches(it)) }
            require(runId == "play-integrity-$workflowRunId-$runAttempt")
            val deviceGrantSha256 = requireNotNull(grantSha256Input).also { require(SHA256.matches(it)) }
            val expectedPins = mapOf(
                "application_identifier" to expectedPackage,
                "app_version" to expectedVersion,
                "build_number" to expectedBuild,
                "signing_certificate_sha256" to expectedCertificate,
                "cloud_project_number" to cloudProject.toString(),
                "installer_package" to PLAY_INSTALLER,
                "play_track" to playTrack,
                "require_licensed" to "true",
                "source_commit" to sourceCommit,
                "core_commit" to coreCommit,
                "contract_bundle_sha256" to contractHash,
                "gateway_image_digest" to gatewayDigest,
                "gateway_configuration_sha256" to configurationHash,
                "gateway_origin" to gatewayOrigin,
                "gateway_environment" to environment,
                "gateway_deployment_key_id" to deploymentKeyId,
                "gateway_deployment_statement_sha256" to deploymentStatementHash,
                "gateway_deployment_public_key_sha256" to deploymentPublicKeyHash,
                "error_mapping_feature" to errorMappingFeature,
            )
            ConformanceValues(
                gateway,
                applicationId,
                environment,
                identityProvider,
                feature,
                errorMappingFeature,
                model,
                cloudProject,
                playTrack,
                expectedPins,
                requireLicensed,
                runId,
                workflowRunId,
                runAttempt,
                deviceGrantSha256,
                sourceCommit,
            )
        }.getOrNull()
    }
}

internal fun isValidModel(value: String): Boolean =
    value.isNotEmpty() && value.toByteArray(StandardCharsets.UTF_8).size <= 256 &&
        value.trim() == value && value.none { it.isISOControl() }

/**
 * Mutates signature bytes, not the unused low bits of an unpadded Base64URL
 * tail. The result remains a syntactically valid three-segment compact JWT.
 */
internal fun tamperedDpopProof(proof: String): String {
    val segments = proof.split('.', limit = 3)
    require(segments.size == 3 && segments.all(String::isNotEmpty))
    val signature = segments[2]
    val replacement = if (signature.first() == 'A') 'B' else 'A'
    return "${segments[0]}.${segments[1]}.$replacement${signature.drop(1)}"
}

private fun android.os.Bundle.required(name: String, pattern: Regex): String =
    getString(name)?.takeIf(pattern::matches) ?: error("$name is invalid")

private fun pass(value: Boolean): String = if (value) "passed" else "failed"

private fun credentialHash(request: Request): String {
    val value = requireNotNull(request.header("Authorization")).also { require(it.startsWith("DPoP ")) }
    return sha256(value)
}

private fun sha256(value: String): String = MessageDigest.getInstance("SHA-256")
    .digest(value.toByteArray(StandardCharsets.UTF_8))
    .joinToString("") { "%02x".format(Locale.US, it.toInt() and 0xff) }

private data class SafeResponse(
    val status: Int,
    val byteCount: Int,
    val problemCode: String?,
    val requestId: String?,
) {
    fun test(id: String, passed: Boolean): EvidenceTest = EvidenceTest(
        id = id,
        status = pass(passed),
        httpStatus = status,
        errorCode = problemCode,
        requestId = requestId,
    )
}

private suspend fun Call.awaitBounded(maximumBytes: Long): SafeResponse =
    suspendCancellableCoroutine { continuation ->
        continuation.invokeOnCancellation { cancel() }
        enqueue(object : Callback {
            override fun onFailure(call: Call, e: IOException) {
                if (continuation.isActive) continuation.resumeWithException(e)
            }

            override fun onResponse(call: Call, response: Response) {
                try {
                    val result = response.use { bounded ->
                        val source = bounded.body.source()
                        val sink = okio.Buffer()
                        var count = 0L
                        while (true) {
                            val read = source.read(sink, minOf(8_192L, maximumBytes + 1 - count))
                            if (read == -1L) break
                            count += read
                            check(count <= maximumBytes) { "response exceeded bounded evidence limit" }
                        }
                        val body = sink.readUtf8()
                        val requestId = bounded.header("X-Latchway-Request-ID")
                            ?.takeIf { SAFE_REQUEST_ID.matches(it) }
                        val mediaType = bounded.body.contentType()?.toString()
                            ?.substringBefore(';')?.trim()?.lowercase()
                        val problem = if (mediaType == "application/problem+json") {
                            runCatching { JSONObject(body) }.getOrNull()
                        } else {
                            null
                        }
                        val code = problem?.optString("code")?.takeIf { SAFE_CODE.matches(it) }
                        val documentationUrl = code?.let {
                            "https://docs.latchway.dev/errors/${it.replace('_', '-')}"
                        }
                        val validProblem = problem != null &&
                            problem.optInt("status", -1) == bounded.code &&
                            problem.optString("request_id") == requestId &&
                            problem.optString("type") == documentationUrl &&
                            problem.optString("documentation_url") == documentationUrl &&
                            problem.optString("title").isNotBlank() &&
                            problem.optString("detail").isNotBlank() &&
                            problem.has("retryable")
                        SafeResponse(
                            status = bounded.code,
                            byteCount = count.toInt(),
                            problemCode = code.takeIf { validProblem },
                            requestId = requestId,
                        )
                    }
                    if (continuation.isActive) continuation.resume(result)
                } catch (error: Exception) {
                    if (continuation.isActive) continuation.resumeWithException(error)
                }
            }
        })
    }

private val SAFE_REQUEST_ID = Regex("^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")
private val SAFE_CODE = Regex("^[a-z][a-z0-9_]{0,63}$")
internal const val PLAY_INSTALLER = "com.android.vending"
