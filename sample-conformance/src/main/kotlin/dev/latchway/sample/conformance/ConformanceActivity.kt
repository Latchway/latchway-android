package dev.latchway.sample.conformance

import android.app.Activity
import android.content.pm.PackageManager
import android.os.Bundle
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import com.google.firebase.FirebaseApp
import com.google.firebase.auth.FirebaseAuth
import dev.latchway.core.KeyBacking
import dev.latchway.firebaseauth.FirebaseIdentityTokenProvider
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
        val values = ConformanceValues.load(this, intent.getStringExtra(EXTRA_RUN_ID))
        if (values == null) {
            status.text = "FAIL: protected build pins or run identifier are missing."
            return
        }
        if (FirebaseApp.getApps(this).isEmpty() || FirebaseAuth.getInstance().currentUser == null) {
            status.text = "FAIL: this Play-installed app requires a real signed-in Firebase user."
            return
        }

        val startedAt = timestamp()
        val identity = runCatching { applicationIdentity(this, values) }.getOrElse {
            status.text = "FAIL: signed application identity could not be inspected."
            return
        }
        val tests = mutableListOf<EvidenceTest>()
        var backing: KeyBacking? = null
        var trustLevel = "none"
        var acceptedProductionPolicy = false
        var gatewayVersion = "unknown"
        status.text = "Running live Play Integrity, DPoP, stream, and quota checks…"

        val client = LatchwayClient(
            configuration = LatchwayConfiguration(
                baseUrl = values.gateway,
                applicationId = values.applicationId,
                environment = values.environment,
            ),
            identityTokenProvider = FirebaseIdentityTokenProvider(),
            attestationProvider = PlayIntegrityAttestationProvider(this, values.cloudProjectNumber),
            context = this,
        )
        val rawClient = OkHttpClient.Builder()
            .followRedirects(false)
            .followSslRedirects(false)
            .retryOnConnectionFailure(false)
            .build()

        try {
            // Clear only Latchway's encrypted session. The Play installation,
            // Firebase account, and hardware key remain intact, while the next
            // authorization must execute a fresh Standard Integrity challenge
            // for this exact candidate instead of reusing an older session.
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
        } catch (error: CancellationException) {
            throw error
        } catch (_: Exception) {
            // The persisted observation contains fixed test IDs and safe status
            // metadata only. Tokens, proofs, evidence, and exception messages are
            // deliberately excluded.
        } finally {
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

    private fun readinessMessage(): String = when {
        FirebaseApp.getApps(this).isEmpty() -> "Firebase application configuration is required."
        else -> "Install the exact Release build from Google Play, sign in, and run conformance."
    }

    private companion object {
        const val EXTRA_AUTORUN = "dev.latchway.AUTORUN"
        const val EXTRA_RUN_ID = "dev.latchway.RUN_ID"
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
        )
    }
}

internal data class ConformanceValues(
    val gateway: HttpUrl,
    val applicationId: String,
    val environment: String,
    val feature: String,
    val model: String,
    val cloudProjectNumber: Long,
    val playTrack: String,
    val expectedPins: Map<String, String>,
    val requireLicensed: Boolean,
    val runId: String,
) {
    fun quotaUrl(): HttpUrl = gateway.resolve("/client/v1/features/$feature/quota")
        ?: error("invalid quota URL")

    fun streamUrl(): HttpUrl = gateway.resolve("/v1/chat/completions")
        ?: error("invalid stream URL")

    companion object {
        private val IDENTIFIER = Regex("^[a-z][a-z0-9_-]{0,62}$")
        private val APPLICATION_ID = Regex("^app_[0-7][0-9A-HJKMNP-TV-Z]{25}$")
        private val RUN_ID = Regex("^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")
        private val SHA256 = Regex("^[0-9a-f]{64}$")
        private val COMMIT = Regex("^[0-9a-f]{40}$")
        private val IMAGE = Regex("^sha256:[0-9a-f]{64}$")
        private val TRACK = Regex("^(internal|closed|open|production)$")
        private val PACKAGE = Regex("^[A-Za-z0-9][A-Za-z0-9._-]{2,254}$")
        private val GATEWAY_ORIGIN = Regex("^https://[a-z0-9][A-Za-z0-9.-]*(?::[1-9][0-9]{0,4})?(?:/[A-Za-z0-9_~.-]+)*$")
        private val KEY_ID = Regex("^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")

        fun load(activity: Activity, runIdInput: String?): ConformanceValues? = runCatching {
            val metadata = activity.packageManager
                .getApplicationInfo(activity.packageName, PackageManager.GET_META_DATA).metaData
            val gatewayText = metadata.required("dev.latchway.GATEWAY_URL", GATEWAY_ORIGIN)
            val gatewayOrigin = metadata.required("dev.latchway.GATEWAY_ORIGIN", GATEWAY_ORIGIN)
            require(gatewayText == gatewayOrigin)
            val gateway = requireNotNull(gatewayText.toHttpUrlOrNull())
            require(gateway.isHttps)
            val applicationId = metadata.required("dev.latchway.APPLICATION_ID", APPLICATION_ID)
            val environment = metadata.required("dev.latchway.ENVIRONMENT", IDENTIFIER)
            val feature = metadata.required("dev.latchway.FEATURE", IDENTIFIER)
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
            )
            ConformanceValues(
                gateway,
                applicationId,
                environment,
                feature,
                model,
                cloudProject,
                playTrack,
                expectedPins,
                requireLicensed,
                runId,
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
                        val validProblem = problem != null &&
                            problem.optInt("status", -1) == bounded.code &&
                            problem.optString("request_id") == requestId &&
                            problem.optString("type") == "https://latchway.dev/problems/$code" &&
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
