package dev.latchway.sample.firebase

import android.app.Activity
import android.content.Context
import android.content.pm.PackageManager
import android.os.Bundle
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import com.google.firebase.FirebaseApp
import com.google.firebase.auth.FirebaseAuth
import dev.latchway.core.KeyBacking
import dev.latchway.core.LatchwayException
import dev.latchway.firebaseauth.FirebaseIdentityTokenProvider
import dev.latchway.okhttp.LatchwayClient
import dev.latchway.okhttp.LatchwayConfiguration
import dev.latchway.okhttp.latchwayFeature
import dev.latchway.playintegrity.PlayIntegrityAttestationProvider
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import okhttp3.Call
import okhttp3.Callback
import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import okio.Buffer
import org.json.JSONObject
import java.io.IOException
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/** Runnable Firebase + Play Integrity golden journey using only public SDK APIs. */
public class MainActivity : Activity() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main)
    private lateinit var status: TextView
    private lateinit var runButton: Button

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        status = TextView(this).apply {
            text = "Configure Firebase, sign in normally, then run the Latchway golden journey."
        }
        runButton = Button(this).apply {
            text = "Run golden journey"
            setOnClickListener { startGoldenJourney() }
        }
        setContentView(LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(48, 48, 48, 48)
            addView(status)
            addView(runButton)
        })
    }

    override fun onDestroy() {
        scope.cancel()
        super.onDestroy()
    }

    private fun startGoldenJourney() {
        if (!runButton.isEnabled) return
        runButton.isEnabled = false
        scope.launch {
            try {
                runGoldenJourney()
            } finally {
                runButton.isEnabled = true
            }
        }
    }

    private suspend fun runGoldenJourney() {
        val deployment = GoldenJourneyDeployment.load(this)
        if (deployment == null) {
            status.text = "FAIL configuration: supply the documented Gradle properties."
            return
        }
        if (FirebaseApp.getApps(this).isEmpty() || FirebaseAuth.getInstance().currentUser == null) {
            status.text = "FAIL Firebase: configure Firebase and sign in through the app first."
            return
        }

        var stage = GoldenJourneyStage.CONFIGURATION
        var sessionEstablished = false
        var revocationAttempted = false
        val latchway = LatchwayClient(
            configuration = LatchwayConfiguration(
                baseUrl = deployment.gateway,
                applicationId = deployment.applicationId,
                environment = deployment.environment,
                identityProvider = "firebase",
                defaultFeature = deployment.feature,
            ),
            identityTokenProvider = FirebaseIdentityTokenProvider(
                firebaseAuth = FirebaseAuth.getInstance(),
                forceRefresh = true,
            ),
            attestationProvider = PlayIntegrityAttestationProvider(
                context = applicationContext,
                cloudProjectNumber = deployment.cloudProjectNumber,
            ),
            context = applicationContext,
        )
        val http = latchway.buildOkHttpClient(
            OkHttpClient.Builder()
                .followRedirects(false)
                .followSslRedirects(false)
                .retryOnConnectionFailure(false),
        )

        try {
            stage = GoldenJourneyStage.RESPONSE
            val request = Request.Builder()
                .url(checkNotNull(deployment.gateway.resolve("v1/responses")))
                .header("Accept", "text/event-stream")
                .post(
                    JSONObject()
                        .put("model", deployment.model)
                        .put("input", "Return the word verified.")
                        .put("stream", true)
                        .toString()
                        .toRequestBody("application/json".toMediaType()),
                )
                .latchwayFeature(deployment.feature)
                .build()
            val streamed = http.newCall(request).awaitIncremental(MAXIMUM_STREAM_BYTES)
            if (streamed.status !in 200..299 || streamed.byteCount == 0L || streamed.requestId == null) {
                throw GoldenJourneyFailure(stage, streamed.status, streamed.requestId)
            }
            sessionEstablished = true

            stage = GoldenJourneyStage.DIAGNOSTICS
            val diagnostics = latchway.diagnostics()
            if (diagnostics.requestId.isBlank() ||
                diagnostics.trustProvider != "play_integrity" ||
                diagnostics.trustLevel !in setOf("device_verified", "strong_device_verified") ||
                diagnostics.key.backing == KeyBacking.SOFTWARE
            ) {
                throw GoldenJourneyFailure(stage, requestId = diagnostics.requestId)
            }

            stage = GoldenJourneyStage.QUOTA
            val quota = latchway.quota(deployment.feature)
            if (quota.feature != deployment.feature) {
                throw GoldenJourneyFailure(stage, requestId = diagnostics.requestId)
            }

            stage = GoldenJourneyStage.REVOCATION
            revocationAttempted = true
            latchway.revokeCurrentInstallation()
            FirebaseAuth.getInstance().signOut()
            status.text = "PASS · response ${streamed.requestId} · diagnostics ${diagnostics.requestId} · " +
                "quota ${quota.limits.size} limits · installation revoked · Firebase signed out"
        } catch (error: Exception) {
            // Cleanup revocation is attempted once only after a session was
            // proven. Never replay an indeterminate revocation automatically.
            withContext(NonCancellable) {
                if (sessionEstablished && !revocationAttempted) {
                    revocationAttempted = true
                    runCatching { latchway.revokeCurrentInstallation() }
                }
                runCatching { FirebaseAuth.getInstance().signOut() }
            }
            if (error is CancellationException) throw error
            status.text = safeFailure(stage, error)
        } finally {
            latchway.close()
            http.dispatcher.cancelAll()
            http.connectionPool.evictAll()
            http.dispatcher.executorService.shutdown()
        }
    }
}

private enum class GoldenJourneyStage {
    CONFIGURATION,
    RESPONSE,
    DIAGNOSTICS,
    QUOTA,
    REVOCATION,
}

private class GoldenJourneyFailure(
    val stage: GoldenJourneyStage,
    val status: Int? = null,
    val requestId: String? = null,
) : Exception()

private data class GoldenJourneyDeployment(
    val gateway: HttpUrl,
    val applicationId: String,
    val environment: String,
    val feature: String,
    val model: String,
    val cloudProjectNumber: Long,
) {
    companion object {
        @Suppress("DEPRECATION")
        fun load(context: Context): GoldenJourneyDeployment? {
            val metadata = runCatching {
                context.packageManager.getApplicationInfo(
                    context.packageName,
                    PackageManager.GET_META_DATA,
                ).metaData
            }.getOrNull() ?: return null
            fun value(name: String): String = metadata.get(name)?.toString().orEmpty()
            val gateway = value("dev.latchway.gatewayUrl").toHttpUrlOrNull() ?: return null
            val applicationId = value("dev.latchway.applicationId")
            val environment = value("dev.latchway.environment")
            val feature = value("dev.latchway.feature")
            val model = value("dev.latchway.model")
            val project = value("dev.latchway.cloudProjectNumber").toLongOrNull() ?: return null
            if (!gateway.isHttps || !gateway.encodedPath.endsWith('/') || gateway.query != null ||
                !APPLICATION_ID.matches(applicationId) || !IDENTIFIER.matches(environment) ||
                !IDENTIFIER.matches(feature) || !IDENTIFIER.matches(model) || project <= 0
            ) {
                return null
            }
            return GoldenJourneyDeployment(
                gateway,
                applicationId,
                environment,
                feature,
                model,
                project,
            )
        }

        private val APPLICATION_ID = Regex("^app_[0-7][0-9A-HJKMNP-TV-Z]{25}$")
        private val IDENTIFIER = Regex("^[a-z][a-z0-9_-]{0,62}$")
    }
}

private data class StreamObservation(
    val status: Int,
    val byteCount: Long,
    val requestId: String?,
)

private suspend fun Call.awaitIncremental(maximumBytes: Long): StreamObservation =
    suspendCancellableCoroutine { continuation ->
        continuation.invokeOnCancellation { cancel() }
        enqueue(object : Callback {
            override fun onFailure(call: Call, e: IOException) {
                if (continuation.isActive) continuation.resumeWithException(e)
            }

            override fun onResponse(call: Call, response: Response) {
                try {
                    val observation = response.use { streamed ->
                        val source = streamed.body.source()
                        val buffer = Buffer()
                        var count = 0L
                        while (true) {
                            val read = source.read(buffer, 8_192L)
                            if (read == -1L) break
                            count += read
                            check(count <= maximumBytes) { "stream exceeded the example limit" }
                            buffer.clear()
                        }
                        StreamObservation(
                            status = streamed.code,
                            byteCount = count,
                            requestId = streamed.header("X-Latchway-Request-ID")
                                ?.takeIf(SAFE_REQUEST_ID::matches),
                        )
                    }
                    if (continuation.isActive) continuation.resume(observation)
                } catch (error: Exception) {
                    if (continuation.isActive) continuation.resumeWithException(error)
                }
            }
        })
    }

private fun safeFailure(stage: GoldenJourneyStage, error: Exception): String = when (error) {
    is LatchwayException ->
        "FAIL ${stage.name.lowercase()}: ${error.code.wireValue} · ${error.documentationUrl}" +
            (error.requestId?.let { " · request $it" } ?: "")
    is GoldenJourneyFailure ->
        "FAIL ${error.stage.name.lowercase()}" +
            (error.status?.let { ": HTTP $it" } ?: "") +
            (error.requestId?.let { " · request $it" } ?: "")
    else -> "FAIL ${stage.name.lowercase()}: request did not complete"
}

private const val MAXIMUM_STREAM_BYTES = 1_048_576L
private val SAFE_REQUEST_ID = Regex("^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")
