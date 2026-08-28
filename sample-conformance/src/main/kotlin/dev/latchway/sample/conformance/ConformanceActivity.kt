package dev.latchway.sample.conformance

import android.app.Activity
import android.content.pm.PackageManager
import android.os.Bundle
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import com.google.firebase.FirebaseApp
import com.google.firebase.auth.FirebaseAuth
import dev.latchway.firebaseauth.FirebaseIdentityTokenProvider
import dev.latchway.okhttp.LatchwayClient
import dev.latchway.okhttp.LatchwayConfiguration
import dev.latchway.okhttp.latchwayFeature
import dev.latchway.playintegrity.PlayIntegrityAttestationProvider
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.suspendCancellableCoroutine
import okhttp3.Call
import okhttp3.Callback
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import org.json.JSONArray
import org.json.JSONObject
import java.io.IOException
import java.nio.charset.StandardCharsets
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/** Real-device gate: this activity never substitutes debug evidence for Google Play evidence. */
public class ConformanceActivity : Activity() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main)
    private lateinit var status: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        status = TextView(this).apply { text = readinessMessage() }
        val run = Button(this).apply {
            text = "Run real Play Integrity conformance"
            setOnClickListener { scope.launch { runConformance() } }
        }
        setContentView(LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(48, 48, 48, 48)
            addView(status)
            addView(run)
        })
    }

    override fun onDestroy() {
        scope.cancel()
        super.onDestroy()
    }

    private suspend fun runConformance() {
        val values = configuration() ?: return
        if (FirebaseAuth.getInstance().currentUser == null) {
            status.text = "A real signed-in Firebase user is required."
            return
        }
        status.text = "Requesting real Play Integrity evidence and a Latchway session…"
        try {
            val latchway = LatchwayClient(
                configuration = LatchwayConfiguration(
                    baseUrl = values.gateway,
                    applicationId = values.applicationId,
                    environment = values.environment,
                ),
                identityTokenProvider = FirebaseIdentityTokenProvider(),
                attestationProvider = PlayIntegrityAttestationProvider(
                    this@ConformanceActivity,
                    values.cloudProjectNumber,
                ),
                context = this@ConformanceActivity,
            )
            latchway.use {
                val request = Request.Builder()
                    .url(values.gateway.resolve("/v1/chat/completions") ?: error("Invalid gateway URL"))
                    .latchwayFeature(values.feature)
                    .post(
                        JSONObject()
                            .put("model", values.model)
                            .put(
                                "messages",
                                JSONArray().put(
                                    JSONObject()
                                        .put("role", "user")
                                        .put("content", "Return the word conformance."),
                                ),
                            )
                            .put("stream", true)
                            .toString()
                            .toRequestBody("application/json".toMediaType()),
                    )
                    .build()
                val httpClient = OkHttpClient.Builder()
                    .addInterceptor(latchway.interceptor())
                    .addNetworkInterceptor(latchway.originGuard())
                    .authenticator(latchway.authenticator())
                    .build()
                try {
                    httpClient.newCall(request).awaitFirstStreamByte()
                } finally {
                    httpClient.connectionPool.evictAll()
                    httpClient.dispatcher.executorService.shutdown()
                }
            }
            status.text = "PASS: a real Play-bound streamed request returned data. Record the Play track and device in release evidence."
        } catch (error: CancellationException) {
            throw error
        } catch (error: Exception) {
            status.text = "FAIL: ${error::class.java.simpleName}. Inspect redacted device and gateway diagnostics."
        }
    }

    private fun readinessMessage(): String = when {
        FirebaseApp.getApps(this).isEmpty() -> "Firebase application configuration is required."
        configuration() == null -> "Add non-secret Latchway values to manifest metadata before the Play-track build."
        else -> "Install this exact signed build from a Google Play test track, sign in, then run conformance."
    }

    private fun configuration(): Values? {
        val metadata = packageManager.getApplicationInfo(packageName, PackageManager.GET_META_DATA).metaData
            ?: return null
        val gateway = metadata.getString("dev.latchway.GATEWAY_URL")?.toHttpUrlOrNull() ?: return null
        val applicationId = metadata.getString("dev.latchway.APPLICATION_ID")?.takeIf { it.isNotBlank() }
            ?: return null
        val environment = metadata.getString("dev.latchway.ENVIRONMENT")
            ?.takeIf { IDENTIFIER.matches(it) } ?: return null
        val feature = metadata.getString("dev.latchway.FEATURE")?.takeIf { IDENTIFIER.matches(it) }
            ?: return null
        val model = metadata.getString("dev.latchway.MODEL")?.takeIf(::isValidModel) ?: return null
        val projectNumber = metadata.getString("dev.latchway.CLOUD_PROJECT_NUMBER")?.toLongOrNull()
            ?.takeIf { it > 0 } ?: return null
        return Values(gateway, applicationId, environment, feature, model, projectNumber)
    }

    private data class Values(
        val gateway: okhttp3.HttpUrl,
        val applicationId: String,
        val environment: String,
        val feature: String,
        val model: String,
        val cloudProjectNumber: Long,
    )

    private companion object {
        val IDENTIFIER = Regex("^[a-z][a-z0-9_-]{0,62}$")
    }
}

internal fun isValidModel(value: String): Boolean =
    value.isNotEmpty() && value.toByteArray(StandardCharsets.UTF_8).size <= 256 &&
        value.trim() == value && value.none { it.isISOControl() }

private suspend fun Call.awaitFirstStreamByte(): Unit = suspendCancellableCoroutine { continuation ->
    continuation.invokeOnCancellation { cancel() }
    enqueue(object : Callback {
        override fun onFailure(call: Call, e: IOException) {
            if (continuation.isActive) continuation.resumeWithException(e)
        }

        override fun onResponse(call: Call, response: Response) {
            try {
                response.use {
                    check(it.isSuccessful) { "Gateway returned HTTP ${it.code}" }
                    val firstBytes = it.body.source().readByteArray(1)
                    check(firstBytes.isNotEmpty()) { "Stream returned no bytes" }
                }
                if (continuation.isActive) continuation.resume(Unit)
            } catch (error: Exception) {
                if (continuation.isActive) continuation.resumeWithException(error)
            }
        }
    })
}
