package dev.latchway.sample.conformance

import android.content.ContentProvider
import android.content.ContentValues
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.database.Cursor
import android.net.Uri
import android.os.Binder
import android.os.Build
import android.os.Debug
import android.os.ParcelFileDescriptor
import android.os.Process
import android.util.AtomicFile
import dev.latchway.core.KeyBacking
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone

internal const val OBSERVATION_FILE: String = "latchway-device-observation.json"
internal const val OBSERVATION_SCHEMA: String = "latchway.physical-device-observation.v1"

internal data class EvidenceTest(
    val id: String,
    val status: String,
    val durationMillis: Long = 0,
    val httpStatus: Int? = null,
    val errorCode: String? = null,
    val requestId: String? = null,
) {
    fun toJson(): JSONObject = JSONObject()
        .put("id", id)
        .put("status", status)
        .put("duration_ms", durationMillis)
        .putOptional("http_status", httpStatus)
        .putOptional("error_code", errorCode)
        .putOptional("request_id", requestId)

    companion object {
        fun passed(id: String): EvidenceTest = EvidenceTest(id, "passed")
        fun failed(id: String): EvidenceTest = EvidenceTest(id, "failed")
    }
}

internal data class DeviceObservation(
    val runId: String,
    val startedAt: String,
    val completedAt: String,
    val gatewayVersion: String,
    val application: ApplicationObservation,
    val device: DeviceObservationFacts,
    val provider: ProviderObservation,
    val observedPins: Map<String, String>,
    val tests: List<EvidenceTest>,
) {
    fun toJson(): JSONObject = JSONObject()
        .put("schema_version", OBSERVATION_SCHEMA)
        .put("platform", "android_play_integrity")
        .put(
            "run",
            JSONObject()
                .put("id", runId)
                .put("mode", "release")
                .put("started_at", startedAt)
                .put("completed_at", completedAt),
        )
        .put("gateway_version", gatewayVersion)
        .put("application", application.toJson())
        .put("device", device.toJson())
        .put("provider", provider.toJson())
        .put("observed_pins", JSONObject(observedPins))
        .put("tests", JSONArray(tests.map(EvidenceTest::toJson)))
        .put(
            "redaction",
            JSONObject()
                .put("identity_token_recorded", false)
                .put("session_token_recorded", false)
                .put("refresh_token_recorded", false)
                .put("dpop_proof_recorded", false)
                .put("attestation_evidence_recorded", false)
                .put("private_key_recorded", false)
                .put("provider_credential_recorded", false),
        )
}

internal data class ApplicationObservation(
    val identifier: String,
    val version: String,
    val build: String,
    val buildMode: String,
    val distribution: String,
    val debuggable: Boolean,
    val signingCertificateSha256: String,
    val cloudProjectNumber: String,
    val installerPackage: String,
    val playTrack: String,
) {
    fun toJson(): JSONObject = JSONObject()
        .put("identifier", identifier)
        .put("version", version)
        .put("build", build)
        .put("build_mode", buildMode)
        .put("distribution", distribution)
        .put("debuggable", debuggable)
        .put("signing_certificate_sha256", signingCertificateSha256)
        .put("cloud_project_number", cloudProjectNumber)
        .put("installer_package", installerPackage)
        .put("play_track", playTrack)
}

internal data class DeviceObservationFacts(
    val physical: Boolean,
    val emulator: Boolean,
    val testing: Boolean,
    val debuggerAttached: Boolean,
    val model: String,
    val osVersion: String,
    val osBuild: String,
    val securityLevel: String,
) {
    fun toJson(): JSONObject = JSONObject()
        .put("physical", physical)
        .put("simulator", false)
        .put("emulator", emulator)
        .put("testing", testing)
        .put("debugger_attached", debuggerAttached)
        .put("model", model)
        .put("os_name", "Android")
        .put("os_version", osVersion)
        .put("os_build", osBuild)
        .put("security_level", securityLevel)
}

internal data class ProviderObservation(
    val trustLevel: String,
    val acceptedProductionPolicy: Boolean,
) {
    fun toJson(): JSONObject = JSONObject()
        .put("name", "play_integrity")
        .put("environment", if (acceptedProductionPolicy) "production" else "unverified")
        .put("trust_level", trustLevel)
        .put("request_hash_bound", acceptedProductionPolicy)
        .put("app_recognition", if (acceptedProductionPolicy) "PLAY_RECOGNIZED" else "unverified")
        .put("account_licensing", if (acceptedProductionPolicy) "LICENSED" else "unverified")
}

internal data class ApplicationIdentity(
    val observation: ApplicationObservation,
    val pins: Map<String, String>,
)

@Suppress("DEPRECATION")
internal fun applicationIdentity(context: Context, values: ConformanceValues): ApplicationIdentity {
    val flags = if (Build.VERSION.SDK_INT >= 28) {
        PackageManager.GET_SIGNING_CERTIFICATES
    } else {
        PackageManager.GET_SIGNATURES
    }
    val packageInfo = context.packageInfo(flags)
    val signatures = if (Build.VERSION.SDK_INT >= 28) {
        requireNotNull(packageInfo.signingInfo).apkContentsSigners
    } else {
        requireNotNull(packageInfo.signatures)
    }
    require(signatures.size == 1) { "Conformance APK must have exactly one current signer" }
    val certificate = MessageDigest.getInstance("SHA-256")
        .digest(signatures.single().toByteArray())
        .joinToString("") { "%02x".format(Locale.US, it.toInt() and 0xff) }
    val installer = if (Build.VERSION.SDK_INT >= 30) {
        context.packageManager.getInstallSourceInfo(context.packageName).installingPackageName.orEmpty()
    } else {
        @Suppress("DEPRECATION")
        context.packageManager.getInstallerPackageName(context.packageName).orEmpty()
    }
    val debuggable = context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0
    val version = packageInfo.versionName.orEmpty()
    val build = packageInfo.compatibleVersionCode().toString()
    val observation = ApplicationObservation(
        identifier = context.packageName,
        version = version,
        build = build,
        buildMode = if (debuggable) "debug" else "release",
        distribution = "play_${values.playTrack}",
        debuggable = debuggable,
        signingCertificateSha256 = certificate,
        cloudProjectNumber = values.cloudProjectNumber.toString(),
        installerPackage = installer,
        playTrack = values.playTrack,
    )
    val pins = mapOf(
        "application_identifier" to context.packageName,
        "app_version" to version,
        "build_number" to build,
        "signing_certificate_sha256" to certificate,
        "cloud_project_number" to values.cloudProjectNumber.toString(),
        "installer_package" to installer,
        "play_track" to values.playTrack,
        "require_licensed" to values.requireLicensed.toString(),
        "source_commit" to values.expectedPins.getValue("source_commit"),
        "core_commit" to values.expectedPins.getValue("core_commit"),
        "contract_bundle_sha256" to values.expectedPins.getValue("contract_bundle_sha256"),
        "gateway_image_digest" to values.expectedPins.getValue("gateway_image_digest"),
        "gateway_configuration_sha256" to values.expectedPins.getValue("gateway_configuration_sha256"),
        "gateway_origin" to values.expectedPins.getValue("gateway_origin"),
        "gateway_environment" to values.environment,
        "gateway_deployment_key_id" to values.expectedPins.getValue("gateway_deployment_key_id"),
        "gateway_deployment_statement_sha256" to values.expectedPins.getValue("gateway_deployment_statement_sha256"),
        "gateway_deployment_public_key_sha256" to values.expectedPins.getValue("gateway_deployment_public_key_sha256"),
    )
    return ApplicationIdentity(observation, pins)
}

internal fun deviceFacts(backing: KeyBacking?): DeviceObservationFacts {
    val emulator = isProbablyEmulator()
    return DeviceObservationFacts(
        physical = !emulator,
        emulator = emulator,
        testing = isTestingRuntime(),
        debuggerAttached = Debug.isDebuggerConnected() || Debug.waitingForDebugger(),
        model = listOf(Build.MANUFACTURER, Build.MODEL)
            .filter(String::isNotBlank)
            .joinToString(" ")
            .take(128)
            .ifBlank { "unknown" },
        osVersion = Build.VERSION.RELEASE.take(64).ifBlank { "unknown" },
        osBuild = Build.ID.take(64).ifBlank { "unknown" },
        securityLevel = when (backing) {
            KeyBacking.STRONGBOX -> "strongbox"
            KeyBacking.TRUSTED_EXECUTION_ENVIRONMENT -> "tee"
            KeyBacking.UNKNOWN_SECURE_HARDWARE -> "unknown_secure_hardware"
            KeyBacking.SOFTWARE -> "software"
            null -> "unknown"
        },
    )
}

internal fun writeObservation(context: Context, observation: DeviceObservation) {
    val encoded = observation.toJson().toString(2).toByteArray(StandardCharsets.UTF_8)
    require(encoded.size <= 262_144) { "Redacted observation exceeds 256 KiB" }
    val destination = AtomicFile(File(context.filesDir, OBSERVATION_FILE))
    val stream = destination.startWrite()
    try {
        stream.write(encoded)
        stream.write('\n'.code)
        destination.finishWrite(stream)
    } catch (failure: Exception) {
        destination.failWrite(stream)
        throw failure
    }
}

internal fun timestamp(): String = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", Locale.US).run {
    timeZone = TimeZone.getTimeZone("UTC")
    format(Date())
}

internal fun isProbablyEmulator(): Boolean {
    val fingerprint = Build.FINGERPRINT.lowercase(Locale.US)
    val model = Build.MODEL.lowercase(Locale.US)
    val product = Build.PRODUCT.lowercase(Locale.US)
    val hardware = Build.HARDWARE.lowercase(Locale.US)
    return fingerprint.startsWith("generic") || fingerprint.contains("emulator") ||
        model.contains("sdk_gphone") || model.contains("emulator") || model.contains("android sdk built for") ||
        product.contains("sdk") || hardware.contains("goldfish") || hardware.contains("ranchu")
}

internal fun isTestingRuntime(): Boolean =
    Build.FINGERPRINT.lowercase(Locale.US).contains("robolectric") ||
        runCatching { Class.forName("androidx.test.platform.app.InstrumentationRegistry") }.isSuccess

private fun Context.packageInfo(flags: Int): PackageInfo = if (Build.VERSION.SDK_INT >= 33) {
    packageManager.getPackageInfo(packageName, PackageManager.PackageInfoFlags.of(flags.toLong()))
} else {
    @Suppress("DEPRECATION")
    packageManager.getPackageInfo(packageName, flags)
}

private fun PackageInfo.compatibleVersionCode(): Long = if (Build.VERSION.SDK_INT >= 28) {
    longVersionCode
} else {
    @Suppress("DEPRECATION")
    versionCode.toLong()
}

private fun JSONObject.putOptional(name: String, value: Any?): JSONObject =
    if (value == null) this else put(name, value)

/**
 * Exposes only the fixed redacted observation to root/adb-shell collection.
 * The signature-level DUMP permission and UID check keep application callers
 * from turning this into a general file provider.
 */
public class DeviceEvidenceProvider : ContentProvider() {
    override fun onCreate(): Boolean = true

    override fun openFile(uri: Uri, mode: String): ParcelFileDescriptor {
        if (mode != "r" || uri.pathSegments != listOf("v1", "latest")) {
            throw IllegalArgumentException("Only the latest redacted evidence is readable")
        }
        val caller = Binder.getCallingUid()
        if (caller != Process.SHELL_UID && caller != 0) {
            throw SecurityException("Device evidence is restricted to adb shell/root collection")
        }
        val file = File(requireNotNull(context).filesDir, OBSERVATION_FILE)
        if (!file.isFile || file.length() !in 1..262_144) {
            throw IllegalStateException("Redacted device observation is unavailable")
        }
        return ParcelFileDescriptor.open(file, ParcelFileDescriptor.MODE_READ_ONLY)
    }

    override fun getType(uri: Uri): String = "application/json"
    override fun query(uri: Uri, projection: Array<out String>?, selection: String?, selectionArgs: Array<out String>?, sortOrder: String?): Cursor? = null
    override fun insert(uri: Uri, values: ContentValues?): Uri? = throw UnsupportedOperationException()
    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<out String>?): Int = throw UnsupportedOperationException()
    override fun update(uri: Uri, values: ContentValues?, selection: String?, selectionArgs: Array<out String>?): Int = throw UnsupportedOperationException()
}
