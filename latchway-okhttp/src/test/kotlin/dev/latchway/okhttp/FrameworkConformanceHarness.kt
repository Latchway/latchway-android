package dev.latchway.okhttp

import dev.latchway.core.CoreConfiguration
import dev.latchway.core.InstallationMetadata
import dev.latchway.core.LatchwayClock
import dev.latchway.core.LatchwayCoreClient
import dev.latchway.testsupport.DebugAttestationProvider
import dev.latchway.testsupport.InMemorySessionStateStore
import dev.latchway.testsupport.SoftwareTestInstallationSigner
import dev.latchway.testsupport.StaticIdentityTokenProvider
import okhttp3.EventListener
import okhttp3.OkHttpClient
import okhttp3.OkHttp
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import java.io.Closeable

internal const val FRAMEWORK_FEATURE = "habit-assistant"
internal const val PROVIDER_PLACEHOLDER = "latchway-provider-placeholder-not-a-secret"
internal val FRAMEWORK_ACCESS_TOKEN = "a".repeat(64)

/** A real core session plus the exact internal hooks used by the public Android client. */
internal class FrameworkConformanceHarness(
    private val gateway: LoopbackHttpServer,
    includeRefreshGrant: Boolean = false,
) : Closeable {
    private val now = 1_700_000_000L
    private val signer = SoftwareTestInstallationSigner.generate()
    private val controlHttp = OkHttpClient()
    private val configuration = LatchwayConfiguration(
        baseUrl = gateway.url("/"),
        applicationId = "app_01J00000000000000000000000",
        environment = "production",
        identityProvider = "debug",
        defaultFeature = FRAMEWORK_FEATURE,
        allowInsecureLoopback = true,
    )
    private val core = LatchwayCoreClient.create(
        configuration = CoreConfiguration(
            baseUrl = configuration.baseUrl.toUri(),
            applicationId = configuration.applicationId,
            environment = configuration.environment,
            identityProvider = configuration.identityProvider,
            clientPlatform = configuration.clientPlatform,
            sdkVersion = configuration.sdkVersion,
            framework = configuration.framework,
            allowInsecureLoopback = true,
        ),
        identityTokenProvider = StaticIdentityTokenProvider("i".repeat(32)),
        attestationProvider = DebugAttestationProvider(),
        signer = signer,
        stateStore = InMemorySessionStateStore(),
        transport = OkHttpLatchwayTransport(controlHttp),
        installationMetadata = InstallationMetadata("1.0.0", "test", "framework fixture"),
        clock = LatchwayClock { now },
    )

    init {
        gateway.enqueueControl(
            LoopbackResponse().setResponseCode(201).setBody(challenge()),
        )
        gateway.enqueueControl(
            LoopbackResponse().setResponseCode(201).setBody(grant(FRAMEWORK_ACCESS_TOKEN, "r".repeat(32))),
        )
        if (includeRefreshGrant) {
            gateway.enqueueControl(
                LoopbackResponse().setResponseCode(200).setBody(grant("b".repeat(64), "s".repeat(32))),
            )
        }
    }

    private val hooks = LatchwayOkHttpHooks(
        configuration = configuration,
        authorizer = { _, request, feature, nonce ->
            core.authorize(request.method, request.url.toUri(), feature, nonce)
        },
        refresher = { core.refresh() },
        clearer = { _, authorization -> core.clearSessionIfCurrent(authorization) },
        terminalResponseObserver = { _, _ -> Unit },
    )

    fun okHttpBuilder(eventListener: EventListener? = null): OkHttpClient.Builder =
        OkHttpClient.Builder()
            .apply { if (eventListener != null) this.eventListener(eventListener) }
            .addInterceptor(hooks.interceptor())
            .addNetworkInterceptor(hooks.originGuard())
            .authenticator(hooks.authenticator())

    override fun close() {
        core.close()
        controlHttp.dispatcher.cancelAll()
        controlHttp.connectionPool.evictAll()
        controlHttp.dispatcher.executorService.shutdown()
    }

    private fun challenge(): String = """
        {
          "challenge_id":"chl_01J00000000000000000000001",
          "challenge_nonce":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
          "binding_version":1,
          "issued_at":$now,
          "expires_at":"2023-11-14T22:23:20Z",
          "attestation":{
            "provider":"debug",
            "mode":"required",
            "client_data_hash":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
          }
        }
    """.trimIndent()

    private fun grant(accessToken: String, refreshToken: String): String = """
        {
          "access_token":"$accessToken",
          "token_type":"DPoP",
          "expires_in":600,
          "refresh_token":"$refreshToken",
          "refresh_expires_in":3600,
          "installation":{
            "id":"ins_01J00000000000000000000001",
            "platform":"android",
            "dpop_jkt":"${signer.publicJwk.thumbprint()}",
            "status":"active"
          },
          "trust":{
            "provider":"debug",
            "level":"debug",
            "verified_at":"2023-11-14T22:13:20Z",
            "expires_at":"2023-11-14T23:13:20Z"
          }
        }
    """.trimIndent()
}

internal fun assertFrameworkAuthorization(request: LoopbackRecordedRequest) {
    val authorization = request.headers["Authorization"]
    assertNotNull(authorization)
    assertTrue(authorization!!.startsWith("DPoP "))
    assertFalse(authorization.contains(PROVIDER_PLACEHOLDER))
    assertEquals(FRAMEWORK_FEATURE, request.headers["X-Latchway-Feature"])
    assertEquals("android", request.headers["X-Latchway-SDK"])
    assertEquals("1.0.0", request.headers["X-Latchway-SDK-Version"])
    assertEquals("2", request.headers["X-Latchway-Protocol-Version"])
    assertEquals("android-okhttp", request.headers["X-Latchway-Framework"])
    assertEquals(OkHttp.VERSION, request.headers["X-Latchway-Framework-Version"])
    assertNotNull(request.headers["X-Latchway-Request-ID"])
    val proof = request.headers["DPoP"]
    assertNotNull(proof)
    assertEquals(2, proof!!.count { it == '.' })
    assertEquals(null, request.headers["Api-Key"])
    assertEquals(null, request.headers["X-Api-Key"])
}
