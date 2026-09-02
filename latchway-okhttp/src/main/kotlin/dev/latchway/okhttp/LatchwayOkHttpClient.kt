package dev.latchway.okhttp

import dev.latchway.core.LatchwayComponentClient
import dev.latchway.core.LatchwayErrorCode
import dev.latchway.core.LatchwayException
import okhttp3.OkHttpClient

/**
 * Build a final client snapshot without mutating the caller's builder.
 *
 * Existing application and network interceptors run before the Latchway
 * authorization and final-dispatch guard. A pre-existing server authenticator
 * remains available only for non-gateway origins. Any manually installed
 * Latchway part is rejected before the validated client is created, which
 * prevents partial and duplicate installation.
 */
internal fun buildLatchwayOkHttpClient(
    builder: OkHttpClient.Builder,
    hooks: LatchwayOkHttpHooks,
    component: LatchwayComponentClient?,
): OkHttpClient {
    val template = try {
        builder.build()
    } catch (error: RuntimeException) {
        throw invalidOkHttpConfiguration(
            "The OkHttp builder could not produce a valid client configuration",
            error,
        )
    }
    if (template.interceptors.any { it is LatchwayOkHttpInstallationPart } ||
        template.networkInterceptors.any { it is LatchwayOkHttpInstallationPart } ||
        template.authenticator is LatchwayOkHttpInstallationPart
    ) {
        throw invalidOkHttpConfiguration(
            "The OkHttp builder already contains a Latchway hook; install Latchway only through buildOkHttpClient",
        )
    }

    val applicationInterceptor = hooks.interceptor(component)
    val originGuard = hooks.originGuard()
    val authenticator = hooks.authenticator(template.authenticator)
    val configured = template.newBuilder()
        .addInterceptor(applicationInterceptor)
        .addNetworkInterceptor(originGuard)
        .authenticator(authenticator)
        .build()

    if (configured.interceptors.lastOrNull() !== applicationInterceptor ||
        configured.networkInterceptors.lastOrNull() !== originGuard ||
        configured.authenticator !== authenticator ||
        configured.interceptors.count { it is LatchwayOkHttpInstallationPart } != 1 ||
        configured.networkInterceptors.count { it is LatchwayOkHttpInstallationPart } != 1
    ) {
        throw invalidOkHttpConfiguration(
            "The complete Latchway OkHttp integration could not be installed",
        )
    }
    return configured
}

private fun invalidOkHttpConfiguration(
    safeMessage: String,
    cause: Throwable? = null,
): LatchwayException = LatchwayException(
    code = LatchwayErrorCode.CONFIGURATION_INVALID,
    safeMessage = safeMessage,
    cause = cause,
)
