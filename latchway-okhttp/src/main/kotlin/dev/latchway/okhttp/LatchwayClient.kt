package dev.latchway.okhttp

import android.content.ContentProvider
import android.content.ContentValues
import android.content.Context
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.database.Cursor
import android.net.Uri
import android.os.Build
import dev.latchway.core.AndroidEncryptedSessionStateStore
import dev.latchway.core.AndroidEncryptedComponentSessionStateStore
import dev.latchway.core.AndroidKeystoreInstallationSigner
import dev.latchway.core.AttestationProvider
import dev.latchway.core.AuthorizedHeaders
import dev.latchway.core.Base64Url
import dev.latchway.core.CoreConfiguration
import dev.latchway.core.IdentityTokenProvider
import dev.latchway.core.InstallationMetadata
import dev.latchway.core.KeyPolicy
import dev.latchway.core.LATCHWAY_SDK_VERSION
import dev.latchway.core.LatchwayComponentClient
import dev.latchway.core.LatchwayClientPlatform
import dev.latchway.core.LatchwayCoreClient
import dev.latchway.core.LatchwayDiagnostics
import dev.latchway.core.LatchwayErrorCode
import dev.latchway.core.LatchwayException
import dev.latchway.core.LatchwayFramework
import dev.latchway.core.LatchwayQuotaSnapshot
import dev.latchway.core.UnsupportedAttestationProvider
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.withContext
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import okhttp3.Authenticator
import okhttp3.ConnectionPool
import okhttp3.CookieJar
import okhttp3.Dispatcher
import okhttp3.HttpUrl
import okhttp3.Interceptor
import okhttp3.OkHttpClient
import okhttp3.OkHttp
import okhttp3.Request
import okhttp3.Response
import org.json.JSONObject
import java.io.Closeable
import java.lang.ref.WeakReference
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.Locale
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean

/** Runtime OkHttp semver emitted in the framework metadata header. */
public val LATCHWAY_OKHTTP_FRAMEWORK_VERSION: String
    get() = OkHttp.VERSION

/** Canonical React Native framework identity emitted by the native-backed fetch bridge. */
public const val LATCHWAY_REACT_NATIVE_FRAMEWORK_ID: String = "react-native-fetch"

/** React Native package semver supported by this native-backed fetch bridge release. */
public const val LATCHWAY_REACT_NATIVE_FRAMEWORK_VERSION: String = "0.82.0"

/** Koog release whose public preconfigured-OkHttp seam passed the adapter conformance suite. */
public const val LATCHWAY_KOOG_FRAMEWORK_VERSION: String = "1.1.1"

/** Closed, audited Android integration identities; arbitrary framework metadata is not accepted. */
public enum class LatchwayFrameworkIntegration {
    OKHTTP,
    KOOG;

    internal fun metadata(): LatchwayFramework = when (this) {
        OKHTTP -> LatchwayFramework("android-okhttp", LATCHWAY_OKHTTP_FRAMEWORK_VERSION)
        KOOG -> LatchwayFramework("koog-android", LATCHWAY_KOOG_FRAMEWORK_VERSION)
    }
}

public data class LatchwayConfiguration(
    val baseUrl: HttpUrl,
    val applicationId: String,
    val environment: String,
    val identityProvider: String = "firebase",
    val clientPlatform: LatchwayClientPlatform = LatchwayClientPlatform.ANDROID,
    val sdkVersion: String = LATCHWAY_SDK_VERSION,
    val defaultFeature: String? = null,
    val keyPolicy: KeyPolicy = KeyPolicy(),
    val allowInsecureLoopback: Boolean = false,
    val frameworkIntegration: LatchwayFrameworkIntegration = LatchwayFrameworkIntegration.OKHTTP,
) {
    /** Runtime-derived contract identity; callers cannot report an arbitrary adapter version. */
    val framework: LatchwayFramework
        get() = when (clientPlatform) {
            LatchwayClientPlatform.ANDROID -> frameworkIntegration.metadata()
            LatchwayClientPlatform.REACT_NATIVE_ANDROID ->
                LatchwayFramework(
                    LATCHWAY_REACT_NATIVE_FRAMEWORK_ID,
                    LATCHWAY_REACT_NATIVE_FRAMEWORK_VERSION,
                )
        }

    init {
        require(
            clientPlatform != LatchwayClientPlatform.REACT_NATIVE_ANDROID ||
                frameworkIntegration == LatchwayFrameworkIntegration.OKHTTP,
        ) {
            "React Native always emits its canonical native-backed fetch framework metadata"
        }
        CoreConfiguration(
            baseUrl = baseUrl.toUri(),
            applicationId = applicationId,
            environment = environment,
            identityProvider = identityProvider,
            clientPlatform = clientPlatform,
            sdkVersion = sdkVersion,
            framework = framework,
            allowInsecureLoopback = allowInsecureLoopback,
        )
        defaultFeature?.let(::validateFeature)
    }
}

public data class LatchwayFeature(public val value: String) {
    init { validateFeature(value) }
}

public fun Request.Builder.latchwayFeature(feature: String): Request.Builder =
    tag(LatchwayFeature::class.java, LatchwayFeature(feature))

public class LatchwayClient(
    private val configuration: LatchwayConfiguration,
    private val identityTokenProvider: IdentityTokenProvider,
    private val attestationProvider: AttestationProvider = UnsupportedAttestationProvider,
    controlClient: OkHttpClient = OkHttpClient(),
    context: Context = LatchwayAndroidRuntime.requireContext(),
) : Closeable {
    private val applicationContext = context.applicationContext
    private val controlClient = isolatedControlClient(controlClient)
    private val coreDelegate = lazy(LazyThreadSafetyMode.SYNCHRONIZED) {
        runBlocking { createCore() }
    }
    private val core: LatchwayCoreClient by coreDelegate
    private val okHttpHooks = LatchwayOkHttpHooks(
        configuration = configuration,
        authorizer = { component, request, feature, nonce ->
            if (component == null) {
                core.authorize(request.method, request.url.toUri(), feature, nonce)
            } else {
                component.authorize(request.method, request.url.toUri(), feature, nonce)
            }
        },
        refresher = { component ->
            if (component == null) core.refresh() else component.refresh()
        },
        clearer = { component, authorization ->
            if (component == null) {
                core.clearSessionIfCurrent(authorization)
            } else {
                component.clearSessionIfCurrent(authorization)
            }
        },
        terminalResponseObserver = ::applyTrustedTerminalResponse,
    )

    /**
     * Builds an immutable OkHttp client with every required Latchway hook.
     *
     * The supplied builder is snapshotted and is never mutated. Its existing
     * interceptors are preserved ahead of Latchway's application interceptor
     * and final network-origin guard. A custom authenticator is delegated only
     * for non-gateway origins. Builders that already contain any manual
     * Latchway hook are rejected so installation cannot be partial or doubled.
     */
    @JvmOverloads
    public fun buildOkHttpClient(
        builder: OkHttpClient.Builder = OkHttpClient.Builder(),
    ): OkHttpClient = buildLatchwayOkHttpClient(builder, okHttpHooks, component = null)

    /** Builds the same complete client with one native component identity. */
    @JvmOverloads
    public fun buildOkHttpClient(
        component: LatchwayComponentClient,
        builder: OkHttpClient.Builder = OkHttpClient.Builder(),
    ): OkHttpClient = buildLatchwayOkHttpClient(builder, okHttpHooks, component)

    @Deprecated(
        message = "Manual hook assembly can omit required origin protection; use buildOkHttpClient()",
    )
    public fun interceptor(): Interceptor = okHttpHooks.interceptor()

    /** Framework-transparent request-time authorization with one native component identity. */
    @Deprecated(
        message = "Manual hook assembly can omit required origin protection; use buildOkHttpClient(component)",
    )
    public fun interceptor(component: LatchwayComponentClient): Interceptor =
        okHttpHooks.interceptor(component)

    /**
     * Install as a network interceptor. It blocks caller provider credentials
     * before gateway dispatch and Latchway credentials on cross-origin redirects.
     */
    @Deprecated(
        message = "Manual hook assembly can omit required hooks; use buildOkHttpClient()",
    )
    public fun originGuard(): Interceptor = okHttpHooks.originGuard()

    @Deprecated(
        message = "Manual hook assembly can omit required origin protection; use buildOkHttpClient()",
    )
    public fun authenticator(): Authenticator = okHttpHooks.authenticator()

    public suspend fun authorize(request: Request, feature: String): Request =
        okHttpHooks.authorize(null, request, feature, nonce = null)

    /** Creates exactly one replacement proof for a validated server DPoP nonce challenge. */
    public suspend fun authorize(request: Request, feature: String, nonce: String): Request =
        okHttpHooks.authorize(null, request, feature, nonce)

    /** Authorizes an OkHttp request with an independently keyed native component session. */
    public suspend fun authorize(
        component: LatchwayComponentClient,
        request: Request,
        feature: String,
        nonce: String? = null,
    ): Request = okHttpHooks.authorize(component, request, feature, nonce)

    public suspend fun quota(feature: String): LatchwayQuotaSnapshot = core.quota(feature)

    public suspend fun revokeCurrentInstallation(): Unit = core.revokeCurrentInstallation()

    public suspend fun provisionComponent(
        definitionId: String,
        requestedFeatures: Set<String>,
    ): LatchwayComponentClient = ComponentProvisioningLocks.withLock(
        "${storageNamespace(configuration)}:$definitionId",
    ) {
        validateComponentDefinition(definitionId)
        require(requestedFeatures.isNotEmpty() && requestedFeatures.size <= 256) {
            "requestedFeatures must contain between 1 and 256 unique features"
        }
        requestedFeatures.forEach(::validateFeature)
        val storage = componentStorage(configuration, definitionId)
        val signer = AndroidKeystoreInstallationSigner.create(
            context = applicationContext,
            alias = storage.keyAlias,
            policy = configuration.keyPolicy,
        )
        val stateStore = AndroidEncryptedComponentSessionStateStore(applicationContext, storage.stateNamespace)
        val component = try {
            core.provisionComponent(definitionId, requestedFeatures, signer, stateStore)
        } catch (error: Exception) {
            retireUnregisteredComponent(stateStore, signer)
            throw error
        }
        val componentId = try {
            requireNotNull(component.diagnostics().componentId)
        } catch (error: Exception) {
            runCatching { component.revoke() }
            retireUnregisteredComponent(stateStore, signer)
            throw error
        }
        try {
            registerComponent(definitionId, componentId, storage, signer)
        } catch (error: Exception) {
            // Never leave an independently keyed session untracked: family
            // retirement relies only on this safe, non-secret registry.
            runCatching { component.revoke() }
            retireUnregisteredComponent(stateStore, signer)
            throw LatchwayException(
                code = LatchwayErrorCode.SECURE_STATE_UNAVAILABLE,
                safeMessage = "The native component registry could not be persisted",
                cause = error,
            )
        }
        component
    }

    public suspend fun openComponent(definitionId: String): LatchwayComponentClient =
        ComponentProvisioningLocks.withLock("${storageNamespace(configuration)}:$definitionId") {
            validateComponentDefinition(definitionId)
            val storage = componentStorage(configuration, definitionId)
            val signer = AndroidKeystoreInstallationSigner.create(
                context = applicationContext,
                alias = storage.keyAlias,
                policy = configuration.keyPolicy,
            )
            val stateStore = AndroidEncryptedComponentSessionStateStore(
                applicationContext,
                storage.stateNamespace,
            )
            val component = try {
                core.openComponent(
                    definitionId = definitionId,
                    signer = signer,
                    stateStore = stateStore,
                )
            } catch (error: LatchwayException) {
                if (error.code == LatchwayErrorCode.COMPONENT_NOT_PROVISIONED ||
                    error.code == LatchwayErrorCode.COMPONENT_KEY_REPLACED
                ) {
                    retireUnregisteredComponent(stateStore, signer)
                }
                throw error
            }
            val componentId = requireNotNull(component.diagnostics().componentId)
            try {
                registerComponent(definitionId, componentId, storage, signer)
            } catch (error: Exception) {
                retireUnregisteredComponent(stateStore, signer)
                throw LatchwayException(
                    code = LatchwayErrorCode.SECURE_STATE_UNAVAILABLE,
                    safeMessage = "The native component registry could not be persisted",
                    cause = error,
                )
            }
            component
        }

    public suspend fun revokeComponent(componentId: String) {
        val registry = ComponentRegistry(applicationContext, storageNamespace(configuration))
        try {
            core.revokeComponent(componentId)
        } catch (error: LatchwayException) {
            if (error.code in COMPONENT_REVOKE_TERMINAL_CODES) {
                withContext(NonCancellable) { registry.retire(componentId, applicationContext) }
            }
            throw error
        }
        withContext(NonCancellable) { registry.retire(componentId, applicationContext) }
    }

    public suspend fun revokeCurrentInstallationFamily() {
        try {
            core.revokeCurrentInstallationFamily()
        } finally {
            // Family revocation is an explicit destructive request. Clear
            // descendant native material even when transport outcome or root
            // key cleanup is indeterminate; the root can re-provision a child
            // only if the server family remained active.
            withContext(NonCancellable) {
                ComponentRegistry(applicationContext, storageNamespace(configuration)).retireAll(applicationContext)
            }
        }
    }

    public suspend fun diagnostics(): LatchwayDiagnostics = core.diagnostics()

    public suspend fun refresh(): Unit = core.refresh()

    public suspend fun clearSession(): Unit = core.clearSession()

    override fun close() {
        if (coreDelegate.isInitialized()) core.close()
        controlClient.dispatcher.cancelAll()
        controlClient.connectionPool.evictAll()
        controlClient.dispatcher.executorService.shutdown()
    }

    private fun applyTrustedTerminalResponse(
        response: Response,
        component: LatchwayComponentClient?,
    ) {
        if (!isGatewayOrigin(response.request.url)) return
        val code = response.problemCode() ?: return
        if (code in ROOT_TERMINAL_PROBLEM_CODES) {
            runCatching {
                runBlocking {
                    withContext(NonCancellable) {
                        try {
                            core.markCurrentInstallationRevoked()
                        } finally {
                            ComponentRegistry(applicationContext, storageNamespace(configuration))
                                .retireAll(applicationContext)
                        }
                    }
                }
            }
        } else if (component != null && code in COMPONENT_RESPONSE_TERMINAL_CODES) {
            runCatching { runBlocking { component.markTerminal(code) } }
        }
    }

    private suspend fun createCore(): LatchwayCoreClient {
        val namespace = storageNamespace(configuration)
        val signer = AndroidKeystoreInstallationSigner.create(
            context = applicationContext,
            alias = "dev.latchway.installation.$namespace.dpop.v1",
            policy = configuration.keyPolicy,
        )
        return LatchwayCoreClient.create(
            configuration = CoreConfiguration(
                baseUrl = configuration.baseUrl.toUri(),
                applicationId = configuration.applicationId,
                environment = configuration.environment,
                identityProvider = configuration.identityProvider,
                clientPlatform = configuration.clientPlatform,
                sdkVersion = configuration.sdkVersion,
                framework = configuration.framework,
                allowInsecureLoopback = configuration.allowInsecureLoopback,
            ),
            identityTokenProvider = identityTokenProvider,
            attestationProvider = attestationProvider,
            signer = signer,
            stateStore = AndroidEncryptedSessionStateStore(applicationContext, namespace),
            transport = OkHttpLatchwayTransport(controlClient),
            installationMetadata = applicationContext.installationMetadata(),
        )
    }

    private fun isGatewayOrigin(url: HttpUrl): Boolean =
        url.scheme == configuration.baseUrl.scheme &&
            url.host == configuration.baseUrl.host &&
            url.port == configuration.baseUrl.port

    private suspend fun registerComponent(
        definitionId: String,
        componentId: String,
        storage: ComponentStorage,
        signer: AndroidKeystoreInstallationSigner,
    ) {
        ComponentRegistry(applicationContext, storageNamespace(configuration)).register(
            RegisteredComponent(
                definitionId = definitionId,
                componentId = componentId,
                keyAlias = storage.keyAlias,
                stateNamespace = storage.stateNamespace,
                keyThumbprint = signer.publicJwk.thumbprint(),
            ),
        )
    }

    private suspend fun retireUnregisteredComponent(
        stateStore: AndroidEncryptedComponentSessionStateStore,
        signer: AndroidKeystoreInstallationSigner,
    ): Unit = withContext(NonCancellable) {
        try {
            stateStore.destroy()
        } finally {
            signer.reset()
        }
    }
}

internal object LatchwayAndroidRuntime {
    @Volatile private var contextReference = WeakReference<Context>(null)

    fun install(context: Context) {
        contextReference = WeakReference(context.applicationContext)
    }

    fun requireContext(): Context = contextReference.get() ?: throw IllegalStateException(
        "Latchway Android context provider has not initialized",
    )
}

public class LatchwayContextProvider : ContentProvider() {
    override fun onCreate(): Boolean {
        context?.let(LatchwayAndroidRuntime::install)
        return true
    }

    override fun query(
        uri: Uri,
        projection: Array<out String>?,
        selection: String?,
        selectionArgs: Array<out String>?,
        sortOrder: String?,
    ): Cursor? = throw UnsupportedOperationException("LatchwayContextProvider does not expose data")

    override fun getType(uri: Uri): String? = null
    override fun insert(uri: Uri, values: ContentValues?): Uri? =
        throw UnsupportedOperationException("LatchwayContextProvider does not expose data")
    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<out String>?): Int =
        throw UnsupportedOperationException("LatchwayContextProvider does not expose data")
    override fun update(uri: Uri, values: ContentValues?, selection: String?, selectionArgs: Array<out String>?): Int =
        throw UnsupportedOperationException("LatchwayContextProvider does not expose data")
}

/**
 * Preserve explicit TLS/DNS/time-out choices while enforcing a separate execution pool and removing
 * application hooks that could recurse into Latchway or observe control-plane credentials.
 */
internal fun isolatedControlClient(template: OkHttpClient): OkHttpClient {
    val builder = template.newBuilder()
    builder.interceptors().clear()
    builder.networkInterceptors().clear()
    return builder
        .dispatcher(Dispatcher())
        .connectionPool(ConnectionPool())
        .authenticator(Authenticator.NONE)
        .proxyAuthenticator(Authenticator.NONE)
        .cookieJar(CookieJar.NO_COOKIES)
        .followRedirects(false)
        .followSslRedirects(false)
        .build()
}

private fun Context.installationMetadata(): InstallationMetadata {
    val packageInfo = if (Build.VERSION.SDK_INT >= 33) {
        packageManager.getPackageInfo(packageName, PackageManager.PackageInfoFlags.of(0))
    } else {
        @Suppress("DEPRECATION")
        packageManager.getPackageInfo(packageName, 0)
    }
    return InstallationMetadata(
        appVersion = packageInfo.versionName?.takeIf { it.isNotBlank() }
            ?: packageInfo.compatibleVersionCode().toString(),
        osVersion = Build.VERSION.RELEASE,
        deviceModel = listOf(Build.MANUFACTURER, Build.MODEL).filter { it.isNotBlank() }.joinToString(" ").take(128),
    )
}

private fun PackageInfo.compatibleVersionCode(): Long = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
    longVersionCode
} else {
    @Suppress("DEPRECATION")
    versionCode.toLong()
}

internal fun storageNamespace(configuration: LatchwayConfiguration): String {
    val input = "${configuration.baseUrl.scheme}://${configuration.baseUrl.host}:${configuration.baseUrl.port}" +
        configuration.baseUrl.encodedPath +
        "${configuration.applicationId}/${configuration.environment}/${configuration.identityProvider}"
    val platformInput = "$input/${configuration.clientPlatform.wireValue}"
    return Base64Url.encode(
        MessageDigest.getInstance("SHA-256").digest(platformInput.toByteArray(StandardCharsets.UTF_8)),
    )
        .take(32)
}

private data class ComponentStorage(
    val keyAlias: String,
    val stateNamespace: String,
)

private object ComponentProvisioningLocks {
    private val locks = ConcurrentHashMap<String, Mutex>()

    suspend fun <T> withLock(key: String, operation: suspend () -> T): T {
        val mutex = locks[key] ?: Mutex().let { locks.putIfAbsent(key, it) ?: it }
        return mutex.withLock { operation() }
    }
}

private object ComponentRegistryLocks {
    private val locks = ConcurrentHashMap<String, Mutex>()

    suspend fun <T> withLock(key: String, operation: suspend () -> T): T {
        val mutex = locks[key] ?: Mutex().let { locks.putIfAbsent(key, it) ?: it }
        return mutex.withLock { operation() }
    }
}

private fun componentStorage(
    configuration: LatchwayConfiguration,
    definitionId: String,
): ComponentStorage {
    val digest = MessageDigest.getInstance("SHA-256").digest(
        "${storageNamespace(configuration)}/$definitionId".toByteArray(StandardCharsets.UTF_8),
    )
    val identifier = Base64Url.encode(digest).take(32)
    return ComponentStorage(
        keyAlias = "dev.latchway.component.$identifier.dpop.v1",
        stateNamespace = "c.$identifier",
    )
}

private fun validateComponentDefinition(definitionId: String) {
    require(Regex("^[a-z][a-z0-9_-]{0,62}$").matches(definitionId)) {
        "definitionId is not a canonical identifier"
    }
}

internal fun isAllowedDataPlaneRequest(
    gatewayBaseUrl: HttpUrl,
    request: Request,
    feature: String,
): Boolean {
    if (!request.url.hasSameOrigin(gatewayBaseUrl)) return false
    if (request.url.username.isNotEmpty() || request.url.password.isNotEmpty() || request.url.fragment != null) {
        return false
    }
    val basePath = gatewayBaseUrl.encodedPath
    if (!basePath.endsWith('/') || !request.url.encodedPath.startsWith(basePath)) return false
    val relativePath = "/" + request.url.encodedPath.removePrefix(basePath)
    if (relativePath in STANDARD_DATA_PLANE_PATHS) {
        return request.method == "POST"
    }
    if (request.method !in OPAQUE_DATA_PLANE_METHODS) return false
    if (request.url.query != null) return false
    val prefix = "/proxy/$feature/"
    if (!relativePath.startsWith(prefix)) return false
    val remaining = relativePath.removePrefix(prefix)
    val lowerRemaining = remaining.lowercase(Locale.US)
    return remaining.length in 1..2_048 &&
        remaining.split('/').all { it.isNotEmpty() && it != "." && it != ".." } &&
        "%2e" !in lowerRemaining && "%2f" !in lowerRemaining && "%5c" !in lowerRemaining &&
        '\\' !in remaining &&
        !remaining.startsWith("http:", ignoreCase = true) &&
        !remaining.startsWith("https:", ignoreCase = true)
}

private val STANDARD_DATA_PLANE_PATHS = setOf(
    "/v1/responses",
    "/v1/chat/completions",
    "/v1/embeddings",
    "/v1/messages",
)

private val OPAQUE_DATA_PLANE_METHODS = setOf("GET", "POST", "PUT", "PATCH", "DELETE")

private data class RegisteredComponent(
    val definitionId: String,
    val componentId: String,
    val keyAlias: String,
    val stateNamespace: String,
    val keyThumbprint: String,
) {
    fun encode(): String = listOf(
        definitionId,
        componentId,
        keyAlias,
        stateNamespace,
        keyThumbprint,
    ).joinToString("|")

    companion object {
        fun decode(value: String): RegisteredComponent? {
            val fields = value.split('|')
            if (fields.size != 5) return null
            return runCatching {
                validateComponentDefinition(fields[0])
                require(Regex("^cmp_[A-Za-z0-9_-]{16,128}$").matches(fields[1]))
                require(Regex("^[A-Za-z0-9._-]{1,128}$").matches(fields[2]))
                require(Regex("^[A-Za-z0-9._-]{1,80}$").matches(fields[3]))
                require(Base64Url.decode(fields[4]).size == 32)
                RegisteredComponent(fields[0], fields[1], fields[2], fields[3], fields[4])
            }.getOrNull()
        }
    }
}

/** Stores only safe component/key references; credentials remain AES-GCM encrypted. */
private class ComponentRegistry(
    context: Context,
    private val namespace: String,
) {
    private val preferences = context.applicationContext.getSharedPreferences(
        "dev.latchway.component-registry.$namespace",
        Context.MODE_PRIVATE,
    )

    suspend fun register(component: RegisteredComponent) = ComponentRegistryLocks.withLock(namespace) {
        val current = entries().associateBy { it.componentId }.toMutableMap()
        current.entries.removeAll { it.value.definitionId == component.definitionId }
        current[component.componentId] = component
        check(preferences.edit().putStringSet(ENTRIES, current.values.mapTo(HashSet()) { it.encode() }).commit()) {
            "Component registry could not be persisted"
        }
    }

    suspend fun retire(componentId: String, context: Context): Unit =
        ComponentRegistryLocks.withLock(namespace) {
            val current = entries().associateBy { it.componentId }.toMutableMap()
            val component = current[componentId] ?: return@withLock
            // Keep the safe reference durable until both native secret stores
            // have been retired; a transient Keystore failure stays retryable.
            retire(component, context)
            current.remove(componentId)
            persist(current.values)
        }

    suspend fun retireAll(context: Context): Unit = ComponentRegistryLocks.withLock(namespace) {
        val remaining = entries().associateBy { it.componentId }.toMutableMap()
        var firstFailure: Exception? = null
        remaining.values.toList().forEach { component ->
            try {
                retire(component, context)
                remaining.remove(component.componentId)
            } catch (error: Exception) {
                firstFailure = firstFailure ?: error
            }
        }
        persist(remaining.values)
        firstFailure?.let { throw it }
    }

    private fun entries(): List<RegisteredComponent> =
        preferences.getStringSet(ENTRIES, emptySet()).orEmpty().mapNotNull(RegisteredComponent::decode)

    private suspend fun retire(component: RegisteredComponent, context: Context) {
        try {
            AndroidEncryptedComponentSessionStateStore(context, component.stateNamespace).destroy()
        } finally {
            AndroidKeystoreInstallationSigner.destroy(component.keyAlias, component.keyThumbprint)
        }
    }

    private fun persist(components: Collection<RegisteredComponent>) {
        check(preferences.edit().putStringSet(ENTRIES, components.mapTo(HashSet()) { it.encode() }).commit()) {
            "Component registry could not be persisted"
        }
    }

    private companion object {
        const val ENTRIES = "components.v1"
    }
}

private val COMPONENT_REVOKE_TERMINAL_CODES = setOf(
    LatchwayErrorCode.COMPONENT_REVOKED,
    LatchwayErrorCode.COMPONENT_KEY_INVALID,
    LatchwayErrorCode.COMPONENT_KEY_REPLACED,
    LatchwayErrorCode.INSTALLATION_FAMILY_REVOKED,
    LatchwayErrorCode.INSTALLATION_FAMILY_NOT_FOUND,
)

internal fun validateFeature(feature: String) {
    require(Regex("^[a-z][a-z0-9_-]{0,62}$").matches(feature)) { "feature is not a canonical identifier" }
}

internal fun responseCount(response: Response): Int {
    var count = 1
    var previous = response.priorResponse
    while (previous != null) {
        count++
        previous = previous.priorResponse
    }
    return count
}

internal class LatchwayNetworkAttemptBudget(val requestId: String) {
    private val claimed = AtomicBoolean(false)
    fun claim(): Boolean = claimed.compareAndSet(false, true)
}

internal data class LatchwayRetryNonce(val value: String) {
    init { require(isValidNonce(value)) { "DPoP retry nonce is invalid" } }
}

internal fun Request.Builder.latchwayRetryNonce(nonce: String?): Request.Builder =
    tag(LatchwayRetryNonce::class.java, nonce?.let(::LatchwayRetryNonce))

internal fun Request.latchwayRetryNonce(): String? =
    tag(LatchwayRetryNonce::class.java)?.value

internal fun claimNetworkAttempt(request: Request) {
    val budget = request.tag(LatchwayNetworkAttemptBudget::class.java) ?: throw LatchwayException(
        code = LatchwayErrorCode.CONFIGURATION_INVALID,
        safeMessage = "Install the Latchway application interceptor before the network interceptor",
    )
    if (!budget.claim()) {
        throw LatchwayException(
            code = LatchwayErrorCode.TRANSPORT_REQUEST_NOT_REPLAYABLE,
            safeMessage = "The request may already have reached the upstream and cannot be replayed automatically",
        )
    }
}

@Suppress("UNNECESSARY_SAFE_CALL") // Response.body is nullable in supported OkHttp 4.x.
internal fun Response.problemCode(): LatchwayErrorCode? = try {
    if ((code != 401 && code != 403) || body?.contentType()?.let {
            it.type != "application" || it.subtype != "problem+json"
        } != false
    ) {
        null
    } else {
        val responseRequestId = header("X-Latchway-Request-ID")?.takeIf(::isValidRequestId)
        if (responseRequestId == null) {
            null
        } else {
            val problem = JSONObject(peekBody(64 * 1024).string())
            val problemStatus = problem.get("status")
            val rawCode = problem.get("code") as? String
            val requestId = problem.get("request_id") as? String
            val type = problem.get("type") as? String
            val documentationUrl = problem.get("documentation_url") as? String
            val title = problem.get("title") as? String
            val detail = problem.get("detail") as? String
            val retryable = problem.get("retryable") as? Boolean
            if (problemStatus !is Number || problemStatus.toDouble() != code.toDouble() ||
                requestId != responseRequestId || rawCode == null || title.isNullOrBlank() ||
                detail.isNullOrBlank() || retryable == null
            ) {
                null
            } else {
                val problemCode = LatchwayErrorCode.fromWire(rawCode).takeIf { it.wireValue == rawCode }
                val canonicalDocumentationUrl = problemCode?.documentationUrl?.toASCIIString()
                if (type != canonicalDocumentationUrl || documentationUrl != canonicalDocumentationUrl) {
                    null
                } else when (code) {
                    401 -> problemCode?.takeIf {
                        (it in AUTHENTICATOR_PROBLEM_CODES && retryable == it.canonicalRetryability()) ||
                            (it in COMPONENT_RESPONSE_TERMINAL_CODES && !retryable)
                    }
                    403 -> problemCode?.takeIf {
                        (it in ROOT_TERMINAL_PROBLEM_CODES || it in COMPONENT_RESPONSE_TERMINAL_CODES) &&
                            !retryable
                    }
                    else -> null
                }
            }
        }
    }
} catch (_: Exception) {
    null
}

internal fun observeInstallationRevocation(
    response: Response,
    trustedOrigin: (HttpUrl) -> Boolean,
    markRevoked: () -> Unit,
) {
    if (trustedOrigin(response.request.url) &&
        response.problemCode() in ROOT_TERMINAL_PROBLEM_CODES
    ) {
        markRevoked()
    }
}

internal fun gatewayOriginGuard(gatewayOrigin: HttpUrl): Interceptor = Interceptor { chain ->
    val request = chain.request()
    val isGatewayOrigin = request.url.hasSameOrigin(gatewayOrigin)
    if (!isGatewayOrigin &&
        (request.hasLatchwayCredentials() || request.tag(AuthorizedHeaders::class.java) != null)
    ) {
        throw LatchwayException(
            code = LatchwayErrorCode.TRANSPORT_DESTINATION_NOT_ALLOWED,
            safeMessage = "Latchway credentials cannot follow a redirect to another origin",
        )
    }
    if (isGatewayOrigin) {
        rejectUpstreamCredentials(request, authorizationWillBeReplaced = false)
    }
    chain.proceed(request)
}

internal val FORBIDDEN_CALLER_CREDENTIAL_NAMES: Set<String> = setOf(
    "authorization",
    "proxy-authorization",
    "api-key",
    "api_key",
    "apikey",
    "x-api-key",
    "openai-api-key",
    "openai_api_key",
    "x-openai-api-key",
    "anthropic-api-key",
    "anthropic_api_key",
    "x-goog-api-key",
    "x-goog-api_key",
    "access_token",
    "token",
    "key",
)

internal fun rejectUpstreamCredentials(
    request: Request,
    authorizationWillBeReplaced: Boolean,
) {
    val hasForbiddenHeader = request.headers.names().any { name ->
        val normalized = name.lowercase(Locale.US)
        if (normalized == "cookie") {
            true
        } else if (normalized !in FORBIDDEN_CALLER_CREDENTIAL_NAMES) {
            false
        } else if (normalized == "authorization") {
            !authorizationWillBeReplaced && !request.hasLatchwayAuthorization()
        } else {
            true
        }
    }
    if (hasForbiddenHeader) throw upstreamCredentialError()

    if (request.url.queryParameterNames.any {
            it.lowercase(Locale.US) in FORBIDDEN_CALLER_CREDENTIAL_NAMES
        }
    ) {
        throw upstreamCredentialError()
    }
}

private fun Request.hasLatchwayAuthorization(): Boolean {
    val values = headers.values("Authorization")
    if (values.size != 1) return false
    val value = values.single()
    val authorized = tag(AuthorizedHeaders::class.java)
    return if (authorized != null) {
        value == authorized.authorizationHeader()
    } else {
        value.startsWith("DPoP ") && value.length > 5
    }
}

private fun upstreamCredentialError(): LatchwayException = LatchwayException(
    code = LatchwayErrorCode.REQUEST_INVALID,
    safeMessage = "Upstream provider credentials must not be supplied to Latchway",
)

internal fun Request.hasLatchwayCredentials(): Boolean =
    header("DPoP") != null || header("Authorization")?.startsWith("DPoP ") == true ||
        headers.names().any { it.startsWith("X-Latchway-", ignoreCase = true) }

private fun HttpUrl.hasSameOrigin(other: HttpUrl): Boolean =
    scheme == other.scheme && host == other.host && port == other.port

internal fun isValidNonce(value: String): Boolean =
    value.length in 16..512 && value.none { it.isISOControl() }

private fun isValidRequestId(value: String): Boolean =
    value.length in 8..128 && Regex("^[A-Za-z0-9][A-Za-z0-9._:-]*$").matches(value)

private val AUTHENTICATOR_PROBLEM_CODES: Set<LatchwayErrorCode> = setOf(
    LatchwayErrorCode.DPOP_NONCE_REQUIRED,
    LatchwayErrorCode.SESSION_EXPIRED,
    LatchwayErrorCode.SESSION_REVOKED,
    LatchwayErrorCode.REFRESH_TOKEN_REUSED,
)

private val ROOT_TERMINAL_PROBLEM_CODES: Set<LatchwayErrorCode> = setOf(
    LatchwayErrorCode.INSTALLATION_REVOKED,
    LatchwayErrorCode.INSTALLATION_FAMILY_REVOKED,
)

private val COMPONENT_RESPONSE_TERMINAL_CODES: Set<LatchwayErrorCode> = setOf(
    LatchwayErrorCode.COMPONENT_REVOKED,
    LatchwayErrorCode.COMPONENT_KEY_INVALID,
    LatchwayErrorCode.COMPONENT_KEY_REPLACED,
)

private fun LatchwayErrorCode.canonicalRetryability(): Boolean = when (this) {
    LatchwayErrorCode.DPOP_NONCE_REQUIRED,
    LatchwayErrorCode.SESSION_EXPIRED -> true
    else -> false
}

internal enum class AuthenticationAction { NONE, NONCE, REFRESH, CLEAR }

internal data class AuthenticationDecision(
    val action: AuthenticationAction,
    val nonce: String? = null,
)

internal fun authenticationDecision(response: Response): AuthenticationDecision {
    if (responseCount(response) > 1) return AuthenticationDecision(AuthenticationAction.NONE)
    val body = response.request.body
    if (body != null && (body.isOneShot() || body.isDuplex())) {
        return AuthenticationDecision(AuthenticationAction.NONE)
    }
    return when (response.problemCode()) {
        LatchwayErrorCode.DPOP_NONCE_REQUIRED -> {
            val nonce = response.header("DPoP-Nonce")?.takeIf(::isValidNonce)
                ?: return AuthenticationDecision(AuthenticationAction.NONE)
            AuthenticationDecision(AuthenticationAction.NONCE, nonce)
        }
        LatchwayErrorCode.SESSION_EXPIRED -> AuthenticationDecision(AuthenticationAction.REFRESH)
        LatchwayErrorCode.SESSION_REVOKED,
        LatchwayErrorCode.REFRESH_TOKEN_REUSED -> AuthenticationDecision(AuthenticationAction.CLEAR)
        else -> AuthenticationDecision(AuthenticationAction.NONE)
    }
}
