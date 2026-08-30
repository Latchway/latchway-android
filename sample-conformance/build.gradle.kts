plugins {
    alias(libs.plugins.android.application)
}

val playCandidateEnabled = providers.gradleProperty("latchway.playCandidate")
    .map(String::toBooleanStrict)
    .orElse(false)
    .get()
val playSigningMode = providers.gradleProperty("latchway.playSigningMode")
    .orElse("unsigned")
    .get()
require(playSigningMode == "unsigned") {
    "repository candidate builds must be unsigned; sign only on the isolated no-checkout signer"
}

android {
    namespace = "dev.latchway.sample.conformance"
    compileSdk = 37
    defaultConfig {
        applicationId = providers.gradleProperty("latchway.packageName")
            .orElse("dev.latchway.sample.conformance").get()
        minSdk = 23
        targetSdk = 37
        versionCode = providers.gradleProperty("latchway.versionCode").orElse("1").get().toInt()
        versionName = providers.gradleProperty("latchway.versionName").orElse("1.0.0").get()
        manifestPlaceholders["latchwayGatewayUrl"] = providers.gradleProperty("latchway.gatewayUrl").orElse("").get()
        manifestPlaceholders["latchwayApplicationId"] = providers.gradleProperty("latchway.applicationId").orElse("").get()
        manifestPlaceholders["latchwayEnvironment"] = providers.gradleProperty("latchway.environment").orElse("").get()
        manifestPlaceholders["latchwayIdentityProvider"] = providers.gradleProperty("latchway.identityProvider").orElse("").get()
        manifestPlaceholders["latchwayFeature"] = providers.gradleProperty("latchway.feature").orElse("").get()
        manifestPlaceholders["latchwayErrorMappingFeature"] = providers.gradleProperty("latchway.errorMappingFeature").orElse("").get()
        manifestPlaceholders["latchwayModel"] = providers.gradleProperty("latchway.model").orElse("").get()
        manifestPlaceholders["latchwayCloudProjectNumber"] = providers.gradleProperty("latchway.cloudProjectNumber").orElse("0").get()
        manifestPlaceholders["latchwayPlayTrack"] = providers.gradleProperty("latchway.playTrack").orElse("").get()
        manifestPlaceholders["latchwaySourceCommit"] = providers.gradleProperty("latchway.sourceCommit").orElse("").get()
        manifestPlaceholders["latchwayCoreCommit"] = providers.gradleProperty("latchway.coreCommit").orElse("").get()
        manifestPlaceholders["latchwayContractBundleSha256"] = providers.gradleProperty("latchway.contractBundleSha256").orElse("").get()
        manifestPlaceholders["latchwayGatewayImageDigest"] = providers.gradleProperty("latchway.gatewayImageDigest").orElse("").get()
        manifestPlaceholders["latchwayGatewayConfigurationSha256"] = providers.gradleProperty("latchway.gatewayConfigurationSha256").orElse("").get()
        manifestPlaceholders["latchwayGatewayOrigin"] = providers.gradleProperty("latchway.gatewayOrigin").orElse("").get()
        manifestPlaceholders["latchwayGatewayDeploymentKeyId"] = providers.gradleProperty("latchway.gatewayDeploymentKeyId").orElse("").get()
        manifestPlaceholders["latchwayGatewayDeploymentStatementSha256"] = providers.gradleProperty("latchway.gatewayDeploymentStatementSha256").orElse("").get()
        manifestPlaceholders["latchwayGatewayDeploymentPublicKeySha256"] = providers.gradleProperty("latchway.gatewayDeploymentPublicKeySha256").orElse("").get()
        manifestPlaceholders["latchwayExpectedPackage"] = applicationId.orEmpty()
        manifestPlaceholders["latchwayExpectedVersion"] = versionName.orEmpty()
        manifestPlaceholders["latchwayExpectedBuild"] = versionCode.toString()
        manifestPlaceholders["latchwayExpectedCertificateSha256"] = providers.gradleProperty("latchway.signingCertificateSha256").orElse("").get()
        manifestPlaceholders["latchwayRequireLicensed"] = providers.gradleProperty("latchway.requireLicensed").orElse("false").get()
    }
    buildTypes {
        getByName("release") {
            isDebuggable = false
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

if (playCandidateEnabled) {
    val requiredCandidateProperties = listOf(
        "latchway.packageName",
        "latchway.versionCode",
        "latchway.versionName",
        "latchway.gatewayUrl",
        "latchway.gatewayOrigin",
        "latchway.gatewayDeploymentKeyId",
        "latchway.gatewayDeploymentStatementSha256",
        "latchway.gatewayDeploymentPublicKeySha256",
        "latchway.gatewayConfigurationSha256",
        "latchway.gatewayImageDigest",
        "latchway.applicationId",
        "latchway.environment",
        "latchway.identityProvider",
        "latchway.feature",
        "latchway.errorMappingFeature",
        "latchway.model",
        "latchway.cloudProjectNumber",
        "latchway.playTrack",
        "latchway.sourceCommit",
        "latchway.coreCommit",
        "latchway.contractBundleSha256",
        "latchway.signingCertificateSha256",
        "latchway.requireLicensed",
    )
    requiredCandidateProperties.forEach { property ->
        require(!providers.gradleProperty(property).orNull.isNullOrBlank()) {
            "$property is required for a Play conformance candidate"
        }
    }
    require(providers.gradleProperty("latchway.requireLicensed").get() == "true") {
        "a Play conformance candidate must require licensed accounts"
    }
    val candidatePackage = providers.gradleProperty("latchway.packageName").get()
    require(Regex("^[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z][A-Za-z0-9_]*)+$").matches(candidatePackage) && candidatePackage.length <= 255) {
        "latchway.packageName must be a dotted Android application ID"
    }
    val candidateVersionCode = providers.gradleProperty("latchway.versionCode").get().toLongOrNull()
    require(candidateVersionCode != null && candidateVersionCode in 1..2_100_000_000) {
        "latchway.versionCode must be within the Google Play range"
    }
}

dependencies {
    implementation(project(":latchway-okhttp"))
    implementation(project(":latchway-play-integrity"))
    implementation(libs.coroutines.android)
    testImplementation(libs.junit)
}
