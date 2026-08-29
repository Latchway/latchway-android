plugins {
    alias(libs.plugins.android.application)
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
        versionName = providers.gradleProperty("latchway.versionName").orElse("0.1.0").get()
        manifestPlaceholders["latchwayGatewayUrl"] = providers.gradleProperty("latchway.gatewayUrl").orElse("").get()
        manifestPlaceholders["latchwayApplicationId"] = providers.gradleProperty("latchway.applicationId").orElse("").get()
        manifestPlaceholders["latchwayEnvironment"] = providers.gradleProperty("latchway.environment").orElse("").get()
        manifestPlaceholders["latchwayFeature"] = providers.gradleProperty("latchway.feature").orElse("").get()
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
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

dependencies {
    implementation(project(":latchway-okhttp"))
    implementation(project(":latchway-play-integrity"))
    implementation(project(":latchway-firebase-auth"))
    implementation(platform(libs.firebase.bom))
    implementation(libs.firebase.auth)
    implementation(libs.coroutines.android)
    testImplementation(libs.junit)
}
