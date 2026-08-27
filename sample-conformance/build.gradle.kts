plugins {
    alias(libs.plugins.android.application)
}

android {
    namespace = "dev.latchway.sample.conformance"
    compileSdk = 37
    defaultConfig {
        applicationId = "dev.latchway.sample.conformance"
        minSdk = 23
        targetSdk = 37
        versionCode = 1
        versionName = "0.1.0"
        manifestPlaceholders["latchwayGatewayUrl"] = providers.gradleProperty("latchway.gatewayUrl").orElse("").get()
        manifestPlaceholders["latchwayApplicationId"] = providers.gradleProperty("latchway.applicationId").orElse("").get()
        manifestPlaceholders["latchwayEnvironment"] = providers.gradleProperty("latchway.environment").orElse("").get()
        manifestPlaceholders["latchwayFeature"] = providers.gradleProperty("latchway.feature").orElse("").get()
        manifestPlaceholders["latchwayCloudProjectNumber"] = providers.gradleProperty("latchway.cloudProjectNumber").orElse("0").get()
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
}
