plugins {
    alias(libs.plugins.android.application)
}

android {
    namespace = "dev.latchway.sample.firebase"
    compileSdk = 37
    defaultConfig {
        applicationId = "dev.latchway.sample.firebase"
        minSdk = 23
        targetSdk = 37
        versionCode = 1
        versionName = "1.0.0"
        manifestPlaceholders["latchwayGatewayUrl"] = providers.gradleProperty("latchway.gatewayUrl")
            .orElse("https://gateway.example.com/").get()
        manifestPlaceholders["latchwayApplicationId"] = providers.gradleProperty("latchway.applicationId")
            .orElse("app_01J00000000000000000000000").get()
        manifestPlaceholders["latchwayEnvironment"] = providers.gradleProperty("latchway.environment")
            .orElse("production").get()
        manifestPlaceholders["latchwayFeature"] = providers.gradleProperty("latchway.feature")
            .orElse("assistant-responses").get()
        manifestPlaceholders["latchwayModel"] = providers.gradleProperty("latchway.model")
            .orElse("assistant-default").get()
        manifestPlaceholders["latchwayCloudProjectNumber"] = providers.gradleProperty("latchway.cloudProjectNumber")
            .orElse("0").get()
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
