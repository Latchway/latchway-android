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
        versionName = "0.1.0"
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
