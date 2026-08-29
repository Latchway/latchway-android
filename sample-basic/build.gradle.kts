plugins {
    alias(libs.plugins.android.application)
}

android {
    namespace = "dev.latchway.sample.basic"
    compileSdk = 37
    defaultConfig {
        applicationId = "dev.latchway.sample.basic"
        minSdk = 23
        targetSdk = 37
        versionCode = 1
        versionName = "1.0.0"
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

dependencies {
    implementation(project(":latchway-okhttp"))
    implementation(project(":latchway-play-integrity"))
}
