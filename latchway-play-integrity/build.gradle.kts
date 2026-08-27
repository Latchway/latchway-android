plugins {
    alias(libs.plugins.android.library)
}

android {
    namespace = "dev.latchway.playintegrity"
    compileSdk = 37
    defaultConfig { minSdk = 23 }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

dependencies {
    api(project(":latchway-core"))
    implementation(libs.play.integrity)
    implementation(libs.coroutines.core)
    implementation(libs.coroutines.play.services)
    testImplementation(libs.junit)
    testImplementation(libs.json)
    testImplementation(libs.coroutines.core)
}
