plugins {
    alias(libs.plugins.android.library)
}

android {
    namespace = "dev.latchway.okhttp"
    compileSdk = 37
    defaultConfig { minSdk = 23 }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

dependencies {
    api(project(":latchway-core"))
    api(libs.okhttp)
    implementation(libs.coroutines.core)
    testImplementation(libs.junit)
    testImplementation(libs.json)
    testImplementation(libs.okhttp.mockwebserver)
    testImplementation(libs.coroutines.core)
}
