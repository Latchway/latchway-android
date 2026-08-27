plugins {
    alias(libs.plugins.android.library)
}

android {
    namespace = "dev.latchway.testsupport"
    compileSdk = 37
    defaultConfig { minSdk = 23 }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

dependencies {
    api(project(":latchway-core"))
    implementation(libs.coroutines.core)
    testImplementation(libs.junit)
}
