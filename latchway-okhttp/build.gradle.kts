plugins {
    alias(libs.plugins.android.library)
    `maven-publish`
    signing
}

android {
    namespace = "dev.latchway.okhttp"
    compileSdk = 37
    defaultConfig { minSdk = 23 }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    publishing {
        singleVariant("release") {
            withSourcesJar()
            withJavadocJar()
        }
    }
}

val okhttpCompatibilityVersion = providers.gradleProperty("latchway.okhttp.version").orNull

dependencies {
    api(project(":latchway-core"))
    if (okhttpCompatibilityVersion == null) {
        api(libs.okhttp)
    } else {
        api("com.squareup.okhttp3:okhttp:$okhttpCompatibilityVersion")
    }
    implementation(libs.coroutines.core)
    testImplementation(libs.junit)
    testImplementation(libs.json)
    testImplementation(libs.coroutines.core)
}
