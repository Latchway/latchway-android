plugins {
    alias(libs.plugins.android.library)
    `maven-publish`
    signing
}

android {
    namespace = "dev.latchway.firebaseauth"
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

dependencies {
    api(project(":latchway-core"))
    api(platform(libs.firebase.bom))
    api(libs.firebase.auth)
    implementation(libs.coroutines.play.services)
    testImplementation(libs.junit)
    testImplementation(libs.coroutines.core)
}
