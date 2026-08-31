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
val retrofitCompatibilityVersion = providers.gradleProperty("latchway.retrofit.version").orNull
val openAiKotlinCompatibilityVersion = providers.gradleProperty("latchway.openaiKotlin.version").orNull
val langChain4jCompatibilityVersion = providers.gradleProperty("latchway.langchain4j.version").orNull
val langChain4jOkHttpCompatibilityVersion = providers.gradleProperty("latchway.langchain4jOkHttp.version").orNull
val selectedOkHttpVersion = okhttpCompatibilityVersion ?: libs.versions.okhttp.get()

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
    testImplementation(project(":test-support"))
    // Third-party fixtures must not silently upgrade the adapter runtime and
    // turn the OkHttp compatibility gate into a false positive.
    testImplementation("com.squareup.okhttp3:okhttp:$selectedOkHttpVersion") {
        version { strictly(selectedOkHttpVersion) }
    }
    if (retrofitCompatibilityVersion == null) {
        testImplementation(libs.retrofit) {
            exclude(group = "com.squareup.okhttp3", module = "okhttp")
        }
    } else {
        testImplementation("com.squareup.retrofit2:retrofit:$retrofitCompatibilityVersion") {
            exclude(group = "com.squareup.okhttp3", module = "okhttp")
        }
    }
    testImplementation(
        if (openAiKotlinCompatibilityVersion == null) libs.openai.kotlin
        else "com.aallam.openai:openai-client:$openAiKotlinCompatibilityVersion",
    )
    testImplementation(libs.ktor.client.okhttp) {
        exclude(group = "com.squareup.okhttp3", module = "okhttp")
    }
    testImplementation(
        if (langChain4jCompatibilityVersion == null) libs.langchain4j.open.ai
        else "dev.langchain4j:langchain4j-open-ai:$langChain4jCompatibilityVersion",
    )
    if (langChain4jOkHttpCompatibilityVersion == null) {
        testImplementation(libs.langchain4j.http.client.okhttp) {
            exclude(group = "com.squareup.okhttp3", module = "okhttp")
            exclude(group = "com.squareup.okhttp3", module = "okhttp-jvm")
        }
    } else {
        testImplementation(
            "dev.langchain4j:langchain4j-http-client-okhttp:$langChain4jOkHttpCompatibilityVersion",
        ) {
            exclude(group = "com.squareup.okhttp3", module = "okhttp")
            exclude(group = "com.squareup.okhttp3", module = "okhttp-jvm")
        }
    }
}
