plugins {
    id("com.android.library") version "9.3.2"
}

val latchwayVersion = providers.gradleProperty("latchway.version").orNull
    ?: throw GradleException("latchway.version must identify the publication under test")

android {
    namespace = "dev.latchway.publicationsmoke"
    compileSdk = 37

    defaultConfig {
        minSdk = 23
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

dependencies {
    implementation(platform("dev.latchway:latchway-bom:$latchwayVersion"))
    implementation("dev.latchway:latchway-core")
    implementation("dev.latchway:latchway-okhttp")
    implementation("dev.latchway:latchway-play-integrity")
    implementation("dev.latchway:latchway-firebase-auth")
}

val expectedModules = setOf(
    "latchway-bom",
    "latchway-core",
    "latchway-okhttp",
    "latchway-play-integrity",
    "latchway-firebase-auth",
)

val verifyResolvedLatchwayArtifacts = tasks.register("verifyResolvedLatchwayArtifacts") {
    group = "verification"
    description = "Proves that an independent consumer resolves the BOM and every public module."
    inputs.property("latchwayVersion", latchwayVersion)
    doLast {
        val classpath = configurations.getByName("releaseCompileClasspath")
        val resolved = classpath
            .incoming
            .resolutionResult
            .allComponents
            .mapNotNull { it.moduleVersion }
            .filter { it.group == "dev.latchway" }
            .associate { it.name to it.version }
        check(resolved.keys == expectedModules) {
            "Expected only $expectedModules, but resolved $resolved"
        }
        resolved.forEach { (module, version) ->
            check(version == latchwayVersion) {
                "$module resolved at $version instead of $latchwayVersion"
            }
        }
        check(classpath.files.isNotEmpty()) {
            "The published consumer compile classpath is empty"
        }
    }
}

tasks.named("assemble") {
    dependsOn(verifyResolvedLatchwayArtifacts)
}
