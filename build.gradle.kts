import org.gradle.api.GradleException
import org.gradle.api.artifacts.repositories.PasswordCredentials
import org.gradle.api.configuration.BuildFeatures
import org.gradle.api.publish.PublishingExtension
import org.gradle.api.publish.maven.MavenPublication
import org.gradle.api.publish.maven.tasks.PublishToMavenRepository
import org.gradle.api.tasks.bundling.AbstractArchiveTask
import org.gradle.api.tasks.Delete
import org.gradle.authentication.http.BasicAuthentication
import org.gradle.plugins.signing.Sign
import org.gradle.plugins.signing.SigningExtension
import javax.inject.Inject

buildscript {
    dependencies {
        // AGP 9 built-in Kotlin consumes this deliberately pinned KGP version.
        classpath("org.jetbrains.kotlin:kotlin-gradle-plugin:2.3.21")
    }
}

plugins {
    alias(libs.plugins.android.application) apply false
    alias(libs.plugins.android.library) apply false
}

data class PublishedModule(
    val path: String,
    val component: String,
    val displayName: String,
    val description: String,
)

abstract class InjectedBuildFeatures {
    @get:Inject
    abstract val buildFeatures: BuildFeatures
}

val publishedModules = listOf(
    PublishedModule(
        path = ":latchway-core",
        component = "release",
        displayName = "Latchway Android Core",
        description = "Device-bound Latchway sessions, DPoP, and Android Keystore security primitives.",
    ),
    PublishedModule(
        path = ":latchway-okhttp",
        component = "release",
        displayName = "Latchway Android OkHttp",
        description = "Origin-pinned and replay-safe OkHttp integration for the Latchway Android SDK.",
    ),
    PublishedModule(
        path = ":latchway-play-integrity",
        component = "release",
        displayName = "Latchway Android Play Integrity",
        description = "Google Play Integrity attestation integration for the Latchway Android SDK.",
    ),
    PublishedModule(
        path = ":latchway-firebase-auth",
        component = "release",
        displayName = "Latchway Android Firebase Authentication",
        description = "Optional Firebase Authentication identity adapter for the Latchway Android SDK.",
    ),
    PublishedModule(
        path = ":latchway-bom",
        component = "javaPlatform",
        displayName = "Latchway Android BOM",
        description = "A bill of materials that aligns every published Latchway Android module.",
    ),
)

val releaseVersion = providers.gradleProperty("latchway.version")
    .orElse(providers.environmentVariable("LATCHWAY_VERSION"))
    .orElse("1.0.0-SNAPSHOT")
    .get()
val semanticVersion = Regex("^[0-9]+\\.[0-9]+\\.[0-9]+(?:-[0-9A-Za-z][0-9A-Za-z.-]*)?$")
if (!semanticVersion.matches(releaseVersion)) {
    throw GradleException("latchway.version must be a semantic version")
}

allprojects {
    group = "dev.latchway"
    version = releaseVersion

    tasks.withType(AbstractArchiveTask::class.java).configureEach {
        isPreserveFileTimestamps = false
        isReproducibleFileOrder = true
    }
}

val centralPublishingEnabled = providers.gradleProperty("latchway.central.enabled")
    .orElse(providers.environmentVariable("LATCHWAY_CENTRAL_ENABLED"))
    .map { it.toBooleanStrict() }
    .orElse(false)
    .get()
val explicitSigningEnabled = providers.gradleProperty("latchway.signing.enabled")
    .orElse(providers.environmentVariable("LATCHWAY_SIGNING_ENABLED"))
    .map { it.toBooleanStrict() }
    .orElse(false)
    .get()
val signingEnabled = centralPublishingEnabled || explicitSigningEnabled

val configurationCacheActive = objects.newInstance<InjectedBuildFeatures>()
    .buildFeatures
    .configurationCache
    .active
    .get()
if (signingEnabled && configurationCacheActive) {
    throw GradleException(
        "Signing and Central publication require --no-configuration-cache so secret material cannot be persisted",
    )
}

val centralUsername = providers.gradleProperty("latchway.central.username")
    .orElse(providers.environmentVariable("LATCHWAY_MAVEN_CENTRAL_USERNAME"))
val centralPassword = providers.gradleProperty("latchway.central.password")
    .orElse(providers.environmentVariable("LATCHWAY_MAVEN_CENTRAL_PASSWORD"))
val signingKey = providers.gradleProperty("latchway.signing.key")
    .orElse(providers.environmentVariable("LATCHWAY_SIGNING_KEY"))
val signingPassword = providers.gradleProperty("latchway.signing.password")
    .orElse(providers.environmentVariable("LATCHWAY_SIGNING_PASSWORD"))

fun requiredSecret(value: String?, name: String): String =
    value?.takeIf(String::isNotBlank)
        ?: throw GradleException("$name is required for the explicitly enabled publication operation")

val centralUsernameValue = if (centralPublishingEnabled) {
    requiredSecret(centralUsername.orNull, "Maven Central username")
} else {
    null
}
val centralPasswordValue = if (centralPublishingEnabled) {
    requiredSecret(centralPassword.orNull, "Maven Central password")
} else {
    null
}
val signingKeyValue = if (signingEnabled) {
    requiredSecret(signingKey.orNull, "ASCII-armored OpenPGP signing key")
} else {
    null
}
val signingPasswordValue = if (signingEnabled) {
    requiredSecret(signingPassword.orNull, "OpenPGP signing password")
} else {
    null
}

if (centralPublishingEnabled && releaseVersion.endsWith("-SNAPSHOT")) {
    throw GradleException("Maven Central publication requires a non-SNAPSHOT latchway.version")
}

val cleanPublicationTestRepository = tasks.register<Delete>("cleanPublicationTestRepository") {
    group = "publishing"
    description = "Deletes the isolated Maven repository used by publication verification."
    delete(layout.buildDirectory.dir("publication-test-repository"))
}

val runtimeSdkVersion = providers.fileContents(
    layout.projectDirectory.file("latchway-core/src/main/kotlin/dev/latchway/core/LatchwayApi.kt"),
).asText.map { source ->
    Regex("LATCHWAY_SDK_VERSION: String = \\\"([^\\\"]+)\\\"")
        .find(source)
        ?.groupValues
        ?.get(1)
        ?: throw GradleException("Could not find LATCHWAY_SDK_VERSION")
}.get()
val expectedRuntimeVersion = releaseVersion.removeSuffix("-SNAPSHOT")
if (runtimeSdkVersion != expectedRuntimeVersion) {
    throw GradleException(
        "Publication version $releaseVersion does not match LATCHWAY_SDK_VERSION $runtimeSdkVersion",
    )
}

publishedModules.forEach { module ->
    val target = project(module.path)
    target.plugins.withId("maven-publish") {
        val publishing = target.extensions.getByType(PublishingExtension::class.java)
        val publication = publishing.publications.register(
            "release",
            MavenPublication::class.java,
        ) {
            groupId = "dev.latchway"
            artifactId = target.name
            version = releaseVersion
            pom {
                name.set(module.displayName)
                description.set(module.description)
                url.set("https://github.com/latchway/latchway-android")
                inceptionYear.set("2026")
                licenses {
                    license {
                        name.set("The Apache License, Version 2.0")
                        url.set("https://www.apache.org/licenses/LICENSE-2.0.txt")
                        distribution.set("repo")
                    }
                }
                developers {
                    developer {
                        id.set("latchway")
                        name.set("Latchway contributors")
                        organization.set("Latchway")
                        organizationUrl.set("https://github.com/latchway")
                    }
                }
                scm {
                    connection.set("scm:git:https://github.com/latchway/latchway-android.git")
                    developerConnection.set("scm:git:ssh://git@github.com/latchway/latchway-android.git")
                    url.set("https://github.com/latchway/latchway-android")
                    tag.set(if (releaseVersion.endsWith("-SNAPSHOT")) "HEAD" else "v$releaseVersion")
                }
                issueManagement {
                    system.set("GitHub")
                    url.set("https://github.com/latchway/latchway-android/issues")
                }
            }
        }

        target.afterEvaluate {
            publication.configure {
                from(target.components.getByName(module.component))
                if (module.component == "javaPlatform") {
                    artifact(target.tasks.named("sourcesJar"))
                    artifact(target.tasks.named("javadocJar"))
                }
            }
        }

        publishing.repositories.maven {
            name = "publicationTest"
            url = rootProject.layout.buildDirectory.dir("publication-test-repository").get().asFile.toURI()
        }

        if (centralPublishingEnabled) {
            publishing.repositories.maven {
                name = "central"
                url = uri(
                    "https://ossrh-staging-api.central.sonatype.com/service/local/staging/deploy/maven2/",
                )
                credentials(PasswordCredentials::class.java) {
                    username = centralUsernameValue
                    password = centralPasswordValue
                }
                authentication {
                    create("basic", BasicAuthentication::class.java)
                }
            }
        }

        target.plugins.withId("signing") {
            if (signingEnabled) {
                target.extensions.configure(SigningExtension::class.java) {
                    isRequired = true
                    useInMemoryPgpKeys(signingKeyValue, signingPasswordValue)
                    sign(publication.get())
                }
                target.tasks.withType(Sign::class.java).configureEach {
                    notCompatibleWithConfigurationCache(
                        "In-memory release signing material must never be retained in the configuration cache.",
                    )
                }
            }
        }

        target.tasks.withType(PublishToMavenRepository::class.java).configureEach {
            if (repository.name == "publicationTest") {
                dependsOn(cleanPublicationTestRepository)
            }
            if (repository.name == "central") {
                notCompatibleWithConfigurationCache(
                    "Maven Central credentials must never be retained in the configuration cache.",
                )
            }
        }
    }
}

val localPublicationTasks = publishedModules.map {
    "${it.path}:publishReleasePublicationToPublicationTestRepository"
}
tasks.register("publishPublicArtifactsToPublicationTestRepository") {
    group = "publishing"
    description = "Publishes all five public artifacts to the isolated verification repository."
    dependsOn(localPublicationTasks)
}

tasks.register("publishPublicArtifactsToCentralRepository") {
    group = "publishing"
    description = "Stages all five signed public artifacts through the Maven Central compatibility API."
    if (centralPublishingEnabled) {
        dependsOn(publishedModules.map { "${it.path}:publishReleasePublicationToCentralRepository" })
    } else {
        doFirst {
            throw GradleException(
                "Central publication is disabled; explicitly set -Platchway.central.enabled=true and provide release credentials",
            )
        }
    }
}
