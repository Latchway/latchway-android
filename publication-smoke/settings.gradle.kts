pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

val latchwayRepository = providers.gradleProperty("latchway.testRepository").orNull
    ?: throw GradleException("latchway.testRepository must point to the isolated publication repository")
val metadataMode = providers.gradleProperty("latchway.metadataMode").orElse("gradle").get()
if (metadataMode !in setOf("gradle", "pom")) {
    throw GradleException("latchway.metadataMode must be gradle or pom")
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        exclusiveContent {
            forRepository {
                maven {
                    name = "latchwayPublicationUnderTest"
                    url = uri(latchwayRepository)
                    metadataSources {
                        if (metadataMode == "gradle") {
                            gradleMetadata()
                        }
                        mavenPom()
                        artifact()
                    }
                }
            }
            filter {
                includeGroup("dev.latchway")
            }
        }
        google()
        mavenCentral()
    }
}

rootProject.name = "latchway-android-publication-consumer"
