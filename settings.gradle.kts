pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "latchway-android"

include(
    ":latchway-core",
    ":latchway-okhttp",
    ":latchway-play-integrity",
    ":latchway-firebase-auth",
    ":latchway-bom",
    ":test-support",
    ":sample-basic",
    ":sample-firebase",
    ":sample-conformance",
)
