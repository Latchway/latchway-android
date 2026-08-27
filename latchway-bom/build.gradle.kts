plugins {
    `java-platform`
}

javaPlatform {
    allowDependencies()
}

dependencies {
    constraints {
        api(project(":latchway-core"))
        api(project(":latchway-okhttp"))
        api(project(":latchway-play-integrity"))
        api(project(":latchway-firebase-auth"))
        api(project(":test-support"))
    }
}
