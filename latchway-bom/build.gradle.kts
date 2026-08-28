plugins {
    `java-platform`
    `maven-publish`
    signing
}

javaPlatform {
    allowDependencies()
}

tasks.register<Jar>("sourcesJar") {
    archiveClassifier.set("sources")
}

tasks.register<Jar>("javadocJar") {
    archiveClassifier.set("javadoc")
}

dependencies {
    constraints {
        api(project(":latchway-core"))
        api(project(":latchway-okhttp"))
        api(project(":latchway-play-integrity"))
        api(project(":latchway-firebase-auth"))
    }
}
