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

allprojects {
    group = "dev.latchway"
    version = "0.1.0-SNAPSHOT"
}
