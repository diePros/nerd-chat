import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    kotlin("jvm")
    id("org.jetbrains.kotlin.plugin.compose")
    id("org.jetbrains.compose")
}

kotlin { compilerOptions { jvmTarget.set(JvmTarget.JVM_17) } }
java { sourceCompatibility = JavaVersion.VERSION_17; targetCompatibility = JavaVersion.VERSION_17 }

// RULE: sources in src/main use only APIs that exist both in JetBrains Compose (desktop, compiled here) and in androidx Compose
// (compiled by :app from this same directory). No android.*, no LocalContext, no BackHandler: the host app passes those in.
dependencies {
    implementation(project(":model"))
    implementation(compose.runtime)
    implementation(compose.foundation)
    implementation(compose.material3)
    implementation(compose.ui)
    implementation("com.google.zxing:core:3.5.3") // QR encoder only (pure Java, Apache-2.0); there is no camera code in this app
    testImplementation(compose.desktop.currentOs)
    testImplementation(kotlin("test"))
}
tasks.test { useJUnitPlatform(); systemProperty("shots.dir", layout.buildDirectory.dir("shots").get().asFile.absolutePath); systemProperty("java.awt.headless", "true") }
