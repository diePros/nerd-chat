import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins { kotlin("jvm") }

kotlin { compilerOptions { jvmTarget.set(JvmTarget.JVM_17) } }
java { sourceCompatibility = JavaVersion.VERSION_17; targetCompatibility = JavaVersion.VERSION_17 }

dependencies {
    api("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.10.2")
    testImplementation(kotlin("test"))
}

// The JNI end-to-end test loads the HOST build of the bridge library. Build it first (needs cargo); without cargo the task is a no-op and
// the test skips itself. `-x buildBridgeHost` skips the build explicitly.
val repoRoot = rootDir.parentFile
val hostLib = File(repoRoot, "target/release/libnerdchat_bridge.so")
val buildBridgeHost by tasks.registering(Exec::class) {
    group = "build"; description = "cargo build --release -p nerd-chat-android (host library for the JNI test)"
    workingDir = repoRoot
    commandLine("cargo", "build", "--locked", "--release", "-p", "nerd-chat-android")
    isIgnoreExitValue = true
    // cargo missing or failing must not break the pure-Kotlin tests: the JNI test then skips
    doFirst { if (System.getenv("PATH")?.split(File.pathSeparator)?.none { File(it, "cargo").canExecute() } == true) { println("cargo not found: the JNI test will be skipped"); enabled = false } }
}
tasks.test {
    useJUnitPlatform()
    dependsOn(buildBridgeHost)
    systemProperty("nerdchat.lib", hostLib.absolutePath)
    testLogging { events("skipped", "failed"); showStandardStreams = false }
}
