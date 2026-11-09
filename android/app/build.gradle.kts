import java.security.MessageDigest
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.plugin.compose")
}

// ---- the Rust core: libsineloco_bridge.so for each ABI, built with cargo + the NDK linker and packaged as native libraries ----
// -Pdemo=true: the in-memory demo backend. Only the literal value `true` counts (a `demo=false` or an empty value must not turn it on), and a RELEASE build refuses it.
val demoBuild = providers.gradleProperty("demo").map { it.equals("true", ignoreCase = true) }.orElse(false).get()
gradle.taskGraph.whenReady { if (demoBuild && allTasks.any { it.project.path == ":app" && it.name.contains("Release", ignoreCase = true) }) throw GradleException("-Pdemo=true must never be used for a release build: it would ship the fake backend (any password opens it)") }
val ndkVersion = "29.0.14206865"
val repoRoot = rootDir.parentFile
val sdkDir: String? = System.getenv("ANDROID_HOME") ?: System.getenv("ANDROID_SDK_ROOT")
    ?: File(rootDir, "local.properties").takeIf { it.isFile }?.readLines()?.firstOrNull { it.startsWith("sdk.dir=") }?.removePrefix("sdk.dir=")
val hostTag = when {
    System.getProperty("os.name").startsWith("Mac") -> "darwin-x86_64"
    System.getProperty("os.name").startsWith("Linux") -> "linux-x86_64"
    else -> error("building the Rust core is supported on Linux and macOS (use WSL2 on Windows)")
}
val ndkBin = File(sdkDir ?: "", "ndk/$ndkVersion/toolchains/llvm/prebuilt/$hostTag/bin")
val rustAbis = mapOf("arm64-v8a" to "aarch64-linux-android", "x86_64" to "x86_64-linux-android")
val rustOut = layout.buildDirectory.dir("rustJniLibs")
val rustFlags = listOf("-C link-arg=-Wl,-z,max-page-size=16384", "-C link-arg=-Wl,--build-id=none",
    "--remap-path-prefix=${repoRoot}=/src", "--remap-path-prefix=${System.getProperty("user.home")}/.cargo=/cargo", "--remap-path-prefix=${System.getProperty("user.home")}/.rustup=/rustup").joinToString(" ")
val rustTasks = rustAbis.map { (abi, triple) ->
    tasks.register<Exec>("buildRust_$abi") {
        group = "build"; description = "cargo build --release -p sine-loco-android --target $triple"
        workingDir = repoRoot
        commandLine("cargo", "build", "--locked", "--release", "-p", "sine-loco-android", "--target", triple)
        val clang = File(ndkBin, "$triple" + "29-clang")
        val under = triple.replace('-', '_'); val upper = triple.uppercase().replace('-', '_')
        environment("CARGO_TARGET_${upper}_LINKER", clang.path); environment("CC_$under", clang.path); environment("AR_$under", File(ndkBin, "llvm-ar").path)
        // 16 KB page alignment (Android 15+), no build-id and remapped paths so that the library is reproducible
        environment("RUSTFLAGS", rustFlags)
        doFirst { if (!clang.isFile) throw GradleException("NDK $ndkVersion not found at $ndkBin: sdkmanager \"ndk;$ndkVersion\" (docs/ANDROID_DEV_SETUP.md)") }
        val so = File(repoRoot, "target/$triple/release/libsineloco_bridge.so")
        val dest = rustOut.map { it.dir(abi).file("libsineloco_bridge.so") }
        outputs.file(dest)
        // EVERYTHING that changes the library: all crates, the vendored crypto patch, the workspace manifest (release profile: panic=abort, strip), the lock file, the toolchain pin, the flags
        inputs.files(fileTree(File(repoRoot, "crates")) { include("**/*.rs", "**/Cargo.toml") }, fileTree(File(repoRoot, "vendor")), File(repoRoot, "Cargo.toml"), File(repoRoot, "Cargo.lock"), File(repoRoot, "rust-toolchain.toml"))
        inputs.property("rustflags", rustFlags)
        doLast { so.copyTo(dest.get().asFile, overwrite = true) }
    }
}


android {
    namespace = "app.sineloco"
    compileSdk = 37
    defaultConfig {
        applicationId = "app.sineloco"
        minSdk = 29          // Android 10: W^X app data, scoped storage and the modern permission model are the floor
        targetSdk = 36
        versionCode = 1
        versionName = "0.1.0"
        // 64-bit ARM (every Pixel/GrapheneOS device and nearly all phones) plus x86_64 for the emulator. The Rust core will be built for the same two.
        ndk { abiFilters += listOf("arm64-v8a", "x86_64") }
        // -Pdemo: the in-memory demo backend instead of the Rust core (previews, screenshots, UI work without a vault)
        resValue("bool", "sineloco_demo", demoBuild.toString())
    }
    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            // Signing: set SINELOCO_KEYSTORE / SINELOCO_KEYSTORE_PASSWORD / SINELOCO_KEY_ALIAS when building a release (never committed).
            System.getenv("SINELOCO_KEYSTORE")?.let { ks ->
                signingConfig = signingConfigs.create("release") {
                    storeFile = file(ks)
                    storePassword = System.getenv("SINELOCO_KEYSTORE_PASSWORD")
                    keyAlias = System.getenv("SINELOCO_KEY_ALIAS") ?: "sineloco"
                    keyPassword = System.getenv("SINELOCO_KEYSTORE_PASSWORD")
                }
            }
        }
    }
    compileOptions { sourceCompatibility = JavaVersion.VERSION_17; targetCompatibility = JavaVersion.VERSION_17 }
    buildFeatures { compose = true; resValues = true }
    // The screens live in :ui as plain JVM Compose (so they can be compiled and rendered anywhere); here the SAME files are compiled against androidx Compose.
    sourceSets.getByName("main").kotlin.directories.add("../ui/src/main/kotlin")
    sourceSets.getByName("main").jniLibs.directories.add(rustOut.get().asFile.path)
    lint { abortOnError = true; warningsAsErrors = false }
    // libtor.so is an EXECUTABLE (see scripts/build-tor-android.sh): it must be extracted to the native library directory, the only place Android 10+ allows exec from
    packaging { resources.excludes += "/META-INF/{AL2.0,LGPL2.1}"; jniLibs { useLegacyPackaging = true } }
}
kotlin { compilerOptions { jvmTarget.set(JvmTarget.JVM_17) } }

// every task that gathers the native libraries needs the Rust build first
tasks.matching { it.name.matches(Regex("merge.*JniLibFolders|merge.*NativeLibs")) }.configureEach { rustTasks.forEach { r -> dependsOn(r) } }

dependencies {
    implementation(project(":model"))
    implementation(platform("androidx.compose:compose-bom:2026.09.00"))
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.foundation:foundation")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.activity:activity-compose:1.13.0")
    implementation("androidx.core:core-ktx:1.19.1")
    implementation("com.google.zxing:core:3.5.3") // QR encoder (the :ui sources use it); no camera code, the phone's own camera app scans
}

// A RELEASE must ship exactly the libtor.so that scripts/build-tor-android.sh produced and that was pinned in android/libtor.sha256 (reproducible build, checked by the script).
// A debug build only warns (you may be testing a tor you just rebuilt). Update the pin file in the same commit as a deliberate tor upgrade.
fun registerVerifyLibtor(name: String, strict: Boolean) = tasks.register(name) {
    group = "verification"; description = "libtor.so in src/main/jniLibs must match android/libtor.sha256 (strict: fail, else warn)"
    val pins = layout.projectDirectory.file("../libtor.sha256").asFile
    val libs = layout.projectDirectory.dir("src/main/jniLibs").asFile
    doLast {
        val problems = mutableListOf<String>()
        pins.readLines().filter { it.isNotBlank() }.forEach { line ->
            val (want, rel) = line.trim().split(Regex("\\s+"), limit = 2)
            val f = File(libs, rel)
            if (!f.isFile) problems += "$rel is missing (run scripts/build-tor-android.sh)"
            else {
                val got = MessageDigest.getInstance("SHA-256").digest(f.readBytes()).joinToString("") { "%02x".format(it) }
                if (got != want) problems += "$rel: sha256 $got is not the pinned $want"
            }
        }
        // every native library that would be packaged must be a pinned one: an extra .so dropped into jniLibs would ship unchecked
        val pinned = pins.readLines().filter { it.isNotBlank() }.map { it.trim().split(Regex("\\s+"), limit = 2)[1] }.toSet()
        libs.walkTopDown().filter { it.isFile && it.name.endsWith(".so") }.forEach { f ->
            val rel = f.relativeTo(libs).path
            if (rel !in pinned) problems += "$rel is not in android/libtor.sha256 (unpinned native library)"
        }
        if (problems.isNotEmpty()) {
            val msg = "libtor.so does not match android/libtor.sha256:\n  " + problems.joinToString("\n  ")
            if (strict) throw GradleException(msg) else logger.warn("WARNING: $msg")
        }
    }
}
val verifyLibtorStrict = registerVerifyLibtor("verifyLibtorStrict", true)
val verifyLibtorLoose = registerVerifyLibtor("verifyLibtorLoose", false)
// decided per VARIANT by the task's own name (a task name given on the command line such as `assemble` or `build` also builds the release variant): release is strict, everything else warns
tasks.matching { it.name.matches(Regex("merge.*JniLibFolders")) }.configureEach { dependsOn(if (name.contains("Release")) verifyLibtorStrict else verifyLibtorLoose) }
