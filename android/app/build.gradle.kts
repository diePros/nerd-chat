import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.plugin.compose")
}

// ---- the Rust core: libnerdchat_bridge.so for each ABI, built with cargo + the NDK linker and packaged as native libraries ----
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
val rustTasks = rustAbis.map { (abi, triple) ->
    tasks.register<Exec>("buildRust_$abi") {
        group = "build"; description = "cargo build --release -p nerd-chat-android --target $triple"
        workingDir = repoRoot
        commandLine("cargo", "build", "--locked", "--release", "-p", "nerd-chat-android", "--target", triple)
        val clang = File(ndkBin, "$triple" + "29-clang")
        val under = triple.replace('-', '_'); val upper = triple.uppercase().replace('-', '_')
        environment("CARGO_TARGET_${upper}_LINKER", clang.path); environment("CC_$under", clang.path); environment("AR_$under", File(ndkBin, "llvm-ar").path)
        // 16 KB page alignment (Android 15+), no build-id and remapped paths so that the library is reproducible
        environment("RUSTFLAGS", listOf("-C link-arg=-Wl,-z,max-page-size=16384", "-C link-arg=-Wl,--build-id=none",
            "--remap-path-prefix=${repoRoot}=/src", "--remap-path-prefix=${System.getProperty("user.home")}/.cargo=/cargo", "--remap-path-prefix=${System.getProperty("user.home")}/.rustup=/rustup").joinToString(" "))
        doFirst { if (!clang.isFile) throw GradleException("NDK $ndkVersion not found at $ndkBin: sdkmanager \"ndk;$ndkVersion\" (docs/ANDROID_DEV_SETUP.md)") }
        val so = File(repoRoot, "target/$triple/release/libnerdchat_bridge.so")
        val dest = rustOut.map { it.dir(abi).file("libnerdchat_bridge.so") }
        outputs.file(dest)
        inputs.files(fileTree(File(repoRoot, "crates")) { include("**/*.rs", "**/Cargo.toml") }, File(repoRoot, "Cargo.lock"))
        doLast { so.copyTo(dest.get().asFile, overwrite = true) }
    }
}


android {
    namespace = "app.nerdchat"
    compileSdk = 37
    defaultConfig {
        applicationId = "app.nerdchat"
        minSdk = 29          // Android 10: W^X app data, scoped storage and the modern permission model are the floor
        targetSdk = 36
        versionCode = 1
        versionName = "0.1.0"
        // 64-bit ARM (every Pixel/GrapheneOS device and nearly all phones) plus x86_64 for the emulator. The Rust core will be built for the same two.
        ndk { abiFilters += listOf("arm64-v8a", "x86_64") }
        // -Pdemo: the in-memory demo backend instead of the Rust core (previews, screenshots, UI work without a vault)
        resValue("bool", "nerdchat_demo", providers.gradleProperty("demo").isPresent.toString())
    }
    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            // Signing: set NERDCHAT_KEYSTORE / NERDCHAT_KEYSTORE_PASSWORD / NERDCHAT_KEY_ALIAS when building a release (never committed).
            System.getenv("NERDCHAT_KEYSTORE")?.let { ks ->
                signingConfig = signingConfigs.create("release") {
                    storeFile = file(ks)
                    storePassword = System.getenv("NERDCHAT_KEYSTORE_PASSWORD")
                    keyAlias = System.getenv("NERDCHAT_KEY_ALIAS") ?: "nerdchat"
                    keyPassword = System.getenv("NERDCHAT_KEYSTORE_PASSWORD")
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
    packaging { resources.excludes += "/META-INF/{AL2.0,LGPL2.1}" }
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
}
