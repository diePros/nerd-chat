import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.plugin.compose")
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
    buildFeatures { compose = true }
    // The screens live in :ui as plain JVM Compose (so they can be compiled and rendered anywhere); here the SAME files are compiled against androidx Compose.
    sourceSets.getByName("main").kotlin.directories.add("../ui/src/main/kotlin")
    lint { abortOnError = true; warningsAsErrors = false }
    packaging { resources.excludes += "/META-INF/{AL2.0,LGPL2.1}" }
}
kotlin { compilerOptions { jvmTarget.set(JvmTarget.JVM_17) } }

dependencies {
    implementation(project(":model"))
    implementation(platform("androidx.compose:compose-bom:2026.09.00"))
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.foundation:foundation")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.activity:activity-compose:1.13.0")
    implementation("androidx.core:core-ktx:1.19.1")
}
