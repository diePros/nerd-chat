// Sine Loco for Android (Kotlin). Modules:
//   :model  pure Kotlin: data model, the ChatBackend contract, colour palettes (+ tests). No UI, no Android.
//   :ui     the Compose screens as plain JVM Compose, so they compile and render screenshots on any machine without the Android SDK.
//   :app    the Android application: compiles the SAME source files of :ui against androidx Compose. Only included when an Android SDK exists.
val hasSdk = System.getenv("ANDROID_HOME") != null || System.getenv("ANDROID_SDK_ROOT") != null || file("local.properties").exists()

pluginManagement {
    repositories { gradlePluginPortal(); mavenCentral(); google() }
}
dependencyResolutionManagement {
    repositories { mavenCentral(); google() }
}
rootProject.name = "sine-loco-android"
include(":model", ":ui")
if (hasSdk) include(":app")
