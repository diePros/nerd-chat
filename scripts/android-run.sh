#!/usr/bin/env bash
# Build the debug APK (building libtor.so first when it is missing), start the emulator `sineloco` (created on first use) and install + launch the app.
#   usage: scripts/android-run.sh [--headless]
# Needs: ANDROID_HOME (default ~/android-sdk) with emulator, platform-tools, NDK r29, the system image `system-images;android-36;default;x86_64`, a JDK 17+ (JAVA_HOME or ~/jdk/jdk-17*), /dev/kvm access.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export ANDROID_HOME="${ANDROID_HOME:-$HOME/android-sdk}"
[ -n "${JAVA_HOME:-}" ] || { J="$(ls -d "$HOME"/jdk/jdk-17* 2>/dev/null | head -1)"; [ -n "$J" ] && export JAVA_HOME="$J" PATH="$J/bin:$PATH"; }
ADB="$ANDROID_HOME/platform-tools/adb"; EMU="$ANDROID_HOME/emulator/emulator"; AVD=sineloco
for abi in x86_64 arm64-v8a; do [ -f "$ROOT/android/app/src/main/jniLibs/$abi/libtor.so" ] || "$ROOT/scripts/build-tor-android.sh" "$abi"; done
( cd "$ROOT/android" && ./gradlew :app:assembleDebug )
if ! "$EMU" -list-avds | grep -qx "$AVD"; then
  echo no | "$ANDROID_HOME/cmdline-tools/latest/bin/avdmanager" create avd -n "$AVD" -k "system-images;android-36;default;x86_64" -d pixel_6 --force
  # avdmanager creates the device WITHOUT host keyboard input: typing on the PC keyboard would do nothing
  sed -i 's/^hw.keyboard=.*/hw.keyboard=yes/' "$HOME/.android/avd/$AVD.avd/config.ini"
fi
[ -f "$HOME/.android/avd/$AVD.avd/config.ini" ] && sed -i 's/^hw.keyboard=.*/hw.keyboard=yes/' "$HOME/.android/avd/$AVD.avd/config.ini"
if ! "$ADB" devices | grep -q "emulator-.*device"; then
  OPTS="-no-snapshot -no-audio"; [ "${1:-}" = "--headless" ] && OPTS="$OPTS -no-window -no-boot-anim -gpu swiftshader_indirect"
  nohup "$EMU" -avd "$AVD" $OPTS >/tmp/sineloco-emulator.log 2>&1 &
  "$ADB" wait-for-device
  until [ "$("$ADB" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = 1 ]; do sleep 3; done
fi
"$ADB" install -r -g "$ROOT/android/app/build/outputs/apk/debug/app-debug.apk"
"$ADB" shell am start -n app.sineloco/.MainActivity
echo "Running. The screen is not capturable (FLAG_SECURE); read it with: $ADB shell uiautomator dump"
