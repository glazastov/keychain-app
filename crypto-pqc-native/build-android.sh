#!/usr/bin/env bash
# Cross-compiles crypto-pqc-native for all four Android ABIs and drops the
# resulting .so files into ./jniLibs/<abi>/libcrypto_pqc_native.so, ready to
# be copied into an Android library module's src/main/jniLibs/.
#
# Requires: rustup targets aarch64-linux-android, armv7-linux-androideabi,
# x86_64-linux-android, i686-linux-android; cargo-ndk (`cargo install cargo-ndk`);
# and an installed Android NDK (adjust NDK_VERSION/ANDROID_SDK_ROOT below if yours differs).
set -euo pipefail

ANDROID_SDK_ROOT="${ANDROID_SDK_ROOT:-$HOME/Android/Sdk}"
NDK_VERSION="${NDK_VERSION:-27.2.12479018}"
export ANDROID_NDK_HOME="$ANDROID_SDK_ROOT/ndk/$NDK_VERSION"
export ANDROID_NDK_ROOT="$ANDROID_NDK_HOME"
export ANDROID_NDK="$ANDROID_NDK_HOME"

if [ ! -d "$ANDROID_NDK_HOME" ]; then
  echo "Android NDK not found at $ANDROID_NDK_HOME" >&2
  echo "Install it with: sdkmanager --install \"ndk;$NDK_VERSION\"" >&2
  exit 1
fi

cd "$(dirname "$0")"
cargo ndk \
  -t arm64-v8a -t armeabi-v7a -t x86_64 -t x86 \
  -P 23 \
  -o jniLibs \
  build --release
