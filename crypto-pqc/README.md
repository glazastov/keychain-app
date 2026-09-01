# crypto-pqc

Kotlin API for ML-KEM-768 (`MlKem768`) and ML-DSA-65 (`MlDsa65`), backed by
the `crypto-pqc-native` Rust/liboqs crate via JNI (`src/main/jniLibs/`,
built by `../crypto-pqc-native/build-android.sh`).

- `com.keychain.crypto.pqc.MlKem768` / `MlDsa65` — typed keygen/encapsulate/
  decapsulate/sign/verify, sizes fixed per FIPS 203/204.
- `com.keychain.crypto.pqc.jni.KemNative` / `SigNative` — raw JNI bridge;
  not meant to be called directly.

## Status (2026-09-01)

- Compiles (`./gradlew :crypto-pqc:compileDebugKotlin`, needs `JAVA_HOME`
  pointed at a JDK 21 — see root `build.gradle`'s JDK check).
- Instrumented tests in `src/androidTest/` exercise the real native library
  on-device (`MlKem768`/`MlDsa65` round-trips); plain JVM unit tests can't
  load the Android `.so` files, so there's no `src/test/` coverage for the
  native calls themselves. **These have not been run** — this dev
  environment only builds, it doesn't run an emulator/device — so they're
  unverified until run in CI or on a real device.
- Not yet wired into `OpenKeychain`'s own build — this module isn't a
  dependency of `:OpenKeychain` yet, and there's no UI or OpenPGP-PQC
  hybrid packet composition on top of these primitives yet.
