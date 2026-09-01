# crypto-pqc-native

Rust crate exposing post-quantum primitives from [liboqs](https://github.com/open-quantum-safe/liboqs)
(MIT/BSD-licensed) to the Kotlin `:crypto-pqc` module via JNI:

- **ML-KEM-768** (Kyber, FIPS 203) — key encapsulation
- **ML-DSA-65** (Dilithium, FIPS 204) — signatures

## Why this crate exists

This is part of a plan to add post-quantum cryptography to keychain-app
**without** making the new code a derivative of OpenKeychain's GPLv3
application code. It intentionally knows nothing about OpenPGP packet
formats, keyrings, or passphrase caching — it only exposes raw algorithm
operations (keygen / encapsulate / decapsulate / sign / verify).
Packet-format composition (the OpenPGP-PQC hybrid format) lives in the
Kotlin `:crypto-pqc` module, which is expected to call
`extern/bouncycastle-pg` (MIT) directly rather than any of the
`org.sufficientlysecure.keychain.pgp.Pgp*Operation` classes.

See the project's licensing decisions for the full rationale; this file
exists to keep that boundary visible to anyone touching this crate later.

## License

MIT (see `Cargo.toml`). Depends on:
- `oqs` / `oqs-sys` (MIT), which vendors and builds `liboqs` (MIT) via the
  `vendored` Cargo feature — no system-installed liboqs required.
- `jni` (MIT/Apache-2.0) for the JNI bridge.

## Status (2026-09-01)

- Builds and passes round-trip tests on the host (`x86_64-unknown-linux-gnu`):
  `cargo test --lib`.
- **Cross-compiles for Android.** Run `./build-android.sh` (needs the
  Android NDK installed, `cargo install cargo-ndk`, and the Rust targets
  `aarch64-linux-android` / `armv7-linux-androideabi` / `x86_64-linux-android`
  / `i686-linux-android`) — it produces
  `jniLibs/{arm64-v8a,armeabi-v7a,x86_64,x86}/libcrypto_pqc_native.so`.
- Remaining work: wire `jniLibs/` into an Android library module's
  `src/main/jniLibs/` (or drive `build-android.sh` from a Gradle task), and
  write the Kotlin `:crypto-pqc` module with `KemNative` / `SigNative`
  `external fun` declarations matching the JNI symbols exported here
  (`Java_com_keychain_crypto_pqc_native_*`), plus the OpenPGP-PQC hybrid
  packet composition on top.
