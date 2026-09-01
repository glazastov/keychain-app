package com.keychain.crypto.pqc.jni

/**
 * Raw JNI bridge to the ML-KEM-768 functions in crypto-pqc-native
 * (see ../../../../../crypto-pqc-native/src/lib.rs). Byte layouts:
 *  - [generateKeypair] returns `publicKey || secretKey`.
 *  - [encapsulate] returns `ciphertext || sharedSecret`.
 *  - [decapsulate] returns the shared secret alone.
 * Callers should go through [com.keychain.crypto.pqc.MlKem768] rather than
 * this class directly — it does the slicing and exposes typed results.
 */
internal object KemNative {
    init {
        System.loadLibrary("crypto_pqc_native")
    }

    external fun generateKeypair(): ByteArray
    external fun encapsulate(publicKey: ByteArray): ByteArray
    external fun decapsulate(secretKey: ByteArray, ciphertext: ByteArray): ByteArray
}
