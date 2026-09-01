package com.keychain.crypto.pqc.jni

/**
 * Raw JNI bridge to the ML-DSA-65 functions in crypto-pqc-native
 * (see ../../../../../crypto-pqc-native/src/lib.rs). Byte layouts:
 *  - [generateKeypair] returns `publicKey || secretKey`.
 *  - [sign] returns the detached signature.
 *  - [verify] returns whether `signature` is valid over `message` for `publicKey`.
 * Callers should go through [com.keychain.crypto.pqc.MlDsa65] rather than
 * this class directly — it does the slicing and exposes typed results.
 */
internal object SigNative {
    init {
        System.loadLibrary("crypto_pqc_native")
    }

    external fun generateKeypair(): ByteArray
    external fun sign(secretKey: ByteArray, message: ByteArray): ByteArray
    external fun verify(publicKey: ByteArray, message: ByteArray, signature: ByteArray): Boolean
}
