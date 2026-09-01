package com.keychain.crypto.pqc

import com.keychain.crypto.pqc.jni.SigNative

/**
 * ML-DSA-65 (Dilithium, FIPS 204) signatures, security level 3 — paired
 * with [MlKem768] for the OpenPGP-PQC hybrid identity.
 *
 * Sizes are fixed by the algorithm (FIPS 204, table 2).
 */
object MlDsa65 {
    const val PUBLIC_KEY_SIZE = 1952
    const val SECRET_KEY_SIZE = 4032
    const val SIGNATURE_SIZE = 3309

    data class Keypair(val publicKey: ByteArray, val secretKey: ByteArray)

    fun generateKeypair(): Keypair {
        val combined = SigNative.generateKeypair()
        check(combined.size == PUBLIC_KEY_SIZE + SECRET_KEY_SIZE) {
            "unexpected ML-DSA-65 keypair length: ${combined.size}"
        }
        return Keypair(
            publicKey = combined.copyOfRange(0, PUBLIC_KEY_SIZE),
            secretKey = combined.copyOfRange(PUBLIC_KEY_SIZE, combined.size),
        )
    }

    fun sign(secretKey: ByteArray, message: ByteArray): ByteArray {
        require(secretKey.size == SECRET_KEY_SIZE) { "secret key must be $SECRET_KEY_SIZE bytes" }
        val signature = SigNative.sign(secretKey, message)
        check(signature.size == SIGNATURE_SIZE) {
            "unexpected ML-DSA-65 signature length: ${signature.size}"
        }
        return signature
    }

    fun verify(publicKey: ByteArray, message: ByteArray, signature: ByteArray): Boolean {
        require(publicKey.size == PUBLIC_KEY_SIZE) { "public key must be $PUBLIC_KEY_SIZE bytes" }
        require(signature.size == SIGNATURE_SIZE) { "signature must be $SIGNATURE_SIZE bytes" }
        return SigNative.verify(publicKey, message, signature)
    }
}
