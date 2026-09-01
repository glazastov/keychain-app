package com.keychain.crypto.pqc

import com.keychain.crypto.pqc.jni.KemNative

/**
 * ML-KEM-768 (Kyber, FIPS 203) key encapsulation, security level 3 — the
 * level most OpenPGP-PQC hybrid drafts pair with Curve25519/P-384.
 *
 * Sizes are fixed by the algorithm (FIPS 203, table 2/3).
 */
object MlKem768 {
    const val PUBLIC_KEY_SIZE = 1184
    const val SECRET_KEY_SIZE = 2400
    const val CIPHERTEXT_SIZE = 1088
    const val SHARED_SECRET_SIZE = 32

    data class Keypair(val publicKey: ByteArray, val secretKey: ByteArray)
    data class Encapsulation(val ciphertext: ByteArray, val sharedSecret: ByteArray)

    fun generateKeypair(): Keypair {
        val combined = KemNative.generateKeypair()
        check(combined.size == PUBLIC_KEY_SIZE + SECRET_KEY_SIZE) {
            "unexpected ML-KEM-768 keypair length: ${combined.size}"
        }
        return Keypair(
            publicKey = combined.copyOfRange(0, PUBLIC_KEY_SIZE),
            secretKey = combined.copyOfRange(PUBLIC_KEY_SIZE, combined.size),
        )
    }

    fun encapsulate(publicKey: ByteArray): Encapsulation {
        require(publicKey.size == PUBLIC_KEY_SIZE) { "public key must be $PUBLIC_KEY_SIZE bytes" }
        val combined = KemNative.encapsulate(publicKey)
        check(combined.size == CIPHERTEXT_SIZE + SHARED_SECRET_SIZE) {
            "unexpected ML-KEM-768 encapsulation length: ${combined.size}"
        }
        return Encapsulation(
            ciphertext = combined.copyOfRange(0, CIPHERTEXT_SIZE),
            sharedSecret = combined.copyOfRange(CIPHERTEXT_SIZE, combined.size),
        )
    }

    fun decapsulate(secretKey: ByteArray, ciphertext: ByteArray): ByteArray {
        require(secretKey.size == SECRET_KEY_SIZE) { "secret key must be $SECRET_KEY_SIZE bytes" }
        require(ciphertext.size == CIPHERTEXT_SIZE) { "ciphertext must be $CIPHERTEXT_SIZE bytes" }
        val sharedSecret = KemNative.decapsulate(secretKey, ciphertext)
        check(sharedSecret.size == SHARED_SECRET_SIZE) {
            "unexpected ML-KEM-768 shared secret length: ${sharedSecret.size}"
        }
        return sharedSecret
    }
}
