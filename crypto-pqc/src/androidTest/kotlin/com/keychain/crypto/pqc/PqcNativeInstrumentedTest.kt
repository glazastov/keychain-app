package com.keychain.crypto.pqc

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Exercises the real crypto-pqc-native JNI bindings on-device (the .so
 * files under src/main/jniLibs are Android ELF binaries and cannot be
 * loaded by JVM unit tests on the host).
 */
@RunWith(AndroidJUnit4::class)
class PqcNativeInstrumentedTest {

    @Test
    fun mlKem768RoundTrip() {
        val keypair = MlKem768.generateKeypair()
        assertTrue(keypair.publicKey.size == MlKem768.PUBLIC_KEY_SIZE)
        assertTrue(keypair.secretKey.size == MlKem768.SECRET_KEY_SIZE)

        val encapsulation = MlKem768.encapsulate(keypair.publicKey)
        val recovered = MlKem768.decapsulate(keypair.secretKey, encapsulation.ciphertext)

        assertArrayEquals(encapsulation.sharedSecret, recovered)
    }

    @Test
    fun mlDsa65SignAndVerify() {
        val keypair = MlDsa65.generateKeypair()
        val message = "crypto-pqc instrumented test".toByteArray()

        val signature = MlDsa65.sign(keypair.secretKey, message)
        assertTrue(MlDsa65.verify(keypair.publicKey, message, signature))

        val tampered = "crypto-pqc instrumented TEST".toByteArray()
        assertFalse(MlDsa65.verify(keypair.publicKey, tampered, signature))
    }
}
