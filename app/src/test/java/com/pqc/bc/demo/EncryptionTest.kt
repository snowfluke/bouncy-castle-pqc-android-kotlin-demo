package com.pqc.bc.demo

import com.pqc.bc.demo.lib.Encryption
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test
import java.security.KeyPair

/**
 * Example local unit test, which will execute on the development machine (host).
 *
 * See [testing documentation](http://d.android.com/tools/testing).
 */
class EncryptionTest {
    private lateinit var aliceKp: KeyPair
    private lateinit var bobKp: KeyPair


    @Before()
    fun setup(){
        aliceKp = Encryption.generateKeypair()
        bobKp = Encryption.generateKeypair()
    }

    @Test
    fun testIntroduction() {
        println("THIS IS BOUNCY CASTLE UNIT TEST")
    }

    @Test
    fun testKeyPair(){
        val alicePubKey = aliceKp.public.encoded
        val alicePrivateKey = aliceKp.private.encoded

        val bobPubKey = bobKp.public.encoded
        val bobPrivateKey = bobKp.private.encoded

        println("Alice: Pub=${alicePubKey.size}Bytes,Priv=${alicePrivateKey.size}Bytes")
        println("Bob: Pub=${bobPubKey.size}Bytes,Priv=${bobPrivateKey.size}Bytes")

    }

    @OptIn(ExperimentalStdlibApi::class)
    @Test
    fun testSessionKey(){
        val sessionKey = Encryption.generateSessionKey()
        println("Session-key: (${sessionKey.encoded.size} Bytes) ${sessionKey.encoded.toHexString()}")
    }

    @OptIn(ExperimentalStdlibApi::class)
    @Test
    fun testWrappingKey(){
        val sessionKey = Encryption.generateSessionKey()
        println("Session-key: (${sessionKey.encoded.size} Bytes) ${sessionKey.encoded.toHexString()}")

        val wrappedKey = Encryption.wrapKey(key = sessionKey, targetPublicKey = bobKp.public)
        println("Wrapped-key: (${wrappedKey.size} Bytes) ${wrappedKey.toHexString()}")

        val unwrappedKey = Encryption.unwrapKey(wrappedKey = wrappedKey, myPrivateKey = bobKp.private)
        println("Unwrapped-key: (${unwrappedKey.encoded.size} Bytes) ${unwrappedKey.encoded.toHexString()}")

        assertArrayEquals(sessionKey.encoded, unwrappedKey.encoded)

    }

    @OptIn(ExperimentalStdlibApi::class)
    @Test
    fun testEncryptDecrypt(){
        val sessionKey = Encryption.generateSessionKey()
        val msg = "Hello, Mom"

        val encryptedMsg = Encryption.encrypt(sessionKey, msg)
        val decryptedMsg = Encryption.decrypt(sessionKey, encryptedMsg)

        println("Message: (${msg.toByteArray().size} Bytes) $msg")
        println("Encrypted: (${encryptedMsg.size} Bytes) ${encryptedMsg.toHexString()}")
        println("Decrypted: (${decryptedMsg.toByteArray().size} Bytes) $decryptedMsg")

        assertEquals(msg, decryptedMsg)

    }

    @Test
    fun testKeypairEncoding(){
        val base64PublicKey = Encryption.keyBytesToBase64(aliceKp.public.encoded)
        val publicKeyBytes = Encryption.base64ToKeyBytes(base64PublicKey)

        val base64PrivateKey = Encryption.keyBytesToBase64(aliceKp.private.encoded)
        val privateKeyBytes = Encryption.base64ToKeyBytes(base64PrivateKey)

        assertArrayEquals(aliceKp.public.encoded, publicKeyBytes)
        assertArrayEquals(aliceKp.private.encoded, privateKeyBytes)
    }

    @Test
    fun testRecoverSessionKey(){
        val sessionKey = Encryption.generateSessionKey()
        val base64SessionKey = Encryption.keyBytesToBase64(sessionKey.encoded)
        val sessionKeyBytes = Encryption.base64ToKeyBytes(base64SessionKey)

        val recoveredSessionKey = Encryption.recoverSessionkey(sessionKeyBytes)
        assertArrayEquals(sessionKey.encoded, recoveredSessionKey.encoded)
    }

    @Test
    fun testRecoverKeypair(){
        val base64PublicKey = Encryption.keyBytesToBase64(aliceKp.public.encoded)
        val publicKeyBytes = Encryption.base64ToKeyBytes(base64PublicKey)

        val base64PrivateKey = Encryption.keyBytesToBase64(aliceKp.private.encoded)
        val privateKeyBytes = Encryption.base64ToKeyBytes(base64PrivateKey)

        val recoveredPublicKey = Encryption.recoverPublicKey(publicKeyBytes)
        val recoveredPrivateKey = Encryption.recoverPrivateKey(privateKeyBytes)

        assertArrayEquals(aliceKp.public.encoded, recoveredPublicKey.encoded)
        assertArrayEquals(aliceKp.private.encoded, recoveredPrivateKey.encoded)

    }


}