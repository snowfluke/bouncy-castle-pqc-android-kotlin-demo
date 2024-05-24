package com.pqc.bc.demo.lib

import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider
import org.bouncycastle.pqc.jcajce.spec.NTRUParameterSpec
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Security
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

class Encryption {

    companion object {
        private const val PROVIDER_NAME = "BC"
        private const val PQC_PROVIDER_NAME = "BCPQC"
        private const val SYM_ALGO = "AES"
        private const val SYM_KEYSIZE = 128
        private const val ASYM_ALGO = "NTRU"

        init {
            Security.addProvider(BouncyCastleProvider())
            Security.addProvider(BouncyCastlePQCProvider())
        }

//      NTRU
        fun generateKeypair(): KeyPair {
            val keygen = KeyPairGenerator.getInstance(ASYM_ALGO, PQC_PROVIDER_NAME)
            val ntruParameterSpec = NTRUParameterSpec.ntruhrss701

            keygen.initialize(ntruParameterSpec)
            return keygen.generateKeyPair()
        }

//        AES
        fun generateSessionKey(): SecretKey {
            val keygen = KeyGenerator.getInstance(SYM_ALGO, PROVIDER_NAME)
            keygen.init(SYM_KEYSIZE)

            return keygen.generateKey()

        }

        fun wrapKey(key: SecretKey, targetPublicKey: PublicKey): ByteArray {
            val cipher = Cipher.getInstance(ASYM_ALGO, PQC_PROVIDER_NAME)
            cipher.init(Cipher.WRAP_MODE, targetPublicKey)

            return cipher.wrap(key)
        }

        fun unwrapKey(wrappedKey: ByteArray, myPrivateKey: PrivateKey): SecretKey {
            val cipher = Cipher.getInstance(ASYM_ALGO, PQC_PROVIDER_NAME)
            cipher.init(Cipher.UNWRAP_MODE, myPrivateKey)

            return cipher.unwrap(wrappedKey, SYM_ALGO, Cipher.SECRET_KEY) as SecretKey

        }

        fun encrypt(sessionKey: SecretKey, msg: String): ByteArray{
            val cipher = Cipher.getInstance(SYM_ALGO, PROVIDER_NAME)
            cipher.init(Cipher.ENCRYPT_MODE, sessionKey)

            return cipher.doFinal(msg.toByteArray())
        }

        fun decrypt(sessionKey: SecretKey, cipherText: ByteArray): String {
            val cipher = Cipher.getInstance(SYM_ALGO, PROVIDER_NAME)
            cipher.init(Cipher.DECRYPT_MODE, sessionKey)

            return cipher.doFinal(cipherText).decodeToString()
        }

    }

}