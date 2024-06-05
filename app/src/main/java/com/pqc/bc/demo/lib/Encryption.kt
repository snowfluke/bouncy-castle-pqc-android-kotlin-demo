package com.pqc.bc.demo.lib

import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider
import org.bouncycastle.pqc.jcajce.spec.NTRUParameterSpec
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Security
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

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

        fun keyBytesToBase64(key: ByteArray): String{
            return Base64.getEncoder().encodeToString(key)
        }

        fun base64ToKeyBytes(base64: String): ByteArray {
            return Base64.getDecoder().decode(base64)
        }


        fun recoverPublicKey(pubKey: ByteArray): PublicKey {
            val keyFactory = KeyFactory.getInstance(ASYM_ALGO, PQC_PROVIDER_NAME)
            val encodedKey = X509EncodedKeySpec(pubKey)

            return  keyFactory.generatePublic(encodedKey)
        }

        fun recoverPrivateKey(privKey: ByteArray): PrivateKey {
            val keyFactory = KeyFactory.getInstance(ASYM_ALGO, PQC_PROVIDER_NAME)
            val encodedKey = PKCS8EncodedKeySpec(privKey)

            return  keyFactory.generatePrivate(encodedKey)
        }

        fun recoverSessionkey(key: ByteArray): SecretKey {
            return SecretKeySpec(key, SYM_ALGO)
        }

    }

}