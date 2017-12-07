package com.andrius.master

import java.nio.charset.StandardCharsets.UTF_8
import java.security._
import javax.crypto.Cipher

import com.andrius.master.McEliece.cipher
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider
import org.bouncycastle.pqc.jcajce.spec.McElieceKeyGenParameterSpec


case class McEliece(params: McElieceKeyGenParameterSpec, keyPair: KeyPair) {

  def encrypt(plainByteMessage: Array[Byte]): Array[Byte] = {
    cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic, params)
    cipher.doFinal(plainByteMessage)
  }

  def encrypt(plainStringMessage: String): Array[Byte] =
    encrypt(plainStringMessage.getBytes(UTF_8))

  def decrypt(encryptedByteMessage: Array[Byte]): Array[Byte] = {
    cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate, params)
    cipher.doFinal(encryptedByteMessage)
  }

  def decryptString(encryptedByteMessage: Array[Byte]): String =
    new String(decrypt(encryptedByteMessage), UTF_8.displayName())

}

object McEliece {

  // Load BouncyCastle algorithms
  Security.addProvider(new BouncyCastlePQCProvider)

  lazy val AlgorithmName: String = "McEliece"
  lazy val keyPairGenerator: KeyPairGenerator = KeyPairGenerator.getInstance(AlgorithmName)
  lazy val cipher: Cipher = Cipher.getInstance(AlgorithmName)
  /**
    * Constructor.
    *
    * @param m degree of the finite field GF(2^m)
    * @param t error correction capability of the code
    */
  def initialize(m: Int, t: Int): McEliece = {
    val params = new McElieceKeyGenParameterSpec(m, t)
    keyPairGenerator.initialize(params)
    McEliece(
      params = params,
      keyPairGenerator.generateKeyPair
    )
  }
}
