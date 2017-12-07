package com.andrius.master

import java.nio.charset.StandardCharsets.UTF_8
import java.security.spec.{PKCS8EncodedKeySpec, X509EncodedKeySpec}
import java.security.{KeyFactory, KeyPairGenerator, SecureRandom, Security}
import javax.crypto.Cipher

import org.bouncycastle.crypto.InvalidCipherTextException
import org.bouncycastle.pqc.crypto.mceliece.{McElieceKeyGenerationParameters, McElieceKeyPairGenerator, McElieceParameters}
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider
import org.bouncycastle.pqc.jcajce.spec.McElieceKeyGenParameterSpec
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils
import scala.util.Random


object Main {

  def main(args: Array[String]): Unit = {
    //val name = StdIn.readInt("Enter Goppa polynomial degree m? ")
    // Goppa polynomial degree
    val m: Int = 9//3
    // Error correcting capability:
    val t: Int = 33//2
    // Linear code length security parameter n:
    val n: Int = 1 << m // 2^m.
    // Linear code dimension security parameter k:
    val k: Int = n - m * t

    val mcEliece = McEliece.initialize(m, t)
    println(mcEliece.decryptString(mcEliece.encrypt("hello")))
    //val kf = KeyFactory.getInstance("McEliece")
    val kpg = KeyPairGenerator.getInstance("McEliece")


    val params = new McElieceKeyGenParameterSpec(m, t)
    kpg.initialize(params)
    val keyPair = kpg.generateKeyPair

    var pubKey = keyPair.getPublic
    var privKey = keyPair.getPrivate

    /// now let's do something
    val cipher = Cipher.getInstance("McEliece")
    val msg = "Hello abudabi very nice".getBytes(UTF_8)
    cipher.init(Cipher.ENCRYPT_MODE, pubKey, params)
    val cBytes2 = cipher.doFinal(msg)
    cipher.init(Cipher.DECRYPT_MODE, privKey, params)
    val dBytes2 = cipher.doFinal(cBytes2)
    println(ByteUtils.equals(dBytes2, cBytes2), ByteUtils.toHexString(dBytes2), ByteUtils.toHexString(cBytes2))
    println(new String(dBytes2, "UTF-8"))
    // val initialize message

    // The kind of cipher we want to use:

    // initialize for encryption
    cipher.init(Cipher.ENCRYPT_MODE, pubKey, params, new SecureRandom)
    val plainTextSize = cipher.getBlockSize
    val mLength = Random.nextInt(plainTextSize) + 1
    val mBytes = new Array[Byte](mLength)
    Random.nextBytes(mBytes)
    // encrypt
    val cBytes = cipher.doFinal(mBytes)


    // initialize for decryption
    cipher.init(Cipher.DECRYPT_MODE, privKey, params)

    // decrypt
    val dBytes = cipher.doFinal(cBytes)

    println(ByteUtils.equals(dBytes, mBytes), ByteUtils.toHexString(dBytes), ByteUtils.toHexString(mBytes))
    // message decrypt

    /*val encPubKey = pubKey.getEncoded
    val encPrivKey = privKey.getEncoded
    println(encPubKey, encPrivKey)

    val pubKeySpec = new X509EncodedKeySpec(encPubKey)
    val privKeySpec = new PKCS8EncodedKeySpec(encPrivKey)

    val decPubKey = kf.generatePublic(pubKeySpec)
    val decPrivKey = kf.generatePrivate(privKeySpec)

    println(pubKey == decPubKey)
    println(privKey == decPrivKey)*/
    //performKeyPairEncodingTest()
    //KeyFactory.getInstance("McEliece")

    /*val a = new McEliece
    val message = "This is secret message!!!"
    val key = "Secret key!!!!!!"*/
  }

}