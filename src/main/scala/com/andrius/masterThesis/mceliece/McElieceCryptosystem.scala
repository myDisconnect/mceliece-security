package com.andrius.masterThesis.mceliece

import com.andrius.masterThesis.mceliece.McElieceCryptosystem._
import com.andrius.masterThesis.utils.Vector
import java.nio.charset.{Charset, StandardCharsets}
import java.security._
import javax.crypto.Cipher

import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider
import org.bouncycastle.pqc.jcajce.provider.mceliece.{BCMcEliecePrivateKey, BCMcEliecePublicKey}
import org.bouncycastle.pqc.jcajce.spec.McElieceKeyGenParameterSpec
import org.bouncycastle.pqc.math.linearalgebra.GF2Vector

import scala.util.Random

/**
  * Original McEliece cryptosystem
  *
  * @see for encryption/decryption source: org.bouncycastle.pqc.crypto.mceliece.McElieceCipher
  * @param config McEliece configuration parameters
  */
class McElieceCryptosystem(config: McElieceConfiguration) {

  private val sr = new SecureRandom

  val Debug: Boolean = config.debugOptions.verbose

  // Generate original McEliece cryptosystem public and private keys
  val (publicKey: BCMcEliecePublicKey, privateKey: BCMcEliecePrivateKey, params: McElieceKeyGenParameterSpec) = config match {
    case file: FileConfiguration =>

    case basic: BasicConfiguration =>
      val params = new McElieceKeyGenParameterSpec(basic.m, basic.t)
      val keyPairGenerator = KeyPairGenerator.getInstance(AlgorithmName)
      keyPairGenerator.initialize(params)
      val keys = keyPairGenerator.generateKeyPair
      (keys.getPublic, keys.getPrivate, params)
  }
  val n: Int = 1 << params.getM // 2^m.
  // Linear code dimension security parameter k:
  val k: Int = n - params.getM * params.getT

  def encryptVector(m: GF2Vector): GF2Vector = {
    val z = new GF2Vector(n, publicKey.getT, sr)
    val g = publicKey.getG
    val mG = g.leftMultiply(m)
    // m*G+z
    mG.add(z).asInstanceOf[GF2Vector]
  }

  def encrypt(m: GF2Vector): Array[Byte] = {
    encryptVector(m).getEncoded
  }

  def encrypt(plainByteMessage: Array[Byte]): Array[Byte] =
    encrypt(Vector.computeMessageRepresentative(publicKey.getK, plainByteMessage))

  def encrypt(plainStringMessage: String): Array[Byte] =
    encrypt(plainStringMessage.getBytes(McElieceCryptosystem.Charset))

  def decrypt(encryptedMessage: Array[Byte]): Array[Byte] = {
    cipher.init(Cipher.DECRYPT_MODE, privateKey, params)
    cipher.doFinal(encryptedMessage)
  }

  def decryptString(encryptedByteMessage: Array[Byte]): String =
    new String(decrypt(encryptedByteMessage), McElieceCryptosystem.Charset)

  /*def generateRandomMessage: Array[Byte] = {
    cipher.init(Cipher.ENCRYPT_MODE, publicKey, params)
    val plainTextSize = cipher.getBlockSize
    val mLength = Random.nextInt(plainTextSize) + 1
    val mBytes = new Array[Byte](mLength)
    Random.nextBytes(mBytes)
    mBytes
  }*/

}

object McElieceCryptosystem {

  val Charset: Charset = StandardCharsets.UTF_8
  // @TODO for simplicity just move it to constructor
  // @TODO remove abstractions, they ugly (use McElieceCipher)
  // Load BouncyCastle algorithms
  Security.addProvider(new BouncyCastlePQCProvider)
  lazy val AlgorithmName: String = "McEliece"
  lazy val cipher: Cipher = Cipher.getInstance(AlgorithmName)

  def computeMessageString(mr: GF2Vector): String = new String(Vector.computeMessage(mr), Charset)

  sealed trait McElieceConfiguration {
    val debugOptions: DebugOptions
  }

  /**
    *
    * @param m            degree of the finite field GF(2^m)
    * @param t            error correction capability of the code
    * @param debugOptions Options for debugging
    */
  case class BasicConfiguration(m: Int, t: Int, debugOptions: DebugOptions = DebugOptions()) extends McElieceConfiguration

  /**
    *
    * @param filename     File to read mcEliece keys
    * @param debugOptions Options for debugging
    */
  case class FileConfiguration(filename: String, debugOptions: DebugOptions = DebugOptions()) extends McElieceConfiguration

  case class DebugOptions(verbose: Boolean = false, writeToFile: Option[String] = None)

}
