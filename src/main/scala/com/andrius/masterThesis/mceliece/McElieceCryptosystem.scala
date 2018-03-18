package com.andrius.masterThesis.mceliece

import java.nio.charset.{Charset, StandardCharsets}
import java.security._

import com.andrius.masterThesis.mceliece.McElieceCryptosystem._
import com.andrius.masterThesis.utils.{GeneratorParityCheckMatrix, Goppa, Logging, Vector}
import org.bouncycastle.pqc.math.linearalgebra.{GF2Matrix, GF2Vector, GF2mField, GoppaCode, Permutation, PolynomialGF2mSmallM, PolynomialRingGF2, PolynomialRingGF2m}

/**
  * McEliece public key cryptosystem implementation
  *
  * Notes on current implementation used:
  * - The systematic generator matrix is recovered from parity-check matrix via Permutation
  *
  * @see R.J. McEliece. A public-key cryptosystem based on algebraic. (https://tmo.jpl.nasa.gov/progress_report2/42-44/44N.PDF)
  * @see Great introductory slides about McEliece: http://www-math.ucdenver.edu/~wcherowi/courses/m5410/mcleice.pdf
  * @see for public/private keys generation implementation source: org.bouncycastle.pqc.crypto.mceliece.McElieceKeyPairGenerator
  * @see for encryption/decryption implementation source: org.bouncycastle.pqc.crypto.mceliece.McElieceCipher
  * @param config McEliece configuration parameters
  */
class McElieceCryptosystem(config: Configuration) {
  import McElieceCryptosystem._

  private val sr = new SecureRandom

  // Degree of the finite field GF(2^m)
  val m: Int = config.m

  // Error correction capability of the code
  val t: Int = config.t

  // Linear code length
  val n: Int = config.n

  // Linear code dimension
  val k: Int = config.k

  // Generate original McEliece cryptosystem public and private keys
  private val generatedKeys = {
    // finite field GF(2^m)
    // @todo remove this
    val fieldPoly = PolynomialRingGF2.getIrreduciblePolynomial(m)
    //val fieldPoly = Goppa.getIrreduciblePolynomial(m)
    val field = new GF2mField(m, fieldPoly)

    // irreducible Goppa polynomial
    val gp = new PolynomialGF2mSmallM(field, t, PolynomialGF2mSmallM.RANDOM_IRREDUCIBLE_POLYNOMIAL, sr)
    val ring = new PolynomialRingGF2m(field, gp)

    // matrix used to compute square roots in (GF(2^m))^t
    val sqRootMatrix = ring.getSquareRootMatrix

    // generate (k x n) canonical check matrix
    val h = GoppaCode.createCanonicalCheckMatrix(field, gp)

    // get (k x n) generator matrix from parity check matrix
    //val g = GeneratorParityCheckMatrix.findNullSpace(h)

    // canonical parity-check matrix is not always can be converted to systematic, so we permute it
    // @see https://math.stackexchange.com/a/348046/538670
    val mmp = GoppaCode.computeSystematicForm(h, sr)
    val shortH = mmp.getSecondMatrix
    val p1 = mmp.getPermutation

    // compute short systematic form of generator matrix
    val shortG = shortH.computeTranspose.asInstanceOf[GF2Matrix]

    // obtain number of rows of G (= dimension of the code)
    val k = shortG.getNumRows

    // extend to full systematic form
    val gPrime = shortG.extendLeftCompactForm

    // generate random invertible (k x k)-matrix S and its inverse S^-1
    val matrixSandInverse = GF2Matrix.createRandomRegularMatrixAndItsInverse(k, sr)

    // generate random n-length permutation P
    val p = new Permutation(n, sr)

    // compute public matrix G' = S * G * P
    val gPub = matrixSandInverse(0).rightMultiply(gPrime).rightMultiply(p).asInstanceOf[GF2Matrix]

    if (config.verbose.keyPairGeneration) {
      Logging.keyPairGenerationResults(gp, gPrime, matrixSandInverse(0), p1.rightMultiply(p))
    }
    // generate public and private keys
    // we pass parity-check matrix to private key for syndrome decoding
    McElieceKeyPair(
      McEliecePublicKey(gPub, t, p1),
      McEliecePrivateKey(matrixSandInverse(1), h, p1.rightMultiply(p).computeInverse, field, gp, sqRootMatrix)
    )
  }

  val publicKey: McEliecePublicKey = generatedKeys.publicKey
  // This should be always private, but in order to test SSA left public
  val privateKey: McEliecePrivateKey = generatedKeys.privateKey

  /**
    * Encrypt message vector with public key
    *
    * @param m message vector
    * @return cipher vector
    */
  def encryptVector(m: GF2Vector): GF2Vector = {
    // generate random n-length vector of t hamming weight
    val e = new GF2Vector(n, t, sr)
    // compute m * G'
    val mG = publicKey.gPublic.leftMultiply(m)

    if (config.verbose.cipherGeneration) {
      Logging.cipherGenerationResults(m, mG.asInstanceOf[GF2Vector], e)
    }
    // compute c = m * G' + e
    mG.add(e).asInstanceOf[GF2Vector]
  }

  /**
    * Encrypt message vector with public key
    *
    * @param m message vector
    * @return cipher byte array
    */
  def encrypt(m: GF2Vector): Array[Byte] = {
    encryptVector(m).getEncoded
  }

  /**
    * Encrypt message byte array with public key
    *
    * @param m message byte array
    * @return cipher byte array
    */
  def encrypt(m: Array[Byte]): Array[Byte] = {
    encrypt(Vector.computeMessageRepresentative(k, m))
  }

  /**
    * Encrypt UTF-8 message string with public key
    *
    * @param m UTF-8 message string
    * @return message byte array
    */
  def encrypt(m: String): Array[Byte] = {
    encrypt(m.getBytes(McElieceCryptosystem.Charset))
  }

  /**
    * Decrypt cipher vector with private key
    *
    * @param c cipher vector
    * @return message vector
    */
  def decryptVector(c: GF2Vector): GF2Vector = {
    // compute c * P^-1
    val cPInv = c.multiply(privateKey.pInv).asInstanceOf[GF2Vector]

    // compute syndrome
    val syndrome = privateKey.h.rightMultiply(cPInv).asInstanceOf[GF2Vector]

    // decode syndrome
    val e = GoppaCode.syndromeDecode(syndrome, privateKey.field, privateKey.gp, privateKey.qInv)

    // subtract error vector
    val mSG = cPInv.add(e).multiply(publicKey.pLocal).asInstanceOf[GF2Vector]

    // extract mS (last k columns of mSG)
    val mS = mSG.extractRightVector(k)

    // compute plaintext vector
    privateKey.sInv.leftMultiply(mS).asInstanceOf[GF2Vector]
  }

  /**
    * Decrypt cipher vector with private key
    *
    * @param c cipher vector
    * @return message byte array
    */
  def decrypt(c: GF2Vector): Array[Byte] = {
    val mVec = decryptVector(c)
    // compute and return plaintext
    Vector.computeMessage(mVec)
  }

  /**
    * Decrypt cipher byte array with private key
    *
    * @param c cipher byte array
    * @return message byte array
    */
  def decrypt(c: Array[Byte]): Array[Byte] = {
    val cVec = GF2Vector.OS2VP(n, c)
    decrypt(cVec)
  }

  /**
    * Decrypt cipher byte array with private key
    *
    * @param c cipher byte array
    * @return message string
    */
  def decryptString(c: Array[Byte]): String = {
    new String(decrypt(c), McElieceCryptosystem.Charset)
  }

}

object McElieceCryptosystem {

  val Charset: Charset = StandardCharsets.UTF_8

  case class Configuration(m: Int, t: Int, verbose: VerboseOptions = VerboseOptions()) {
    val n: Int = 1 << m
    val k: Int = n - m * t
  }

  case class McEliecePublicKey(gPublic: GF2Matrix, t: Int, pLocal: Permutation)

  case class McEliecePrivateKey(
      sInv: GF2Matrix,
      h: GF2Matrix,
      pInv: Permutation,
      field: GF2mField,
      gp: PolynomialGF2mSmallM,
      // below parameter is not mandatory, added for convenience
      qInv: Array[PolynomialGF2mSmallM]
   )

  case class McElieceKeyPair(publicKey: McEliecePublicKey, privateKey: McEliecePrivateKey)

  case class VerboseOptions(
      keyPairGeneration: Boolean = false,
      cipherGeneration: Boolean = false,
      partialResults: Boolean = true,
      totalResults: Boolean = true,
      ramUsage: Boolean = false
  )

}
