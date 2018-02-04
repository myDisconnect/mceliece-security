package com.andrius.masterThesis.mceliece

import java.nio.charset.{Charset, StandardCharsets}
import java.security._

import com.andrius.masterThesis.mceliece.McElieceCryptosystem._
import com.andrius.masterThesis.utils.{Logging, Vector}
import org.bouncycastle.pqc.crypto.mceliece.{McEliecePrivateKeyParameters, McEliecePublicKeyParameters}
import org.bouncycastle.pqc.jcajce.provider.mceliece.{BCMcEliecePrivateKey, BCMcEliecePublicKey}
import org.bouncycastle.pqc.math.linearalgebra.{GF2Matrix, GF2Vector, GF2mField, GoppaCode, Permutation, PolynomialGF2mSmallM, PolynomialRingGF2}

/**
  * Original McEliece cryptosystem (A wrapper for bouncycastle McEliece implementation with small modifications
  * and more flexible methods)
  *
  * @see R.J. McEliece. A public-key cryptosystem based on algebraic. (https://tmo.jpl.nasa.gov/progress_report2/42-44/44N.PDF)
  * @see Great introductory slides about McEliece: http://www-math.ucdenver.edu/~wcherowi/courses/m5410/mcleice.pdf
  * @see for public/private keys generation implementation source: org.bouncycastle.pqc.crypto.mceliece.McElieceKeyPairGenerator
  * @see for encryption/decryption implementation source: org.bouncycastle.pqc.crypto.mceliece.McElieceCipher
  * @param config McEliece configuration parameters
  */
class McElieceCryptosystem(config: Configuration) {

  private val sr = new SecureRandom

  // Degree of the finite field GF(2^m)
  private val m: Int = config.m

  // Error correction capability of the code
  private val t: Int = config.t

  // Linear code length
  private val n: Int = config.n

  // Linear code dimension
  private val k: Int = config.k

  // Generate original McEliece cryptosystem public and private keys
  private val generatedKeys = {
    // finite field GF(2^m)
    val fieldPoly = PolynomialRingGF2.getIrreduciblePolynomial(m)
    val field = new GF2mField(m, fieldPoly)

    // irreducible Goppa polynomial
    val gp = new PolynomialGF2mSmallM(field, t, PolynomialGF2mSmallM.RANDOM_IRREDUCIBLE_POLYNOMIAL, sr)

    // generate canonical check matrix
    val h = GoppaCode.createCanonicalCheckMatrix(field, gp)

    // compute short systematic form of check matrix
    val mmp = GoppaCode.computeSystematicForm(h, sr)
    val shortH = mmp.getSecondMatrix
    val p1 = mmp.getPermutation

    // compute short systematic form of generator matrix
    val shortG = shortH.computeTranspose.asInstanceOf[GF2Matrix]

    // extend to full systematic form
    val gPrime = shortG.extendLeftCompactForm

    // obtain number of rows of G (= dimension of the code)
    val k = shortG.getNumRows

    // generate random invertible (k x k)-matrix S and its inverse S^-1
    val matrixSandInverse = GF2Matrix.createRandomRegularMatrixAndItsInverse(k, sr)

    // generate random permutation P2
    val p2 = new Permutation(n, sr)

    // compute public matrix G=S*G'*P2
    val g = matrixSandInverse(0).rightMultiply(gPrime).asInstanceOf[GF2Matrix].rightMultiply(p2).asInstanceOf[GF2Matrix]
    if (config.verbose.keyPairGeneration) {
      Logging.keyPairGenerationResults(gp, gPrime, matrixSandInverse(0), p1.rightMultiply(p2))
    }
    // generate keys
    McElieceCryptosystem.McElieceKeyPair(
      new BCMcEliecePublicKey(new McEliecePublicKeyParameters(n, t, g)),
      new BCMcEliecePrivateKey(new McEliecePrivateKeyParameters(n, k, field, gp, p1, p2, matrixSandInverse(1)))
    )
  }

  val publicKey: BCMcEliecePublicKey = generatedKeys.publicKey
  private val privateKey = generatedKeys.privateKey

  /**
    * Encrypt vector with public key
    *
    * @param m message
    * @return cipher
    */
  def encryptVector(m: GF2Vector): GF2Vector = {
    val e = new GF2Vector(n, publicKey.getT, sr)
    val g = publicKey.getG
    val mG = g.leftMultiply(m)
    if (config.verbose.cipherGeneration) {
      Logging.cipherGenerationResults(m, mG.asInstanceOf[GF2Vector], e)
    }
    // compute mG+e
    mG.add(e).asInstanceOf[GF2Vector]
  }

  def encrypt(m: GF2Vector): Array[Byte] = {
    encryptVector(m).getEncoded
  }

  def encrypt(m: Array[Byte]): Array[Byte] =
    encrypt(Vector.computeMessageRepresentative(publicKey.getK, m))

  def encrypt(m: String): Array[Byte] =
    encrypt(m.getBytes(McElieceCryptosystem.Charset))

  /**
    * Decrypt vector with private key
    *
    * @param c cipher
    * @return message
    */
  def decryptVector(c: GF2Vector): GF2Vector = {
    val field = privateKey.getField
    val gp = privateKey.getGoppaPoly
    val sInv = privateKey.getSInv
    val p1 = privateKey.getP1
    val p2 = privateKey.getP2
    val h = privateKey.getH
    val qInv = privateKey.getQInv

    // compute permutation P = P1 * P2
    val p = p1.rightMultiply(p2)

    // compute P^-1
    val pInv = p.computeInverse

    // compute c P^-1
    val cPInv = c.multiply(pInv).asInstanceOf[GF2Vector]

    // compute syndrome of c P^-1
    val syndrome = h.rightMultiply(cPInv).asInstanceOf[GF2Vector]

    // decode syndrome
    var z = GoppaCode.syndromeDecode(syndrome, field, gp, qInv)
    var mSG = cPInv.add(z).asInstanceOf[GF2Vector]

    // multiply codeword with P1 and error vector with P
    mSG = mSG.multiply(p1).asInstanceOf[GF2Vector]
    z = z.multiply(p).asInstanceOf[GF2Vector]

    // extract mS (last k columns of mSG)
    val mS = mSG.extractRightVector(k)

    // compute plaintext vector
    sInv.leftMultiply(mS).asInstanceOf[GF2Vector]
  }

  def decrypt(c: GF2Vector): Array[Byte] = {
    val mVec = decryptVector(c)
    // compute and return plaintext
    Vector.computeMessage(mVec)
  }

  def decrypt(c: Array[Byte]): Array[Byte] = {
    val cVec = GF2Vector.OS2VP(n, c)
    decrypt(cVec)
  }

  def decryptString(encryptedByteMessage: Array[Byte]): String =
    new String(decrypt(encryptedByteMessage), McElieceCryptosystem.Charset)

}

object McElieceCryptosystem {

  val Charset: Charset = StandardCharsets.UTF_8

  case class Configuration(m: Int, t: Int, verbose: VerboseOptions = VerboseOptions()) {
    val n: Int = 1 << m
    val k: Int = n - m * t
  }

  case class McElieceKeyPair(publicKey: BCMcEliecePublicKey, privateKey: BCMcEliecePrivateKey)

  case class VerboseOptions(
                             keyPairGeneration: Boolean = false,
                             cipherGeneration: Boolean = false,
                             partialResults: Boolean = true,
                             totalResults: Boolean = true,
                             ramUsage: Boolean = false
                           )

}
