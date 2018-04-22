package com.andrius.masterThesis.attacks.critical

import com.andrius.masterThesis.mceliece.McElieceCryptosystem.McEliecePublicKey
import com.andrius.masterThesis.utils.{CombinatoricsUtils, GeneratorMatrixUtils, MathUtils, MatrixUtils, VectorUtils}
import org.bouncycastle.pqc.math.linearalgebra.{GF2Matrix, GF2Vector}

import scala.collection.mutable
import scala.collection.mutable.ListBuffer
import scala.util.Random

/**
  * @see Thomas A. Berson. Failure of the McEliece Public-Key Cryptosystem Under Message-Resend and Related-Message Attack (https://link.springer.com/content/pdf/10.1007/BFb0052237.pdf)
  * @see P. L. Cayrel, C. T. Gueye, O. Ndiaye, R. Niebuhr. Critical attacks in code-based cryptography (https://www.researchgate.net/profile/Cheikh_Thiecoumba_Gueye/publication/281657709_Critical_attacks_in_code-based_cryptography/links/592c30c1aca27295a81024ce/Critical-attacks-in-code-based-cryptography.pdf)
  * @param publicKey McEliece public key
  */
class MessageResend(publicKey: McEliecePublicKey) {

  val g: GF2Matrix           = publicKey.gPublic
  val gTransposed: GF2Matrix = publicKey.gPublic.computeTranspose.asInstanceOf[GF2Matrix]
  val n: Int                 = g.getNumColumns
  val k: Int                 = g.getNumRows
  val t: Int                 = publicKey.t

  /**
    * Trying to find error vector and solve it's linear equation.
    *
    * Main relation: e1 + e2 = c1 + c2
    * WARNING: This attack has a chance to return incorrect message vector when:
    * - selected incorrect error vector from the sum
    * - selected incorrect error vector from missing positions
    *
    * @param c1 cipher for message m
    * @param c2 cipher for message m
    * @return message vector
    */
  def attack1(c1: GF2Vector, c2: GF2Vector): GF2Vector = {
    val c1c2Sum        = c1.add(c2).asInstanceOf[GF2Vector]
    val c1c2hw         = c1c2Sum.getHammingWeight
    val expectedErrors = 2 * t
    require(c1c2hw <= 2 * t, "Received ciphers are not from the same message")
    require(c1c2hw != 0, "Received ciphers are identical")

    // Let's precompute positions, where c1 or c2 are garbled by an error vector a.k.a
    // collision free error vector positions
    val l0 = ListBuffer.empty[Int]
    for (j <- 0 until c1c2Sum.getLength) {
      if (c1c2Sum.getBit(j) == 1) {
        l0 += j
      }
    }
    // Not all error-vector positions are known, some collision exist
    if (c1c2hw != expectedErrors) {
      for (el <- Random.shuffle((0 until c1c2Sum.getLength).diff(l0)).take((expectedErrors - c1c2hw) / 2)) {
        l0 += el
      }
    }
    val colPositions = MathUtils.sample(l0.toList, t)
    val cTry         = VectorUtils.subtractColumnPositions(c1, colPositions)

    GeneratorMatrixUtils.solve(gTransposed, cTry)
  }

  /**
    * Looking for a G relation with error free positions in the ciphertexts.
    * If these columns are linearly independent, then square matrix associated with them can be inverted,
    * and m can be retrieved.
    * Main relation: e1 + e2 = c1 + c2
    * WARNING: This attack has a chance to return incorrect message vector when:
    *  - error vectors e1 and e2 colide in the same positions and these positions are selected in
    *  linearly independent columns.
    *
    * @param c1 cipher for message m
    * @param c2 cipher for message m
    * @return message vector
    */
  def attack2(c1: GF2Vector, c2: GF2Vector): GF2Vector = {
    val c1c2Sum = c1.add(c2).asInstanceOf[GF2Vector]
    val c1c2hw  = c1c2Sum.getHammingWeight
    require(c1c2hw <= 2 * t, "Received ciphers are not from the same message")
    require(c1c2hw != 0, "Received ciphers are identical")

    var decipheredMsg         = new GF2Vector(k)
    var found                 = false
    val failedTriesDictionary = mutable.HashSet.empty[Set[Int]]

    // Let's precompute positions, where most probably neither c1 or c2 are garbled by an error vector
    val l1 = ListBuffer.empty[Int]
    for (j <- 0 until c1c2Sum.getLength) {
      if (c1c2Sum.getBit(j) == 0) {
        l1 += j
      }
    }
    val collisionFreePositionList = l1.toList
    val possibleTries             = CombinatoricsUtils.combinations(l1.length, k)
    var tries: BigInt             = 0
    while (!found && tries < possibleTries) {
      // Let's take a random sample from most likely error-free vectors
      val colPositions = MathUtils.sample(collisionFreePositionList, k)
      // Order is not important, because we are looking for linearly independent columns
      val iSet = colPositions.toSet
      if (!failedTriesDictionary.contains(iSet)) {
        tries += 1
        failedTriesDictionary += iSet
        val newMatSeq = MatrixUtils.createGF2MatrixFromColumns(g, colPositions)

        try {
          val restrictedPub = newMatSeq.computeInverse().asInstanceOf[GF2Matrix]
          found = true
          val c1Prime = VectorUtils.createGF2VectorFromColumns(c1, colPositions)
          decipheredMsg = restrictedPub.leftMultiply(c1Prime).asInstanceOf[GF2Vector]
        } catch {
          case _: ArithmeticException =>
          // Matrix is not invertible
        }
      }
    }
    if (!found) {
      throw new Exception("[Cannot decrypt message] Impossible to find linearly independent columns")
    }
    decipheredMsg
  }

}

object MessageResend {

  /**
    * Get correct error vector guess probability
    *
    * @param n        code length
    * @param t        error correction capability of the code
    * @param l1Length L1 list length
    * @return probability
    */
  def getAttack1GuessProbability(n: Int, t: Int, l1Length: Int): Double = {
    (1 / getAttack1TriesExpected(n, t, l1Length)).toDouble
  }

  /**
    * Get correct error vector guess probability
    *
    * @param k        code dimension
    * @param t        error correction capability of the code
    * @param l0Length L0 list length
    * @param l1Length L1 list length
    * @return probability
    */
  def getAttack2GuessProbability(k: Int, t: Int, l0Length: Int, l1Length: Int): Double = {
    val unknownErrors = t - l1Length / 2
    CombinatoricsUtils.combinations(l0Length - unknownErrors, k).toDouble /
      CombinatoricsUtils.combinations(l0Length, k).toDouble
  }

  /**
    * Get expected tries to find correct error vector
    *
    * @param n        code length
    * @param t        error correction capability of the code
    * @param l1Length L1 list length
    * @return expected tries
    */
  def getAttack1TriesExpected(n: Int, t: Int, l1Length: Int): Int = {
    val unknownErrors = t - l1Length / 2
    val knownErrors   = t - unknownErrors
    (CombinatoricsUtils.combinations(2 * knownErrors, knownErrors) *
      CombinatoricsUtils.combinations(n - t, unknownErrors)).toInt
  }

  /**
    * Get expected tries to find correct error vector
    *
    * @param n        code length
    * @param k        code dimension
    * @param t        error correction capability of the code
    * @param l1Length L1 list length
    * @return expected tries
    */
  def getAttack2TriesExpected(n: Int, k: Int, t: Int, l1Length: Int): Int = {
    (1 / getAttack2GuessProbability(n, k, t, l1Length)).toInt
  }

}
