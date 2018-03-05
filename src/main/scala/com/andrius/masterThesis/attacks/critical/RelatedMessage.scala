package com.andrius.masterThesis.attacks.critical

import com.andrius.masterThesis.utils.{Math, Matrix, Vector}
import org.bouncycastle.pqc.jcajce.provider.mceliece.BCMcEliecePublicKey
import org.bouncycastle.pqc.math.linearalgebra.{GF2Matrix, GF2Vector}

import scala.collection.mutable
import scala.collection.mutable.ListBuffer
import scala.util.Random

/**
  * @see Thomas A. Berson. Failure of the McEliece Public-Key Cryptosystem Under Message-Resend and Related-Message Attack
  *      (https://link.springer.com/content/pdf/10.1007%2FBFb0052237.pdf)
  * @param publicKey McEliece public key
  */
class RelatedMessage(publicKey: BCMcEliecePublicKey) {

  val g: GF2Matrix = publicKey.getG
  val n: Int = publicKey.getG.getNumColumns
  val k: Int = publicKey.getG.getNumRows
  val t: Int = publicKey.getT

  /**
    * This attack is almost exactly like Message-Resend attack, except messages m1 and m2 are not equal
    * and we know the linear relation between m1 and m2
    *
    * Main relation: e1 + e2 = c1 + c2 + delta(m1 + m2) * G
    * WARNING: This attack has a chance to return incorrect message vector (error vectors e1 and e2 ones collision case)
    *
    * @see com.andrius.masterThesis.attacks.critical.MessageResend
    * @param c1     cipher for message m1
    * @param c2     cipher for message m2
    * @param mDelta linear relation between m1 and m2
    * @return message vector
    */
  def attack(c1: GF2Vector, c2: GF2Vector, mDelta: GF2Vector): GF2Vector = {
    var decipheredMsg = new GF2Vector(k)
    var found = false
    val failedTriesDictionary = new mutable.HashSet[Set[Int]]()
    val c1c2delta = g.leftMultiply(mDelta).add(c1.add(c2)).asInstanceOf[GF2Vector]
    val collisionFreePositions = new ListBuffer[Int]()
    for (j <- 0 until c1c2delta.getLength) {
      if (c1c2delta.getBit(j) != 1) {
        collisionFreePositions += j
      }
    }
    val collisionFreePositionList = collisionFreePositions.toList
    while (!found) {
      // Let's take a random sample from most likely error-free vectors
      val colPositions = Math.sample(collisionFreePositionList, k)
      // Order is not important, because columns are linearly independent
      val iSet = colPositions.toSet
      if (!failedTriesDictionary.contains(iSet)) {
        failedTriesDictionary += iSet
        val newMatSeq = Matrix.createGF2MatrixFromColumns(g, colPositions)

        try {
          val restrictedPub = newMatSeq.computeInverse().asInstanceOf[GF2Matrix]
          found = true
          val c1Prime = Vector.createGF2VectorFromColumns(c1, colPositions)
          decipheredMsg = restrictedPub.leftMultiply(c1Prime).asInstanceOf[GF2Vector]
        } catch {
          case _: ArithmeticException =>
          // Matrix is not invertible
        }
      }
    }
    decipheredMsg
  }
}
