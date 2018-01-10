package com.andrius.masterThesis.attacks.critical

import com.andrius.masterThesis.utils.Vector
import org.bouncycastle.pqc.jcajce.provider.mceliece.BCMcEliecePublicKey
import org.bouncycastle.pqc.math.linearalgebra.{GF2Matrix, GF2Vector}

import scala.collection.mutable.ListBuffer
import scala.util.Random

/**
  * @see Thomas A. Berson. Failure of the McEliece Public-Key Cryptosystem Under Message-Resend and Related-Message Attack
  *      (https://link.springer.com/content/pdf/10.1007%2FBFb0052237.pdf)
  * @param publicKey  McEliece public key
  */
class RelatedMessage(publicKey: BCMcEliecePublicKey) {

  // Only using transposed matrix, because moving columns is easier
  val g: GF2Matrix = publicKey.getG
  val gT: GF2Matrix = publicKey.getG.computeTranspose().asInstanceOf[GF2Matrix]
  val n: Int = publicKey.getG.getNumColumns
  val k: Int = publicKey.getG.getNumRows
  val t: Int = publicKey.getT

  /**
    * This attack is almost exactly like Message-Resend attack, except messages m1 and m2 are not equal
    * and we know the linear relation between m1 and m2
    *
    * Main relation: e1 + e2 = c1 + c2 + delta(m1 + m2) * G
    * Note: This attack has a chance to return incorrect message vector (error vectors e1 and e2 ones collision case)
    *
    * @see com.andrius.masterThesis.attacks.critical.MessageResend
    * @param c1 cipher for message m1
    * @param c2 cipher for message m2
    * @param mDelta linear relation between m1 and m2
    * @return message vector
    */
  def attack(c1: GF2Vector, c2: GF2Vector, mDelta: GF2Vector): GF2Vector = {
    var out = new GF2Vector(k, Array.fill((k - 1) / 32 + 1)(0))
    val c1c2delta = g.leftMultiply(mDelta).add(c1.add(c2)).asInstanceOf[GF2Vector]
    var found = false
    while (!found) {
      var i = 0
      val rowsSelected = new ListBuffer[Int]()
      val newMatSeq = Array.ofDim[Int](k, k)
      while (i < k) {
        val j = Random.nextInt(n)
        // Don’t select a row corresponding to one of the errors and don't take a row twice
        // This can fail if error vector contains 1 in the same place
        if (c1c2delta.getBit(j) != 1 && !rowsSelected.contains(j)) {
          rowsSelected += j
          newMatSeq(i) = gT.getRow(j)
          i += 1
        }
      }

      try {
        val restrictedPub = new GF2Matrix(k, newMatSeq)
          .computeTranspose()
          .asInstanceOf[GF2Matrix]
          .computeInverse()
          .asInstanceOf[GF2Matrix]
        found = true
        val c1Prime = Vector.vectorFromColumns(c1, rowsSelected.toList)
        out = restrictedPub.leftMultiply(c1Prime).asInstanceOf[GF2Vector]
      } catch {
        case _: ArithmeticException =>
        // Matrix is not invertible
      }
    }
    out
  }
}
