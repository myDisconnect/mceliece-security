package com.andrius.masterThesis.attacks.critical

import com.andrius.masterThesis.mceliece.McElieceCryptosystem.McEliecePublicKey
import com.andrius.masterThesis.utils.{MathUtils, MatrixUtils, VectorUtils}
import org.bouncycastle.pqc.math.linearalgebra.{GF2Matrix, GF2Vector}

import scala.collection.mutable
import scala.collection.mutable.ListBuffer

/**
  * @see Thomas A. Berson. Failure of the McEliece Public-Key Cryptosystem Under Message-Resend and Related-Message Attack
  *      (https://link.springer.com/content/pdf/10.1007%2FBFb0052237.pdf)
  * @param publicKey McEliece public key
  */
class RelatedMessage(publicKey: McEliecePublicKey) {

  val g: GF2Matrix = publicKey.gPublic
  val n: Int = g.getNumColumns
  val k: Int = g.getNumRows
  val t: Int = publicKey.t

  /**
    * Trying to find error vector and solve it's linear equation.
    * This attack is almost exactly like Message-Resend attack(1), except messages m1 and m2 are not equal
    * and we know the linear relation between m1 and m2.
    *
    * Main relation: e1 + e2 = c1 + c2 + delta(m1 + m2) * G'
    * WARNING: This attack has a chance to return incorrect message vector when:
    * - selected incorrect error vector from the sum
    * - selected incorrect error vector from missing positions
    *
    * @param c1 cipher for message m
    * @param c2 cipher for message m
    * @param mDelta linear relation between m1 and m2
    * @return message vector
    */
  def attack1(c1: GF2Vector, c2: GF2Vector, mDelta: GF2Vector): GF2Vector = {
    new MessageResend(publicKey).attack1(c1, g.leftMultiply(mDelta).add(c2).asInstanceOf[GF2Vector])
  }

  /**
    * Looking for a G relation with error free positions in the ciphertexts.
    * This attack is almost exactly like Message-Resend attack(2), except messages m1 and m2 are not equal
    * and we know the linear relation between m1 and m2.
    *
    * Main relation: e1 + e2 = c1 + c2 + delta(m1 + m2) * G'
    * WARNING: This attack has a chance to return incorrect message vector (error vectors e1 and e2 ones collision case)
    *
    * @see com.andrius.masterThesis.attacks.critical.MessageResend
    * @param c1     cipher for message m1
    * @param c2     cipher for message m2
    * @param mDelta linear relation between m1 and m2
    * @return message vector
    */
  def attack2(c1: GF2Vector, c2: GF2Vector, mDelta: GF2Vector): GF2Vector = {
    new MessageResend(publicKey).attack2(c1, g.leftMultiply(mDelta).add(c2).asInstanceOf[GF2Vector])
  }

}
