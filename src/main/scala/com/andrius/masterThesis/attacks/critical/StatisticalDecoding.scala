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
class StatisticalDecoding(publicKey: BCMcEliecePublicKey) {

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
  /*def attack(c1: GF2Vector, c2: GF2Vector, mDelta: GF2Vector): GF2Vector = {

  }*/
}
