package com.andrius.masterThesis.attacks.critical

import com.andrius.masterThesis.attacks.critical.KnownPartialPlaintext.ReducedSecurityComplexity
import com.andrius.masterThesis.mceliece.McElieceCryptosystem.McEliecePublicKey
import com.andrius.masterThesis.utils.Matrix
import org.bouncycastle.pqc.math.linearalgebra.{GF2Matrix, GF2Vector}

/**
  * Known partial plaintext attack
  *
  * @see A. Canteaut, N, Sendrier. Cryptanalysis of the Original McEliece Cryptosystem (https://link.springer.com/content/pdf/10.1007/3-540-49649-1_16.pdf)
  * @see K. Kobara, H. Imai. Semantically secure McEliece public-key cryptosystems-conversions for McEliece PKC (https://link.springer.com/content/pdf/10.1007/3-540-44586-2_2.pdf)
  * @param publicKey McEliece public key
  */
class KnownPartialPlaintext(publicKey: McEliecePublicKey) {

  val g: GF2Matrix = publicKey.gPublic
  val n: Int = g.getNumColumns
  val k: Int = g.getNumRows
  val t: Int = publicKey.t

  /**
    * This attack only reduces the security complexity of the encrypted message.
    * Main relation: y = mG + e = m_left*G_left + m_right*G_right + e
    *
    * @param knownRight known message vector from right
    * @param c          cipher
    * @return
    */
  def attack(knownRight: GF2Vector, c: GF2Vector): ReducedSecurityComplexity = {
    val kRight = knownRight.getLength
    val kLeft = k - kRight

    val gRight = Matrix.createGF2MatrixFromRows(g, Range(kLeft, k).toList)
    val gLeft = Matrix.createGF2MatrixFromRows(g, Range(0, kLeft).toList)

    val cNew = c.add(gRight.leftMultiply(knownRight)).asInstanceOf[GF2Vector]
    val pubKeyNew = McEliecePublicKey(gLeft, t, publicKey.pLocal)

    ReducedSecurityComplexity(cNew, pubKeyNew)
  }

}

object KnownPartialPlaintext {

  case class ReducedSecurityComplexity(cipher: GF2Vector, publicKey: McEliecePublicKey)

}
