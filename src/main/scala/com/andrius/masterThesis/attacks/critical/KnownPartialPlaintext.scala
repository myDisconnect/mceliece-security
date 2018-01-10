package com.andrius.masterThesis.attacks.critical

import com.andrius.masterThesis.attacks.critical.KnownPartialPlaintext.ReducedSecurityComplexity
import com.andrius.masterThesis.utils.Matrix
import org.bouncycastle.pqc.crypto.mceliece.McEliecePublicKeyParameters
import org.bouncycastle.pqc.jcajce.provider.mceliece.BCMcEliecePublicKey
import org.bouncycastle.pqc.math.linearalgebra.{GF2Matrix, GF2Vector}

/**
  * Known partial plaintext attack
  *
  * @param publicKey McEliece public key
  */
class KnownPartialPlaintext(publicKey: BCMcEliecePublicKey) {
  val g: GF2Matrix = publicKey.getG
  val n: Int = g.getNumColumns
  val k: Int = g.getNumRows
  val t: Int = publicKey.getT

  /**
    *
    * @param cKnownRight known message vector
    * @param c cipher
    * @return
    */
  def attack(cKnownRight: GF2Vector, c: GF2Vector): ReducedSecurityComplexity = {
    val kRight = cKnownRight.getLength
    val kLeft = k - kRight

    val gRight = Matrix.matrixFromRows(g, Range(kLeft, k).toList)
    val gLeft = Matrix.matrixFromRows(g, Range(0, kLeft).toList)

    val cNew = c.add(gRight.leftMultiply(cKnownRight)).asInstanceOf[GF2Vector]
    val pubKeyNew = new BCMcEliecePublicKey(new McEliecePublicKeyParameters(n, t, gLeft))

    ReducedSecurityComplexity(cNew, pubKeyNew)
  }

}

object KnownPartialPlaintext {
  case class ReducedSecurityComplexity( cipher: GF2Vector, publicKey: BCMcEliecePublicKey)
}
