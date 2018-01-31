package com.andrius.masterThesis.attacks.structural

import com.andrius.masterThesis.utils.Matrix
import org.bouncycastle.pqc.crypto.mceliece.McEliecePublicKeyParameters
import org.bouncycastle.pqc.jcajce.provider.mceliece.BCMcEliecePublicKey
import org.bouncycastle.pqc.math.linearalgebra.GF2Matrix
import org.scalatest.FlatSpec

class SupportSplittingAlgorithmTest extends FlatSpec {

  behavior of "SupportSplittingAlgorithmTest"

  it should "generateAllCodewords" in {

    val g = Matrix.createGF2Matrix(Seq(
      Seq(1, 0, 0, 0),
      Seq(0, 1, 0, 0),
      Seq(0, 0, 1, 0),
      Seq(0, 0, 0, 1)
    ))
    val publicKey = new BCMcEliecePublicKey(new McEliecePublicKeyParameters(g.getNumColumns, 0, g))
    val ssa = new SupportSplittingAlgorithm(publicKey)
    assert(ssa.generateAllCodewords(g).length == 16, "Not all codewords were generated")
  }

  it should "execute ssa and never fail" in {
    val g = Matrix.createGF2Matrix(Seq(
      Seq(1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1),
      Seq(0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0),
      Seq(0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1),
      Seq(0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1),
      Seq(0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0),
      Seq(0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1),
      Seq(0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 1, 0),
      Seq(0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 1, 1, 0, 0, 1, 1, 1),
      Seq(0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 0, 0, 0),
      Seq(0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 1, 0, 0, 0, 1, 0)
    ))
    val publicKey = new BCMcEliecePublicKey(new McEliecePublicKeyParameters(g.getNumColumns, 0, g))
    val g2 = new GF2Matrix(g)
    val ssa = new SupportSplittingAlgorithm(publicKey)

    val gCodewords = ssa.generateAllCodewords(g)
    val cCodewords = ssa.generateAllCodewords(g2)
    ssa.ssa(gCodewords, cCodewords)
    // An exception means no permutation was found
  }

  it should "attack and never fail" in {

  }

}
