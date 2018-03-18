package com.andrius.masterThesis.utils

import org.bouncycastle.pqc.math.linearalgebra.{GF2Matrix, GF2Vector}
import org.scalatest.FlatSpec

class GeneratorParityCheckMatrixTest extends FlatSpec {

  "findNullSpace" should "find non-systematic parity-check matrix generator matrix" in {
    val testH = Matrix.createGF2Matrix(Seq(
      Seq(1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 1, 0, 1),
      Seq(0, 1, 0, 1, 0, 1, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0),
      Seq(1, 1, 1, 1, 1, 0, 1, 0, 0, 1, 0, 1, 0, 0, 0, 0),
      Seq(1, 1, 1, 1, 1, 0, 1, 0, 0, 0, 0, 0, 1, 1, 1, 1),
      Seq(0, 1, 0, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1, 1, 1, 1),
      Seq(1, 0, 0, 1, 0, 1, 1, 1, 0, 1, 0, 0, 1, 1, 1, 1),
      Seq(0, 0, 0, 1, 1, 1, 0, 1, 0, 0, 1, 0, 1, 1, 0, 1),
      Seq(1, 1, 0, 1, 0, 1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 1)
    ))
    val testHTransposed = testH.computeTranspose().asInstanceOf[GF2Matrix]
    val testG = GeneratorParityCheckMatrix.findNullSpace(testH)
    val testGCodewords = GeneratorParityCheckMatrix.generateAllCodewords(testG)
    println(testGCodewords, testGCodewords.length, testGCodewords.map(_.toString).distinct.length)
    assert(
      testGCodewords.forall(testHTransposed.leftMultiply(_).asInstanceOf[GF2Vector].getHammingWeight == 0),
      "nullSpace implemented incorrectly"
    )

  }

}
