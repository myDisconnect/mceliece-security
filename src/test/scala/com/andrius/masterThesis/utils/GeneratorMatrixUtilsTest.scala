package com.andrius.masterThesis.utils

import org.bouncycastle.pqc.math.linearalgebra.{GF2Matrix, GF2Vector}
import org.scalatest.FlatSpec

class GeneratorMatrixUtilsTest extends FlatSpec {

  "findNullSpace" should "find non-systematic parity-check matrix generator matrix" in {
    val testH = MatrixUtils.createGF2Matrix(Seq(
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
    val testG = GeneratorMatrixUtils.findNullSpace(testH)
    val testGCodewords = GeneratorMatrixUtils.generateAllCodewords(testG)

    assert(
      testGCodewords.forall(testHTransposed.leftMultiply(_).asInstanceOf[GF2Vector].getHammingWeight == 0),
      "nullSpace implemented incorrectly"
    )
  }

  "generateAllCodewords" should "generate all possible codewords" in {
    val g = MatrixUtils.createGF2Matrix(Seq(
      Seq(1, 1, 1, 1),
      Seq(1, 0, 0, 0)
    ))
    val expectedResult = List(
      VectorUtils.createGF2Vector(Seq(0, 0, 0, 0)),
      VectorUtils.createGF2Vector(Seq(1, 0, 0, 0)),
      VectorUtils.createGF2Vector(Seq(1, 1, 1, 1)),
      VectorUtils.createGF2Vector(Seq(0, 1, 1, 1))
    )
    assert(GeneratorMatrixUtils.generateAllCodewords(g) == expectedResult)

    val g2 = MatrixUtils.createGF2Matrix(Seq(
      Seq(1, 0, 1, 1),
      Seq(0, 1, 0, 0)
    ))
    val expectedResult2 = List(
      VectorUtils.createGF2Vector(Seq(0, 0, 0, 0)),
      VectorUtils.createGF2Vector(Seq(0, 1, 0, 0)),
      VectorUtils.createGF2Vector(Seq(1, 0, 1, 1)),
      VectorUtils.createGF2Vector(Seq(1, 1, 1, 1))
    )
    assert(GeneratorMatrixUtils.generateAllCodewords(g2) == expectedResult2)
  }

}
