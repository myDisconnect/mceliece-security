package com.andrius.masterThesis.utils

import org.scalatest.FlatSpec

class MatrixTest extends FlatSpec {

  "identity" should "create identity matrix a.k.a eye" in {
    val identityMatrixExpected = Matrix.createGF2Matrix(
      Seq(
        Seq(1, 0, 0, 0),
        Seq(0, 1, 0, 0),
        Seq(0, 0, 1, 0),
        Seq(0, 0, 0, 1)
      )
    )
    assert(
      Matrix.identity(4, 4).equals(identityMatrixExpected),
      "Identity matrix implemented incorrectly"
    )
  }

  "getSubMatrix" should "get selected matrix sub view" in {
    val identityMatrix = Matrix.identity(4, 4)
    val submatrixExpected = Matrix.createGF2Matrix(
      Seq(
        Seq(0, 0),
        Seq(1, 0)
      )
    )
    assert(
      Matrix.getSubMatrix(identityMatrix, 1, 2, 2, 3).equals(submatrixExpected),
      "get submatrix implemented incorrectly"
    )
  }
}
