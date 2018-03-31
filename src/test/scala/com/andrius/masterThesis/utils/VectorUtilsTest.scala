package com.andrius.masterThesis.utils

import org.scalatest.FlatSpec

class VectorUtilsTest extends FlatSpec {

  "createModifiedGF2Vector" should "create modified vector in selected positions" in {
    val vector = VectorUtils.createGF2Vector(List(0, 1, 1, 0, 1))
    val invertedColumnList = List(1, 3, 4)

    val vectorExpected = VectorUtils.createGF2Vector(List(0, 0, 1, 1, 0))

    assert(
      VectorUtils.subtractColumnPositions(vector, invertedColumnList).equals(vectorExpected),
      "Incorrectly implemented createModifiedGF2Vector"
    )
  }

}
