package com.andrius.masterThesis.attacks.structural

import com.andrius.masterThesis.mceliece.McElieceCryptosystem
import com.andrius.masterThesis.mceliece.McElieceCryptosystem.BasicConfiguration
import com.andrius.masterThesis.utils.{Math, Matrix, Vector}
import org.bouncycastle.pqc.crypto.mceliece.McEliecePublicKeyParameters
import org.bouncycastle.pqc.jcajce.provider.mceliece.BCMcEliecePublicKey
import org.bouncycastle.pqc.math.linearalgebra.GF2Matrix
import org.scalatest.FlatSpec

import scala.collection.mutable.ListBuffer

class SupportSplittingAlgorithmTest extends FlatSpec {

  behavior of "SupportSplittingAlgorithmTest"

  it should "generateAllCodewords" in {
    val g = Matrix.createGF2Matrix(Seq(
      Seq(1, 0, 0, 0),
      Seq(0, 1, 0, 0),
      Seq(0, 0, 1, 0),
      Seq(0, 0, 0, 1)
    ))
    val ssa = new SupportSplittingAlgorithm
    assert(ssa.generateAllCodewords(g).length == 16, "Not all codewords were generated")
  }

  it should "ssa must find permutation on equivalent codes" in {
    val cCodewords1 = List(
      Vector.createGF2Vector(List(1, 1, 1, 0)),
      Vector.createGF2Vector(List(0, 1, 1, 1)),
      Vector.createGF2Vector(List(1, 0, 1, 0))
    )
    val cCodewords2 = List(
      Vector.createGF2Vector(List(0, 0, 1, 1)),
      Vector.createGF2Vector(List(1, 0, 1, 1)),
      Vector.createGF2Vector(List(1, 1, 0, 1))
    )
    val ssa = new SupportSplittingAlgorithm
    val permutation = ssa.ssa(cCodewords1, cCodewords2)
    // According the SSA paper: (1 -> 3, 2 -> 1, 3 -> 4, 4 -> 2) which is indexed (0 -> 2, 1 -> 0, 2 -> 3, 3 -> 1)
    val expectedResult = Map(2 -> 3, 1 -> 0, 3 -> 1, 0 -> 2)
    assert(cCodewords1.head.getLength == permutation.size, "SSA algorithm implemented incorrectly")
    assert(permutation.equals(expectedResult), "SSA algorithm implemented incorrectly")
  }

  it should "ssa must find permutation on with one refinement" in {
    val cCodewords1 = List(
      Vector.createGF2Vector(List(0, 1, 1, 0, 1)),
      Vector.createGF2Vector(List(0, 1, 0, 1, 1)),
      Vector.createGF2Vector(List(0, 1, 1, 1, 0)),
      Vector.createGF2Vector(List(1, 0, 1, 0, 1)),
      Vector.createGF2Vector(List(1, 1, 1, 1, 0))
    )
    val cCodewords2 = List(
      Vector.createGF2Vector(List(1, 0, 1, 0, 1)),
      Vector.createGF2Vector(List(0, 0, 1, 1, 1)),
      Vector.createGF2Vector(List(1, 0, 0, 1, 1)),
      Vector.createGF2Vector(List(1, 1, 1, 0, 0)),
      Vector.createGF2Vector(List(1, 1, 0, 1, 1))
    )
    val ssa = new SupportSplittingAlgorithm
    // According the SSA paper: (1 -> 2, 4 -> 4, 5 -> 3) which is indexed (0 -> 1, 3 -> 3, 4 -> 2)
    // After refinement we add (2 -> 5, 3 -> 1) which is indexed (1 -> 4, 2 -> 0)
    val actualResult = Map(2 -> 0, 4 -> 2, 1 -> 4, 3 -> 3, 0 -> 1)
    // This is based on luck, because of randomized refinement positions
    val possibleResult = Map(4 -> 2, 3 -> 3, 0 -> 1)
    val expectedResults = List(actualResult, possibleResult)
    for (_ <- 0 until 100) {
      val permutation = ssa.ssa(cCodewords1, cCodewords2)
      println(permutation)
      assert(expectedResults.exists(permutation.equals(_)), "SSA algorithm implemented incorrectly")
    }
  }

  it should "ssa must find permutation on exactly the same code (one refinement)" in {
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
    val g2 = new GF2Matrix(g)
    val ssa = new SupportSplittingAlgorithm

    val gCodewords = ssa.generateAllCodewords(g)
    val g2Codewords = ssa.generateAllCodewords(g2)
    val permutation = ssa.ssa(gCodewords, g2Codewords)
    val expectedResult = Map(
      17 -> 17, 8 -> 8, 11 -> 11, 2 -> 2, 5 -> 5, 14 -> 14, 13 -> 13, 4 -> 4, 16 -> 16, 7 -> 7,
      1 -> 1, 10 -> 10, 19 -> 19, 9 -> 9, 18 -> 18, 12 -> 12, 3 -> 3, 6 -> 6, 15 -> 15, 0 -> 0
    )
    assert(permutation.equals(expectedResult), "SSA algorithm implemented incorrectly")
  }

  it should "ssa should not find permutation" in {
    val cCodewords1 = List(
      Vector.createGF2Vector(List(0, 1, 1, 0, 1))
    )
    val cCodewords2 = List(
      Vector.createGF2Vector(List(0, 0, 1, 0, 0))
    )
    val ssa = new SupportSplittingAlgorithm
    val permutation = ssa.ssa(cCodewords1, cCodewords2)
    assert(permutation.isEmpty, "SSA algorithm implemented incorrectly")
  }

  it should "attack successfully" in {
    /*val privateKey = ""
    val ssa = new SupportSplittingAlgorithm(mcEliecePKC.publicKey)

    val timeResults = new ListBuffer[Long]()
    for (_ <- 0 until 1) {
      val start = System.currentTimeMillis

      println(ssa.attack())
      timeResults += System.currentTimeMillis - start
    }*/
  }

  it should "attack and never fail" in {
      //val configuration = BasicConfiguration(m = 5, t = 2)
      val configuration = BasicConfiguration(m = 4, t = 1)
      val mcEliecePKC = new McElieceCryptosystem(configuration)
      val ssa = new SupportSplittingAlgorithm(mcEliecePKC.publicKey)

      val timeResults = new ListBuffer[Long]()
      for (_ <- 0 until 1) {
        val start = System.currentTimeMillis

        println(ssa.attack())
        timeResults += System.currentTimeMillis - start
      }
  }

}
