package com.andrius.masterThesis.attacks.structural

import java.security.SecureRandom

import com.andrius.masterThesis.mceliece.McElieceCryptosystem
import com.andrius.masterThesis.mceliece.McElieceCryptosystem._
import com.andrius.masterThesis.utils.{GeneratorMatrix, Matrix, Vector}
import org.bouncycastle.pqc.math.linearalgebra.{GF2Matrix, GF2mField, GoppaCode, Permutation, PolynomialGF2mSmallM, PolynomialRingGF2, PolynomialRingGF2m}
import org.scalatest.FlatSpec

/**
  * @see Few examples are taken from:
  *      N. Sendrier. The Support Splitting Algorithm (https://hal.archives-ouvertes.fr/inria-00073037/document)
  */
class SupportSplittingAlgorithmTest extends FlatSpec {

  behavior of "The Support Splitting Algorithm"

  it should "find permutation on equivalent codes without refinements" in {
    val c1Codewords = List(
      Vector.createGF2Vector(List(1, 1, 1, 0)),
      Vector.createGF2Vector(List(0, 1, 1, 1)),
      Vector.createGF2Vector(List(1, 0, 1, 0))
    )
    val c2Codewords = List(
      Vector.createGF2Vector(List(0, 0, 1, 1)),
      Vector.createGF2Vector(List(1, 0, 1, 1)),
      Vector.createGF2Vector(List(1, 1, 0, 1))
    )
    val c1Signature = SupportSplittingAlgorithm.getSignature(c1Codewords)
    val permutation = SupportSplittingAlgorithm.findPermutation(c1Signature, c1Codewords, c2Codewords)

    // According the SSA paper: (1 -> 3, 2 -> 1, 3 -> 4, 4 -> 2) which is indexed (0 -> 2, 1 -> 0, 2 -> 3, 3 -> 1)
    val expectedResult = Map(2 -> 3, 1 -> 0, 3 -> 1, 0 -> 2)
    assert(permutation.equals(expectedResult), "SSA algorithm implemented incorrectly")
    assert(SupportSplittingAlgorithm.getRefinementCount(c1Signature) == 0, "SSA algorithm implemented incorrectly")
  }

  it should "find permutation on equivalent codes with exactly one refinement" in {
    val c1Codewords = List(
      Vector.createGF2Vector(List(0, 1, 1, 0, 1)),
      Vector.createGF2Vector(List(0, 1, 0, 1, 1)),
      Vector.createGF2Vector(List(0, 1, 1, 1, 0)),
      Vector.createGF2Vector(List(1, 0, 1, 0, 1)),
      Vector.createGF2Vector(List(1, 1, 1, 1, 0))
    )
    val c2Codewords = List(
      Vector.createGF2Vector(List(1, 0, 1, 0, 1)),
      Vector.createGF2Vector(List(0, 0, 1, 1, 1)),
      Vector.createGF2Vector(List(1, 0, 0, 1, 1)),
      Vector.createGF2Vector(List(1, 1, 1, 0, 0)),
      Vector.createGF2Vector(List(1, 1, 0, 1, 1))
    )
    val c1Signature = SupportSplittingAlgorithm.getSignature(c1Codewords)
    val permutation = SupportSplittingAlgorithm.findPermutation(c1Signature, c1Codewords, c2Codewords)

    // According the SSA paper: (1 -> 2, 4 -> 4, 5 -> 3) which is indexed (0 -> 1, 3 -> 3, 4 -> 2)
    // After refinement we add (2 -> 5, 3 -> 1) which is indexed (1 -> 4, 2 -> 0)
    val expectedResult = Map(2 -> 0, 4 -> 2, 1 -> 4, 3 -> 3, 0 -> 1)
    assert(permutation.equals(expectedResult), "SSA algorithm implemented incorrectly")
    assert(SupportSplittingAlgorithm.getRefinementCount(c1Signature) == 1, "SSA algorithm implemented incorrectly")
  }

  it should "find permutation on exactly the same code with one refinement" in {
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

    val gCodewords = GeneratorMatrix.generateAllCodewords(g)
    val gSignature = SupportSplittingAlgorithm.getSignature(gCodewords)
    val permutation = SupportSplittingAlgorithm.findPermutation(gSignature, gCodewords, gCodewords)

    val expectedResult = Map(
      17 -> 17, 8 -> 8, 11 -> 11, 2 -> 2, 5 -> 5, 14 -> 14, 13 -> 13, 4 -> 4, 16 -> 16, 7 -> 7,
      1 -> 1, 10 -> 10, 19 -> 19, 9 -> 9, 18 -> 18, 12 -> 12, 3 -> 3, 6 -> 6, 15 -> 15, 0 -> 0
    )
    assert(permutation.equals(expectedResult), "SSA algorithm implemented incorrectly")
    assert(SupportSplittingAlgorithm.getRefinementCount(gSignature) == 1, "SSA algorithm implemented incorrectly")
  }

  it should "not find permutation on not equivalent codes" in {
    val c1Codewords = List(
      Vector.createGF2Vector(List(0, 1, 1, 0, 1))
    )
    val c2Codewords = List(
      Vector.createGF2Vector(List(0, 0, 1, 0, 0))
    )

    val thrown = intercept[Exception] {
      SupportSplittingAlgorithm.findPermutation(
        SupportSplittingAlgorithm.getSignature(c1Codewords),
        c1Codewords,
        c2Codewords
      )
    }
    assert(
      thrown.getMessage === "[Cannot find signatures] Fully discriminant signature doesn't exist",
      "SSA algorithm implemented incorrectly"
    )
  }

  it should "not find permutation on not equivalent generator matrices" in {
    val g1 = Matrix.createGF2Matrix(Seq(
      Seq(1, 1, 0, 0, 0, 0),
      Seq(0, 0, 1, 1, 0, 0),
      Seq(0, 0, 0, 0, 1, 1)
    ))
    val g2 = Matrix.createGF2Matrix(Seq(
      Seq(1, 0, 0, 0, 1, 0),
      Seq(0, 1, 0, 1, 1, 1),
      Seq(0, 0, 1, 0, 1, 0)
    ))
    val g1Codewords = GeneratorMatrix.generateAllCodewords(g1)
    val thrown = intercept[Exception] {
      SupportSplittingAlgorithm.findPermutation(
        SupportSplittingAlgorithm.getSignature(g1Codewords),
        g1Codewords,
        GeneratorMatrix.generateAllCodewords(g2)
      )
    }
    assert(
      thrown.getMessage.startsWith("[Cannot find signatures]"),
      "SSA algorithm implemented incorrectly"
    )
  }

  it should "find permutation by puncturing the column twice" in {
    val g = Matrix.createGF2Matrix(Seq(
      Seq(1, 1, 1, 1),
      Seq(1, 0, 0, 0)
    ))
    val g2 = Matrix.createGF2Matrix(Seq(
      Seq(1, 0, 1, 1),
      Seq(0, 1, 0, 0)
    ))
    val gCodewords = GeneratorMatrix.generateAllCodewords(g)
    val gSignature = SupportSplittingAlgorithm.getSignature(gCodewords)
    val g2Codewords = GeneratorMatrix.generateAllCodewords(g2)

    val permutation = SupportSplittingAlgorithm.findPermutation(gSignature, gCodewords, g2Codewords)
    val swappedByPermutation = SupportSplittingAlgorithm.swapByPermutationMap(gCodewords, permutation)
    assert(
      swappedByPermutation.forall(g2Codewords.contains),
      "SSA algorithm implemented incorrectly"
    )
    val existTwoDuplicatePunctures = gSignature
      .keySet
      .exists(_.groupBy(identity).collect { case (x, ys) if ys.length == 2 => x }.nonEmpty)

    assert(existTwoDuplicatePunctures, "SSA algorithm implemented incorrectly")
  }

  it should "attack should always be successful with the same irreductible Goppa Polynomial" in {
    /*val configuration = Configuration(m = 4, t = 1)
    val mcEliecePKC = new McElieceCryptosystem(configuration)
    val g1 = mcEliecePKC.publicKey.gPublic
    val g2 = GeneratorMatrix.findNullSpace(mcEliecePKC.privateKey.h).rightMultiply(mcEliecePKC.publicKey.pLocal).asInstanceOf[GF2Matrix]
    println(s"Public G = \n$g1\nPrivate G=\n$g2")

    val g1Codewords = GeneratorMatrix.generateAllCodewords(g1)
    val g2Codewords = GeneratorMatrix.generateAllCodewords(g2)

    val g1Signature = SupportSplittingAlgorithm.getSignature(g1Codewords)

    val permutation = SupportSplittingAlgorithm.findPermutation(g1Signature, g1Codewords, g2Codewords)
    println(permutation)
    val permutedCodewords = SupportSplittingAlgorithm.swapByPermutationMap(g1Codewords, permutation)
    println(s"codewords expected: $g2Codewords\npermutedCodewords: $permutedCodewords")
    assert(
      permutedCodewords.forall(g2Codewords.contains),
      "SSA algorithm implemented incorrectly"
    )*/
  }

  it should "attack should fail with different irreductible Goppa Polynomials" in {
    /*val configuration = Configuration(m = 4, t = 1, VerboseOptions(keyPairGeneration = true))
    val mcEliecePKC = new McElieceCryptosystem(configuration)
    val g1 = mcEliecePKC.publicKey.gPublic
    val g1private = GeneratorMatrix.generateAllCodewords(GeneratorMatrix.findNullSpace(mcEliecePKC.privateKey.h).rightMultiply(mcEliecePKC.publicKey.pLocal).asInstanceOf[GF2Matrix])
    val g1Codewords = GeneratorMatrix.generateAllCodewords(g1)
    for (_ <- 0 until 100) {
      val mcEliecePKC2 = new McElieceCryptosystem(configuration)
      val g2 = GeneratorMatrix.findNullSpace(mcEliecePKC2.privateKey.h).rightMultiply(mcEliecePKC2.publicKey.pLocal).asInstanceOf[GF2Matrix]
      //println(s"Public G = \n$g1\nPrivate G=\n$g2")

      val g2Codewords = GeneratorMatrix.generateAllCodewords(g2)
      println(s"g1 codewords contains g2 codewords = ${g1private.forall(g2Codewords.contains)}")

      val g1Signature = SupportSplittingAlgorithm.getSignature(g1Codewords)

      val permutation = SupportSplittingAlgorithm.findPermutation(g1Signature, g1Codewords, g2Codewords)
    }*/
    /*println(permutation)
    val permutedCodewords = SupportSplittingAlgorithm.swapByPermutationMap(g1Codewords, permutation)
    println(s"codewords expected: $g2Codewords\npermutedCodewords: $permutedCodewords")
    assert(
      permutedCodewords.forall(g2Codewords.contains),
      "SSA algorithm implemented incorrectly"
    )*/
  }

  "The Support Splitting Algorithm based attack" should "attack should always be successful, m = 2, t = 2" in {
    val configuration = Configuration(m = 3, t = 2, VerboseOptions(keyPairGeneration = true))

    //for (_ <- 0 until 5) {
    val mcEliecePKC = new McElieceCryptosystem(configuration)
    SupportSplittingAlgorithm.getSignature(GeneratorMatrix.generateAllCodewords(mcEliecePKC.publicKey.gPublic))
    //val ssa = new SupportSplittingAlgorithm(mcEliecePKC.publicKey)
    //println(s"Public ${mcEliecePKC.privateKey.getGoppaPoly}\nPublic G' = \n${mcEliecePKC.publicKey.getG}")
    //ssa.attack
    /*val privateKey = ""

    val timeResults = new ListBuffer[Long]()
    for (_ <- 0 until 1) {
      val start = System.currentTimeMillis

      println(ssa.attack())
      timeResults += System.currentTimeMillis - start
    }*/
    //permutation
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
    /*for (_ <- 0 until 1000) {
      //val configuration = BasicConfiguration(m = 5, t = 2)
      val configuration = Configuration(m = 4, t = 1)
      val mcEliecePKC = new McElieceCryptosystem(configuration)
      val ssa = new SupportSplittingAlgorithm(mcEliecePKC.publicKey)

      val timeResults = new ListBuffer[Long]()
      for (_ <- 0 until 1) {
        val start = System.currentTimeMillis

        println(ssa.attack())
        timeResults += System.currentTimeMillis - start
      }
    }*/
  }
  it should "debuggy" in {
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
    SupportSplittingAlgorithm.getSignature(cCodewords1)
  }

  "swapByPermutationMap" should "swap codewords in permutation map positions" in {
    val g = Matrix.createGF2Matrix(Seq(
      Seq(1, 1, 1, 1),
      Seq(1, 0, 0, 0)
    ))
    val g2 = Matrix.createGF2Matrix(Seq(
      Seq(1, 0, 1, 1),
      Seq(0, 1, 0, 0)
    ))
    val gCodewords = GeneratorMatrix.generateAllCodewords(g)
    val g2Codewords = GeneratorMatrix.generateAllCodewords(g2)
    val permutation = Map(2 -> 3, 1 -> 2, 3 -> 0, 0 -> 1)
    assert(
      SupportSplittingAlgorithm.swapByPermutationMap(gCodewords, permutation).forall(g2Codewords.contains),
      "SSA algorithm implemented incorrectly"
    )
  }

}
