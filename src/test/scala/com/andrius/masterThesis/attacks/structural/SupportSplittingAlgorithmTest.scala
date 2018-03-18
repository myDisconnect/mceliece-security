package com.andrius.masterThesis.attacks.structural

import java.security.SecureRandom

import com.andrius.masterThesis.mceliece.McElieceCryptosystem
import com.andrius.masterThesis.mceliece.McElieceCryptosystem._
import com.andrius.masterThesis.utils.{GeneratorParityCheckMatrix, Matrix, Vector}
import org.bouncycastle.pqc.math.linearalgebra.{GF2Matrix, GF2mField, GoppaCode, Permutation, PolynomialGF2mSmallM, PolynomialRingGF2, PolynomialRingGF2m}
import org.scalatest.FlatSpec

/**
  * @see Most examples taken from:
  *      N. Sendrier. The Support Splitting Algorithm (https://hal.archives-ouvertes.fr/inria-00073037/document)
  */
class SupportSplittingAlgorithmTest extends FlatSpec {

  behavior of "Support splitting algorithm"

  it should "find permutation on equivalent codes" in {
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
    val permutation = SupportSplittingAlgorithm.findPermutation(
      SupportSplittingAlgorithm.getSignature(cCodewords1),
      cCodewords2
    )
    // According the SSA paper: (1 -> 3, 2 -> 1, 3 -> 4, 4 -> 2) which is indexed (0 -> 2, 1 -> 0, 2 -> 3, 3 -> 1)
    val expectedResult = Map(2 -> 3, 1 -> 0, 3 -> 1, 0 -> 2)
    assert(permutation.equals(expectedResult), "SSA algorithm implemented incorrectly")
  }

  it should "find permutation on with one refinement" in {
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
    val permutation = SupportSplittingAlgorithm.findPermutation(
      SupportSplittingAlgorithm.getSignature(cCodewords1),
      cCodewords2
    )
    // According the SSA paper: (1 -> 2, 4 -> 4, 5 -> 3) which is indexed (0 -> 1, 3 -> 3, 4 -> 2)
    // After refinement we add (2 -> 5, 3 -> 1) which is indexed (1 -> 4, 2 -> 0)
    val expectedResult = Map(2 -> 0, 4 -> 2, 1 -> 4, 3 -> 3, 0 -> 1)
    assert(permutation.equals(expectedResult), "SSA algorithm implemented incorrectly")
  }

  it should "find permutation on exactly the same code (one refinement)" in {
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

    val gCodewords = GeneratorParityCheckMatrix.generateAllCodewords(g)
    val permutation = SupportSplittingAlgorithm.findPermutation(
      SupportSplittingAlgorithm.getSignature(gCodewords),
      gCodewords
    )
    val expectedResult = Map(
      17 -> 17, 8 -> 8, 11 -> 11, 2 -> 2, 5 -> 5, 14 -> 14, 13 -> 13, 4 -> 4, 16 -> 16, 7 -> 7,
      1 -> 1, 10 -> 10, 19 -> 19, 9 -> 9, 18 -> 18, 12 -> 12, 3 -> 3, 6 -> 6, 15 -> 15, 0 -> 0
    )
    assert(permutation.equals(expectedResult), "SSA algorithm implemented incorrectly")
  }

  it should "not find permutation" in {
    val cCodewords1 = List(
      Vector.createGF2Vector(List(0, 1, 1, 0, 1))
    )
    val cCodewords2 = List(
      Vector.createGF2Vector(List(0, 0, 1, 0, 0))
    )

    val thrown = intercept[Exception] {
      SupportSplittingAlgorithm.findPermutation(
        SupportSplittingAlgorithm.getSignature(cCodewords1),
        cCodewords2
      )
    }
    assert(thrown.getMessage === "[Cannot find a signatures] Fully discriminant signature doesn't exist", "SSA algorithm implemented incorrectly")
  }

  it should "not find a permutation map on not permutable linear codes" in {
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

    val thrown = intercept[Exception] {
      SupportSplittingAlgorithm.findPermutation(
        SupportSplittingAlgorithm.getSignature(GeneratorParityCheckMatrix.generateAllCodewords(g1)),
        GeneratorParityCheckMatrix.generateAllCodewords(g2)
      )
    }
    assert(
      thrown.getMessage === "[Cannot find a signatures] Fully discriminant signature doesn't exist",
      "SSA algorithm implemented incorrectly"
    )
  }

  it should "attack successfully with the same irreductible Goppa Polynomial(GF(2)[X]/<1+x^1+x^2>)" in {
    val g = Matrix.createGF2Matrix(Seq(
      Seq(1, 1, 1, 1),
      Seq(1, 0, 0, 0)
    ))
    val g2 = Matrix.createGF2Matrix(Seq(
      Seq(1, 0, 1, 1),
      Seq(0, 1, 0, 0)
    ))
    val gCodewords = GeneratorParityCheckMatrix.generateAllCodewords(g)
    /* gCodewords generates codewords:
    List(
      Vector.createGF2Vector(List(0, 0, 0, 0)),
      Vector.createGF2Vector(List(1, 0, 0, 0)),
      Vector.createGF2Vector(List(1, 1, 1, 1)),
      Vector.createGF2Vector(List(0, 1, 1, 1))
    )
    */
    val g2Codewords = GeneratorParityCheckMatrix.generateAllCodewords(g2)
    /* g2Codewords generates codewords
    List(
      Vector.createGF2Vector(List(0, 0, 0, 0)),
      Vector.createGF2Vector(List(0, 1, 0, 0)),
      Vector.createGF2Vector(List(1, 0, 1, 1)),
      Vector.createGF2Vector(List(1, 1, 1, 1))
    )
    */
    val permutation = SupportSplittingAlgorithm.findPermutation(
      SupportSplittingAlgorithm.getSignature(gCodewords),
      g2Codewords
    )
    val expectedResult = Map(2 -> 2, 1 -> 0, 3 -> 3, 0 -> 1)
    assert(permutation.equals(expectedResult), "SSA algorithm implemented incorrectly")
  }

  it should "attack should always be successful with the same irreductible Goppa Polynomial" in {
    val (m, t) = (2, 1)
    val (keyPair1, keyPair2) = getTwoMcElieceKeyPairsWithTheSameGoppaPoly(m, t)
    val permutation = SupportSplittingAlgorithm.findPermutation(
      SupportSplittingAlgorithm.getSignature(GeneratorParityCheckMatrix.generateAllCodewords(keyPair1.publicKey.gPublic)),
      GeneratorParityCheckMatrix.generateAllCodewords(keyPair2.publicKey.gPublic)
    )
    permutation
    /*val privateKey = ""
    val ssa = new SupportSplittingAlgorithm(mcEliecePKC.publicKey)

    val timeResults = new ListBuffer[Long]()
    for (_ <- 0 until 1) {
      val start = System.currentTimeMillis

      println(ssa.attack())
      timeResults += System.currentTimeMillis - start
    }*/
  }
  it should "attack should always be successful, m = 2, t = 2" in {
    val configuration = Configuration(m = 3, t = 2, VerboseOptions(keyPairGeneration = true))

    //for (_ <- 0 until 5) {
    val mcEliecePKC = new McElieceCryptosystem(configuration)
    SupportSplittingAlgorithm.getSignature(GeneratorParityCheckMatrix.generateAllCodewords(mcEliecePKC.publicKey.gPublic))
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

  protected def getTwoMcElieceKeyPairsWithTheSameGoppaPoly(m: Int, t: Int): (McElieceKeyPair, McElieceKeyPair) = {
    val sr = new SecureRandom

    // finite field GF(2^m)
    val fieldPoly = PolynomialRingGF2.getIrreduciblePolynomial(m)
    val field = new GF2mField(m, fieldPoly)

    // irreducible Goppa polynomial
    val gp = new PolynomialGF2mSmallM(field, t, PolynomialGF2mSmallM.RANDOM_IRREDUCIBLE_POLYNOMIAL, sr)
    val ring = new PolynomialRingGF2m(field, gp)

    // matrix used to compute square roots in (GF(2^m))^t
    val sqRootMatrix = ring.getSquareRootMatrix

    // generate (k x n) canonical check matrix
    val h = GoppaCode.createCanonicalCheckMatrix(field, gp)

    // get (k x n) generator matrix from parity check matrix
    //val g = GeneratorParityCheckMatrix.findNullSpace(h)
    val mmp = GoppaCode.computeSystematicForm(h, sr)
    val shortH = mmp.getSecondMatrix
    val p1 = mmp.getPermutation

    // compute short systematic form of generator matrix
    val shortG = shortH.computeTranspose.asInstanceOf[GF2Matrix]

    // extend to full systematic form
    val gPrime = shortG.extendLeftCompactForm

    (getMcElieceKeyPair(field, gp, h, gPrime, p1, sqRootMatrix, t, sr), getMcElieceKeyPair(field, gp, h, gPrime, p1, sqRootMatrix, t, sr))
  }

  protected def getMcElieceKeyPair(
                                    field: GF2mField,
                                    gp: PolynomialGF2mSmallM,
                                    h: GF2Matrix,
                                    g: GF2Matrix,
                                    p1: Permutation,
                                    sqRootMatrix: Array[PolynomialGF2mSmallM],
                                    t: Int, sr: SecureRandom
                                  ): McElieceKeyPair = {
    // generate random invertible (k x k)-matrix S and its inverse S^-1
    val matrixSandInverse = GF2Matrix.createRandomRegularMatrixAndItsInverse(h.getNumColumns, sr)

    val n = h.getNumColumns

    // generate random n-length permutation P
    val p = new Permutation(n, sr)

    // compute public matrix G' = S * G * P
    val gPub = matrixSandInverse(0).rightMultiply(g).rightMultiply(p).asInstanceOf[GF2Matrix]

    // generate public and private keys
    McElieceKeyPair(
      McEliecePublicKey(gPub, t, p1),
      McEliecePrivateKey(matrixSandInverse(1), h, p.computeInverse, field, gp, sqRootMatrix)
    )
  }

}
