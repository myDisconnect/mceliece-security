package com.andrius.masterThesis.attacks.structural

import java.security.SecureRandom

import com.andrius.masterThesis.mceliece.McElieceCryptosystem
import com.andrius.masterThesis.mceliece.McElieceCryptosystem.{Configuration, McElieceKeyPair, VerboseOptions}
import com.andrius.masterThesis.utils.{GeneratorMatrix, Matrix, Vector}
import org.bouncycastle.pqc.crypto.mceliece.{McEliecePrivateKeyParameters, McEliecePublicKeyParameters}
import org.bouncycastle.pqc.jcajce.provider.mceliece.{BCMcEliecePrivateKey, BCMcEliecePublicKey}
import org.bouncycastle.pqc.math.linearalgebra.{GF2Matrix, GF2mField, GoppaCode, Permutation, PolynomialGF2mSmallM, PolynomialRingGF2}
import org.scalatest.FlatSpec

/**
  * @see Most examples taken from:
  *      N. Sendrier. The Support Splitting Algorithm (https://hal.archives-ouvertes.fr/inria-00073037/document)
  */
class SupportSplittingAlgorithmTest extends FlatSpec {

  behavior of "SupportSplittingAlgorithmAttack"

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
    val permutation = SupportSplittingAlgorithm.findPermutation(
      SupportSplittingAlgorithm.getSignature(cCodewords1),
      cCodewords2
    )
    // According the SSA paper: (1 -> 3, 2 -> 1, 3 -> 4, 4 -> 2) which is indexed (0 -> 2, 1 -> 0, 2 -> 3, 3 -> 1)
    val expectedResult = Map(2 -> 3, 1 -> 0, 3 -> 1, 0 -> 2)
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
    val permutation = SupportSplittingAlgorithm.findPermutation(
      SupportSplittingAlgorithm.getSignature(cCodewords1),
      cCodewords2
    )
    // According the SSA paper: (1 -> 2, 4 -> 4, 5 -> 3) which is indexed (0 -> 1, 3 -> 3, 4 -> 2)
    // After refinement we add (2 -> 5, 3 -> 1) which is indexed (1 -> 4, 2 -> 0)
    val expectedResult = Map(2 -> 0, 4 -> 2, 1 -> 4, 3 -> 3, 0 -> 1)
    assert(permutation.equals(expectedResult), "SSA algorithm implemented incorrectly")
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

    val gCodewords = Matrix.generateAllCodewords(g)
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

  it should "ssa should not find permutation" in {
    val cCodewords1 = List(
      Vector.createGF2Vector(List(0, 1, 1, 0, 1))
    )
    val cCodewords2 = List(
      Vector.createGF2Vector(List(0, 0, 1, 0, 0))
    )

    val thrown = intercept[Exception]{
      SupportSplittingAlgorithm.findPermutation(
        SupportSplittingAlgorithm.getSignature(cCodewords1),
        cCodewords2
      )
    }
    assert(thrown.getMessage === "Couldn't find signature", "SSA algorithm implemented incorrectly")
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
    val gCodewords = Matrix.generateAllCodewords(g)
    /* gCodewords generates codewords:
    List(
      Vector.createGF2Vector(List(0, 0, 0, 0)),
      Vector.createGF2Vector(List(1, 0, 0, 0)),
      Vector.createGF2Vector(List(1, 1, 1, 1)),
      Vector.createGF2Vector(List(0, 1, 1, 1))
    )
    */
    val g2Codewords = Matrix.generateAllCodewords(g2)
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
      SupportSplittingAlgorithm.getSignature(Matrix.generateAllCodewords(keyPair1.publicKey.getG)),
      Matrix.generateAllCodewords(keyPair2.publicKey.getG)
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
  it should "attack should always be successful, m = 2, t = 1" in {
    val configuration = Configuration(m = 2, t = 1, VerboseOptions(keyPairGeneration = true))

    //for (_ <- 0 until 5) {
    val mcEliecePKC = new McElieceCryptosystem(configuration)
    val ssa = new SupportSplittingAlgorithm(mcEliecePKC.publicKey)
    println(s"Public ${mcEliecePKC.privateKey.getGoppaPoly}\nPublic g=\n${mcEliecePKC.publicKey.getG}")
    ssa.attack
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

  protected def getTwoMcElieceKeyPairsWithTheSameGoppaPoly(m: Int, t: Int): (McElieceKeyPair, McElieceKeyPair) = {
    val sr = new SecureRandom

    val fieldPoly = PolynomialRingGF2.getIrreduciblePolynomial(m)
    val field = new GF2mField(m, fieldPoly)
    // irreducible Goppa polynomial
    val gp = new PolynomialGF2mSmallM(field, t, PolynomialGF2mSmallM.RANDOM_IRREDUCIBLE_POLYNOMIAL, sr)

    // generate canonical check matrix
    val h = GoppaCode.createCanonicalCheckMatrix(field, gp)

    (getMcElieceKeyPair(field, gp, h, t, sr), getMcElieceKeyPair(field, gp, h, t, sr))
  }

  protected def getMcElieceKeyPair(field: GF2mField, gp: PolynomialGF2mSmallM, h: GF2Matrix, t: Int, sr: SecureRandom): McElieceKeyPair = {
    val mmp = GoppaCode.computeSystematicForm(h, sr)
    val shortH = mmp.getSecondMatrix
    val p1 = mmp.getPermutation

    // compute short systematic form of generator matrix
    val shortG = shortH.computeTranspose.asInstanceOf[GF2Matrix]

    // extend to full systematic form
    val gPrime = shortG.extendLeftCompactForm

    // obtain number of rows of G (= dimension of the code)
    val k = shortG.getNumRows
    val n = gPrime.getNumColumns

    // generate random invertible (k x k)-matrix S and its inverse S^-1
    val matrixSandInverse = GF2Matrix.createRandomRegularMatrixAndItsInverse(k, sr)

    // generate random permutation P2
    val p2 = new Permutation(n, sr)

    // compute public matrix G=S*G'*P2
    val g = matrixSandInverse(0).rightMultiply(gPrime).rightMultiply(p2).asInstanceOf[GF2Matrix]
    // generate keys
    McElieceKeyPair(
      new BCMcEliecePublicKey(new McEliecePublicKeyParameters(n, t, g)),
      new BCMcEliecePrivateKey(new McEliecePrivateKeyParameters(n, k, field, gp, p1, p2, matrixSandInverse(1)))
    )
  }

}
