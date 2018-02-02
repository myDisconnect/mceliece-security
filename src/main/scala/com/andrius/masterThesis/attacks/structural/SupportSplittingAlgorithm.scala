package com.andrius.masterThesis.attacks.structural

import java.security.SecureRandom

import com.andrius.masterThesis.utils.{Math, Vector}
import org.bouncycastle.pqc.jcajce.provider.mceliece.BCMcEliecePublicKey
import org.bouncycastle.pqc.math.linearalgebra.{GF2Matrix, GF2Vector, GF2mField, GoppaCode, IntUtils, PolynomialGF2mSmallM, PolynomialRingGF2}

import scala.collection.immutable.Range
import scala.collection.mutable
import scala.collection.mutable.ListBuffer
import scala.util.Random

/**
  * @see N. Sendrier. Finding the permutation between equivalent codes: the support splitting algorithm.
  * @see N. Sendrier. The Support Splitting Algorithm (https://hal.archives-ouvertes.fr/inria-00073037/document)
  * @see Great slides (https://who.rocq.inria.fr/Dimitrios.Simos/talks/CBCSlides2012.pdf)
  * @see Inria Cryptography course on McEliece cryptosystem: (https://www.canal-u.tv/video/inria/4_2_support_splitting_algorithm.32925)
  */
class SupportSplittingAlgorithm {
  var gCodewords: List[GF2Vector] = List.empty[GF2Vector]
  var t: Int = 0
  var k: Int = 0
  var n: Int = 0
  var m: Int = 0

  def this(publicKey: BCMcEliecePublicKey) {
    this()
    this.gCodewords = generateAllCodewords(publicKey.getG)
    this.k = publicKey.getK
    this.t = publicKey.getT
    this.n = publicKey.getN
    this.m = (n - k) / t
  }

  /**
    * @return private matrix g
    */
  def attack(): GF2Matrix = {
    require(gCodewords.nonEmpty, "No public key passed")
    val sr = new SecureRandom

    val fieldPoly = PolynomialRingGF2.getIrreduciblePolynomial(m)
    val field = new GF2mField(m, fieldPoly)

    var found = false
    var permutationMap = mutable.Map.empty[Int, Int]
    while (!found) {
      val c = getRandomGoppaCodeGeneratorMatrix(field, sr)
      val cCodewords = generateAllCodewords(c)
      permutationMap = ssa(gCodewords, cCodewords)
      println(permutationMap, s"size: ${permutationMap.size}")
      if (permutationMap.size == n) {
        found = true
      }
    }
    //permutationMap
    //
    getRandomGoppaCodeGeneratorMatrix(field, sr)
  }

  /**
    * Random Goppa code generator matrix
    *
    * @param field finite field GF(2^m)
    * @return
    */
  def getRandomGoppaCodeGeneratorMatrix(field: GF2mField, sr: SecureRandom): GF2Matrix = {
    // irreducible Goppa polynomial
    val gp = new PolynomialGF2mSmallM(field, t, PolynomialGF2mSmallM.RANDOM_IRREDUCIBLE_POLYNOMIAL, sr)
    println(gp)
    // generate canonical check matrix
    val h = GoppaCode.createCanonicalCheckMatrix(field, gp)

    // compute short systematic form of check matrix
    val mmp = GoppaCode.computeSystematicForm(h, sr)
    val shortH = mmp.getSecondMatrix
    val p1 = mmp.getPermutation

    // compute short systematic form of generator matrix
    val shortG = shortH.computeTranspose.asInstanceOf[GF2Matrix]

    // extend to full systematic form
    shortG.extendLeftCompactForm
  }

  /**
    * Support Splitting Algorithm
    *
    * @param gCodewords list of public key generator matrix codewords
    * @param cCodewords list of selected linear code codewords
    * @return
    */
  def ssa(gCodewords: List[GF2Vector], cCodewords: List[GF2Vector]): mutable.Map[Int, Int] = {
    require(gCodewords.nonEmpty && cCodewords.nonEmpty)
    val n = gCodewords.head.getLength
    var gMultiPositions = List(Range(0, n).toList)
    var cMultiPositions = List(Range(0, n).toList)

    val gSignatures = mutable.Map.empty[Int, ListBuffer[String]]
    val cSignatures = mutable.Map.empty[Int, ListBuffer[String]]

    val singletons = ListBuffer.empty[Int]

    gMultiPositions = ssaStep(gCodewords, gMultiPositions, gSignatures, singletons)
    cMultiPositions = ssaStep(cCodewords, cMultiPositions, cSignatures, singletons)
    while (gMultiPositions.nonEmpty && isSamePartitioned(gMultiPositions, cMultiPositions)) {
      //val newPuncturePos = Random.nextInt(n)
      // using singletons, random puncture is less efficient than singletons
      val newPuncturePos = if (singletons.nonEmpty) {
        singletons(Random.nextInt(singletons.length))
      } else {
        Random.nextInt(n)
      }
      println(s"newPuncturePos=$newPuncturePos")
      // Refine
      gMultiPositions = ssaStep(puncture(gCodewords, newPuncturePos), gMultiPositions, gSignatures, singletons)
      cMultiPositions = ssaStep(puncture(cCodewords, newPuncturePos), cMultiPositions, cSignatures, singletons)
      println(s"gMultiPositions = $gMultiPositions, cMultiPositions = $cMultiPositions")
    }
    // @todo test if we fail
    findPermutation(gSignatures, cSignatures)
  }

  /**
    * Note. It is possible to use the hull of weight enumerator,
    * but it is less efficient with n <= 1000 (@see N. Sendrier. The Support Splitting Algorithm)
    *
    * @param codewords      given linear code codewords
    * @param multiPositions positions to puncture codewords at
    * @param signatures     single position permutation of linear code
    * @param singletons     successfully mapped signatures
    * @return positions to puncture codewords at
    */
  def ssaStep(
               codewords: List[GF2Vector],
               multiPositions: List[List[Int]],
               signatures: mutable.Map[Int, ListBuffer[String]],
               singletons: ListBuffer[Int]
             ): List[List[Int]] = {
    val newMultiPositions = ListBuffer.empty[List[Int]]
    for (positions <- multiPositions) {
      val partition = mutable.Map.empty[String, ListBuffer[Int]]
      for (position <- positions) {
        val weightEnumPos = getHammingWeightDistribution(puncture(codewords, position))
        // Could use hashCode for efficiency
        val enum = weightEnumPos.toString

        if (partition.isDefinedAt(enum)) {
          partition(enum) += position
        } else {
          val newList = new ListBuffer[Int]()
          newList += position
          partition(enum) = newList
        }
        if (signatures.isDefinedAt(position)) {
          signatures(position) += enum
        } else {
          val newList = new ListBuffer[String]()
          newList += enum
          signatures(position) = newList
        }
      }
      for (positions <- partition.values) {
        if (positions.length > 1) {
          newMultiPositions += positions.toList
        } else {
          singletons += positions.head
        }
      }
    }
    newMultiPositions.toList
  }

  /**
    * Generate all possible codewords from generator matrix (very slow)
    *
    * @param g generator matrix
    * @return
    */
  def generateAllCodewords(g: GF2Matrix): List[GF2Vector] = {
    val n = g.getNumColumns
    val k = g.getNumRows
    val codewords = new ListBuffer[GF2Vector]()
    for (messageWords <- Math.permutationsWithRepetitions(Range.inclusive(0, 1).toList, k)) {
      var result = new GF2Vector(n, Array.fill((n - 1) / 32 + 1)(0))
      for (i <- Range(0, k)) {
        if (messageWords(i) == 1) {
          result = result.add(new GF2Vector(n, g.getRow(i))).asInstanceOf[GF2Vector]
        }
      }
      codewords += result
    }
    codewords.toList
  }

  /**
    * Get Hamming weight distribution
    *
    * @param codewords list of codeword vectors
    * @return
    */
  def getHammingWeightDistribution(codewords: List[GF2Vector]): mutable.Map[Int, Int] = {
    val weightDistribution = mutable.Map.empty[Int, Int]
    for (codeword <- codewords) {
      val hammingWeight = codeword.getHammingWeight
      if (weightDistribution.isDefinedAt(hammingWeight)) {
        weightDistribution(hammingWeight) += 1
      } else {
        weightDistribution += (hammingWeight -> 1)
      }
    }
    weightDistribution
  }

  /**
    * Puncture codewords in one position
    *
    * @param codewords list of codeword vectors
    * @param position  position to puncture
    * @return new punctured list of codeword vectors
    */
  def puncture(codewords: List[GF2Vector], position: Int): List[GF2Vector] = {
    val puncturedCodewords = new ListBuffer[GF2Vector]()
    for (vector <- codewords) {
      val out = IntUtils.clone(vector.getVecArray)
      Vector.setColumn(out, 0, position)
      puncturedCodewords += new GF2Vector(vector.getLength, out)
    }
    puncturedCodewords.toList
  }

  /**
    * Check if the same positions were partitioned
    *
    * @param positions1 positions from public key codewords
    * @param positions2 positions from selected Goppa code codewords
    * @return
    */
  def isSamePartitioned(positions1: List[List[Int]], positions2: List[List[Int]]): Boolean = {
    // length -> count
    var lengths = mutable.Map.empty[Int, Int]
    for (pos <- positions1) {
      val l = pos.length
      if (lengths.isDefinedAt(l)) {
        lengths(l) += 1
      } else {
        lengths += (l -> 1)
      }
    }
    // check if position2 element lengths contains lengths
    def containsAll(lengths: mutable.Map[Int, Int], positions: List[List[Int]]): Boolean = {
      def contain(positions: List[List[Int]], found: Boolean): Boolean = {
        if (positions.isEmpty) found
        else if (!found) found
        else {
          var found = true
          val l = positions.head.length
          if (lengths.isDefinedAt(l)) {
            if (lengths(l) == 1) {
              lengths.remove(l)
            } else {
              lengths(l) -= 1
            }
          } else {
            found = false
          }
          contain(positions.tail, found)
        }
      }

      contain(positions, found = true)
    }
    containsAll(lengths, positions2) && lengths.isEmpty
  }

  /**
    * Create the permutation map for two codes based on their signatures
    *
    * @param gSignatures signature of g
    * @param cSignatures signature of c
    * @return permutation map
    */
  def findPermutation(
                       gSignatures: mutable.Map[Int, ListBuffer[String]],
                       cSignatures: mutable.Map[Int, ListBuffer[String]]
                     ): mutable.Map[Int, Int] = {
    val permutation = mutable.Map.empty[Int, Int]
    for {
      (gPosition, gSignature) <- gSignatures
      (cPosition, cSignature) <- cSignatures
    } yield {
      if (gSignature.length == cSignature.length && findPermutationInPosition(gSignature, cSignature, 0)) {
        permutation(gPosition) = cPosition
      }
    }
    permutation
  }

  /**
    * Check if signature mappings are identical
    *
    * @param gSignature one signature of g
    * @param cSignature one signature of c
    * @param level      position in signature list
    * @return
    */
  def findPermutationInPosition(gSignature: ListBuffer[String], cSignature: ListBuffer[String], level: Int): Boolean = {
    if (level < gSignature.length) {
      if (gSignature(level) == cSignature(level)) {
        findPermutationInPosition(gSignature, cSignature, level + 1)
      } else {
        false
      }
    } else {
      true
    }
  }


}
