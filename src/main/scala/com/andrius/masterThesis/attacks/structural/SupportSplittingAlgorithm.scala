package com.andrius.masterThesis.attacks.structural

import com.andrius.masterThesis.utils.{Math, Vector}
import org.bouncycastle.pqc.jcajce.provider.mceliece.BCMcEliecePublicKey
import org.bouncycastle.pqc.math.linearalgebra.{GF2Matrix, GF2Vector, IntUtils}

import scala.collection.immutable.Range
import scala.collection.mutable
import scala.collection.mutable.ListBuffer
import scala.util.Random

/**
  * @see N. Sendrier. Finding the permutation between equivalent codes: the support splitting algorithm.
  * @see N. Sendrier. The Support Splitting Algorithm (https://hal.archives-ouvertes.fr/inria-00073037/document)
  * @see Great slides (https://who.rocq.inria.fr/Dimitrios.Simos/talks/CBCSlides2012.pdf)
  * @see Inria Cryptography course on McEliece cryptosystem: (https://www.canal-u.tv/video/inria/4_2_support_splitting_algorithm.32925)
  * @param publicKey McEliece public key
  */
class SupportSplittingAlgorithm(publicKey: BCMcEliecePublicKey) {

  val g: GF2Matrix = publicKey.getG
  val n: Int = g.getNumColumns
  val k: Int = g.getNumRows
  val t: Int = publicKey.getT
  val gCodewords: List[GF2Vector] = generateAllCodewords(g)

  /**
    *
    * @return private matrix g
    */
  def attack(): GF2Matrix = {
    // code
    //val cCodewords = generateAllCodewords(code)
    c
    //ssa(
  }

  /**
    * Generate all codewords from generator matrix
    *
    * @param g generator matrix
    * @return
    */
  def generateAllCodewords(g: GF2Matrix): List[GF2Vector] = {
    val codewords = new ListBuffer[GF2Vector]()
    for (messageWords <- Math.permutationsWithRepetitions(Range.inclusive(0, 1).toList, k)) {
      var result = new GF2Vector(n, Array.fill((n - 1) / 32 + 1)(0))
      for (i <- Range(0, k)) {
        if (messageWords(i) == 1) {
          result = result.add(new GF2Vector(g.getNumColumns, g.getRow(i))).asInstanceOf[GF2Vector]
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
    * Step #3 Puncture codewords
    *
    * @param codewords list of codeword vectors
    * @param position  position to puncture
    * @return new punctured list of codeword vectors
    */
  def puncture(codewords: List[GF2Vector], position: Int): List[GF2Vector] = {
    val puncturedCodewords = new ListBuffer[GF2Vector]()
    for (vector <- codewords) {
      val out = IntUtils.clone(vector.getVecArray)
      for (i <- 0 until vector.getLength) {
        Vector.setColumn(out, 0, position)
      }
      puncturedCodewords += new GF2Vector(vector.getLength, out)
    }
    puncturedCodewords.toList
  }

  /**
    * Support Splitting Algorithm
    *
    * @param gCodewords list of public key generator matrix codewords
    * @param cCodewords list of selected linear code codewords
    * @return
    */
  def ssa(
           gCodewords: List[GF2Vector],
           cCodewords: List[GF2Vector]
         ): (mutable.Map[Int, ListBuffer[Int]], mutable.Map[Int, ListBuffer[Int]]
    ) = {
    var gMultiPositions = List(Range(0, n).toList)
    var cMultiPositions = List(Range(0, n).toList)

    val gSignatures = mutable.Map.empty[Int, ListBuffer[Int]]
    val cSignatures = mutable.Map.empty[Int, ListBuffer[Int]]

    val singletons = ListBuffer.empty[Int]

    gMultiPositions = ssaStep(gCodewords, gMultiPositions, gSignatures, singletons)
    cMultiPositions = ssaStep(cCodewords, cMultiPositions, cSignatures, singletons)
    while (gMultiPositions.nonEmpty && isSamePartitioned(gMultiPositions, cMultiPositions)) {
      // @todo rethink this strategy, maybe save results and iterate?
      val newPuncturePosition = Random.nextInt(n)
      // @todo use singletons, random puncture is less efficient than singletons
      gMultiPositions = ssaRefine(gCodewords, newPuncturePosition, gMultiPositions, gSignatures, singletons)
      cMultiPositions = ssaRefine(cCodewords, newPuncturePosition, cMultiPositions, cSignatures, singletons)
    }
    (gSignatures, cSignatures)
  }

  /**
    * @param codewords      given linear code codewords
    * @param multiPositions positions to puncture codewords at
    * @param signatures     single position permutation of linear code
    * @param singletons     successfully mapped signatures
    * @return positions to puncture codewords at
    */
  def ssaStep(
               codewords: List[GF2Vector],
               multiPositions: List[List[Int]],
               signatures: mutable.Map[Int, ListBuffer[Int]],
               singletons: ListBuffer[Int]
             ): List[List[Int]] = {
    val newMultiPositions = ListBuffer.empty[List[Int]]
    for (positions <- multiPositions) {
      val partition = mutable.Map.empty[Int, ListBuffer[Int]]
      for (position <- positions) {
        val weightEnumPos = getHammingWeightDistribution(puncture(codewords, position))
        val enum = weightEnumPos.hashCode

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
          val newList = new ListBuffer[Int]()
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
    * @param codewords      given linear code codewords
    * @param puncturePos    new puncture position
    * @param multiPositions positions to puncture codewords at
    * @param signatures     single position permutation of linear code
    * @param singletons     successfully mapped signatures
    * @return
    */
  def ssaRefine(
                 codewords: List[GF2Vector],
                 puncturePos: Int,
                 multiPositions: List[List[Int]],
                 signatures: mutable.Map[Int, ListBuffer[Int]],
                 singletons: ListBuffer[Int]
               ): List[List[Int]] = {
    val puncturedCodewords = puncture(codewords, puncturePos)
    ssaStep(puncturedCodewords, multiPositions, signatures, singletons)
  }

}
