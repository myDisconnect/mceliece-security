package com.andrius.masterThesis.attacks.structural

import java.security.SecureRandom

import com.andrius.masterThesis.attacks.structural.SupportSplittingAlgorithm.SSAVerboseOptions
import com.andrius.masterThesis.mceliece.McElieceCryptosystem.McEliecePublicKey
import com.andrius.masterThesis.utils.{GeneratorMatrix, Goppa, Logging, Vector}
import org.bouncycastle.pqc.math.linearalgebra.{GF2Matrix, GF2Vector, GF2mField, IntUtils, Permutation, PolynomialGF2mSmallM}

import scala.collection.mutable
import scala.collection.mutable.ListBuffer
import scala.util.Random

/**
  * Implementation of the Support Splitting Algorithm
  * Notes:
  * - The algorithm is non-deterministic.
  * - Contains a safeguard, because there is a possibility that the algorithm doesn't terminate.
  * - Inequivalent codes may have the same weight enumerator.
  * - It is possible that two different irreductible goppa codes have the same generator matrix.
  *
  * @see N. Sendrier. Finding the permutation between equivalent codes: the support splitting algorithm.
  * @see N. Sendrier. The Support Splitting Algorithm (https://hal.archives-ouvertes.fr/inria-00073037/document)
  * @see Great slides (https://who.rocq.inria.fr/Dimitrios.Simos/talks/CBCSlides2012.pdf)
  * @see Inria Cryptography course on McEliece cryptosystem: (https://www.canal-u.tv/video/inria/4_2_support_splitting_algorithm.32925)
  */
class SupportSplittingAlgorithm(publicKey: McEliecePublicKey, verbose: SSAVerboseOptions = SSAVerboseOptions()) {
  import SupportSplittingAlgorithm._

  val g: GF2Matrix = publicKey.gPublic
  val p: Permutation = publicKey.pLocal.computeInverse
  val n: Int = g.getNumColumns
  val k: Int = g.getNumRows
  val t: Int = publicKey.t
  val m: Int = (n - k) / t

  var publicKeySignature: Map[Seq[Int], Seq[String]] = getSignature(GeneratorMatrix.generateAllCodewords(g))

  /**
    * @return private key matrix g
    */
  /*def attack: GF2Matrix = {
    val sr = new SecureRandom
    val failedGPTriesDictionary = mutable.HashSet.empty[(Int, PolynomialGF2mSmallM)]
    var generatorMatrix: Option[GF2Matrix] = None
    var permutationMap = Map.empty[Int, Int]

    var iteration = 0
    while (generatorMatrix.isEmpty) {
      val fieldPoly = Goppa.getIrreduciblePolynomial(m, sr)
      val field = new GF2mField(m, fieldPoly)
      val goppaPoly = new PolynomialGF2mSmallM(field, t, PolynomialGF2mSmallM.RANDOM_IRREDUCIBLE_POLYNOMIAL, sr)
      if (!failedGPTriesDictionary.contains((fieldPoly, goppaPoly))) {
        failedGPTriesDictionary += ((fieldPoly, goppaPoly))
        iteration += 1
        val gMatrix = GeneratorMatrix.getGeneratorMatrix(field, goppaPoly, p)
        try {
          /*permutationMap = findPermutation(
            publicKeySignature,
            GeneratorMatrix.generateAllCodewords(gMatrix)
          )*/
          generatorMatrix = Some(gMatrix)
        } catch {
          case e: Exception =>
            // could not find identical signature
        }
        if (verbose.generatorMatrixGeneration) {
          Logging.ssaGeneratorMatrixGenerationResults(goppaPoly, gMatrix, iteration)
        }
      }
    }
    if (verbose.resultReceived) {
      Logging.ssaResults(g, generatorMatrix.get, permutationMap, iteration)
    }
    generatorMatrix.get
  }*/

}

object SupportSplittingAlgorithm {

  case class SSAVerboseOptions(
      generatorMatrixGeneration: Boolean = true,
      resultReceived: Boolean = true
  )
  case class SsaStepResult(
      duplicatePositions: ListBuffer[ListBuffer[Seq[Int]]],
      signature: Map[Seq[Int], Seq[String]],
      partitions: Map[Int, Seq[String]]
  )

  /**
    * Get discriminant signature for given codewords
    *
    * @param codewords codewords list
    * @return signature of given codeword or exception
    * @throws Exception if impossible to find signature
    */
  def getSignature(codewords: List[GF2Vector]): Map[Seq[Int], Seq[String]] = {
    val n = codewords.head.getLength
    val signature = ssa(codewords, 0 until n)
    if (signature.size != n) {
      throw new Exception("[Cannot find signatures] Fully discriminant signature doesn't exist")
    }
    signature
  }

  /**
    * Punctures codewords and checks Hamming weight distribution
    *
    * @param codewords         codewords list
    * @param puncturePositions list positions to puncture codewords at
    * @param partitions        map of partitions
    * @return SSA step result
    */
  def ssaStep(
               codewords: List[GF2Vector],
               puncturePositions: Iterator[Seq[Int]],
               partitions: Map[Int, Seq[String]]
             ): SsaStepResult = {
    val duplicatePositions = ListBuffer[ListBuffer[Seq[Int]]]()
    val localPartitions = mutable.Map.empty[String, ListBuffer[Seq[Int]]]
    val returnPartitions = mutable.Map(partitions.toSeq: _*)
    val signature = mutable.Map.empty[Seq[Int], Seq[String]]

    for (puncturePositions <- puncturePositions) {
      val weightEnumPos = getHammingWeightDistribution(puncture(codewords, puncturePositions))
      // using HashCode for efficiency
      //val enum = weightEnumPos.hashCode.toString
      // uncomment this To debug the received weight enumerator
      val enum = weightEnumPos.toSeq.sortBy(_._1).map(t => t._1 + "->" + t._2).mkString(",")

      if (!localPartitions.isDefinedAt(enum)) {
        localPartitions(enum) = ListBuffer.empty[Seq[Int]]
      }
      localPartitions(enum) += puncturePositions

      val signatureFor = puncturePositions.head
      returnPartitions.update(signatureFor, returnPartitions(signatureFor) :+ enum)
    }
    for (partition <- localPartitions.values) {
      val signatureFor = partition.head
      if (partition.length > 1) {
        duplicatePositions += partition
      } else {
        // Add partition to signature and remove it from partitions
        signature(signatureFor) = returnPartitions(signatureFor.head)
        returnPartitions.remove(signatureFor.head)
      }
    }
    SsaStepResult(duplicatePositions, signature.toMap, returnPartitions.toMap)
  }

  /**
    * Support splitting algorithm implementation
    *
    * @param codewords          codewords list
    * @param puncturePositions  list positions to puncture codewords at
    * @param duplicatePositions positions which have identical invariant
    * @param partitions         map of partitioned position and it's invariants
    * @param signature          signature map of punctured position -> invariant
    * @param signatureToMatch   signature we trying to find
    * @return codewords signature if possible
    * @throws Exception if impossible to find signature
    */
  def ssa(
           codewords: List[GF2Vector],
           puncturePositions: Seq[Int],
           signature: mutable.Map[Seq[Int], Seq[String]] = mutable.Map.empty[Seq[Int], Seq[String]],
           duplicatePositions: ListBuffer[Seq[Int]] = ListBuffer.empty[Seq[Int]],
           partitions: Map[Int, Seq[String]] = Map.empty[Int, Seq[String]],
           signatureToMatch: Option[Map[Seq[Int], Seq[String]]] = None
         ): Map[Seq[Int], Seq[String]] = {
    var localSignature = Map.empty[Seq[Int], Seq[String]]
    var extraSsaStepsToRefine = ListBuffer.empty[SsaStepResult]
    val shouldCompare = signatureToMatch.isDefined

    // initial puncture
    if (duplicatePositions.isEmpty && signature.isEmpty) {
      val partitionMap = puncturePositions.map(_ -> Seq.empty[String]).toMap
      val ssaStepResult = ssaStep(codewords, puncturePositions.combinations(1), partitionMap)

      if (
        shouldCompare && ssaStepResult.signature.nonEmpty &&
          ssaStepResult.signature.values.exists { sigReceived =>
            !signatureToMatch.get.values.toSeq.contains(sigReceived)
          }
      ) {
        throw new Exception("[Cannot find matching signatures] Different signature received")
      }
      if (ssaStepResult.duplicatePositions.isEmpty) {
        // all signatures are unique
        localSignature = ssaStepResult.signature
      } else {
        // contains duplicate positions, need to refine
        extraSsaStepsToRefine += ssaStepResult
      }
    } else {
      val puncturePositionsIt = scala.util.Random.shuffle(puncturePositions).iterator
      // val puncturePositionsIt = puncturePositions.iterator

      while (localSignature.isEmpty && puncturePositionsIt.hasNext) {
        val puncturePosition = puncturePositionsIt.next
        var refinementPositions = ListBuffer.empty[Seq[Int]]
        for (position <- duplicatePositions) {
          refinementPositions += position :+ puncturePosition
        }
        val ssaStepResult = ssaStep(codewords, refinementPositions.iterator, partitions)
        if (!shouldCompare || ssaStepResult.signature.isEmpty || isMatchedSignature(ssaStepResult.signature, signatureToMatch.get)
        ) {
          if (ssaStepResult.duplicatePositions.isEmpty) {
            localSignature = ssaStepResult.signature
          } else {
            extraSsaStepsToRefine += ssaStepResult
          }
        }
        // else we ignore this solution
      }
    }
    if (localSignature.isEmpty) {
      val nextLevelIt = extraSsaStepsToRefine.sortBy(_.signature.size).iterator
      while (localSignature.isEmpty && nextLevelIt.hasNext) {
        var nextLevelSignatures = Map.empty[Seq[Int], Seq[String]]
        val refine = nextLevelIt.next
        val uniqueDuplicateIt = refine.duplicatePositions.iterator
        var found = true

        while (found && uniqueDuplicateIt.hasNext) {
          val uniqueDuplicatePositions = uniqueDuplicateIt.next
          val newPuncturePositions = getPuncturePositions(puncturePositions, uniqueDuplicatePositions)

          val result = ssa(
            codewords,
            newPuncturePositions,
            signature ++ refine.signature,
            uniqueDuplicatePositions,
            refine.partitions,
            signatureToMatch
          )
          if (result.isEmpty) {
            found = false
          } else {
            nextLevelSignatures ++= result
          }
        }
        // we found a solution for selected duplicate positions
        if (found) {
          localSignature = nextLevelSignatures ++ refine.signature
        }
      }
    }
    localSignature
  }

  /**
    * Find permutation between signatures and codewords
    *
    * @param signatureToMatch map of position -> weight enumerator
    * @param codewords  codewords list
    * @return permutation map
    * @throws Exception if permutation/signature cannot be found or no signature received
    */
  def findPermutation(signatureToMatch: Map[Seq[Int], Seq[String]], codewordsToMatch: List[GF2Vector], codewords: List[GF2Vector]): Map[Int, Int] = {
    val n = codewordsToMatch.head.getLength
    val signatureReceived = ssa(
      codewords,
      puncturePositions = 0 until n,
      signatureToMatch = Some(signatureToMatch)
    )

    if (signatureReceived.isEmpty) {
      throw new Exception("[Cannot find signatures] No signature received")
    } else if (!isPermutationEquivalent(codewords, signatureReceived, codewordsToMatch, signatureToMatch)) {
      throw new Exception("[Cannot find signatures] Not permutationally equivalent")
    }
    println(s"Signatures received(${signatureReceived.size}) with keys (${signatureReceived.keys}):\n$signatureReceived\n" +
      s"Signatures matched (${signatureToMatch.size}) with keys (${signatureToMatch.keys}): \n$signatureToMatch"
    )
    mapSignatures(signatureToMatch, signatureReceived)
  }

  /**
    * Create the permutation map for two codes based on their signatures
    *
    * @param signature        signature of given code
    * @param signatureToMatch signature of given code
    * @return permutation map
    * @throws Exception if permutation or signature cannot be found
    */
  def mapSignatures(signature: Map[Seq[Int], Seq[String]], signatureToMatch: Map[Seq[Int], Seq[String]]): Map[Int, Int] = {
    val permutation = mutable.Map.empty[Int, Int]
    for {
      (position, signature) <- signature
      (positionToMatch, signatureToMatch) <- signatureToMatch
    } yield {
      if (signature == signatureToMatch) {
        permutation(position.head) = positionToMatch.head
      }
    }
    if (permutation.size != signature.size) {
      throw new Exception("[Cannot find a permutation] Different signatures received.")
    }
    permutation.toMap
  }

  /**
    * Get puncture positions
    *
    * @param puncturePositions        already punctured positions
    * @param uniqueDuplicatePositions duplicate position group
    * @return puncture positions
    */
  def getPuncturePositions(puncturePositions: Seq[Int], uniqueDuplicatePositions: ListBuffer[Seq[Int]]): Seq[Int] = {
    // first we try unique positions (singletons + not used)
    val positionsPunctured = uniqueDuplicatePositions.flatten.distinct

    puncturePositions.diff(positionsPunctured)
  }

  /**
    * Get Hamming weight distribution (NP-hard hard problem)
    * Note. It is possible to use the hull of weight enumerator,
    * but it is less efficient with n <= 1000 (@see N. Sendrier. The Support Splitting Algorithm)
    *
    * @param codewords list of codeword vectors
    * @return Hamming weight enumerator map
    */
  def getHammingWeightDistribution(codewords: List[GF2Vector]): Map[Int, Int] = {
    val weightDistribution = mutable.Map.empty[Int, Int]
    for (codeword <- codewords) {
      val hammingWeight = codeword.getHammingWeight
      if (weightDistribution.isDefinedAt(hammingWeight)) {
        weightDistribution(hammingWeight) += 1
      } else {
        weightDistribution += (hammingWeight -> 1)
      }
    }
    weightDistribution.toMap
  }

  /**
    * Puncture codewords in given positions. Ignores duplicates!
    *
    * @param codewords list of codeword vectors
    * @param positions list of positions to puncture codewords
    * @return new punctured list of codeword vectors
    */
  def puncture(codewords: List[GF2Vector], positions: Seq[Int]): List[GF2Vector] = {
    val puncturedCodewords = new ListBuffer[GF2Vector]()
    for (vector <- codewords) {
      val out = IntUtils.clone(vector.getVecArray)
      for (position <- positions) {
        Vector.setColumn(out, 0, position)
      }
      val newVector = new GF2Vector(vector.getLength, out)
      if (!puncturedCodewords.contains(newVector)) {
        puncturedCodewords += newVector
      }
    }
    puncturedCodewords.toList
  }

  /**
    * Swap codewords by a given permutation
    *
    * @param codewords      list of codeword vectors
    * @param permutationMap permutation map
    * @return list of permuted codewords
    */
  def swapByPermutationMap(codewords: List[GF2Vector], permutationMap: Map[Int, Int]): List[GF2Vector] = {
    val permutedCodewords = new ListBuffer[GF2Vector]()
    val positions = new ListBuffer[Int]()
    for (permutation <- permutationMap.toSeq.sortBy(_._2)) {
      positions += permutation._1
    }
    for (codeword <- codewords) {
      permutedCodewords += Vector.createGF2VectorFromColumns(codeword, positions.toList)
    }
    permutedCodewords.toList
  }

  /**
    * Get refinement count for signature
    *
    * @param signature signature of code
    * @return count of refinement performed
    */
  def getRefinementCount(signature: Map[Seq[Int], Seq[String]]): Int = {
    signature.keySet.reduceLeft[Seq[Int]]((x, y) => if (x.length > y.length) x else y).length - 1
  }

  /**
    * Check if all received signature contains matching signature on the same level
    *
    * @param signature        signature received
    * @param signatureToMatch signature to match
    * @return
    */
  def isMatchedSignature(signature: Map[Seq[Int], Seq[String]], signatureToMatch: Map[Seq[Int], Seq[String]]): Boolean = {
    signature.forall { sig =>
      val sigMatched = signatureToMatch.find { sigToMatch => sigToMatch._2 == sig._2 }
      sigMatched.isDefined && sigMatched.get._1.length == sig._1.length
    }
  }

  /**
    * @todo puncture in one position only
    * @param codewords        list of codeword vectors
    * @param signature        signature of given code
    * @param codewordsToMatch list of codeword vectors to match
    * @param signatureToMatch signature of mathing code
    * @return
    */
  def isPermutationEquivalent(
                               codewords: List[GF2Vector],
                               signature: Map[Seq[Int], Seq[String]],
                               codewordsToMatch: List[GF2Vector],
                               signatureToMatch: Map[Seq[Int], Seq[String]]
                             ): Boolean = {
    var matched = true
    val puncturedSignatures = ListBuffer.empty[Map[Int, Int]]
    val positionsToPuncture = 0 until codewords.head.getLength
    for {
      puncturedPositions <- signature.keys
      puncturePosition <- positionsToPuncture.diff(puncturedPositions)
    } yield {
      println(s"Puncturing received: $puncturePosition")
      puncturedSignatures += getHammingWeightDistribution(puncture(
        codewords,
        puncturedPositions :+ puncturePosition
      ))
    }
    println(s"puncturedSignatures: $puncturedSignatures")
    println(s"Matched ${signatureToMatch.filter(el => signature.values.toSeq.contains(el._2))}")
    val signatureToMatchIt = signatureToMatch.filter(el => signature.values.toSeq.contains(el._2)).keys.iterator
    while (matched && signatureToMatchIt.hasNext) {
      val puncturedPositions = signatureToMatchIt.next
      val uniquePuncturePos = positionsToPuncture.diff(puncturedPositions).iterator
      while (matched && uniquePuncturePos.hasNext) {
        val puncturePosition = uniquePuncturePos.next
        println(s"Puncturing original position: $puncturePosition")
        val matchedPosition = getHammingWeightDistribution(puncture(
          codewordsToMatch,
          puncturedPositions :+ puncturePosition
        ))
        if (puncturedSignatures.contains(matchedPosition)) {
          puncturedSignatures -= matchedPosition
        } else {
          println(s"puncturedSignatures: $puncturedSignatures, matchedPosition: $matchedPosition")
          matched = false
        }
      }
    }
    println(s"[after] puncturedSignatures: $puncturedSignatures")
    println(s"Matched: $matched")
    matched
  }

}
