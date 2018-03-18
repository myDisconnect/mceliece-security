package com.andrius.masterThesis.attacks.structural

import java.security.SecureRandom

import com.andrius.masterThesis.attacks.structural.SupportSplittingAlgorithm.SSAVerboseOptions
import com.andrius.masterThesis.mceliece.McElieceCryptosystem.McEliecePublicKey
import com.andrius.masterThesis.utils.{GeneratorParityCheckMatrix, Logging, Matrix, Vector}
import org.bouncycastle.pqc.math.linearalgebra.{GF2Matrix, GF2Vector, GF2mField, IntUtils, Permutation, PolynomialGF2mSmallM, PolynomialRingGF2}

import scala.collection.mutable
import scala.collection.mutable.ListBuffer

/**
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

  var publicKeySignature: Map[Seq[Int], String] = getSignature(GeneratorParityCheckMatrix.generateAllCodewords(g))

  /**
    * @return private key matrix g
    */
  def attack: GF2Matrix = {
    val sr = new SecureRandom
    val failedGPTriesDictionary = mutable.HashSet.empty[PolynomialGF2mSmallM]
    var generatorMatrix: Option[GF2Matrix] = None
    var permutationMap = Map.empty[Int, Int]

    val fieldPoly = PolynomialRingGF2.getIrreduciblePolynomial(m)
    val field = new GF2mField(m, fieldPoly)

    var iteration = 0
    while (generatorMatrix.isEmpty) {
      // It is possible to find permutation between two different Goppa polynomials
      // Also it is possible that two different irreductible goppa codes have the same generator matrix
      val goppaPoly = new PolynomialGF2mSmallM(field, t, PolynomialGF2mSmallM.RANDOM_IRREDUCIBLE_POLYNOMIAL, sr)
      if (!failedGPTriesDictionary.contains(goppaPoly)) {
        failedGPTriesDictionary += goppaPoly
        iteration +=1
        val gMatrix = GeneratorParityCheckMatrix.getGeneratorMatrix(field, goppaPoly, p, sr)
        try {
          permutationMap = SupportSplittingAlgorithm.findPermutation(
            publicKeySignature,
            GeneratorParityCheckMatrix.generateAllCodewords(gMatrix)
          )
          generatorMatrix = Some(gMatrix)
        } catch {
          case e: Exception =>
            println(s"${e.getMessage}")
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
  }

}

object SupportSplittingAlgorithm {

  case class SSAVerboseOptions(
      generatorMatrixGeneration: Boolean = true,
      resultReceived: Boolean = true
  )
  case class SsaStepResult(duplicatePositions: ListBuffer[ListBuffer[Seq[Int]]], signatures: Map[Seq[Int], String])
  case class ExtraSsaRefine(ssaStep: SsaStepResult, puncturedPosition: Option[Int] = None)
  case class SsaResult(signatures: Map[Int, String])

  /**
    * Get weight enumerator signature for given codewords
    *
    * @param codewords codewords list
    * @return signature of given codeword or exception
    * @throws Exception if impossible to find signature
    */
  def getSignature(codewords: List[GF2Vector]): Map[Seq[Int], String] = {
    val n = codewords.head.getLength
    val signatures = ssa(codewords, 0 until n)
    if (signatures.size != n) {
      throw new Exception("[Cannot find a signatures] Fully discriminant signature doesn't exist")
    }
    signatures
  }

  /**
    * Punctures codewords and checks Hamming weight distribution
    *
    * @param codewords         codewords list
    * @param puncturePositions list positions to puncture codewords at
    * @return
    */
  def ssaStep(codewords: List[GF2Vector], puncturePositions: Iterator[Seq[Int]]): SsaStepResult = {
    val duplicatePositions = ListBuffer[ListBuffer[Seq[Int]]]()
    val partitions = mutable.Map.empty[String, ListBuffer[Seq[Int]]]
    val signatures = mutable.Map.empty[Seq[Int], String]

    for (puncturePositions <- puncturePositions) {
      val weightEnumPos = getHammingWeightDistribution(puncture(codewords, puncturePositions))
      // Could use hashCode for efficiency
      val enum = weightEnumPos.toSeq.sortBy(_._1).toString
      if (!partitions.isDefinedAt(enum)) {
        partitions(enum) = new ListBuffer[Seq[Int]]()
      }
      partitions(enum) += puncturePositions
    }
    for ((enum, partition) <- partitions) {
      if (partition.length > 1) {
        duplicatePositions += partition
      } else {
        signatures(partition.head) = enum
      }
    }
    SsaStepResult(duplicatePositions, signatures.toMap)
  }

  /**
    *
    * @param codewords          codewords list
    * @param puncturePositions  list positions to puncture codewords at
    * @param signatures         map of position -> weight enumerator
    * @param duplicatePositions positions which have identical weight enumerator
    * @param signaturesToFind   map of signatures we trying to find
    * @return signatures if possible
    */
  def ssa(codewords: List[GF2Vector],
          puncturePositions: Seq[Int],
          signatures: Map[Seq[Int], String] = Map.empty[Seq[Int], String],
          duplicatePositions: ListBuffer[Seq[Int]] = ListBuffer.empty[Seq[Int]],
          signaturesToFind: Option[Map[Seq[Int], String]] = None
         ): Map[Seq[Int], String] = {
    var localSignatures = Map.empty[Seq[Int], String]
    var extraSsaStepsToRefine = ListBuffer.empty[ExtraSsaRefine]
    val shouldCompare = signaturesToFind.isDefined
    // Initial puncture
    if (duplicatePositions.isEmpty && signatures.isEmpty) {
      val ssaStepResult = ssaStep(codewords, puncturePositions.combinations(1))
      println(
        s"Result: $ssaStepResult"
      )
      if (ssaStepResult.duplicatePositions.isEmpty) {
        // check if all signatures are unique
        if (!shouldCompare || ssaStepResult.signatures.values.toSeq.forall(signaturesToFind.get.values.toSeq.contains)) {
          localSignatures = ssaStepResult.signatures
        }
        // else we ignore this solution
      } else {
        extraSsaStepsToRefine += ExtraSsaRefine(ssaStepResult)
      }
    } else {
      //val puncturePositionsIt = scala.util.Random.shuffle(puncturePositions).iterator
      // @TODO ask if is possible without the knowledge of S, show example
      val puncturePositionsIt = puncturePositions.diff(duplicatePositions.flatten.distinct).iterator

      while (localSignatures.isEmpty && puncturePositionsIt.hasNext) {
        val puncturePosition = puncturePositionsIt.next
        var refinementPositions = ListBuffer.empty[Seq[Int]]
        for (position <- duplicatePositions) {
          // the unique keys just don't work (what the fuck?!!!)
          // refinementPositions += (position :+ puncturePosition).distinct
          refinementPositions += position :+ puncturePosition
        }
        val ssaStepResult = ssaStep(codewords, refinementPositions.iterator)
        /*println(
          s"Puncture position added: $puncturePosition\nPucture positions:\n" +
            s"$refinementPositions\nResult: $ssaStepResult"
        )*/
        // check if we have only signatures
        if (ssaStepResult.duplicatePositions.isEmpty) {
          // check if all signatures are unique
          val duplicateSignatures = ListBuffer.empty[ListBuffer[Seq[Int]]]
          val newSignatures = mutable.Map.empty[Seq[Int], String]
          // at first we try only unique partitions, when we try all
          val currentSignatures = signatures.values.toSeq
          for {
            (newSignature, partition) <- ssaStepResult.signatures
          } yield {
            if (currentSignatures.contains(partition)) {
              duplicateSignatures += ListBuffer[Seq[Int]](newSignature)
            } else {
              newSignatures(newSignature) = partition
            }
          }
          if (duplicateSignatures.nonEmpty) {
            //println(s"Duplicates $duplicateSignatures\nNew Signatures: $newSignatures")
          }
          if (duplicateSignatures.isEmpty) {
            localSignatures = ssaStepResult.signatures
          } else {
            /*if (!shouldCompare || ssaStepResult.signatures.values.toSeq.forall(signaturesToFind.get.values.toSeq.contains)) {
              throw new Exception("WE ARE FUCKED")
            }*/
            extraSsaStepsToRefine += ExtraSsaRefine(
              SsaStepResult(duplicateSignatures, newSignatures.toMap),
              Some(puncturePosition)
            )
            /*if (
              !ssaStepResult.signatures.values.exists(signatures.values.toSeq.contains)
                && (!shouldCompare || ssaStepResult.signatures.values.toSeq.forall(signaturesToFind.get.values.toSeq.contains))
              ) {
              localSignatures = ssaStepResult.signatures
            }*/
            // we do something
          }
          // else we ignore this solution
        } else {
          extraSsaStepsToRefine += ExtraSsaRefine(ssaStepResult, Some(puncturePosition))
        }
      }
    }
    if (localSignatures.isEmpty) {
      val nextLevelIt = extraSsaStepsToRefine.iterator
      while (localSignatures.isEmpty && nextLevelIt.hasNext) {
        var nextLevelSignatures = Map.empty[Seq[Int], String]
        var found = true
        val refine = nextLevelIt.next
        val uniqueDuplicateIt = refine.ssaStep.duplicatePositions.iterator
        while (found && uniqueDuplicateIt.hasNext) {
          val newPuncturePositions = if (refine.puncturedPosition.isDefined) {
            puncturePositions.diff(Seq(refine.puncturedPosition.get))
          } else {
            puncturePositions
          }
          //println(s"we get here:$newPuncturePositions from $puncturePositions, and pos: ${refine.puncturedPosition}")
          val result = ssa(
            codewords,
            newPuncturePositions,
            signatures ++ refine.ssaStep.signatures ++ nextLevelSignatures,
            uniqueDuplicateIt.next
          )
          if (result.isEmpty) {
            found = false
          } else {
            nextLevelSignatures ++= result
          }
        }
        if (found) {
          localSignatures = nextLevelSignatures ++ refine.ssaStep.signatures
        }
      }
    }
    localSignatures
  }

  /**
    * Find permutation between signatures and codewords
    *
    * @param signatures map of position -> weight enumerator
    * @param codewords  codewords list
    * @return
    * @throws Exception if permutation or signature cannot be found
    */
  def findPermutation(signatures: Map[Seq[Int], String], codewords: List[GF2Vector]): Map[Int, Int] = {
    val n = codewords.head.getLength
    val signaturesToMatch = ssa(codewords, 0 until n, signaturesToFind = Some(signatures))

    if (signaturesToMatch.nonEmpty) {
      mapSignatures(signatures, signaturesToMatch)
    } else {
      throw new Exception("[Cannot find signatures] No signature received")
    }
  }

  /**
    * Create the permutation map for two linear codes based on their signatures
    *
    * @param signatures        signature of linear code C
    * @param signaturesToMatch signature of linear code C'
    * @return permutation map
    * @throws Exception if permutation or signature cannot be found
    */
  def mapSignatures(signatures: Map[Seq[Int], String], signaturesToMatch: Map[Seq[Int], String]): Map[Int, Int] = {
    val permutation = mutable.Map.empty[Int, Int]
    for {
      (position, signature) <- signatures
      (positionToMatch, signatureToMatch) <- signaturesToMatch
    } yield {
      if (signature == signatureToMatch && position.length == positionToMatch.length) {
        permutation(position.head) = positionToMatch.head
      }
    }
    if (permutation.size != signatures.size) {
      throw new Exception("[Cannot find a permutation] Different signatures received.")
    }
    permutation.toMap
  }

  /**
    * Get Hamming weight distribution (NP-hard hard problem)
    * Note. It is possible to use the hull of weight enumerator,
    * but it is less efficient with n <= 1000 (@see N. Sendrier. The Support Splitting Algorithm)
    *
    * @param codewords list of codeword vectors
    * @return Hamming weight enumerator map
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
    * Puncture codewords in given positions
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
      puncturedCodewords += new GF2Vector(vector.getLength, out)
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
    for (permutation <- permutationMap.toSeq.sortBy(_._1)) {
      positions += permutation._2
    }
    for (codeword <- codewords) {
      permutedCodewords += Vector.createGF2VectorFromColumns(codeword, positions.toList)
    }
    permutedCodewords.toList
  }

}
