package com.andrius.masterThesis.attacks.structural

import java.security.SecureRandom

import com.andrius.masterThesis.utils.{GeneratorMatrix, Matrix, Vector}
import org.bouncycastle.pqc.jcajce.provider.mceliece.BCMcEliecePublicKey
import org.bouncycastle.pqc.math.linearalgebra.{GF2Matrix, GF2Vector, GF2mField, IntUtils, PolynomialGF2mSmallM, PolynomialRingGF2}

import scala.collection.mutable
import scala.collection.mutable.ListBuffer

/**
  * @see N. Sendrier. Finding the permutation between equivalent codes: the support splitting algorithm.
  * @see N. Sendrier. The Support Splitting Algorithm (https://hal.archives-ouvertes.fr/inria-00073037/document)
  * @see Great slides (https://who.rocq.inria.fr/Dimitrios.Simos/talks/CBCSlides2012.pdf)
  * @see Inria Cryptography course on McEliece cryptosystem: (https://www.canal-u.tv/video/inria/4_2_support_splitting_algorithm.32925)
  */
class SupportSplittingAlgorithm(publicKey: BCMcEliecePublicKey) {
  import SupportSplittingAlgorithm._

  var publicKeySignature: mutable.Map[Int, String] = getSignature(Matrix.generateAllCodewords(publicKey.getG))
  var k: Int = publicKey.getK
  var t: Int = publicKey.getT
  var n: Int = publicKey.getN
  var m: Int = (n - k) / t

  /**
    * @return private key matrix g
    */
  def attack: GF2Matrix = {
    val sr = new SecureRandom
    val failedGPTriesDictionary = new mutable.HashSet[PolynomialGF2mSmallM]()
    var generatorMatrix: Option[GF2Matrix] = None

    val fieldPoly = PolynomialRingGF2.getIrreduciblePolynomial(m)
    val field = new GF2mField(m, fieldPoly)

    var iterations = 0
    while (generatorMatrix.isEmpty) {
      // It is possible to find permutation between two different Goppa polynomials
      val goppaPoly = new PolynomialGF2mSmallM(field, t, PolynomialGF2mSmallM.RANDOM_IRREDUCIBLE_POLYNOMIAL, sr)
      if (!failedGPTriesDictionary.contains(goppaPoly)) {
        failedGPTriesDictionary += goppaPoly
        iterations +=1
        try {
          generatorMatrix = Some(GeneratorMatrix.getGeneratorMatrix(field, goppaPoly, sr))
          val permutationMap = SupportSplittingAlgorithm.findPermutation(
            publicKeySignature,
            Matrix.generateAllCodewords(generatorMatrix.get)
          )
          println(s"Iterations needed: $iterations\nPermutation Map received $permutationMap\n")
        } catch {
          case e: Exception =>
            generatorMatrix = None
            println(s"${e.getMessage}")
        }
        println(s"Goppa poly: $goppaPoly\neGenerator matrix:\n${generatorMatrix.get}\ncodewords\n${Matrix.generateAllCodewords(generatorMatrix.get)}")
      }
    }
    publicKey.getG
  }

}

object SupportSplittingAlgorithm {

  case class SsaStepResult(
      duplicatePositions: ListBuffer[ListBuffer[Seq[Int]]],
      signatures: mutable.Map[Int, String]
  )
  case class SsaResult(signatures: mutable.Map[Int, String])
  case class ExtraSsaRefine(ssaStep: SsaStepResult, puncturedPosition: Int)

  /**
    *
    * @param codewords codewords list
    * @return signature of given codeword or exception
    * @throws Exception if impossible to find signature
    */
  def getSignature(codewords: List[GF2Vector]): mutable.Map[Int, String] =
  {
    val n = codewords.head.getLength
    val puncturePositions = 0 until n
    val initialSsaResult = ssaStep(codewords, puncturePositions.combinations(1))
    var ssaResult: Option[SsaResult] = None

    // fully discriminant signature found
    if (initialSsaResult.duplicatePositions.isEmpty) {
      ssaResult = Some(SsaResult(initialSsaResult.signatures))
    } else {
      // trying to refine
      ssaResult = ssaRefine(
        codewords,
        initialSsaResult.duplicatePositions,
        initialSsaResult.signatures,
        (initialSsaResult.signatures.keys.toSeq ++ puncturePositions).distinct
      )
    }
    if (ssaResult.isDefined) {
      ssaResult.get.signatures
    } else {
      throw new Exception("Couldn't find signature")
    }
  }

  /**
    *
    * @param codewords         codewords list
    * @param puncturePositions list positions to puncture codewords at
    * @return
    */
  def ssaStep(codewords: List[GF2Vector], puncturePositions: Iterator[Seq[Int]]): SsaStepResult = {
    val duplicatePositions = ListBuffer[ListBuffer[Seq[Int]]]()
    val partitions = mutable.Map.empty[String, ListBuffer[Seq[Int]]]
    val signatures = mutable.Map.empty[Int, String]

    for (puncturePositions <- puncturePositions) {
      val weightEnumPos = getHammingWeightDistribution(puncture(codewords, puncturePositions))
      // Could use hashCode for efficiency
      val enum = weightEnumPos.toString
      if (!partitions.isDefinedAt(enum)) {
        partitions(enum) = new ListBuffer[Seq[Int]]()
      }
      partitions(enum) += puncturePositions
    }
    for ((enum, partition) <- partitions) {
      if (partition.length > 1) {
        duplicatePositions += partition
      } else {
        signatures(partition.head.head) = enum
      }
    }
    SsaStepResult(duplicatePositions, signatures)
  }

  /**
    *
    * @param codewords          codewords list
    * @param duplicatePositions positions which have identical weight enumerator
    * @param signatures         map of position -> weight enumerator
    * @param puncturePositions  list positions to puncture codewords at
    * @param signaturesToFind   map of signatures we trying to find
    * @return signatures if possible
    */
  def ssaRefine(codewords: List[GF2Vector],
                duplicatePositions: ListBuffer[ListBuffer[Seq[Int]]],
                signatures: mutable.Map[Int, String],
                puncturePositions: Seq[Int],
                signaturesToFind: Option[mutable.Map[Int, String]] = None
               ): Option[SsaResult] = {
    var extraSsaStepsToRefine = ListBuffer.empty[ExtraSsaRefine]
    var ssaResult: Option[SsaResult] = None
    val puncturePositionsIt = puncturePositions.iterator
    val shouldCompare = signaturesToFind.isDefined

    while (ssaResult.isEmpty && puncturePositionsIt.hasNext) {
      val puncturePosition = puncturePositionsIt.next
      for {
        uniqueDuplicatePositions <- duplicatePositions
      } yield {
        val refinementPositions = ListBuffer[Seq[Int]]()
        for (position <- uniqueDuplicatePositions) {
          refinementPositions += position :+ puncturePosition
        }
        val ssaStepResult = ssaStep(codewords, refinementPositions.iterator)
        /*println(
          s"Signatures:\n$signatures\nSsa step result duplicate positions:\n" +
            ssaStepResult.duplicatePositions + "\n"
        )*/
        // check if we have all signatures
        if (ssaStepResult.duplicatePositions.isEmpty) {
          // check if all signatures are unique
          if (
            !ssaStepResult.signatures.values.exists(signatures.values.toSeq.contains)
              && (
              !shouldCompare
                || ssaStepResult.signatures.values.toSeq.forall(signaturesToFind.get.values.toSeq.contains)
              )
          ) {
            // fully discriminant signature found
            ssaResult = Some(SsaResult(signatures ++ ssaStepResult.signatures))
          } else {
            // collision or comparing
            if (!ssaStepResult.signatures.values.exists(signatures.values.toSeq.contains))
              println("Collision case!")
            // todo fix collision case
          }
        } else {
          // try to refine again
          extraSsaStepsToRefine += ExtraSsaRefine(ssaStepResult, puncturePosition)
        }
      }
    }
    val refineIt = extraSsaStepsToRefine.iterator
    while (ssaResult.isEmpty && refineIt.hasNext) {
      val toRefine = refineIt.next
      ssaResult = ssaRefine(
        codewords,
        toRefine.ssaStep.duplicatePositions,
        toRefine.ssaStep.signatures ++ signatures,
        puncturePositions.diff(Seq(toRefine.puncturedPosition))
      )
    }
    ssaResult
  }

  /**
    * Find permutation between signatures and codewords
    *
    * @param signatures map of position -> weight enumerator
    * @param codewords  codewords list
    * @return
    * @throws Exception if permutation or signature cannot be found
    */
  def findPermutation(signatures: mutable.Map[Int, String], codewords: List[GF2Vector]): mutable.Map[Int, Int] = {
    val n = codewords.head.getLength
    val puncturePositions = 0 until n
    val initialSsaResult = ssaStep(codewords, puncturePositions.combinations(1))
    // Check if received signatures are compatible with given signatures
    if (initialSsaResult.signatures.values.toList.exists( signature => !signatures.values.toSeq.contains(signature))) {
      throw new Exception("Cannot find a permutation") // Should I use this???
    }
    if (initialSsaResult.duplicatePositions.isEmpty) {
      // fully discriminant signature found
      mapSignatures(signatures, initialSsaResult.signatures)
    } else {
      // trying to refine
      val ssaResult = ssaRefine(
        codewords,
        initialSsaResult.duplicatePositions,
        initialSsaResult.signatures,
        (initialSsaResult.signatures.keys.toSeq ++ puncturePositions).distinct,
        Some(signatures)
      )
      if (ssaResult.isDefined) {
        mapSignatures(signatures, ssaResult.get.signatures)
      } else {
        throw new Exception("Couldn't find signature")
      }
    }
  }

  /**
    * Create the permutation map for two linear codes based on their signatures
    *
    * @param signatures  signature of linear code C
    * @param signatures2 signature of linear code C'
    * @return permutation map
    */
  def mapSignatures(signatures: mutable.Map[Int, String], signatures2: mutable.Map[Int, String]): mutable.Map[Int, Int] = {
    // @TODO check if permutation map is correct
    val permutation = mutable.Map.empty[Int, Int]
    for {
      (position, signature) <- signatures
      (position2, signature2) <- signatures2
    } yield {
      if (signature == signature2) {
        permutation(position) = position2
      }
    }
    permutation
  }

  /**
    * Get Hamming weight distribution
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

}
