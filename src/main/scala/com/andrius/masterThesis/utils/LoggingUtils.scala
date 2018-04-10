package com.andrius.masterThesis.utils

import com.andrius.masterThesis.attacks.Attack
import com.andrius.masterThesis.attacks.structural.SupportSplittingAlgorithm
import org.bouncycastle.pqc.math.linearalgebra.{GF2Matrix, GF2Vector, Permutation, PolynomialGF2mSmallM}

import scala.collection.mutable.ListBuffer

/**
  * Logging utilities
  */
object LoggingUtils {

  def receivedSecurityParametersResults(n: Int, k: Int, t: Int, m: Int): Unit = {
    Console.println(
      s"[RECEIVED SECURITY PARAMETERS] m = $m, t = $t, which is equivalent to (n, k, t) = ($n, $k, $t)"
    )
  }

  def attacksInfo(attackIds: Int*): Unit = {
    Console.println(s"[ATTACK INFO] Executing ${attackIds.map(Attack.map(_)).mkString(" + ")} attack(s).")
  }

  def keyPairGenerationResults(
      goppaPoly: PolynomialGF2mSmallM,
      g: GF2Matrix,
      s: GF2Matrix,
      p: Permutation,
      gPublic: GF2Matrix
  ): Unit = {
    Console.println(
      s"[KEY PAIR GENERATION] Selected irreducible binary Goppa code$goppaPoly\n" +
        s"Private generator matrix G = \n$g" +
        //s"Possible G codewords:\n${GeneratorParityCheckMatrix.generateAllCodewords(gMatrix)}\n" +
        s"Matrix S = \n${s}Permutation P = \n${PermutationUtils.toGF2Matrix(p)}\n" +
        s"Public G = \n$gPublic"
    )
  }

  def cipherGenerationResults(m: GF2Vector, mG: GF2Vector, e: GF2Vector): Unit = {
    Console.println(
      s"[CIPHER GENERATION] Message vector m = $m, random error vector e = $e, m * G' = $mG, " +
        s"cipher c = ${mG.add(e).asInstanceOf[GF2Vector]}"
    )
  }

  def singleKeyPairResults(
      messageCount: Int,
      timeResultsKeyPair: ListBuffer[Long],
      extra: String = ""
  ): Unit = {
    Console.println(
      s"[ATTACK PARTIAL RESULTS] Average attack time on single key pair (from $messageCount samples)" +
        s": ${MathUtils.average(timeResultsKeyPair)} ms. Min: ${timeResultsKeyPair.min} ms. " +
        s"Max: ${timeResultsKeyPair.max} ms. $extra"
    )
  }

  def totalResults(
      messageCount: Int,
      keyPairCount: Int,
      timeResultsTotal: ListBuffer[Long],
      extra: String = ""
  ): Unit = {
    Console.println(
      s"[ATTACK TOTAL RESULTS] Average attack time (from ${keyPairCount * messageCount} samples)" +
        s": ${MathUtils.average(timeResultsTotal)} ms. Min: ${timeResultsTotal.min} ms. " +
        s"Max: ${timeResultsTotal.max} ms. $extra"
    )
  }

  def ramUsageResults(): Unit = {
    val mb      = 1024 * 1024
    val runtime = Runtime.getRuntime
    Console.println(
      s"[RAM USAGE RESULTS] Current RAM used ${(runtime.totalMemory - runtime.freeMemory) / mb}MB/" +
        s"${runtime.totalMemory / mb}MB"
    )
  }

  def ssaGeneratorMatrixGenerationResults(goppaPoly: PolynomialGF2mSmallM, gMatrix: GF2Matrix, iteration: Int): Unit = {
    Console.println(
      s"[SSA G GENERATION] Try number #$iteration. Selected irreducible binary Goppa code$goppaPoly\n" +
        s"Private generator matrix G = \n${gMatrix}Possible codewords:\n" +
        s"${GeneratorMatrixUtils.generateAllCodewords(gMatrix)}"
    )
  }

  def ssaResults(publicG: GF2Matrix, generatedG: GF2Matrix, permutationMap: Map[Int, Int], iteration: Int): Unit = {
    Console.println(
      s"[SSA RESULT GENERATED] Number of tries required $iteration. Public generator matrix G' = \n$publicG" +
        s"Private generator matrix G = \n${generatedG}Permutation map:\n$permutationMap\n" +
        // @TODO DELETE THIS
        s"Permuted public G codewords\n${SupportSplittingAlgorithm
          .swapByPermutationMap(GeneratorMatrixUtils.generateAllCodewords(generatedG), permutationMap)}\n" +
        s"generatedG keywords = ${GeneratorMatrixUtils.generateAllCodewords(publicG)}"
    )
  }

}
