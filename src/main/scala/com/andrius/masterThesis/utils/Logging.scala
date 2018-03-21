package com.andrius.masterThesis.utils

import com.andrius.masterThesis.attacks.Attack
import com.andrius.masterThesis.attacks.structural.SupportSplittingAlgorithm
import org.bouncycastle.pqc.math.linearalgebra.{GF2Matrix, GF2Vector, Permutation, PolynomialGF2mSmallM}

import scala.collection.mutable.ListBuffer

/**
  * Logging utilities
  */
object Logging {

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
                            attackIds: List[Int],
                            messageCount: Int,
                            timeResultsKeyPair: ListBuffer[Long],
                            extra: String = ""
                          ): Unit =
    Console.println(
      s"[ATTACK PARTIAL RESULTS] Average ${Attack.map.filter(attack => attackIds.contains(attack._1)).map(_._2).mkString(" + ")} attack " +
        s"time on single key pair (from $messageCount samples)" + extra +
        s": ${Math.average(timeResultsKeyPair)} ms. Min: ${timeResultsKeyPair.min}. Max: ${timeResultsKeyPair.max}."
    )

  def totalResults(
                    attackIds: List[Int],
                    messageCount: Int,
                    keyPairCount: Int,
                    timeResultsTotal: ListBuffer[Long],
                    extra: String = ""
                  ): Unit =
    Console.println(s"[ATTACK TOTAL RESULTS] Average ${Attack.map.filter(attack => attackIds.contains(attack._1)).map(_._2).mkString(" + ")} attack " +
      s"time (from ${keyPairCount * messageCount} samples)" + extra +
      s": ${Math.average(timeResultsTotal)} ms. Min: ${timeResultsTotal.min}. Max: ${timeResultsTotal.max}.")

  def ramUsageResults(): Unit = {
    val mb = 1024*1024
    val runtime = Runtime.getRuntime
    Console.println(
      s"[RAM USAGE RESULTS] Current RAM used ${(runtime.totalMemory - runtime.freeMemory) / mb}MB/" +
        s"${runtime.totalMemory / mb}MB"
    )
  }

  def ssaGeneratorMatrixGenerationResults(goppaPoly: PolynomialGF2mSmallM, gMatrix: GF2Matrix, iteration: Int): Unit = {
    Console.println(
      s"[SSA G GENERATION] Try number #$iteration. Selected irreducible binary Goppa code$goppaPoly\n" +
        s"Private generator matrix G = \n${gMatrix}Possible codewords:\n${GeneratorMatrix.generateAllCodewords(gMatrix)}\n"
    )
  }

  def ssaResults(publicG: GF2Matrix, generatedG: GF2Matrix, permutationMap: Map[Int, Int], iteration: Int): Unit = {
    Console.println(
      s"[SSA RESULT GENERATED] Number of tries required $iteration. Public generator matrix G' = \n$publicG" +
        s"Private generator matrix G = \n${generatedG}Permutation map:\n$permutationMap\n" +
        // @TODO DELETE THIS
        s"Permuted public G codewords\n${SupportSplittingAlgorithm.swapByPermutationMap(GeneratorMatrix.generateAllCodewords(generatedG), permutationMap)}\n" +
        s"generatedG keywords = ${GeneratorMatrix.generateAllCodewords(publicG)}"
    )
  }

}
