package com.andrius.masterThesis.utils

import com.andrius.masterThesis.attacks.Attack
import org.bouncycastle.pqc.math.linearalgebra
import org.bouncycastle.pqc.math.linearalgebra.{GF2Matrix, GF2Vector, Permutation, PolynomialGF2mSmallM}

import scala.collection.mutable.ListBuffer

object Logging {

  def keyPairGenerationResults(
                                goppaPoly: PolynomialGF2mSmallM,
                                gMatrix: GF2Matrix,
                                sMatrix: GF2Matrix,
                                pPermutation: Permutation,
                              ): Unit = {
    println(
      s"[KEY PAIR GENERATION] Selected irreducible binary Goppa code$goppaPoly\n" +
        s"Private generator matrix G=\n${gMatrix}Matrix S=\n${sMatrix}Permutation P=$pPermutation"
    )
  }

  def cipherGenerationResults(m: GF2Vector, mG: GF2Vector, e: GF2Vector): Unit = {
    println(
      s"[CIPHER GENERATION] Message vector m=$m, m*Gpub=$mG, random error vector e=$e, " +
        s"cipher c=${mG.add(e).asInstanceOf[GF2Vector]}"
    )
  }

  def totalResults(
                    attackIds: List[Int],
                    messageCount: Int,
                    keyPairCount: Int,
                    timeResultsTotal: ListBuffer[Long],
                    extra: String = ""
                  ): Unit =
    println(s"[ATTACK TOTAL RESULTS] Average ${Attack.map.filter(attack => attackIds.contains(attack._1)).map(_._2).mkString(" + ")} attack " +
      s"time (from ${keyPairCount * messageCount} samples) " + extra +
      s": ${Math.average(timeResultsTotal)} ms")

  def singleKeyPairResults(
                            attackIds: List[Int],
                            messageCount: Int,
                            timeResultsKeyPair: ListBuffer[Long],
                            extra: String = ""
                          ): Unit =
    println(
      s"[ATTACK PARTIAL RESULTS] Average ${Attack.map.filter(attack => attackIds.contains(attack._1)).map(_._2).mkString(" + ")} attack " +
        s"time on single key pair (from $messageCount samples) " + extra +
        s": ${Math.average(timeResultsKeyPair)} ms"
    )

}
