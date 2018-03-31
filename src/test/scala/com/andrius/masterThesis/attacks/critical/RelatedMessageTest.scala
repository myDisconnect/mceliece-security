package com.andrius.masterThesis.attacks.critical

import com.andrius.masterThesis.mceliece.McElieceCryptosystem
import com.andrius.masterThesis.mceliece.McElieceCryptosystem.Configuration
import com.andrius.masterThesis.utils.{CombinatoricsUtils, VectorUtils}
import org.bouncycastle.pqc.math.linearalgebra.GF2Vector
import org.scalatest.FlatSpec

class RelatedMessageTest extends FlatSpec {

  val logPartial = false
  val logTotal = false

  val configuration = Configuration(m = 5, t = 3)

  "Related message attack based on linearly independent error-free positions" should "succeed in most cases" in {
    var totalTries = 0
    var totalExpectedTries = 0d

    for (_ <- 0 until 5) {
      val mcEliecePKC = new McElieceCryptosystem(configuration)
      val relatedMessage = new RelatedMessage(mcEliecePKC.publicKey)
      for (_ <- 0 until 100) {
        val msg1 = VectorUtils.generateMessageVector(configuration.k)
        // For example, we know that message vector always differ in every 32 position
        val mDelta = new GF2Vector(configuration.k, Array.fill((configuration.k - 1) / 32 + 1)(1))
        val msg2 = msg1.add(mDelta).asInstanceOf[GF2Vector]
        val cipher1 = mcEliecePKC.encryptVector(msg1)
        val cipher2 = mcEliecePKC.encryptVector(msg2)
        if (!cipher1.equals(mcEliecePKC.publicKey.gPublic.leftMultiply(mDelta).add(cipher2).asInstanceOf[GF2Vector])) {
          var tries = 1
          totalTries += 1
          while (!relatedMessage.attack2(cipher1, cipher2, mDelta).equals(msg1)) {
            tries += 1
            totalTries += 1
          }
          val l1Length = cipher1.add(
            mcEliecePKC.publicKey.gPublic.leftMultiply(mDelta).add(cipher2).asInstanceOf[GF2Vector]
          ).asInstanceOf[GF2Vector].getHammingWeight
          val l0Length = configuration.n - l1Length
          val unknownErrors = mcEliecePKC.publicKey.t - l1Length / 2
          val guessProbability = CombinatoricsUtils.combinations(
            l0Length - unknownErrors, configuration.k).toDouble /
            CombinatoricsUtils.combinations(l0Length, configuration.k).toDouble
          val expectedTries = 1 / guessProbability
          totalExpectedTries += expectedTries
          if (logPartial) {
            println(f"Attack succeeded in $tries tries with ${guessProbability * 100}%1.2f%% probability and expected $expectedTries%1.2f tries")
          }
        }
      }
      if (logTotal) {
        println(s"Attacks succeeded in $totalTries tries out of expected ${math.ceil(totalExpectedTries).toInt}")
      }
    }
  }

  "Related message attack based on finding error vector positions" should "succeed in most cases" in {
    var totalTries = 0
    var totalExpectedTries = 0d

    for (_ <- 0 until 5) {
      val mcEliecePKC = new McElieceCryptosystem(configuration)
      val relatedMessage = new RelatedMessage(mcEliecePKC.publicKey)
      for (_ <- 0 until 100) {
        val msg1 = VectorUtils.generateMessageVector(configuration.k)
        // For example, we know that message vector always differ in every 32 position
        val mDelta = new GF2Vector(configuration.k, Array.fill((configuration.k - 1) / 32 + 1)(1))
        val msg2 = msg1.add(mDelta).asInstanceOf[GF2Vector]
        val cipher1 = mcEliecePKC.encryptVector(msg1)
        val cipher2 = mcEliecePKC.encryptVector(msg2)
        if (!cipher1.equals(mcEliecePKC.publicKey.gPublic.leftMultiply(mDelta).add(cipher2).asInstanceOf[GF2Vector])) {
          var tries = 1
          totalTries += 1
          while (!relatedMessage.attack1(cipher1, cipher2, mDelta).equals(msg1)) {
            tries += 1
            totalTries += 1
          }
          val l1Length = cipher1.add(
            mcEliecePKC.publicKey.gPublic.leftMultiply(mDelta).add(cipher2).asInstanceOf[GF2Vector]
          ).asInstanceOf[GF2Vector].getHammingWeight
          val unknownErrors = (2 * mcEliecePKC.publicKey.t - l1Length) / 2
          val knownErrors = mcEliecePKC.publicKey.t - unknownErrors
          val expectedTries = CombinatoricsUtils.combinations(2 * knownErrors, knownErrors).toDouble *
            CombinatoricsUtils.combinations(configuration.n - mcEliecePKC.publicKey.t, unknownErrors).toDouble
          val guessProbability = 1 / expectedTries
          totalExpectedTries += expectedTries
          if (logPartial) {
            println(f"Attack succeeded in $tries tries with ${guessProbability * 100}%1.2f%% probability and expected $expectedTries%1.2f tries")
          }
        }
      }
      if (logTotal) {
        println(s"Attacks succeeded in $totalTries tries out of expected ${math.ceil(totalExpectedTries).toInt}")
      }
    }
  }

}
