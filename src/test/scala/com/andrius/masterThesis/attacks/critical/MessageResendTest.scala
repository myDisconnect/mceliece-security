package com.andrius.masterThesis.attacks.critical

import com.andrius.masterThesis.mceliece.McElieceCryptosystem
import com.andrius.masterThesis.mceliece.McElieceCryptosystem.Configuration
import com.andrius.masterThesis.utils.{CombinatoricsUtils, VectorUtils}
import org.bouncycastle.pqc.math.linearalgebra.GF2Vector
import org.scalatest.FlatSpec

class MessageResendTest extends FlatSpec {

  val logPartial = false
  val logTotal   = false

  val configuration = Configuration(m = 5, t = 3)

  "Message resend attack based on finding error vector positions" should "succeed in most cases" in {
    var totalTries         = 0
    var totalExpectedTries = 0d

    for (_ <- 0 until 5) {
      val mcEliecePKC   = new McElieceCryptosystem(configuration)
      val messageResend = new MessageResend(mcEliecePKC.publicKey)
      for (_ <- 0 until 100) {
        val msg     = VectorUtils.generateMessageVector(configuration.k)
        val cipher1 = mcEliecePKC.encryptVector(msg)
        val cipher2 = mcEliecePKC.encryptVector(msg)
        if (!cipher1.equals(cipher2)) {
          var tries = 1
          totalTries += 1
          while (!messageResend.attack1(cipher1, cipher2).equals(msg)) {
            tries += 1
            totalTries += 1
          }
          val l1Length = cipher1.add(cipher2).asInstanceOf[GF2Vector].getHammingWeight
          val expectedTries = MessageResend.getAttack1TriesExpected(
            configuration.n,
            configuration.t,
            l1Length
          )
          val guessProbability = 1d / expectedTries
          totalExpectedTries += expectedTries
          if (logPartial) {
            println(
              f"Attack succeeded in $tries tries with ${guessProbability * 100}%1.2f%% probability " +
                s"and expected $expectedTries tries."
            )
          }
        }
      }
      if (logTotal) {
        println(s"Attacks succeeded in $totalTries tries out of expected ${math.ceil(totalExpectedTries).toInt}")
      }
    }
  }

  "Message resend attack based on linearly independent error-free positions" should "succeed in most cases" in {
    var totalTries         = 0
    var totalExpectedTries = 0d

    for (_ <- 0 until 5) {
      val mcEliecePKC   = new McElieceCryptosystem(configuration)
      val messageResend = new MessageResend(mcEliecePKC.publicKey)
      for (_ <- 0 until 100) {
        val msg     = VectorUtils.generateMessageVector(configuration.k)
        val cipher1 = mcEliecePKC.encryptVector(msg)
        val cipher2 = mcEliecePKC.encryptVector(msg)
        if (!cipher1.equals(cipher2)) {
          var tries = 1
          totalTries += 1
          while (!messageResend.attack2(cipher1, cipher2).equals(msg)) {
            tries += 1
            totalTries += 1
          }
          val l1Length = cipher1.add(cipher2).asInstanceOf[GF2Vector].getHammingWeight
          val l0Length = configuration.n - l1Length
          val guessProbability = MessageResend.getAttack2GuessProbability(
            configuration.k,
            configuration.t,
            l0Length,
            l1Length
          )
          val expectedTries = (1 / guessProbability).toInt
          totalExpectedTries += expectedTries
          if (logPartial) {
            println(
              f"Attack succeeded in $tries tries with ${guessProbability * 100}%1.2f%% probability " +
                s"and expected $expectedTries tries."
            )
          }
        }
      }
      if (logTotal) {
        println(s"Attacks succeeded in $totalTries tries out of expected ${math.ceil(totalExpectedTries).toInt}")
      }
    }
  }

}
