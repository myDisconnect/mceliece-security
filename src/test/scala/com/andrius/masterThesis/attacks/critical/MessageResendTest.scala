package com.andrius.masterThesis.attacks.critical

import com.andrius.masterThesis.mceliece.McElieceCryptosystem
import com.andrius.masterThesis.mceliece.McElieceCryptosystem.Configuration
import com.andrius.masterThesis.utils.{Combinatorics, Vector}
import org.bouncycastle.pqc.math.linearalgebra.GF2Vector
import org.scalatest.FlatSpec

class MessageResendTest extends FlatSpec {

  behavior of "MessageResendAttack"

  val logPartial = false
  val logTotal = true

  it should "attack and in most cases succeed" in {
    val configuration = Configuration(m = 5, t = 2)
    var totalTries = 0
    var totalExpectedTries = 0d

    for (_ <- 0 until 5) {
      val mcEliecePKC = new McElieceCryptosystem(configuration)
      val messageResend = new MessageResend(mcEliecePKC.publicKey)
      for (_ <- 0 until 100) {
        val msg = Vector.generateMessageVector(mcEliecePKC.publicKey.getK)
        val cipher1 = mcEliecePKC.encryptVector(msg)
        val cipher2 = mcEliecePKC.encryptVector(msg)
        if (!cipher1.equals(cipher2)) {
          var tries = 1
          totalTries += 1
          while (!messageResend.attack(cipher1, cipher2).equals(msg)) {
            tries += 1
            totalTries += 1
          }
          val l1Length = cipher1.add(cipher2).asInstanceOf[GF2Vector].getHammingWeight
          val l0Length = mcEliecePKC.publicKey.getN - l1Length
          val unknownErrors = (2 * mcEliecePKC.publicKey.getT - l1Length) / 2
          val guessProbability = Combinatorics.combinations(l0Length - unknownErrors, mcEliecePKC.publicKey.getK).toDouble / Combinatorics.combinations(l0Length, mcEliecePKC.publicKey.getK).toDouble
          val expectedTries = 1 / guessProbability
          totalExpectedTries += expectedTries
          if (logPartial) {
            println(f"Attack succeeded in $tries tries with $guessProbability%1.2f probability and expected $expectedTries%1.2f")
          }
        }
      }
      if (logTotal) {
        println(s"Attacks succeeded in $totalTries tries out of expected ${math.ceil(totalExpectedTries).toInt}")
      }
    }
  }

}
