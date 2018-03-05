package com.andrius.masterThesis.attacks.critical

import com.andrius.masterThesis.attacks.noncritical.informationSetDecoding.LeeBrickell
import com.andrius.masterThesis.mceliece.McElieceCryptosystem
import com.andrius.masterThesis.mceliece.McElieceCryptosystem.Configuration
import com.andrius.masterThesis.utils.Vector
import org.scalatest.FlatSpec

class KnownPartialPlaintextTest extends FlatSpec {

  behavior of "KnownPartialPlaintextAttack"

  it should "attack and reduce complexity" in {
    val configuration = Configuration(m = 5, t = 2)
    val mcEliecePKC = new McElieceCryptosystem(configuration)
    val partial = new KnownPartialPlaintext(mcEliecePKC.publicKey)
    for (kRight <- 10 until mcEliecePKC.publicKey.getK) {
      val msg = Vector.generateMessageVector(mcEliecePKC.publicKey.getK)
      val cipher = mcEliecePKC.encryptVector(msg)
      val knownRight = msg.extractRightVector(kRight)
      // Attack counts successful if security complexity was reduced
      val reducedParameters = partial.attack(knownRight, cipher)
      assert(
        reducedParameters.publicKey.getK == mcEliecePKC.publicKey.getK - kRight,
        "Algorithms implemented incorrectly"
      )
    }
  }

  it should "attack with GISD and never fail" in {
    val configuration = Configuration(m = 5, t = 2)

    for (_ <- 0 until 10) {
      val mcEliecePKC = new McElieceCryptosystem(configuration)
      val partial = new KnownPartialPlaintext(mcEliecePKC.publicKey)
      for (kRight <- 1 until mcEliecePKC.publicKey.getK) {
        for (_ <- 0 until 100) {
          val msg = Vector.generateMessageVector(mcEliecePKC.publicKey.getK)
          val cipher = mcEliecePKC.encryptVector(msg)
          val knownRight = msg.extractRightVector(kRight)
          // Attack counts successful if security complexity was reduced
          val reducedParameters = partial.attack(knownRight, cipher)

          // Any other decoding attack can be used
          val leeBrickell = new LeeBrickell(reducedParameters.publicKey)
          assert(
            Vector.concat(leeBrickell.attack(reducedParameters.cipher), knownRight).equals(msg),
            "One of algorithms implemented incorrectly"
          )
        }
      }
    }
  }

}
