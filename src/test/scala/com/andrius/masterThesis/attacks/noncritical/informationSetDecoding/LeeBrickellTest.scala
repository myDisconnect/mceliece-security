package com.andrius.masterThesis.attacks.noncritical.informationSetDecoding

import com.andrius.masterThesis.mceliece.McElieceCryptosystem
import com.andrius.masterThesis.mceliece.McElieceCryptosystem.Configuration
import com.andrius.masterThesis.utils.Vector
import org.scalatest.FlatSpec

class LeeBrickellTest extends FlatSpec {

  behavior of "Lee-Brickell (GISD) attack"

  it should "attack and never fail" in {
    val configuration = Configuration(m = 5, t = 2)

    for (_ <- 0 until 5) {
      val mcEliecePKC = new McElieceCryptosystem(configuration)
      val leeBrickell = new LeeBrickell(mcEliecePKC.publicKey)
      for (_ <- 0 until 100) {

        val msg = Vector.generateMessageVector(configuration.k)
        val cipher = mcEliecePKC.encryptVector(msg)
        assert(leeBrickell.attack(cipher).equals(msg), "Algorithm implemented incorrectly")
      }
    }
  }
}
