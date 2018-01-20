package com.andrius.masterThesis.attacks.noncritical.informationSetDecoding

import com.andrius.masterThesis.mceliece.McElieceCryptosystem
import com.andrius.masterThesis.mceliece.McElieceCryptosystem.BasicConfiguration
import com.andrius.masterThesis.utils.Vector

class LeeBrickellTest extends org.scalatest.FlatSpec {

  behavior of "LeeBrickellTest"

  it should "attack and never fail" in {
    val configuration = BasicConfiguration(m = 5, t = 2)

    for (_ <- 0 until 5) {
      val mcEliecePKC = new McElieceCryptosystem(configuration)
      val leeBrickell = new LeeBrickell(mcEliecePKC.publicKey)
      for (_ <- 0 until 100) {

        val msg = Vector.generateMessageVector(mcEliecePKC.publicKey.getK)
        val cipher = mcEliecePKC.encryptVector(msg)
        assert(leeBrickell.attack(cipher).equals(msg), "Algorithm implemented incorrectly")
      }
    }
  }
}
