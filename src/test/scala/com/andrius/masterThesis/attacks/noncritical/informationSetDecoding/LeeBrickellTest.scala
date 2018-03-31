package com.andrius.masterThesis.attacks.noncritical.informationSetDecoding

import com.andrius.masterThesis.mceliece.McElieceCryptosystem
import com.andrius.masterThesis.mceliece.McElieceCryptosystem.Configuration
import com.andrius.masterThesis.utils.VectorUtils
import org.scalatest.FlatSpec

class LeeBrickellTest extends FlatSpec {

  "attack" should "always be successful" in {
    val configuration = Configuration(m = 5, t = 2)

    for (_ <- 0 until 5) {
      val mcEliecePKC = new McElieceCryptosystem(configuration)
      val leeBrickell = new LeeBrickell(mcEliecePKC.publicKey)
      for (_ <- 0 until 100) {

        val msg = VectorUtils.generateMessageVector(configuration.k)
        val cipher = mcEliecePKC.encryptVector(msg)
        assert(leeBrickell.attack(cipher).equals(msg), "Algorithm implemented incorrectly")
      }
    }
  }
}
