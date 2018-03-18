package com.andrius.masterThesis.mceliece

import com.andrius.masterThesis.mceliece.McElieceCryptosystem.Configuration
import com.andrius.masterThesis.utils.{GeneratorParityCheckMatrix, Vector}
import org.scalatest.FlatSpec

class McElieceCryptosystemTest extends FlatSpec {

  behavior of "McEliece Cryptosystem"

  val configuration = Configuration(m = 5, t = 2)

  it should "encrypt and decrypt bytes" in {
    val msg = "l".getBytes(McElieceCryptosystem.Charset)
    for (_ <- 0 until 100) {
      val mcEliecePKC = new McElieceCryptosystem(configuration)
      assert(
        mcEliecePKC.decrypt(mcEliecePKC.encrypt(msg)).sameElements(msg),
        "Could not encrypt and decrypt bytes"
      )
    }
  }

  it should "encrypt and decrypt string" in {
    val msg = "l"
    for (_ <- 0 until 100) {
      val mcEliecePKC = new McElieceCryptosystem(configuration)
      assert(
        mcEliecePKC.decryptString(mcEliecePKC.encrypt(msg)).equals(msg),
        "Could not encrypt and decrypt string"
      )
    }
  }

  it should "encrypt and decrypt vector" in {
    for (_ <- 0 until 100) {
      val mcEliecePKC = new McElieceCryptosystem(configuration)
      val msg = Vector.generateMessageVector(mcEliecePKC.k)

      assert(
        mcEliecePKC.decryptVector(mcEliecePKC.encryptVector(msg)).equals(msg),
        "Could not encrypt and decrypt vector"
      )
    }
  }

}
