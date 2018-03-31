package com.andrius.masterThesis.mceliece

import com.andrius.masterThesis.mceliece.McElieceCryptosystem.Configuration
import com.andrius.masterThesis.utils.{GeneratorMatrixUtils, VectorUtils}
import org.scalatest.FlatSpec

class McElieceCryptosystemTest extends FlatSpec {

  val configuration = Configuration(m = 5, t = 2)
  val iterations = 100

  behavior of s"McEliece Cryptosystem (m = ${configuration.m}, t = ${configuration.t}) with $iterations iterations"

  it should s"encrypt and decrypt bytes" in {
    val msg = "l".getBytes(McElieceCryptosystem.Charset)
    for (_ <- 0 until iterations) {
      val mcEliecePKC = new McElieceCryptosystem(configuration)
      assert(
        mcEliecePKC.decrypt(mcEliecePKC.encrypt(msg)).sameElements(msg),
        "Could not encrypt and decrypt bytes"
      )
    }
  }

  it should "encrypt and decrypt string" in {
    val msg = "l"
    for (_ <- 0 until iterations) {
      val mcEliecePKC = new McElieceCryptosystem(configuration)
      assert(
        mcEliecePKC.decryptString(mcEliecePKC.encrypt(msg)).equals(msg),
        "Could not encrypt and decrypt string"
      )
    }
  }

  it should "encrypt and decrypt vector" in {
    for (_ <- 0 until iterations) {
      val mcEliecePKC = new McElieceCryptosystem(configuration)
      val msg = VectorUtils.generateMessageVector(mcEliecePKC.k)

      assert(
        mcEliecePKC.decryptVector(mcEliecePKC.encryptVector(msg)).equals(msg),
        "Could not encrypt and decrypt vector"
      )
    }
  }

}
