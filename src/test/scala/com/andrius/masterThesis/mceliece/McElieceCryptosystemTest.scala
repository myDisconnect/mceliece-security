package com.andrius.masterThesis.mceliece

import com.andrius.masterThesis.mceliece.McElieceCryptosystem.Configuration
import com.andrius.masterThesis.utils.Vector
import org.scalatest.FlatSpec

class McElieceCryptosystemTest extends FlatSpec {

  behavior of "McElieceCryptosystemTest"
  val configuration = Configuration(m = 5, t = 2)
  val mcEliecePKC = new McElieceCryptosystem(configuration)

  it should "encrypt and decrypt bytes" in {
    val msg = "l".getBytes(McElieceCryptosystem.Charset)
    assert(
      mcEliecePKC.decrypt(mcEliecePKC.encrypt(msg)).sameElements(msg),
      "Could not something wrong with encryption/decryption"
    )
  }

  it should "encrypt and decrypt string" in {
    val msg = "l"
    assert(
      mcEliecePKC.decryptString(mcEliecePKC.encrypt(msg)).equals(msg),
      "Could not something wrong with encryption/decryption"
    )
  }

  it should "encrypt and decrypt vector" in {
    val msg = Vector.generateMessageVector(mcEliecePKC.publicKey.getK)
    assert(
      mcEliecePKC.decryptVector(mcEliecePKC.encryptVector(msg)).equals(msg),
      "Could not something wrong with encryption/decryption"
    )
  }

}
