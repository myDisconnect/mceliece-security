package com.andrius.masterThesis.attacks.critical

import org.bouncycastle.pqc.jcajce.provider.mceliece.BCMcEliecePublicKey
import org.bouncycastle.pqc.math.linearalgebra.GF2Vector

/**
  *
  * @param publicKey McEliece public key
  * @see https://github.com/chenroger/McElieceDemo
  */
class ChosenCiphertext(publicKey: BCMcEliecePublicKey) {

  def attack(c1: GF2Vector, c2: GF2Vector) = {

  }
}
