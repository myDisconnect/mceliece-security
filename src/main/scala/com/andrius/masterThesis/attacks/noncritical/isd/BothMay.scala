package com.andrius.masterThesis.attacks.noncritical.isd

import org.bouncycastle.pqc.math.linearalgebra.{GF2Matrix, GF2Vector}

/**
  * @todo after finishing all the attacks implement this too :)
  * @see https://eprint.iacr.org/2017/1139.pdf
  */
class BothMay {

  /**
    *
    * @param syndrome
    * @param publicKey
    */
  def attack(syndrome: GF2Vector, publicKey: GF2Matrix) = {
    //PolynomialRingGF2.getIrreduciblePolynomial(m)
    // ka noriu padaryti:
    //publicKey.
    //publicKey
    //GoppaCode.computeSystematicForm().getG()
    //for (row <- 0 to publicKey.getK)
      //for (col <- 0 to publicKey.getN)
    /*for (row <- 0 to publicKey.getN) {
      println(cipherVector.getBit(row*publicKey.getK))
    }*/
    /*for (cipherCol <- cipherVector.getLength)
      println(cipherCol)*/
  }

  /**
    *
    * @param parityCheckMatrix
    * @param syndrome
    * @param t Error-correcting
    */
  def weightDistributionAndStandardForm(parityCheckMatrix: GF2Matrix, syndrome: GF2Vector, t: Int) = {

  }
}
/*
uždavinys rasti klaidu vektoriu e

*/
//01010111010011111100011100001100 10000110101010000110000100110011 01111101111101010110000010011010 11100000001000111110111010100100 01110101110011111110000010010010 10010100100110001110000011111011 00100100001111011111000011011101 01101011100011100101000010011111 10000000110100110000010010111011 11110110011111111000001100101010 10101101010001100010100000010010 10011000101011100101110011000100 01001110101001000011000000010001 10100000011001000100101000010011 11000110001100011011000001010010 10111011000110101001100010101010