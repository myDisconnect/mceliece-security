package com.andrius.masterThesis.utils

import org.bouncycastle.crypto.InvalidCipherTextException
import org.bouncycastle.pqc.math.linearalgebra.{GF2Vector, IntUtils}

import scala.util.Random

/**
  * Vector Utils
  */
object Vector {

  /**
    * Generate a random message vector of given length
    * Contains at least one "1"
    *
    * @param k length
    * @return
    */
  def generateMessageVector(k: Int): GF2Vector = {
    val maxPlainTextSize = k >> 3
    val out = Array.fill[Byte](maxPlainTextSize)(0)
    Random.nextBytes(out)

    computeMessageRepresentative(k, out)
  }

  /**
    * Transform bytes to message vector
    *
    * @see org.bouncycastle.pqc.crypto.mceliece.McElieceCipher
    * @param k     length
    * @param input plaintext in byte array
    * @return
    */
  def computeMessageRepresentative(k: Int, input: Array[Byte]): GF2Vector = {
    val maxPlainTextSize = k >> 3
    val data = new Array[Byte](maxPlainTextSize + (if ((k & 0x07) != 0) 1 else 0))
    System.arraycopy(input, 0, data, 0, input.length)
    data(input.length) = 0x01
    GF2Vector.OS2VP(k, data)
  }

  /**
    * Transform message vector to bytes
    *
    * @see org.bouncycastle.pqc.crypto.mceliece.McElieceCipher
    * @param mr vector
    * @return
    */
  @throws[InvalidCipherTextException]
  def computeMessage(mr: GF2Vector): Array[Byte] = {
    val mrBytes = mr.getEncoded
    // find first non-zero byte
    var index = mrBytes.length - 1
    while (index >= 0 && mrBytes(index) == 0) {
      index -= 1
    }

    // check if padding byte is valid
    if (index < 0 || mrBytes(index) != 0x01) throw new InvalidCipherTextException("Bad Padding: invalid ciphertext")
    // extract and return message
    val mBytes = new Array[Byte](index)
    System.arraycopy(mrBytes, 0, mBytes, 0, index)
    mBytes
  }

  def concat(left: GF2Vector, right: GF2Vector): GF2Vector = {
    val out = IntUtils.clone(left.getVecArray)
    for (i <- 0 until right.getLength) {
      Vector.setColumn(out, Vector.getColumn(right.getVecArray, i), i + left.getLength)
    }
    new GF2Vector(left.getLength + right.getLength, out)
  }

  def vectorFromColumns(in: GF2Vector, columns: List[Int]): GF2Vector = {
    val out = Array.fill((columns.length - 1) / 32 + 1)(0)
    val vector = in.getVecArray
    for ((indexToTake, indexToSet) <- columns.zipWithIndex) {
      Vector.setColumn(out, Vector.getColumn(vector, indexToTake), indexToSet)
    }
    new GF2Vector(columns.length, out)
  }

  def getColumn(in: Array[Int], i: Int): Int = {
    val elem = i % 32
    val length = i / 32
    (in(length) >>> elem) & 1
  }

  def setColumn(in: Array[Int], int: Int, i: Int): Unit = {
    val elem = i % 32
    val length = i / 32
    val a = in(length)
    val el = (a >>> elem) & 1
    if (el != int) {
      in(length) = a ^ (1 << elem)
    }
  }

}
