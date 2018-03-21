package com.andrius.masterThesis.utils

import org.bouncycastle.crypto.InvalidCipherTextException
import org.bouncycastle.pqc.math.linearalgebra.{GF2Vector, IntUtils}

import scala.util.Random

/**
  * Utilities for vectors over finite field GF(2)
  */
object Vector {

  /**
    * Create GF2Vector from sequence of [0,1]
    *
    * @param sequence elements containing 0 or 1
    * @return
    */
  def createGF2Vector(sequence: Seq[Int]): GF2Vector = {
    val length = sequence.length
    val out = Array.fill((length - 1) / 32 + 1)(0)

    for (i <- 0 until length) {
      val q = i >> 5
      val r = i & 0x1f
      out(q) += (1 << r) * sequence(i)
    }
    new GF2Vector(length, out)
  }

  /**
    * Create new vector from column list
    *
    * @param in      input vector
    * @param columns columns to extract from input vector
    * @return
    */
  def createGF2VectorFromColumns(in: GF2Vector, columns: List[Int]): GF2Vector = {
    val out = Array.fill((columns.length - 1) / 32 + 1)(0)
    val vector = in.getVecArray
    for ((indexToTake, indexToSet) <- columns.zipWithIndex) {
      Vector.setColumn(out, Vector.getColumn(vector, indexToTake), indexToSet)
    }
    new GF2Vector(columns.length, out)
  }

  /**
    * Generate a random message vector of given length
    * Contains at least one "1"
    *
    * @param k length
    * @return
    */
  def generateMessageVector(k: Int): GF2Vector = {
    val maxPlainTextSize = (k - 1) >> 3
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
    if (index < 0 || mrBytes(index) != 0x01) {
      throw new InvalidCipherTextException("Bad Padding: invalid ciphertext")
    }
    // extract and return message
    val mBytes = new Array[Byte](index)
    System.arraycopy(mrBytes, 0, mBytes, 0, index)
    mBytes
  }

  /**
    * Merge two GF2Vector into one
    *
    * @param left  GF2Vector
    * @param right GF2Vector
    * @return
    */
  def concat(left: GF2Vector, right: GF2Vector): GF2Vector = {
    val out = IntUtils.clone(left.getVecArray)
    for (i <- 0 until right.getLength) {
      Vector.setColumn(out, Vector.getColumn(right.getVecArray, i), i + left.getLength)
    }
    new GF2Vector(left.getLength + right.getLength, out)
  }

  /**
    * Get vector column (uses GF2Vector.getVecArray)
    *
    * @param in  input vector int array
    * @param pos position of the element in the vector
    * @return value of column. Possible values: 0,1
    */
  def getColumn(in: Array[Int], pos: Int): Int = {
    val elem = pos % 32
    val length = pos / 32
    (in(length) >>> elem) & 1
  }

  /**
    * Set vector column (changes received vector Int array)
    *
    * @param in    input vector int array
    * @param value value to be set. Allowed values: 0,1
    * @param pos   position of the element in the vector
    */
  def setColumn(in: Array[Int], value: Int, pos: Int): Unit = {
    val elem = pos % 32
    val length = pos / 32
    val a = in(length)
    val el = (a >>> elem) & 1
    if (el != value) {
      in(length) = a ^ (1 << elem)
    }
  }

}
