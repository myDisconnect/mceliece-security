package com.andrius.masterThesis.utils

import org.bouncycastle.pqc.math.linearalgebra.{GF2Matrix, Permutation}

/**
  * Utilities for Permutation class
  */
object PermutationUtils {

  /**
    * Transform permutation to GF2Matrix
    *
    * @param p permutation
    * @return GF2Matrix
    */
  def toGF2Matrix(p: Permutation): GF2Matrix = {
    val pVec = p.getVector
    val pLength = pVec.length
    val out = Array.ofDim[Int](pLength, (pLength - 1) / 32 + 1)
    for ((row, p) <- pVec.zipWithIndex) {
      out(row)(p / 32) ^= (1 << (p % 32))
    }
    new GF2Matrix(pLength, out)
  }

}
