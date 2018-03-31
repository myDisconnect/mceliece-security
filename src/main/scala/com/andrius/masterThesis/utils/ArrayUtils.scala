package com.andrius.masterThesis.utils

/**
  * Array utilities
  */
object ArrayUtils {

  /**
    * Clones the provided array
    *
    * @param in array to clone
    * @return a new clone of the provided array
    */
  def cloneArray(in: Array[Array[Int]]): Array[Array[Int]] = {
    val out = Array.ofDim[Int](in.length, in(0).length)
    for {
      i <- in.indices
      j <- in(i).indices
    } out(i)(j) = in(i)(j)
    out
  }

  /**
    * Clones the provided array
    *
    * @param in array to clone
    * @return a new clone of the provided array
    */
  def cloneArray(in: Array[Int]): Array[Int] = {
    val out = Array.ofDim[Int](in.length)
    Array.copy(in, 0, out, 0, in.length)
    out
  }

}
