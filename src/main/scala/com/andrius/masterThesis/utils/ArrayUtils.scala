package com.andrius.masterThesis.utils

/**
  * Array utilities
  */
object ArrayUtils {

  /**
    * Clones the provided array
    *
    * @param in Array to clone
    * @return a new clone of the provided array
    */
  def cloneArray(in: Array[Array[Int]]): Array[Array[Int]] = {
    val length = in.length
    val out = Array.ofDim[Int](length, in(0).length)
    for (i <-0 until length) {
      System.arraycopy(in(i), 0, out(i), 0, in(i).length)
    }
    out
  }

}
