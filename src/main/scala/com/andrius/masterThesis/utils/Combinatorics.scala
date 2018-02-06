package com.andrius.masterThesis.utils

import scala.annotation.tailrec

object Combinatorics {

  /**
    * Possible k-combination of a set S with n elements
    * n! / (k! * (n - k)!)
    *
    * @param n elements in
    * @param k
    * @return
    */
  def countPossibleCombinations(n: BigInt, k: BigInt): BigInt =
    factorial(n) / (factorial(k) * factorial(n - k))

  /**
    * Factorial n!
    *
    * @param n input number
    * @return
    */
  def factorial(n: BigInt): BigInt = {
    @tailrec
    def factorialAccumulator(acc: BigInt, n: BigInt): BigInt = {
      if (n == 0) acc
      else factorialAccumulator(n * acc, n - 1)
    }

    factorialAccumulator(1, n)
  }

}
