package com.andrius.masterThesis.utils

import java.security.SecureRandom

import org.bouncycastle.pqc.math.linearalgebra.PolynomialRingGF2

import scala.collection.mutable

/**
  * Utilities for binary irreductible Goppa codes
  */
object Goppa {

  /**
    * Creates irreducible polynomial with degree d
    *
    * @param deg polynomial degree
    * @return irreducible polynomial p
    */
  def getIrreduciblePolynomial(deg: Int, sr: SecureRandom): Int = {
    require(deg > 0 && deg < 32, "Polynomial degree must be deg must be between 0 < deg < 32")
    if (deg == 0) {
      1
    } else {
      val a = (1 << deg) + 1
      val b = 1 << (deg + 1)
      val subFieldTries = (b - a) / 2 + 1
      var irrPoly = 0
      val failedTriesDictionary = mutable.HashSet.empty[Int]

      while (irrPoly == 0 && failedTriesDictionary.size != subFieldTries) {
        val i = sr.nextInt(subFieldTries) * 2
        if (!failedTriesDictionary.contains(i)) {
          failedTriesDictionary += i
          val degTry = a + i
          if (PolynomialRingGF2.isIrreducible(degTry)) {
            irrPoly = degTry
          }
        }
      }
      irrPoly
    }
  }

}
