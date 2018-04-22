package com.andrius.masterThesis.attacks.noncritical.informationSetDecoding

import com.andrius.masterThesis.mceliece.McElieceCryptosystem.McEliecePublicKey
import com.andrius.masterThesis.utils.{CombinatoricsUtils, MathUtils, MatrixUtils, VectorUtils}
import org.bouncycastle.pqc.math.linearalgebra.{GF2Matrix, GF2Vector}

import scala.collection.immutable.Range
import scala.collection.mutable

/**
  * Implementation of generalized Lee-Brickell algorithm (Also known as Generalized Information-Set Decoding)
  *
  * @param publicKey McEliece public key
  * @see P. J. Lee and E. F. Brickell. An Observation on the Security of McEliece's Public-Key Cryptosystem (https://pdfs.semanticscholar.org/b26c/08563e5f1d0dbf241dfe77ceee9da458149c.pdf)
  * @see C. Peters. Information-set decoding for linear codes over Fq (https://eprint.iacr.org/2009/589.pdf)
  * @see D. Engelbert, R. Overbeck and A. Schmidt. A Summary of McEliece-Type Cryptosystems and their Security (https://eprint.iacr.org/2006/162)
  * @see C. Peters. Explicit Bounds for Generic Decoding Algorithms for Code-Based Cryptography (https://christianepeters.files.wordpress.com/2012/10/20090401-eipsi.pdf)
  */
class LeeBrickell(publicKey: McEliecePublicKey) {

  val g: GF2Matrix = publicKey.gPublic
  val n: Int       = g.getNumColumns
  val k: Int       = g.getNumRows
  val t: Int       = publicKey.t

  /**
    * Try to guess k correct positions in the received word.
    * A “correct” guess is assumed when this error vector has t Hamming weight.
    * When we can find the original message from received error vector
    *
    * @param c cipher
    * @param p the search size parameter (0 <= p <= t), must be small to keep the number of size-p subsets,
    *          p = 2 is optimal for the binary case
    * @return message
    */
  def attack(c: GF2Vector, p: Int = 2): GF2Vector = {
    require(p >= 0 && p <= t, s"The search size parameter must be 0 <= p <= t. Received p = $p, t = $t.")

    var decipheredMsg         = new GF2Vector(k)
    var found                 = false
    val columns               = (0 until n).toList
    val failedTriesDictionary = mutable.HashSet.empty[Set[Int]]
    while (!found) {
      // Step 1. We randomise a possible "information-set" columns
      val i = MathUtils.sample(columns, k)
      // Order is not important, because columns should be linearly independent
      val iSet = i.toSet
      if (!failedTriesDictionary.contains(iSet)) {
        failedTriesDictionary += iSet
        val gi = MatrixUtils.createGF2MatrixFromColumns(g, i)
        try {
          val giInv = gi.computeInverse
          val q     = giInv.rightMultiply(g).asInstanceOf[GF2Matrix] // a.k.a gt
          // Step 2. Create ci (from c columns)
          val ci = VectorUtils.createGF2VectorFromColumns(c, i)
          val y  = c.add(q.leftMultiply(ci)).asInstanceOf[GF2Vector]
          // Step 3. Trying to find error vector of t Hamming weight
          val piIt = Range.inclusive(0, p).iterator
          while (!found && piIt.hasNext) {
            val pi  = piIt.next
            val aIt = Range(0, k).combinations(pi)
            while (!found && aIt.hasNext) {
              val a   = aIt.next
              var sum = new GF2Vector(n)
              for (i <- Range(0, pi)) {
                val row = new GF2Vector(q.getNumColumns, q.getRow(a(i)))
                sum = sum.add(row).asInstanceOf[GF2Vector]
              }

              val e = y.add(sum).asInstanceOf[GF2Vector]
              if (e.getHammingWeight == t) {
                found = true
                val ei = VectorUtils.createGF2VectorFromColumns(e, i)
                decipheredMsg = giInv.leftMultiply(ci.add(ei)).asInstanceOf[GF2Vector]
                // to get a nearest codeword of t Hamming distance from c
                // c.add(e).asInstanceOf[GF2Vector]
              }
            }
          }
        } catch {
          case _: ArithmeticException =>
          // Matrix cannot be inverted. Not an information set
        }
      }
    }
    decipheredMsg
  }

}

object LeeBrickell {

  /**
    * Get correct error vector guess probability on single information-set
    *
    * @param n code length
    * @param k code dimension
    * @param t error correction capability of the code
    * @param p search size
    * @return probability
    */
  def getGuessProbability(n: Int, k: Int, t: Int, p: Int): Double = {
    var probability = 0d
    for (i <- 0 to p if i <= k) {
      probability += (CombinatoricsUtils.combinations(n - k, t - i) * CombinatoricsUtils.combinations(k, i)).toDouble /
        CombinatoricsUtils.combinations(n, t).toDouble
    }
    probability
  }

  /**
    * Get expected tries to find correct error vector on single information-set
    *
    * @param n code length
    * @param k code dimension
    * @param t error correction capability of the code
    * @param p search size
    * @return expected tries
    */
  def getTriesExpected(n: Int, k: Int, t: Int, p: Int): Int = {
    (1 / getGuessProbability(n, k, t, p)).toInt
  }

}
