package com.andrius.masterThesis.attacks.noncritical.informationSetDecoding

import com.andrius.masterThesis.utils.Math
import com.andrius.masterThesis.utils.Matrix
import com.andrius.masterThesis.utils.Vector
import org.bouncycastle.pqc.jcajce.provider.mceliece.BCMcEliecePublicKey
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
class LeeBrickell(publicKey: BCMcEliecePublicKey) {

  val g: GF2Matrix = publicKey.getG
  val n: Int = g.getNumColumns
  val k: Int = g.getNumRows
  val t: Int = publicKey.getT

  /**
    * Try to guess k correct positions in the received word.
    * A “correct” guess is assumed when this error vector has t Hamming weight.
    * When we can find the original message from received error vector
    *
    * @param c cipher
    * @return message
    */
  def attack(c: GF2Vector): GF2Vector = {
    var decipheredMsg = new GF2Vector(k)
    var found = false
    val columns = (0 until n).toList
    val failedDictionary = new mutable.HashSet[Set[Int]]()
    // p - the search size parameter (0 <= p <= t),
    // must be small to keep the number of size-p subsets, p = 2 is optimal (@see 2)
    val p = 2
    while (!found) {
      // Step 1. We randomise a possible "information-set" columns
      val i = Math.sample(columns, k)
      // Order is not important, because columns are linearly independent
      val iSet = i.toSet
      if (!failedDictionary.contains(iSet)) {
        failedDictionary += iSet
        val gi = Matrix.createGF2MatrixFromColumns(g, i)
        try {
          val giInv = gi.computeInverse
          val gt = giInv.rightMultiply(g).asInstanceOf[GF2Matrix]
          // Step 2. Create ci (from c columns)
          val ci = Vector.createGF2VectorFromColumns(c, i)
          val y = c.add(gt.leftMultiply(ci)).asInstanceOf[GF2Vector]
          // Step 3. Trying to find error vector of t Hamming weigh
          for {
            pi <- Range.inclusive(0, p)
            a <- Range(0, k).combinations(pi)
          } yield {
            var sum = new GF2Vector(n)
            for (i <- Range(0, pi)) {
              val row = new GF2Vector(gt.getNumColumns, gt.getRow(a(i)))
              sum = sum.add(row).asInstanceOf[GF2Vector]
            }

            val e = y.add(sum).asInstanceOf[GF2Vector]
            if (e.getHammingWeight == t) {
              found = true
              val ei = Vector.createGF2VectorFromColumns(e, i)
              decipheredMsg = giInv.leftMultiply(ci.add(ei).asInstanceOf[GF2Vector]).asInstanceOf[GF2Vector]
              // to get a nearest codeword of t Hamming distance from c
              // c.add(e).asInstanceOf[GF2Vector]
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
