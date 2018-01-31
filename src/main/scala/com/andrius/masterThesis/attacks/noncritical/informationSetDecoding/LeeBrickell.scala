package com.andrius.masterThesis.attacks.noncritical.informationSetDecoding

import com.andrius.masterThesis.utils.Math
import com.andrius.masterThesis.utils.Matrix._
import com.andrius.masterThesis.utils.Vector._
import org.bouncycastle.pqc.jcajce.provider.mceliece.BCMcEliecePublicKey
import org.bouncycastle.pqc.math.linearalgebra.{GF2Matrix, GF2Vector}

import scala.collection.immutable.Range
import scala.collection.mutable.ListBuffer

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
    var out = new GF2Vector(g.getNumRows, Array.fill((g.getNumRows - 1) / 32 + 1)(0))
    var found = false
    // Dictionary should be optimised
    var dictionary = new ListBuffer[List[Int]]()
    while (!found) {
      // Step 1 We randomise information-set columns
      // @todo think about dictionary vs precomputing vs nothing https://stackoverflow.com/questions/30112035/sample-without-replacement-or-duplicates-in-r
      val i = Math.sample((0 until n).toList, k)
      if (!dictionary.contains(i)) {
        dictionary += i
        val gi = matrixFromColumns(g, i)
        try {
          val giInv = gi.computeInverse
          val gt = giInv.rightMultiply(g).asInstanceOf[GF2Matrix]
          // Step 2
          val ci = vectorFromColumns(c, i)
          val y = c.add(gt.leftMultiply(ci)).asInstanceOf[GF2Vector]
          // Step 3 iterate over all possible gt (new generator matrix) codewords
          for {
            pi <- Range.inclusive(0, t)
            a <- Range(0, k).combinations(pi)
          } yield {
            var sum = new GF2Vector(gt.getNumColumns, Array.fill((gt.getNumColumns - 1) / 32 + 1)(0))
            for (i <- Range(0, pi)) {
              val row = new GF2Vector(gt.getNumColumns, gt.getRow(a(i)))
              sum = sum.add(row).asInstanceOf[GF2Vector]
            }

            val e = y.add(sum).asInstanceOf[GF2Vector]
            if (e.getHammingWeight == t) {
              found = true
              val ei = vectorFromColumns(e, i)
              out = giInv.leftMultiply(ci.add(ei).asInstanceOf[GF2Vector]).asInstanceOf[GF2Vector]
            }
          }
        } catch {
          case _: ArithmeticException =>
          // Matrix cannot be inverted. Not an information set
        }
      }
    }
    out
  }

  /**
    * Try to guess k correct positions in the received word.
    * A “correct” guess is assumed when this error vector has t Hamming weight.
    *
    * @param c cipher
    * @return A nearest codeword of t Hamming distance from c (Error vector)
    */
  def decodeCodeword(c: GF2Vector): GF2Vector = {
    var out = new GF2Vector(g.getNumColumns, Array.fill((g.getNumColumns - 1) / 32 + 1)(0))
    var found = false
    while (!found) {
      // Step 1
      val i = Math.sample((0 until n).toList, k)
      val gi = matrixFromColumns(g, i)
      try {
        val giInv = gi.computeInverse
        val gt = giInv.rightMultiply(g).asInstanceOf[GF2Matrix]
        // Step 2
        val ci = vectorFromColumns(c, i)
        val y = c.add(gt.leftMultiply(ci)).asInstanceOf[GF2Vector]
        // Step 3
        for {
          pi <- Range.inclusive(0, t)
          a <- Range(0, k).combinations(pi)
        } yield {
          var sum = new GF2Vector(gt.getNumColumns, Array.fill((gt.getNumColumns - 1) / 32 + 1)(0))
          for (i <- Range(0, pi)) {
            val row = new GF2Vector(gt.getNumColumns, gt.getRow(a(i)))
            sum = sum.add(row).asInstanceOf[GF2Vector]
          }

          val e = y.add(sum).asInstanceOf[GF2Vector]
          if (e.getHammingWeight == t) {
            found = true
            out = c.add(e).asInstanceOf[GF2Vector]
          }
        }
      } catch {
        case _: ArithmeticException =>
        // Matrix cannot be inverted. Not an information set
      }
    }
    out
  }

}
