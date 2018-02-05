package com.andrius.masterThesis.attacks.critical

import com.andrius.masterThesis.utils.Vector
import org.bouncycastle.pqc.jcajce.provider.mceliece.BCMcEliecePublicKey
import org.bouncycastle.pqc.math.linearalgebra.{GF2Matrix, GF2Vector}

import scala.collection.mutable
import scala.collection.mutable.ListBuffer
import scala.util.Random

/**
  * @see Thomas A. Berson. Failure of the McEliece Public-Key Cryptosystem Under Message-Resend and Related-Message Attack
  *      (https://link.springer.com/content/pdf/10.1007%2FBFb0052237.pdf)
  * @param publicKey McEliece public key
  */
class MessageResend(publicKey: BCMcEliecePublicKey) {

  // Only using transposed matrix, because moving columns is easier
  val gT: GF2Matrix = publicKey.getG.computeTranspose().asInstanceOf[GF2Matrix]
  val n: Int = publicKey.getG.getNumColumns
  val k: Int = publicKey.getG.getNumRows
  val t: Int = publicKey.getT

  /**
    * Looking for a G relation with error free positions in the ciphertexts.
    * If these columns are linearly independent, then square matrix associated with them can be inverted,
    * and m can be retrieved.
    * Main relation: e1 + e2 = c1 + c2
    * Note: This attack has a chance to return incorrect message vector (error vectors e1 and e2 ones collision case)
    *
    * @param c1 cipher for message m
    * @param c2 cipher for message m
    * @return
    */
  def attack(c1: GF2Vector, c2: GF2Vector): GF2Vector = {
    var out = new GF2Vector(k, Array.fill((k - 1) / 32 + 1)(0))
    val c1c2Sum = c1.add(c2).asInstanceOf[GF2Vector]
    var found = false
    val dictionary = new mutable.HashSet[List[Int]]()
    val errorFreePositions = new ListBuffer[Int]()
    for (j <- 0 until c1c2Sum.getLength) {
      if (c1c2Sum.getBit(j) != 1) {
        errorFreePositions += j
      }
    }
    val errorFreePositionList = errorFreePositions.toList
    while (!found) {
      var i = 0
      val rowsSelected = new ListBuffer[Int]()
      val newMatSeq = Array.ofDim[Int](k, k)
      var shuffledFields = Random.shuffle(errorFreePositionList)
      if (!dictionary.contains(shuffledFields)) {
        dictionary += shuffledFields
        while (i < k) {
          val j = shuffledFields.head
          shuffledFields = shuffledFields.tail
          rowsSelected += j
          newMatSeq(i) = gT.getRow(j)
          i += 1
        }

        try {
          val restrictedPub = new GF2Matrix(k, newMatSeq)
            .computeTranspose()
            .asInstanceOf[GF2Matrix]
            .computeInverse()
            .asInstanceOf[GF2Matrix]
          found = true
          val c1Prime = Vector.vectorFromColumns(c1, rowsSelected.toList)
          out = restrictedPub.leftMultiply(c1Prime).asInstanceOf[GF2Vector]
        } catch {
          case _: ArithmeticException =>
          // Matrix is not invertible
        }
      }
    }
    out
  }

}
