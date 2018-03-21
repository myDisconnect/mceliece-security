package com.andrius.masterThesis.utils

import org.bouncycastle.pqc.math.linearalgebra._

import scala.collection.immutable.Range
import scala.collection.mutable.ListBuffer
import scala.util.control.Breaks.{break, breakable}

/**
  * Utilities for generator and parity-check matrices over finite field GF(2)
  */
object GeneratorMatrix {

  /**
    * Get generator matrix for irreductible Goppa polynomial over finite field GF(2)
    *
    * @param field            primitive Goppa finite field GF(2^m)
    * @param goppaPoly        irreducible Goppa polynomial selected
    * @param localPermutation permutation used to get systematic generator matrix
    * @return generator matrix
    */
  def getGeneratorMatrix(field: GF2mField, goppaPoly: PolynomialGF2mSmallM, localPermutation: Permutation): GF2Matrix = {
    // generate canonical check matrix from Goppa polly
    val h = GoppaCode.createCanonicalCheckMatrix(field, goppaPoly)

    GeneratorMatrix.findNullSpace(h).rightMultiply(localPermutation).asInstanceOf[GF2Matrix]
  }

  /**
    * Generate all possible codewords from generator matrix (very slow)
    *
    * @param g generator matrix
    * @return list of all codewords
    */
  def generateAllCodewords(g: GF2Matrix): List[GF2Vector] = {
    val n = g.getNumColumns
    val k = g.getNumRows
    val codewords = new ListBuffer[GF2Vector]()
    for (messageWords <- Math.permutationsWithRepetitions(Range.inclusive(0, 1).toList, k)) {
      var result = new GF2Vector(n)
      for (i <- Range(0, k)) {
        if (messageWords(i) == 1) {
          result =
            result.add(new GF2Vector(n, g.getRow(i))).asInstanceOf[GF2Vector]
        }
      }
      codewords += result
    }
    codewords.toList
  }

  /**
    * Converts any parity-check matrix to it's generator matrix (non-systematic)
    *
    * @see https://en.wikipedia.org/wiki/Kernel_(linear_algebra)#Basis
    * @param h parity-check matrix
    * @return generator matrix
    */
  def findNullSpace(h: GF2Matrix): GF2Matrix = {
    require(h.getNumRows <= h.getNumColumns)

    val m = h.getNumRows
    val n = h.getNumColumns

    // add identity matrix to H
    val temp = Matrix.joinVertically(h, Matrix.identity(n, n))
    val tempArr = temp.getIntArray
    // rearrange columns
    for (i <- 0 until m) {
      var j = i
      while (!Matrix.getMatrixArrayValueBoolean(tempArr, i, j) && j < n) {
        j +=1
      }
      if (i != j) {
        Matrix.swapColumns(tempArr, i, j)
      }
      // elimination
      for (j <- 0 until n) {
        if (Matrix.getMatrixArrayValueBoolean(tempArr, i, j) && (i != j)) {
          for (k <- 0 until temp.getNumRows) {
            // adds columns
            Matrix.setMatrixArrayValue(
              tempArr,
              k,
              j,
              Matrix.getMatrixArrayValueInt(tempArr, k, j) ^ Matrix.getMatrixArrayValueInt(tempArr, k, i)
            )
          }
        }
      }
    }

    var jMax = 0
    for {
      i <- 0 until m
      j <- 0 until n
      if Matrix.getMatrixArrayValueBoolean(tempArr, i, j) && j > jMax
    } jMax = j

    val gT = Matrix.getSubMatrix(temp, m, jMax + 1, temp.getNumRows - 1, n - 1)

    gT.computeTranspose().asInstanceOf[GF2Matrix]
  }

  /**
    * Try to convert any generator matrix to parity check matrix in systematic (standard) form [x | I_n]
    *
    * @param in generator matrix
    * @return parity check matrix in standard form [x | I_n]
    */
  def convertGeneratorMatrixToParityCheckMatrix(in: GF2Matrix): GF2Matrix = {
    reorderRowsToStandardForm(reducedRowEchelonMatrix(in))
      .getRightSubMatrix
      .computeTranspose
      .asInstanceOf[GF2Matrix]
      .extendLeftCompactForm()
  }

  /**
    * Reduced row echelon matrix for binary GF2Matrix
    *
    * @todo rewrite this, kind of ugly/hard to understand
    * @see https://en.wikipedia.org/wiki/Row_echelon_form#Reduced_row_echelon_form
    * @param in matrix
    * @return
    */
  def reducedRowEchelonMatrix(in: GF2Matrix): GF2Matrix = {
    var lead = 0
    val rowCount = in.getNumRows
    val columnCount = in.getNumColumns
    val out = ArrayUtils.cloneArray(in.getIntArray)
    breakable {
      for (r <- 0 until rowCount) {
        if (columnCount <= lead) {
          break
        }
        var i = r
        while ((out(i)(lead / 32) >>> (lead % 32) & 1) != 1) {
          i += 1
          if (rowCount == i) {
            i = r
            lead += 1
            if (columnCount == lead) {
              break
            }
          }
        }
        Matrix.swapRows(out, i, r)
        for (i <- 0 until rowCount) {
          if ((i != r) && (out(i)(lead / 32) >>> (lead % 32) & 1) == 1) {
            Matrix.selfAddRow(out(i), out(r))
          }
        }
        lead += 1
      }
    }
    new GF2Matrix(columnCount, out)
  }

  /**
    * Reorder rows to standard form [I_n | x]
    *
    * @todo rewrite this, kind of ugly/hard to understand
    * @param in generator matrix
    * @return generator matrix in systematic (standard) form
    */
  def reorderRowsToStandardForm(in: GF2Matrix): GF2Matrix = {
    val numRows = in.getNumRows
    val numColumns = in.getNumColumns
    val out = ArrayUtils.cloneArray(in.getIntArray)
    val length = in.getLength
    val rest: Int = numColumns & 0x1f
    val d = if (rest == 0) in.getLength else in.getLength - 1
    for (r <- 0 until numRows) {
      var colsCount = r
      var i = 0
      breakable {
        for (j <- colsCount / 32 until d) {
          for (k <- colsCount % 32 until 32) {
            while (i < numRows && !(((out(i)(length - 1) >>> k) & 1) == 1 ^ (i == r))) {
              i += 1
            }
            if (i == numRows) {
              //found the right column
              if (r != colsCount) {
                Matrix.swapColumns(out, r, colsCount)
              }
              break
            }
            colsCount += 1
          }
        }
        for (k <- colsCount % 32 until rest) {
          while (i < numRows && !(((out(i)(length - 1) >>> k) & 1) == 1 ^ (i == r))) {
            i += 1
          }
          if (i == numRows) {
            //found the right column
            if (r != colsCount) {
              Matrix.swapColumns(out, r, colsCount)
            }
            break
          }
          colsCount += 1
        }
        if (colsCount == numColumns) {
          throw new RuntimeException("Could not find an identity matrix by reordering columns")
        }
      }
    }
    new GF2Matrix(numColumns, out)
  }

}
