package com.andrius.masterThesis.utils

import java.security.SecureRandom

import org.bouncycastle.pqc.math.linearalgebra._

import scala.util.control.Breaks.{break, breakable}

/**
  * Utilities for generator matrices over finite field GF(2)
  */
object GeneratorMatrix {

  /**
    * Get generator matrix in systematic (standard) form for irreductible Goppa polynomial over finite field GF(2)
    *
    * @param field     finite field GF(2^m)
    * @param goppaPoly irreducible Goppa polynomial
    * @param sr        source of randomness
    * @return
    */
  def getGeneratorMatrix(field: GF2mField, goppaPoly: PolynomialGF2mSmallM, sr: SecureRandom): GF2Matrix = {
    // generate canonical check matrix
    val h = GoppaCode.createCanonicalCheckMatrix(field, goppaPoly)

    // compute short systematic form of check matrix
    val mmp = GoppaCode.computeSystematicForm(h, sr)
    val shortH = mmp.getSecondMatrix

    // compute short systematic form of generator matrix
    val shortG = shortH.computeTranspose.asInstanceOf[GF2Matrix]

    // extend to full systematic form
    shortG.extendLeftCompactForm
  }

  /**
    * Try to convert generator matrix to parity check matrix in systematic (standard) form [x | I_n]
    *
    * @param in matrix
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
    * @todo rewrite this, kind of ugly
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
        while (((out(i)(lead / 32) >>> lead % 32) & 1) != 1) {
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
          if ((i != r) && ((out(i)(lead / 32) >>> lead % 32) & 1) == 1) {
            Matrix.selfAdd(out(i), out(r))
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
    * @param in generator matrix
    * @return
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
