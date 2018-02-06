package com.andrius.masterThesis.utils

import org.bouncycastle.pqc.math.linearalgebra.GF2Matrix

import scala.collection.mutable.ListBuffer
import scala.util.control.Breaks.{break, breakable}

/**
  * Matrix utilities
  */
object Matrix {

  /**
    * Try to convert generator matrix to parity check matrix in standard form [x | I_n]
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
    val out = cloneArray(in.getIntArray)
    breakable {
      for (r <- 0 until rowCount) {
        if (columnCount <= lead) {
          break
        }
        var i = r
        while (((out(i)(lead / 32) >>> lead % 32) & 1) != 1) {
          i += 1
          if (rowCount== i) {
            i = r
            lead += 1
            if (columnCount == lead) {
              break
            }
          }
        }
        swapRows(out, i, r)
        for (i <- 0 until rowCount) {
          if ((i != r) && ((out(i)(lead / 32) >>> lead % 32) & 1) == 1) {
            selfAdd(out(i), out(r))
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
    val out = cloneArray(in.getIntArray)
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
                swapColumns(out, r, colsCount)
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
              swapColumns(out, r, colsCount)
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

  /**
    * Add row1 to row2
    *
    * @param row1 Row to add to
    * @param row2 Row added
    */
  def selfAdd(row1: Array[Int], row2: Array[Int]): Unit = {
    for (i <- row1.indices) {
      row1(i) ^= row2(i)
    }
  }

  /**
    * Swap rows of a given matrix two dimensional array
    *
    * @param in      input matrix int array
    * @param posFrom row position to swap from
    * @param posTo   row position to swap to
    */
  def swapRows(in: Array[Array[Int]], posFrom: Int, posTo: Int): Unit = {
    val tmp = in(posFrom)
    in(posFrom) = in(posTo)
    in(posTo) = tmp
  }

  /**
    * Swap columns of a given matrix two dimensional array
    *
    * @todo more efficient swap
    * @param in      input matrix int array
    * @param posFrom column position to swap from
    * @param posTo   column position to swap to
    */
  def swapColumns(in: Array[Array[Int]], posFrom: Int, posTo: Int): Unit = {
    val column1: Array[Int] = getColumn(in, posFrom)
    val column2: Array[Int] = getColumn(in, posTo)
    setColumn(in, column1, posTo)
    setColumn(in, column2, posFrom)
  }

  /**
    * Get matrix column (uses GF2Matrix.getIntArray)
    *
    * @param in  input matrix int array
    * @param pos position of the column elements in the matrix
    * @return values of column. Possible values: array of [0,1]
    */
  def getColumn(in: Array[Array[Int]], pos: Int): Array[Int] = {
    var result = ListBuffer[Int]()
    val elem = pos % 32
    val length = pos / 32
    for (i <- in.indices) {
      result += (in(i)(length) >>> elem) & 1
    }
    result.toArray
  }

  /**
    * Set matrix column (changes received matrix two dimensional Int array)
    *
    * @param in     input vector int array
    * @param values values to be set. Allowed values for single value: 0,1
    * @param pos    position of the element in the vector
    */
  def setColumn(in: Array[Array[Int]], values: Array[Int], pos: Int): Unit = {
    val elem = pos % 32
    val length = pos / 32
    for (i <- in.indices) {
      val a = in(i)(length)
      val el = (a >>> elem) & 1
      if (el != values(i)) {
        in(i)(length) = a ^ (1 << elem)
      }
    }
  }

  /**
    * Create new matrix from column list
    *
    * @param in      input matrix
    * @param columns columns to extract from input matrix
    * @return
    */
  def createGF2MatrixFromColumns(in: GF2Matrix, columns: List[Int]): GF2Matrix = {
    val out = Array.ofDim[Int](in.getNumRows, (columns.length - 1) / 32 + 1)
    val matrix = in.getIntArray

    for ((colToTake, colToSet) <- columns.zipWithIndex) {
      Matrix.setColumn(out, Matrix.getColumn(matrix, colToTake), colToSet)
    }

    new GF2Matrix(columns.length, out)
  }

  /**
    * Create new matrix from row list
    *
    * @param in   input matrix
    * @param rows rows to extract from input matrix
    * @return
    */
  def createGF2MatrixFromRows(in: GF2Matrix, rows: List[Int]): GF2Matrix = {
    val out = Array.ofDim[Int](rows.length, in.getLength)

    for ((rowToTake, rowToSet) <- rows.zipWithIndex) {
      out(rowToSet) = in.getRow(rowToTake)
    }

    new GF2Matrix(in.getNumColumns, out)
  }

  /**
    * Create GF2Matrix from two dimensional sequence of [0,1]
    *
    * @param sequence two dimensional sequence containing 0 or 1
    * @return
    */
  def createGF2Matrix(sequence: Seq[Seq[Int]]): GF2Matrix = {
    val numRows = sequence.length
    val numColumns = sequence.head.length
    val out = Array.ofDim[Int](numRows, (numColumns - 1) / 32 + 1)
    for {
      i <- 0 until numRows
      j <- 0 until numColumns
    } yield {
      val q = j >> 5
      val r = j & 0x1f
      out(i)(q) += (1 << r) * sequence(i)(j)
    }

    new GF2Matrix(numColumns, out)
  }

}
