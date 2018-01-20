package com.andrius.masterThesis.utils

import org.bouncycastle.pqc.math.linearalgebra.GF2Matrix

import scala.collection.mutable.ListBuffer
import scala.util.control.Breaks.{break, breakable}

/**
  * Matrix Utils
  */
object Matrix {

  /**
    * Get any generator matrix and convert it to parity check matrix (if possible)
    *
    * @param in matrix
    * @return
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

  def swapRows(in: Array[Array[Int]], first: Int, second: Int): Unit = {
    val tmp = in(first)
    in(first) = in(second)
    in(second) = tmp
  }

  /**
    * @todo more efficient swap
    * @param in
    * @param i
    * @param j
    */
  def swapColumns(in: Array[Array[Int]], i: Int, j: Int): Unit = {
    //val tmp = cloneArray(in)
    val column1: Array[Int] = getColumn(in, i)
    val column2: Array[Int] = getColumn(in, j)
    setColumn(in, column1, j)
    setColumn(in, column2, i)
  }

  def getColumn(in: Array[Array[Int]], i: Int): Array[Int] = {
    var result = ListBuffer[Int]()
    val elem = i % 32
    val length = i / 32
    for (i <- in.indices) {
      result += (in(i)(length) >>> elem) & 1
    }
    result.toArray
  }

  def setColumn(in: Array[Array[Int]], ints: Array[Int], i: Int): Unit = {
    val elem = i % 32
    val length = i / 32
    for (i <- in.indices) {
      val a = in(i)(length)
      val el = (a >>> elem) & 1
      if (el != ints(i)) {
        in(i)(length) = a ^ (1 << elem)
      }
    }
  }

  def matrixFromColumns(in: GF2Matrix, columns: List[Int]): GF2Matrix = {
    val out = Array.ofDim[Int](in.getNumRows, (columns.length - 1) / 32 + 1)
    val matrix = in.getIntArray

    for ((colToTake, colToSet) <- columns.zipWithIndex) {
      Matrix.setColumn(out, Matrix.getColumn(matrix, colToTake), colToSet)
    }

    new GF2Matrix(columns.length, out)
  }

  def matrixFromRows(in: GF2Matrix, rows: List[Int]): GF2Matrix = {
    val out = Array.ofDim[Int](rows.length, in.getLength)

    for ((rowToTake, rowToSet) <- rows.zipWithIndex) {
      out(rowToSet) = in.getRow(rowToTake)
    }

    new GF2Matrix(in.getNumColumns, out)
  }

}
