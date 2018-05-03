package com.andrius.masterThesis.utils

import org.bouncycastle.pqc.math.linearalgebra.{GF2Matrix, GF2Vector}

import scala.collection.mutable.ListBuffer

/**
  * Utilities for matrices over finite field GF(2)
  */
object MatrixUtils {

  /**
    * Create GF2Matrix from two dimensional sequence of [0,1]
    *
    * @param sequence two dimensional sequence containing 0 or 1
    * @return
    */
  def createGF2Matrix(sequence: Seq[Seq[Int]]): GF2Matrix = {
    val numRows    = sequence.length
    val numColumns = sequence.head.length
    val out        = Array.ofDim[Int](numRows, (numColumns - 1) / 32 + 1)
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

  /**
    * Create new matrix from column list
    *
    * @param in      input matrix
    * @param columns columns to extract from input matrix
    * @return
    */
  def createGF2MatrixFromColumns(in: GF2Matrix, columns: Seq[Int]): GF2Matrix = {
    val out    = Array.ofDim[Int](in.getNumRows, (columns.length - 1) / 32 + 1)
    val matrix = in.getIntArray

    for ((colToTake, colToSet) <- columns.zipWithIndex) {
      MatrixUtils.setColumn(out, MatrixUtils.getColumn(matrix, colToTake), colToSet)
    }

    new GF2Matrix(columns.length, out)
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
    val elem   = pos % 32
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
    val elem   = pos % 32
    val length = pos / 32
    for (i <- in.indices) {
      val a  = in(i)(length)
      val el = a >>> elem & 1
      if (el != values(i)) {
        in(i)(length) = a ^ (1 << elem)
      }
    }
  }

  /**
    * Create new matrix from row list
    *
    * @param in   input matrix
    * @param rows rows to extract from input matrix
    * @return
    */
  def createGF2MatrixFromRows(in: GF2Matrix, rows: Seq[Int]): GF2Matrix = {
    val out = Array.ofDim[Int](rows.length, in.getLength)

    for ((rowToTake, rowToSet) <- rows.zipWithIndex) {
      out(rowToSet) = in.getRow(rowToTake)
    }

    new GF2Matrix(in.getNumColumns, out)
  }

  /**
    * Add row2 to row1
    *
    * @param row1 Row to add to
    * @param row2 Row added
    */
  def selfAddRow(row1: Array[Int], row2: Array[Int]): Unit = {
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
    * @todo more efficient swap (double for loop)
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
    * Get given matrix array position value
    *
    * @param in     matrix int array
    * @param row    row number
    * @param column column number
    * @return true if value is equal to 1 else false
    */
  def getMatrixArrayValueInt(in: Array[Array[Int]], row: Int, column: Int): Int = {
    in(row)(column / 32) >>> (column % 32) & 1
  }

  /**
    * Check if in given matrix positions value is equal to 1
    *
    * @param in     matrix int array
    * @param row    row number
    * @param column column number
    * @return true if value is equal to 1 else false
    */
  def getMatrixArrayValueBoolean(in: Array[Array[Int]], row: Int, column: Int): Boolean = {
    getMatrixArrayValueInt(in, row, column) == 1
  }

  /**
    * Set given matrix positions value
    *
    * @param out    matrix array to set value to
    * @param row    position
    * @param column position
    * @param value  1 or 0
    */
  def setMatrixArrayValue(out: Array[Array[Int]], row: Int, column: Int, value: Int): Unit = {
    if ((out(row)(column / 32) >>> (column % 32) & 1) != value) {
      out(row)(column / 32) ^= (1 << (column % 32))
    }
  }

  /**
    * Concatenate two matrices vertically
    *
    * @param m1 upper matrix
    * @param m2 lower matrix
    * @return new concatenated matrix
    */
  def joinVertically(m1: GF2Matrix, m2: GF2Matrix): GF2Matrix = {
    require(m1.getNumColumns == m2.getNumColumns, "both matrices should have the same column size")

    val out = Array.ofDim[Int](m1.getNumRows + m2.getNumRows, (m1.getNumColumns - 1) / 32 + 1)
    System.arraycopy(ArrayUtils.cloneArray(m1.getIntArray), 0, out, 0, m1.getIntArray.length)
    System.arraycopy(ArrayUtils.cloneArray(m2.getIntArray), 0, out, m1.getIntArray.length, m2.getIntArray.length)

    new GF2Matrix(m1.getNumColumns, out)
  }

  /**
    * Creates new matrix with appended vector as a last column
    *
    * @param a matrix
    * @param b vector
    * @return matrix
    */
  def appendToMatrixVectorColumn(a: GF2Matrix, b: GF2Vector): GF2Matrix = {
    require(a.getNumRows == b.getLength)
    val m      = Array.ofDim[Int](a.getNumRows, a.getNumColumns / 32 + 1)
    val aArray = a.getIntArray
    val bArray = b.getVecArray

    for {
      i <- aArray.indices
      j <- aArray(i).indices
    } m(i)(j) = aArray(i)(j)

    val positionsToAdd = Array.ofDim[Int](b.getLength)
    for (i <- 0 until b.getLength) {
      positionsToAdd(i) = VectorUtils.getColumn(bArray, i)
    }
    MatrixUtils.setColumn(m, positionsToAdd, a.getNumColumns)

    new GF2Matrix(a.getNumColumns + 1, m)
  }

  /** Generate identity matrix
    *
    * @param m Number of rows.
    * @param n Number of columns.
    * @return An m-by-n matrix with ones on the diagonal and zeros elsewhere
    */
  def identity(m: Int, n: Int): GF2Matrix = {
    val out = Array.ofDim[Int](m, (n - 1) / 32 + 1)
    for {
      i <- 0 until m
      j <- 0 until n
      if i == j
    } out(i)(j / 32) ^= (1 << (j % 32))
    new GF2Matrix(m, out)
  }

  /**
    * Create new submatrix from given matrix positions
    *
    * @param in       matrix to take values from
    * @param firstRow row position to start
    * @param firstCol column position to start
    * @param lastRow  row position to end (included)
    * @param lastCol  column position to end (included)
    * @return new submatrix
    */
  def getSubMatrix(in: GF2Matrix, firstRow: Int, firstCol: Int, lastRow: Int, lastCol: Int): GF2Matrix = {
    val rows    = lastRow - firstRow + 1
    val columns = lastCol - firstCol + 1

    require(
      in.getNumColumns >= columns && Seq(firstCol, lastCol).forall(col => col >= 0 && col < in.getNumColumns),
      s"Incorrect column positions given: Start: $firstCol, End: $lastCol"
    )
    require(
      in.getNumRows >= rows && Seq(firstRow, lastRow).forall(row => row >= 0 && row < in.getNumRows),
      s"Incorrect row positions given: Start: $firstRow, End: $lastRow"
    )

    val out     = Array.ofDim[Int](rows, (columns - 1) / 32 + 1)
    val inArray = in.getIntArray
    var row     = 0
    for (i <- firstRow to lastRow) {
      var col = 0
      for (j <- firstCol to lastCol) {
        setMatrixArrayValue(
          out,
          row,
          col,
          getMatrixArrayValueInt(inArray, i, j)
        )
        col += 1
      }
      row += 1
    }

    new GF2Matrix(columns, out)
  }

}
