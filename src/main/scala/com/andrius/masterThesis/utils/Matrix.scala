package com.andrius.masterThesis.utils

import org.bouncycastle.pqc.math.linearalgebra.{GF2Matrix, GF2Vector}

import scala.collection.immutable.Range
import scala.collection.mutable.ListBuffer

/**
  * Utilities for matrices over finite field GF(2)
  */
object Matrix {

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

  /**
    * Create new matrix from column list
    *
    * @param in      input matrix
    * @param columns columns to extract from input matrix
    * @return
    */
  def createGF2MatrixFromColumns(in: GF2Matrix,
                                 columns: List[Int]): GF2Matrix = {
    val out = Array.ofDim[Int](in.getNumRows, (columns.length - 1) / 32 + 1)
    val matrix = in.getIntArray

    for ((colToTake, colToSet) <- columns.zipWithIndex) {
      Matrix.setColumn(out, Matrix.getColumn(matrix, colToTake), colToSet)
    }

    new GF2Matrix(columns.length, out)
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

}
