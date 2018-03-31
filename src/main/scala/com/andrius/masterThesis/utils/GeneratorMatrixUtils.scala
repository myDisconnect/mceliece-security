package com.andrius.masterThesis.utils

import org.bouncycastle.pqc.math.linearalgebra._

import scala.collection.immutable.Range
import scala.collection.mutable.ListBuffer
import scala.util.Random
import scala.util.control.Breaks.{break, breakable}

/**
  * Utilities for generator and parity-check matrices over finite field GF(2)
  */
object GeneratorMatrixUtils {

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

    GeneratorMatrixUtils.findNullSpace(h).rightMultiply(localPermutation).asInstanceOf[GF2Matrix]
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
    for (messageWords <- MathUtils.permutationsWithRepetitions(Range.inclusive(0, 1).toList, k)) {
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
    * @see https://en.wikipedia.org/wiki/Kernel_(linear_algebra)#Computation_by_Gaussian_elimination
    * @param h parity-check matrix
    * @return generator matrix
    */
  def findNullSpace(h: GF2Matrix): GF2Matrix = {
    require(h.getNumRows <= h.getNumColumns)

    val m = h.getNumRows
    val n = h.getNumColumns

    // add identity matrix to H
    val temp = MatrixUtils.joinVertically(h, MatrixUtils.identity(n, n))
    val tempArr = temp.getIntArray
    // rearrange columns
    for (i <- 0 until m) {
      var j = i
      while (!MatrixUtils.getMatrixArrayValueBoolean(tempArr, i, j) && j < n) {
        j +=1
      }
      if (i != j) {
        MatrixUtils.swapColumns(tempArr, i, j)
      }
      // elimination
      for (j <- 0 until n) {
        if (MatrixUtils.getMatrixArrayValueBoolean(tempArr, i, j) && (i != j)) {
          for (k <- 0 until temp.getNumRows) {
            // adds columns
            MatrixUtils.setMatrixArrayValue(
              tempArr,
              k,
              j,
              MatrixUtils.getMatrixArrayValueInt(tempArr, k, j) ^ MatrixUtils.getMatrixArrayValueInt(tempArr, k, i)
            )
          }
        }
      }
    }

    var jMax = 0
    for {
      i <- 0 until m
      j <- 0 until n
      if MatrixUtils.getMatrixArrayValueBoolean(tempArr, i, j) && j > jMax
    } jMax = j

    val gT = MatrixUtils.getSubMatrix(temp, m, jMax + 1, temp.getNumRows - 1, n - 1)

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
    * Solve a system of linear equations over GF(2), i.e. solve for x where Ax=b.
    *
    * @see https://math.stackexchange.com/questions/48682/maximization-with-xor-operator
    * @see https://www.hackerearth.com/practice/notes/gaussian-elimination/
    * @see https://math.stackexchange.com/a/169928/538670
    * @param a m x n matrix
    * @param b n-length vector
    * @return solution vector
    * @throws Exception if no or more than one solution exist
    */
  def solve(a: GF2Matrix, b: GF2Vector): GF2Vector = {
    val nr = a.getNumRows
    val nc = a.getNumColumns

    // construct augmented matrix M
    val m = MatrixUtils.appendToMatrixVectorColumn(a, b)
    val mIntArray = m.getIntArray
    val leads = Array.fill[Int](nr)(-1)
    var c = 0
    breakable {
      for (i <- 0 until nc) {
        breakable {
          /* find suitable row for elimination */
          for (j <- c until nr) {
            if (MatrixUtils.getMatrixArrayValueBoolean(mIntArray, j, i)) {
              // test if this is reference again
              //val z = ArrayUtils.cloneArray(mIntArray(j))
              val z = mIntArray(j)
              MatrixUtils.swapRows(mIntArray, c, j)
              for (k <- c + 1 until nr) {
                if (MatrixUtils.getMatrixArrayValueBoolean(mIntArray, k, i)) {
                  MatrixUtils.selfAddRow(mIntArray(k), z)
                }
              }
              leads(c) = i
              c += 1
              break
            }
          }
        }
        if (c >= nr) {
          break
        }
      }
    }

    if ((0 until nc).diff(leads).nonEmpty) {
      throw new Exception("no or more than one solution exist")
    }
    val x = Array.fill[Int](nc)(-1)
    for (i <- (nr - 1) to 0 by -1) {
      if (leads(i) != -1) {
        val k = leads(i)
        var sum = 0
        for (j <- k + 1 until nc) {
          sum ^= x(j) * MatrixUtils.getMatrixArrayValueInt(mIntArray, i, j)
        }
        x(k) = sum ^ MatrixUtils.getMatrixArrayValueInt(mIntArray, i, nc)
      }
    }
    VectorUtils.createGF2Vector(x.toSeq)
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
        MatrixUtils.swapRows(out, i, r)
        for (i <- 0 until rowCount) {
          if ((i != r) && (out(i)(lead / 32) >>> (lead % 32) & 1) == 1) {
            MatrixUtils.selfAddRow(out(i), out(r))
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
                MatrixUtils.swapColumns(out, r, colsCount)
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
              MatrixUtils.swapColumns(out, r, colsCount)
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
