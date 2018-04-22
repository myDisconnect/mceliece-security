package com.andrius.masterThesis.utils

import scala.annotation.tailrec
import scala.util.Random

/**
  * Math utilities
  */
object MathUtils {

  /**
    * Sample without replacement
    *
    * @param items      list
    * @param sampleSize count
    * @tparam A Type
    * @return
    */
  def sample[A](items: List[A], sampleSize: Int): List[A] = {
    @tailrec
    def collect(items: Vector[A], sampleSize: Int, acc: List[A]): List[A] = {
      if (sampleSize == 0) acc
      else {
        val index = Random.nextInt(items.size)
        collect(items.updated(index, items.head).tail, sampleSize - 1, items(index) :: acc)
      }
    }

    collect(items.toVector, sampleSize, Nil)
  }

  /**
    * Simple average, could be rewritten to use generic types! :)
    *
    * @param items items
    * @return average
    */
  def average(items: Seq[Long]): String = {
    items.foldLeft((0.0, 1))((acc, i) => (acc._1 + (i - acc._1) / acc._2, acc._2 + 1))._1.formatted("%.3f")
  }

  /**
    * Random Pivot
    *
    * @param arr sequence of Long values
    * @tparam T type
    * @return random pivot
    */
  private def choosePivot[T](arr: Seq[T]): T = arr(scala.util.Random.nextInt(arr.size))

  /**
    *
    * @param arr sequence of Long values
    * @param k   size
    * @return median
    */
  @tailrec
  private def findKMedian(arr: Seq[Long], k: Int): Long = {
    val a      = choosePivot[Long](arr)
    val (s, b) = arr.partition(a > _)
    if (s.size == k) a
    // The following test is used to avoid infinite repetition
    else if (s.isEmpty) {
      val (s, b) = arr.partition(a == _)
      if (s.size > k) a
      else findKMedian(b, k - s.size)
    } else if (s.size < k) findKMedian(b, k - s.size)
    else findKMedian(s, k)
  }

  /**
    * Find median using:
    * Random Pivot (quadratic, linear average), Immutable
    *
    * @see https://stackoverflow.com/questions/4662292/scala-median-implementation
    * @param arr sequence of values
    * @return median of sequence
    */
  def findMedian(arr: Seq[Long]): Long = findKMedian(arr, (arr.size - 1) / 2)

  /**
    * Combinations with repetitions
    *
    * @see Modified version of https://rosettacode.org/wiki/Combinations_with_repetitions
    * @param source source of combination with repetitions
    * @param size   size of resulting collection
    * @tparam A type
    * @return
    */
  def combinationWithRepetition[A](source: Seq[A], size: Int): Iterator[Seq[A]] =
    Seq.fill(size)(source).flatten.combinations(size)

  /**
    * Calculates all permutations taking n elements of the source List,
    * with repetitions.
    * Precondition: input.length > 0 && n > 0
    *
    * @see https://rosettacode.org/wiki/Permutations_with_repetitions
    * @param source source of combination with repetitions
    * @param size   size of resulting collection
    * @tparam A type
    * @return
    */
  def permutationsWithRepetitions[A](source: Seq[A], size: Int): Seq[List[A]] = {
    require(source.nonEmpty && size > 0)
    size match {
      case 1 => for (el <- source) yield List(el)
      case _ => for (el <- source; perm <- permutationsWithRepetitions(source, size - 1)) yield el :: perm
    }
  }

}
