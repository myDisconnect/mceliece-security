package com.andrius.masterThesis.utils

import scala.annotation.tailrec
import scala.util.Random

/**
  * Math utilities
  */
object Math {

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
    * @return
    */
  def average(items: Seq[Long]): String = {
    items.foldLeft((0.0, 1)) ((acc, i) => (acc._1 + (i - acc._1) / acc._2, acc._2 + 1))._1.formatted("%.3f")
  }

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
