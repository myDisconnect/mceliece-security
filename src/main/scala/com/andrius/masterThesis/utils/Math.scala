package com.andrius.masterThesis.utils

import scala.util.Random

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
  def average(items: Seq[Long]): Long = {
    items.foldLeft((0l, 1))((acc, i) => (acc._1 + (i - acc._1) / acc._2, acc._2 + 1))._1
  }

}
