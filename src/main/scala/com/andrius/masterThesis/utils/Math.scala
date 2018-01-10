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

}
