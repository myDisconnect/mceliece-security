package com.andrius.masterThesis

import com.andrius.masterThesis.attacks.noncritical.isd.LeeBrickell
import com.andrius.masterThesis.attacks.critical.{KnownPartialPlaintext, MessageResend, RelatedMessage}
import com.andrius.masterThesis.mceliece.McElieceCryptosystem
import com.andrius.masterThesis.mceliece.McElieceCryptosystem.BasicConfiguration
import com.andrius.masterThesis.utils.{Math, Vector}
import com.typesafe.scalalogging.Logger
import org.bouncycastle.pqc.math.linearalgebra.GF2Vector

import scala.collection.mutable.ListBuffer

/**
  * @author Andrius Versockas <andrius.versockas@gmail.com>
  * @todo Delete below:
  *       Great slides about McEliece: http://www-math.ucdenver.edu/~wcherowi/courses/m5410/mcleice.pdf
  *       Good conclusions on McEliece: http://re-search.info/sites/default/files/zajac_workshop_2016.pdf
  */
object Main {
  val logger = Logger("Main")

  def main(args: Array[String]): Unit = {
    val configuration = BasicConfiguration(m = 5, t = 2)
    val mcEliecePKC = new McElieceCryptosystem(configuration)
    mcEliecePKC.decrypt(mcEliecePKC.encrypt("l"))
    /*generalizedInformationSetDecoding(configuration)
    val mb = 1024*1024
    val runtime = Runtime.getRuntime
    logger.info("** Used Memory:  " + (runtime.totalMemory - runtime.freeMemory) / mb)
    logger.info("** Free Memory:  " + runtime.freeMemory / mb)
    logger.info("** Total Memory: " + runtime.totalMemory / mb)
    logger.info("** Max Memory:   " + runtime.maxMemory / mb)
    knownPartialPlaintext(configuration)
    messageResend(configuration)
    relatedMessage(configuration)
*/
  }

  /**
    * Non-Critical: Generalized Information-Set Decoding (GISD) attack
    *
    * @param configuration McEliece PKC configuration
    */
  def generalizedInformationSetDecoding(configuration: BasicConfiguration): Unit = {
    val mcEliecePKC = new McElieceCryptosystem(configuration)
    val leeBrickell = new LeeBrickell(mcEliecePKC.publicKey)

    val timeResults = new ListBuffer[Long]()
    for (_ <- 0 until 1000) {
      val msg = Vector.generateMessageVector(mcEliecePKC.publicKey.getK)
      val cipher = mcEliecePKC.encryptVector(msg)

      val start = System.currentTimeMillis

      leeBrickell.attack(cipher)
      timeResults += System.currentTimeMillis - start
    }
    println(s"Average GISD attack time: ${Math.average(timeResults)} ms")
  }

  /**
    * Critical: Known Partial Plaintext Attack
    *
    * @param configuration McEliece PKC configuration
    */
  def knownPartialPlaintext(configuration: BasicConfiguration): Unit = {
    val mcEliecePKC = new McElieceCryptosystem(configuration)
    val partial = new KnownPartialPlaintext(mcEliecePKC.publicKey)

    // How many places known
    for (kRight <- 1 until mcEliecePKC.publicKey.getK) {
      val timeResults = new ListBuffer[Long]()
      for (_ <- 0 until 1000) {
        val msg = Vector.generateMessageVector(mcEliecePKC.publicKey.getK)
        val cipher = mcEliecePKC.encryptVector(msg)
        val knownRight = msg.extractRightVector(kRight)

        val start = System.currentTimeMillis
        // Attack counts successful if security complexity was reduced
        val reducedParameters = partial.attack(knownRight, cipher)

        // Any other decoding attack can be used
        val leeBrickell = new LeeBrickell(reducedParameters.publicKey)
        leeBrickell.attack(reducedParameters.cipher)

        timeResults += System.currentTimeMillis - start
      }
      println(s"Average Known Partial Plaintext + GISD attacks time with $kRight/${mcEliecePKC.publicKey.getK} " +
        s"known: ${Math.average(timeResults)} ms")
    }
  }

  /**
    * Critical: Message-Resend Attack
    *
    * @param configuration McEliece PKC configuration
    */
  def messageResend(configuration: BasicConfiguration): Unit = {
    val mcEliecePKC = new McElieceCryptosystem(configuration)
    val messageResend = new MessageResend(mcEliecePKC.publicKey)

    val timeResults = new ListBuffer[Long]()
    var extraTries = 0
    var identicalErrors = 0
    for (_ <- 0 until 1000) {
      try {
        val msg = Vector.generateMessageVector(mcEliecePKC.publicKey.getK)

        val cipher1 = mcEliecePKC.encryptVector(msg)
        val cipher2 = mcEliecePKC.encryptVector(msg)
        if (cipher1.equals(cipher2)) {
          throw new IllegalArgumentException("Attack cannot be successful, message m encoded with same error vectors (e1=e2)")
        }
        var found = false
        val start = System.currentTimeMillis
        while (!found) {
            // It is possible to check if padding is correct (filter failures)
            // Vector.computeMessage(messageResend.attack(cipher1, cipher2))
            if (messageResend.attack(cipher1, cipher2).equals(msg)) {
              timeResults += System.currentTimeMillis - start
              found = true
            } else {
              extraTries += 1
            }
        }
      } catch {
        case _: IllegalArgumentException =>
          identicalErrors += 1
      }
      //println(messageResend.attack(cipher1, cipher2).equals(msg), tries)
    }
    println(s"Average Message-Resend Attack time: ${Math.average(timeResults)} ms with extra: $extraTries iterations" +
      s" and $identicalErrors identical error vectors")
  }

  /**
    * Critical: Related-Message Attack
    *
    * @param configuration McEliece PKC configuration
    */
  def relatedMessage(configuration: BasicConfiguration): Unit = {
    val mcEliecePKC = new McElieceCryptosystem(configuration)
    val relatedMessage = new RelatedMessage(mcEliecePKC.publicKey)

    val timeResults = new ListBuffer[Long]()
    var extraTries = 0
    var identicalErrors = 0
    for (_ <- 0 until 1000) {
      try {
        val msg1 = Vector.generateMessageVector(mcEliecePKC.publicKey.getK)
        // For example, we know that message vector always differ in every 32 position
        val mDelta = new GF2Vector(mcEliecePKC.publicKey.getK, Array.fill((mcEliecePKC.publicKey.getK - 1) / 32 + 1)(1))
        val msg2 = msg1.add(mDelta).asInstanceOf[GF2Vector]

        val cipher1 = mcEliecePKC.encryptVector(msg1)
        val cipher2 = mcEliecePKC.encryptVector(msg2)

        if (cipher1.equals(cipher2)) {
          throw new IllegalArgumentException("Attack cannot be successful, message m encoded with same error vectors (e1=e2)")
        }
        var found = false
        val start = System.currentTimeMillis
        while (!found) {
          if (relatedMessage.attack(cipher1, cipher2, mDelta).equals(msg1)) {
            timeResults += System.currentTimeMillis - start
            found = true
          } else {
            extraTries += 1
          }
        }
      } catch {
        case _: IllegalArgumentException =>
          identicalErrors += 1
      }
    }
    println(s"Average Related-Message Attack time: ${Math.average(timeResults)} ms with extra: $extraTries iterations" +
      s" and $identicalErrors identical error vectors")
  }
}