package com.andrius.masterThesis

import com.andrius.masterThesis.attacks.Attacks
import com.andrius.masterThesis.attacks.noncritical.informationSetDecoding.LeeBrickell
import com.andrius.masterThesis.attacks.critical.{KnownPartialPlaintext, MessageResend, RelatedMessage}
import com.andrius.masterThesis.attacks.structural.SupportSplittingAlgorithm
import com.andrius.masterThesis.mceliece.McElieceCryptosystem
import com.andrius.masterThesis.mceliece.McElieceCryptosystem.BasicConfiguration
import com.andrius.masterThesis.utils.{Math, Vector}
import org.bouncycastle.pqc.math.linearalgebra.GF2Vector

import scala.collection.mutable.ListBuffer
import scala.io.StdIn

/**
  * @author Andrius Versockas <andrius.versockas@gmail.com>
  */
object Main {

  def main(args: Array[String]): Unit = {
    // default configuration
    val defaultM = 5
    val defaultT = 2
    Console.println("Enter Goppa code degree of the finite field m [Default: 5]")
    val m = getIntOrDefault(StdIn.readLine(), defaultM)
    Console.println("Enter error correction capability of the code t [Default: 2]")
    val t = getIntOrDefault(StdIn.readLine(), defaultT)
    val configuration = BasicConfiguration(m, t)
    Console.println(s"McEliece cryptosystem security parameters (n, k, t) = (${configuration.n}, ${configuration.k}, " +
      s"${configuration.t})")
    Console.println(s"${Attacks.GISD} - Generalized Information Set Decoding")
    Console.println(s"${Attacks.KnownPartialPlaintext} - Known Partial Plaintext")
    Console.println(s"${Attacks.MessageResend} - Message Resend")
    Console.println(s"${Attacks.RelatedMessage} - Related Message")
    //Console.println(s"${Attacks.SupportSplitting} - Support Splitting Algorithm")
    StdIn.readInt() match {
      case Attacks.GISD =>
        generalizedInformationSetDecoding(configuration)
      case Attacks.KnownPartialPlaintext =>
        knownPartialPlaintext(configuration)
      case Attacks.MessageResend =>
        messageResend(configuration)
      case Attacks.RelatedMessage =>
        relatedMessage(configuration)
      case Attacks.SupportSplitting =>
        Console.println("Currently not stable enough to attack")
        //supportSplittingAlgorithm(configuration)
      case _ =>
        throw new Exception("Unknown attack specified")
    }
  }

  /**
    * Structural: Support Splitting Algorithm attack
    *
    * @param configuration McEliece PKC configuration
    */
  def supportSplittingAlgorithm(configuration: BasicConfiguration, iterations: Int = 1000): Unit = {
    val mcEliecePKC = new McElieceCryptosystem(configuration)
    val ssa = new SupportSplittingAlgorithm(mcEliecePKC.publicKey)

    val timeResults = new ListBuffer[Long]()
    for (_ <- 0 until iterations) {
      val start = System.currentTimeMillis

      ssa.attack()
      timeResults += System.currentTimeMillis - start
    }
    println(s"Average Support Splitting Algorithm attack time: ${Math.average(timeResults)} ms (from $iterations iterations)")
  }

  /**
    * Non-Critical: Generalized Information-Set Decoding (GISD) attack
    *
    * @param configuration McEliece PKC configuration
    */
  def generalizedInformationSetDecoding(configuration: BasicConfiguration, iterations: Int = 1000): Unit = {
    val mcEliecePKC = new McElieceCryptosystem(configuration)
    val leeBrickell = new LeeBrickell(mcEliecePKC.publicKey)

    val timeResults = new ListBuffer[Long]()
    for (_ <- 0 until iterations) {
      val msg = Vector.generateMessageVector(mcEliecePKC.publicKey.getK)
      val cipher = mcEliecePKC.encryptVector(msg)

      val start = System.currentTimeMillis

      leeBrickell.attack(cipher)
      timeResults += System.currentTimeMillis - start
    }
    println(s"Average GISD attack time: ${Math.average(timeResults)} ms (from $iterations iterations)")
  }

  /**
    * Critical: Known Partial Plaintext Attack
    *
    * @param configuration McEliece PKC configuration
    */
  def knownPartialPlaintext(configuration: BasicConfiguration, iterations: Int = 1000): Unit = {
    val mcEliecePKC = new McElieceCryptosystem(configuration)
    val partial = new KnownPartialPlaintext(mcEliecePKC.publicKey)

    // How many places known
    for (kRight <- 1 until mcEliecePKC.publicKey.getK) {
      val timeResults = new ListBuffer[Long]()
      for (_ <- 0 until iterations) {
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
        s"known: ${Math.average(timeResults)} ms (from $iterations iterations)")
    }
  }

  /**
    * Critical: Message-Resend Attack
    *
    * @param configuration McEliece PKC configuration
    */
  def messageResend(configuration: BasicConfiguration, iterations: Int = 1000): Unit = {
    val mcEliecePKC = new McElieceCryptosystem(configuration)
    val messageResend = new MessageResend(mcEliecePKC.publicKey)

    val timeResults = new ListBuffer[Long]()
    var extraTries = 0
    var identicalErrors = 0
    for (_ <- 0 until iterations) {
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
    }
    println(s"Average Message-Resend Attack time: ${Math.average(timeResults)} ms with extra $extraTries iterations " +
      s"(from $iterations iterations) and $identicalErrors identical error vectors")
  }

  /**
    * Critical: Related-Message Attack
    *
    * @param configuration McEliece PKC configuration
    */
  def relatedMessage(configuration: BasicConfiguration, iterations: Int = 1000): Unit = {
    val mcEliecePKC = new McElieceCryptosystem(configuration)
    val relatedMessage = new RelatedMessage(mcEliecePKC.publicKey)

    val timeResults = new ListBuffer[Long]()
    var extraTries = 0
    var identicalErrors = 0
    for (_ <- 0 until iterations) {
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
    println(s"Average Related-Message Attack time ${Math.average(timeResults)} ms with extra $extraTries iterations" +
      s"(from $iterations iterations) and $identicalErrors identical error vectors")
  }

  def getIntOrDefault(input: String, default: Int): Int= {
    if (input.isEmpty) {
      default
    } else {
      input.toInt
    }
  }
}