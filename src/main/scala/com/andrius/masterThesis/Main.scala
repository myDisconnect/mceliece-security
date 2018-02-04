package com.andrius.masterThesis

import com.andrius.masterThesis.attacks.Attack
import com.andrius.masterThesis.attacks.noncritical.informationSetDecoding.LeeBrickell
import com.andrius.masterThesis.attacks.critical.{KnownPartialPlaintext, MessageResend, RelatedMessage}
import com.andrius.masterThesis.attacks.structural.SupportSplittingAlgorithm
import com.andrius.masterThesis.mceliece.McElieceCryptosystem
import com.andrius.masterThesis.mceliece.McElieceCryptosystem.Configuration
import com.andrius.masterThesis.utils.{Logging, UserInputProcessor, Vector}
import org.bouncycastle.pqc.math.linearalgebra.GF2Vector

import scala.collection.mutable.ListBuffer

/**
  * @author Andrius Versockas <andrius.versockas@gmail.com>
  */
object Main {

  def main(args: Array[String]): Unit = {
    val configuration = UserInputProcessor.getMcElieceConfiguration
    val (keyPairCount, messageCount) = UserInputProcessor.getAttackOptions
    val attackId = UserInputProcessor.getAttackId

    Console.println(
      s"Attack(s) will be executed on McEliece cryptosystem with (n, k, t) = (${configuration.n}, " +
        s"${configuration.k}, ${configuration.t}) security parameters (m = ${configuration.m})."
    )

    attackId match {
      case Attack.Id.GISD =>
        generalizedInformationSetDecoding(configuration, keyPairCount, messageCount)
      case Attack.Id.KnownPartialPlaintext =>
        val kRight = UserInputProcessor.getKnownPartial(configuration.k)
        knownPartialPlaintext(configuration, keyPairCount, messageCount, kRight)
      case Attack.Id.MessageResend =>
        messageResend(configuration, keyPairCount, messageCount)
      case Attack.Id.RelatedMessage =>
        relatedMessage(configuration, keyPairCount, messageCount)
      case Attack.Id.SupportSplitting =>
        throw new Exception("Currently not stable enough to attack, low chance of success")
        supportSplittingAlgorithm(configuration, keyPairCount, messageCount)
      case _ =>
        throw new Exception("Unknown attack specified")
    }
  }

  /**
    * Non-Critical: Generalized Information-Set Decoding (GISD) attack
    *
    * @param configuration McEliece PKC configuration
    * @param keyPairCount  McEliece PKC random public & private key pair count
    * @param messageCount  randomly generated message count per key pair
    */
  def generalizedInformationSetDecoding(
                                         configuration: Configuration,
                                         keyPairCount: Int,
                                         messageCount: Int
                                       ): Unit = {
    val attackIds = List(Attack.Id.GISD)
    val timeResultsTotal = new ListBuffer[Long]()
    for (_ <- 0 until keyPairCount) {
      val timeResultsKeyPair = new ListBuffer[Long]()
      val mcEliecePKC = new McElieceCryptosystem(configuration)
      val leeBrickell = new LeeBrickell(mcEliecePKC.publicKey)

      for (_ <- 0 until messageCount) {
        val msg = Vector.generateMessageVector(mcEliecePKC.publicKey.getK)
        val cipher = mcEliecePKC.encryptVector(msg)

        val start = System.currentTimeMillis
        leeBrickell.attack(cipher)
        val end = System.currentTimeMillis - start
        if (configuration.verbose.partialResults) {
          timeResultsKeyPair += end
        }
        if (configuration.verbose.totalResults) {
          timeResultsTotal += end
        }
        if (configuration.verbose.ramUsage) {
          Logging.ramUsageResults()
        }
      }
      if (configuration.verbose.partialResults) {
        Logging.singleKeyPairResults(attackIds, messageCount, timeResultsKeyPair)
      }
    }
    if (configuration.verbose.totalResults) {
      Logging.totalResults(attackIds, messageCount, keyPairCount, timeResultsTotal)
    }
  }

  /**
    * Critical: Known Partial Plaintext Attack
    *
    * @param configuration McEliece PKC configuration
    * @param keyPairCount  McEliece PKC random public & private key pair count
    * @param messageCount  randomly generated message count per key pair
    * @param knownRight    known message vector from right
    */
  def knownPartialPlaintext(
                             configuration: Configuration,
                             keyPairCount: Int,
                             messageCount: Int,
                             knownRight: Int
                           ): Unit = {
    require(configuration.k > knownRight, "Position count cannot be equal or exceed message length")
    require(knownRight >= 0, "Position count cannot be negative")

    val attackIds = List(Attack.Id.KnownPartialPlaintext, Attack.Id.GISD)

    def executeAttack(kRight: Int): ListBuffer[Long] = {
      val timeResultsTotal = new ListBuffer[Long]()
      for (_ <- 0 until keyPairCount) {
        val timeResultsKeyPair = new ListBuffer[Long]()
        val mcEliecePKC = new McElieceCryptosystem(configuration)
        val partial = new KnownPartialPlaintext(mcEliecePKC.publicKey)
        for (_ <- 0 until messageCount) {
          val msg = Vector.generateMessageVector(mcEliecePKC.publicKey.getK)
          val cipher = mcEliecePKC.encryptVector(msg)
          val knownRight = msg.extractRightVector(kRight)

          val start = System.currentTimeMillis
          // attack counts successful if security complexity was reduced
          val reducedParameters = partial.attack(knownRight, cipher)

          // any other decoding attack can be used
          val leeBrickell = new LeeBrickell(reducedParameters.publicKey)
          leeBrickell.attack(reducedParameters.cipher)

          val end = System.currentTimeMillis - start
          if (configuration.verbose.partialResults) {
            timeResultsKeyPair += end
          }
          if (configuration.verbose.totalResults) {
            timeResultsTotal += end
          }
          if (configuration.verbose.ramUsage) {
            Logging.ramUsageResults()
          }
        }
        if (configuration.verbose.partialResults) {
          Logging.singleKeyPairResults(
            attackIds,
            messageCount,
            timeResultsKeyPair,
            s" with $kRight/${mcEliecePKC.publicKey.getK} known"
          )
        }
      }
      timeResultsTotal
    }

    if (knownRight == 0) {
      val timeResultsTotal = new ListBuffer[Long]()
      for (kRight <- 1 until configuration.k) {
        val results = executeAttack(kRight)
        if (configuration.verbose.totalResults) {
          timeResultsTotal ++= results
        }
        if (configuration.verbose.partialResults) {
          Logging.totalResults(
            attackIds,
            messageCount,
            keyPairCount,
            results,
            s" with $kRight/${configuration.k} known")
        }
      }
      if (configuration.verbose.totalResults) {
        Logging.totalResults(
          attackIds,
          messageCount,
          keyPairCount,
          timeResultsTotal,
          s" with 1..${configuration.k - 1}")
      }
    } else {
      val results = executeAttack(knownRight)
      if (configuration.verbose.totalResults) {
        Logging.totalResults(
          attackIds,
          messageCount,
          keyPairCount,
          results,
          s"with $knownRight/${configuration.k} known")
      }
    }
  }

  /**
    * Critical: Message-Resend Attack
    *
    * @param configuration McEliece PKC configuration
    * @param keyPairCount  McEliece PKC random public & private key pair count
    * @param messageCount  randomly generated message count per key pair
    **/
  def messageResend(
                     configuration: Configuration,
                     keyPairCount: Int,
                     messageCount: Int
                   ): Unit = {
    val attackIds = List(Attack.Id.MessageResend)
    var extraTriesTotal = 0
    val timeResultsTotal = new ListBuffer[Long]()
    for (_ <- 0 until keyPairCount) {
      var extraTriesLocal = 0
      var identicalErrorsLocal = 0
      val timeResultsKeyPair = new ListBuffer[Long]()

      val mcEliecePKC = new McElieceCryptosystem(configuration)
      val messageResend = new MessageResend(mcEliecePKC.publicKey)
      for (_ <- 0 until messageCount) {
        val msg = Vector.generateMessageVector(mcEliecePKC.publicKey.getK)

        val cipher1 = mcEliecePKC.encryptVector(msg)
        val cipher2 = mcEliecePKC.encryptVector(msg)
        try {
          if (cipher1.equals(cipher2)) {
            throw new IllegalArgumentException(
              "Attack cannot be successful, message m encoded twice with the same error vector (e1=e2)"
            )
          }
          var found = false
          val start = System.currentTimeMillis
          while (!found) {
            // it is possible to check if padding is correct (filter failures)
            // Vector.computeMessage(messageResend.attack(cipher1, cipher2))
            if (messageResend.attack(cipher1, cipher2).equals(msg)) {
              val end = System.currentTimeMillis - start
              if (configuration.verbose.partialResults) {
                timeResultsKeyPair += end
              }
              if (configuration.verbose.totalResults) {
                timeResultsTotal += end
              }
              found = true
            } else {
              if (configuration.verbose.partialResults) {
                extraTriesLocal += 1
              }
              if (configuration.verbose.totalResults) {
                extraTriesTotal += 1
              }
            }
          }
        } catch {
          case _: IllegalArgumentException =>
            identicalErrorsLocal += 1
        }
      }
      if (configuration.verbose.partialResults) {
        Logging.singleKeyPairResults(
          attackIds,
          messageCount,
          timeResultsKeyPair,
          s" with extra iterations needed $extraTriesLocal and accidental identical errors caught $identicalErrorsLocal"
        )
      }
      if (configuration.verbose.ramUsage) {
        Logging.ramUsageResults()
      }
    }
    if (configuration.verbose.totalResults) {
      Logging.totalResults(
        attackIds,
        messageCount,
        keyPairCount,
        timeResultsTotal,
        s" with extra iterations needed $extraTriesTotal"
      )
    }
  }

  /**
    * Critical: Related-Message Attack
    * Note. Our selected delta = message vectors differ in every 32 position.
    * It is possible generate random deltas.
    *
    * @param configuration McEliece PKC configuration
    * @param keyPairCount  McEliece PKC random public & private key pair count
    * @param messageCount  randomly generated message count per key pair
    */
  def relatedMessage(
                      configuration: Configuration,
                      keyPairCount: Int,
                      messageCount: Int
                    ): Unit = {
    val attackIds = List(Attack.Id.RelatedMessage)
    var extraTriesTotal = 0
    val timeResultsTotal = new ListBuffer[Long]()
    for (_ <- 0 until keyPairCount) {
      val timeResultsKeyPair = new ListBuffer[Long]()
      var extraTriesLocal = 0
      var identicalErrorsLocal = 0

      val mcEliecePKC = new McElieceCryptosystem(configuration)
      val relatedMessage = new RelatedMessage(mcEliecePKC.publicKey)
      for (_ <- 0 until messageCount) {
        val msg1 = Vector.generateMessageVector(mcEliecePKC.publicKey.getK)
        // For example, we know that message vector always differ in every 32 position
        val mDelta = new GF2Vector(mcEliecePKC.publicKey.getK, Array.fill((mcEliecePKC.publicKey.getK - 1) / 32 + 1)(1))
        val msg2 = msg1.add(mDelta).asInstanceOf[GF2Vector]

        val cipher1 = mcEliecePKC.encryptVector(msg1)
        val cipher2 = mcEliecePKC.encryptVector(msg2)
        try {
          if (cipher1.equals(cipher2)) {
            throw new IllegalArgumentException("Attack cannot be successful, message m encoded with same error vectors (e1=e2)")
          }
          var found = false
          val start = System.currentTimeMillis
          while (!found) {
            if (relatedMessage.attack(cipher1, cipher2, mDelta).equals(msg1)) {
              val end = System.currentTimeMillis - start
              if (configuration.verbose.partialResults) {
                timeResultsKeyPair += end
              }
              if (configuration.verbose.totalResults) {
                timeResultsTotal += end
              }
              found = true
            } else {
              if (configuration.verbose.partialResults) {
                extraTriesLocal += 1
              }
              if (configuration.verbose.totalResults) {
                extraTriesTotal += 1
              }
            }
          }
        } catch {
          case _: IllegalArgumentException =>
            identicalErrorsLocal += 1
        }
      }
      if (configuration.verbose.partialResults) {
        Logging.singleKeyPairResults(
          attackIds,
          messageCount,
          timeResultsKeyPair,
          s" with extra iterations needed $extraTriesLocal and accidental identical errors caught $identicalErrorsLocal"
        )
      }
      if (configuration.verbose.ramUsage) {
        Logging.ramUsageResults()
      }
    }
    if (configuration.verbose.totalResults) {
      Logging.totalResults(
        attackIds,
        messageCount,
        keyPairCount,
        timeResultsTotal,
        s" with extra iterations needed $extraTriesTotal"
      )
    }
  }

  /**
    * Structural: Support Splitting Algorithm attack
    *
    * @param configuration McEliece PKC configuration
    * @param keyPairCount  McEliece PKC random public & private key pair count
    * @param messageCount  randomly generated message count per key pair
    */
  def supportSplittingAlgorithm(
                                 configuration: Configuration,
                                 keyPairCount: Int,
                                 messageCount: Int
                               ): Unit = {
    val attackIds = List(Attack.Id.SupportSplitting)
    val timeResultsTotal = new ListBuffer[Long]()
    for (_ <- 0 until keyPairCount) {
      val timeResultsKeyPair = new ListBuffer[Long]()
      val mcEliecePKC = new McElieceCryptosystem(configuration)
      val ssa = new SupportSplittingAlgorithm(mcEliecePKC.publicKey)
      for (_ <- 0 until messageCount) {
        val start = System.currentTimeMillis

        ssa.attack()
        val end = System.currentTimeMillis - start
        if (configuration.verbose.partialResults) {
          timeResultsKeyPair += end
        }
        if (configuration.verbose.totalResults) {
          timeResultsTotal += end
        }
      }
      if (configuration.verbose.partialResults) {
        Logging.singleKeyPairResults(
          attackIds,
          messageCount,
          timeResultsKeyPair
        )
      }
      if (configuration.verbose.ramUsage) {
        Logging.ramUsageResults()
      }
    }
    if (configuration.verbose.totalResults) {
      Logging.totalResults(
        attackIds,
        messageCount,
        keyPairCount,
        timeResultsTotal
      )
    }
  }

}