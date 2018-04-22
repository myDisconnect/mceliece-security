package com.andrius.masterThesis

import com.andrius.masterThesis.attacks.Attack
import com.andrius.masterThesis.attacks.critical.{KnownPartialPlaintext, MessageResend, RelatedMessage}
import com.andrius.masterThesis.attacks.noncritical.informationSetDecoding.LeeBrickell
import com.andrius.masterThesis.attacks.structural.SupportSplittingAlgorithm
import com.andrius.masterThesis.mceliece.McElieceCryptosystem
import com.andrius.masterThesis.mceliece.McElieceCryptosystem.Configuration
import com.andrius.masterThesis.utils.{LoggingUtils, UserInputProcessorUtils, VectorUtils}
import org.bouncycastle.pqc.math.linearalgebra.GF2Vector

import scala.collection.mutable.ListBuffer

/**
  * @author Andrius Versockas <andrius.versockas@gmail.com>
  */
object Main {

  def main(args: Array[String]): Unit = {
    val attackId      = UserInputProcessorUtils.getAttackId
    val configuration = UserInputProcessorUtils.getMcElieceConfiguration
    val keyPairCount  = UserInputProcessorUtils.getKeyPairCount

    val messageCount = attackId match {
      case Attack.Id.SupportSplitting =>
        None
      case _ =>
        Some(UserInputProcessorUtils.getMessageCount)
    }

    attackId match {
      case Attack.Id.GISD =>
        val searchSize = UserInputProcessorUtils.getSearchSizeParameter(configuration.t)
        LoggingUtils.attacksInfo(attackId)
        generalizedInformationSetDecoding(configuration, keyPairCount, messageCount.get, searchSize)
      case Attack.Id.KnownPartialPlaintext =>
        val kRight = UserInputProcessorUtils.getKnownPartial(configuration.k)
        LoggingUtils.attacksInfo(Attack.Id.KnownPartialPlaintext, Attack.Id.GISD)
        knownPartialPlaintext(configuration, keyPairCount, messageCount.get, kRight)
      case Attack.Id.MessageResend =>
        val algorithm = UserInputProcessorUtils.getRelatedMessageAlgorithm
        LoggingUtils.attacksInfo(attackId)
        messageResend(configuration, keyPairCount, messageCount.get, algorithm)
      case Attack.Id.RelatedMessage =>
        val algorithm = UserInputProcessorUtils.getRelatedMessageAlgorithm
        LoggingUtils.attacksInfo(attackId)
        relatedMessage(configuration, keyPairCount, messageCount.get, algorithm)
      case Attack.Id.SupportSplitting =>
        LoggingUtils.attacksInfo(attackId)
        supportSplittingAlgorithm(configuration, keyPairCount)
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
    * @param searchSize    search size parameter
    */
  def generalizedInformationSetDecoding(
      configuration: Configuration,
      keyPairCount: Int,
      messageCount: Int,
      searchSize: Int
  ): Unit = {

    def executeAttack(searchSize: Int): ListBuffer[Long] = {
      val timeResultsTotal = new ListBuffer[Long]()
      for (_ <- 0 until keyPairCount) {
        val timeResultsKeyPair = new ListBuffer[Long]()
        val mcEliecePKC        = new McElieceCryptosystem(configuration)
        val leeBrickell        = new LeeBrickell(mcEliecePKC.publicKey)

        for (_ <- 0 until messageCount) {
          val msg    = VectorUtils.generateMessageVector(configuration.k)
          val cipher = mcEliecePKC.encryptVector(msg)

          val start = System.currentTimeMillis
          leeBrickell.attack(cipher, searchSize)
          val end = System.currentTimeMillis - start
          if (configuration.verbose.partialResults) {
            timeResultsKeyPair += end
          }
          if (configuration.verbose.totalResults) {
            timeResultsTotal += end
          }
          if (configuration.verbose.ramUsage) {
            LoggingUtils.ramUsageResults()
          }
        }
        if (configuration.verbose.partialResults) {
          LoggingUtils.singleKeyPairResults(
            messageCount,
            timeResultsKeyPair
          )
        }
      }
      timeResultsTotal
    }

    if (searchSize == -1) {
      val timeResultsTotal = new ListBuffer[Long]()
      for (searchSize <- 0 to configuration.t) {
        val results = executeAttack(searchSize)
        if (configuration.verbose.totalResults) {
          timeResultsTotal ++= results
        }
        if (configuration.verbose.partialResults) {
          LoggingUtils.totalResults(
            messageCount,
            keyPairCount,
            results,
            s"Search size parameter p = $searchSize. " +
              s"Guess probability on single information-set I = " +
              f"${LeeBrickell.getGuessProbability(configuration.n, configuration.k, configuration.t, searchSize) * 100}%1.4f%%."
          )
        }
      }
      if (configuration.verbose.totalResults) {
        LoggingUtils.totalResults(
          messageCount,
          keyPairCount,
          timeResultsTotal,
          s"Tried all 1..${configuration.t} search size positions."
        )
      }
    } else {
      val results = executeAttack(searchSize)
      if (configuration.verbose.totalResults) {
        LoggingUtils.totalResults(
          messageCount,
          keyPairCount,
          results,
          s"Guess probability on single information-set I = " +
            f"${LeeBrickell.getGuessProbability(configuration.n, configuration.k, configuration.t, searchSize) * 100}%1.4f%%."
        )
      }
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

    def executeAttack(kRight: Int): ListBuffer[Long] = {
      val timeResultsTotal = new ListBuffer[Long]()
      for (_ <- 0 until keyPairCount) {
        val timeResultsKeyPair = new ListBuffer[Long]()
        val mcEliecePKC        = new McElieceCryptosystem(configuration)
        val partial            = new KnownPartialPlaintext(mcEliecePKC.publicKey)
        for (_ <- 0 until messageCount) {
          val msg        = VectorUtils.generateMessageVector(configuration.k)
          val cipher     = mcEliecePKC.encryptVector(msg)
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
            LoggingUtils.ramUsageResults()
          }
        }
        if (configuration.verbose.partialResults) {
          LoggingUtils.singleKeyPairResults(
            messageCount,
            timeResultsKeyPair,
            s"Positions $kRight/${configuration.k} known from right."
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
          LoggingUtils.totalResults(
            messageCount,
            keyPairCount,
            results,
            s"Positions $kRight/${configuration.k} known from right."
          )
        }
      }
      if (configuration.verbose.totalResults) {
        LoggingUtils.totalResults(
          messageCount,
          keyPairCount,
          timeResultsTotal,
          s"Tried all 1..${configuration.k - 1} known positions from right."
        )
      }
    } else {
      val results = executeAttack(knownRight)
      if (configuration.verbose.totalResults) {
        LoggingUtils.totalResults(
          messageCount,
          keyPairCount,
          results,
          s"Positions $knownRight/${configuration.k} known from right."
        )
      }
    }
  }

  /**
    * Critical: Message-Resend Attack
    *
    * @param configuration McEliece PKC configuration
    * @param keyPairCount  McEliece PKC random public & private key pair count
    * @param messageCount  randomly generated message count per key pair
    * @param algorithm     algorithm selected
    **/
  def messageResend(
      configuration: Configuration,
      keyPairCount: Int,
      messageCount: Int,
      algorithm: Int
  ): Unit = {
    var extraTriesTotal  = 0
    val timeResultsTotal = new ListBuffer[Long]()
    for (_ <- 0 until keyPairCount) {
      var extraTriesLocal      = 0
      var identicalErrorsLocal = 0
      val timeResultsKeyPair   = new ListBuffer[Long]()

      val mcEliecePKC   = new McElieceCryptosystem(configuration)
      val messageResend = new MessageResend(mcEliecePKC.publicKey)
      for (_ <- 0 until messageCount) {
        val msg = VectorUtils.generateMessageVector(configuration.k)

        try {
          val cipher1 = mcEliecePKC.encryptVector(msg)
          val cipher2 = mcEliecePKC.encryptVector(msg)
          var found   = false
          while (!found) {
            val start = System.currentTimeMillis
            // it is possible to check if padding is correct (filter failures)
            // Vector.computeMessage(messageResend.attack(cipher1, cipher2))
            val result = algorithm match {
              case Attack.RelatedMessageAlgorithm.IndependentLinearColumns =>
                messageResend.attack2(cipher1, cipher2)
              case _ =>
                messageResend.attack1(cipher1, cipher2)
            }
            if (result.equals(msg)) {
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
            // identical errors generated
            identicalErrorsLocal += 1
        }
      }
      if (configuration.verbose.partialResults) {
        LoggingUtils.singleKeyPairResults(
          messageCount,
          timeResultsKeyPair,
          s"Total tries needed ${extraTriesLocal + messageCount} and accidental identical errors generated " +
            s"$identicalErrorsLocal."
        )
      }
      if (configuration.verbose.ramUsage) {
        LoggingUtils.ramUsageResults()
      }
    }
    if (configuration.verbose.totalResults) {
      LoggingUtils.totalResults(
        messageCount,
        keyPairCount,
        timeResultsTotal,
        s"Total tries needed ${extraTriesTotal + messageCount}."
      )
    }
  }

  /**
    * Critical: Related-Message Attack
    *
    * Note. Our selected delta = message vectors differ in every 32 position.
    * It is possible generate random deltas.
    *
    * @param configuration McEliece PKC configuration
    * @param keyPairCount  McEliece PKC random public & private key pair count
    * @param messageCount  randomly generated message count per key pair
    * @param algorithm     algorithm selected
    */
  def relatedMessage(
      configuration: Configuration,
      keyPairCount: Int,
      messageCount: Int,
      algorithm: Int
  ): Unit = {
    var extraTriesTotal  = 0
    val timeResultsTotal = new ListBuffer[Long]()
    for (_ <- 0 until keyPairCount) {
      val timeResultsKeyPair   = new ListBuffer[Long]()
      var extraTriesLocal      = 0
      var identicalErrorsLocal = 0

      val mcEliecePKC    = new McElieceCryptosystem(configuration)
      val relatedMessage = new RelatedMessage(mcEliecePKC.publicKey)
      for (_ <- 0 until messageCount) {
        val msg1 = VectorUtils.generateMessageVector(configuration.k)
        // For example, we know that message vector always differ in every 32 position
        val mDelta = new GF2Vector(configuration.k, Array.fill((configuration.k - 1) / 32 + 1)(1))
        val msg2   = msg1.add(mDelta).asInstanceOf[GF2Vector]

        var found = false
        try {
          val cipher1 = mcEliecePKC.encryptVector(msg1)
          val cipher2 = mcEliecePKC.encryptVector(msg2)
          val start   = System.currentTimeMillis
          while (!found) {
            val result = algorithm match {
              case Attack.RelatedMessageAlgorithm.IndependentLinearColumns =>
                relatedMessage.attack2(cipher1, cipher2, mDelta)
              case _ =>
                relatedMessage.attack1(cipher1, cipher2, mDelta)
            }
            if (result.equals(msg1)) {
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
            // identical errors generated
            identicalErrorsLocal += 1
        }
      }
      if (configuration.verbose.partialResults) {
        LoggingUtils.singleKeyPairResults(
          messageCount,
          timeResultsKeyPair,
          s"Total tries needed ${extraTriesLocal + messageCount} and accidental identical errors generated " +
            s"$identicalErrorsLocal."
        )
      }
      if (configuration.verbose.ramUsage) {
        LoggingUtils.ramUsageResults()
      }
    }
    if (configuration.verbose.totalResults) {
      LoggingUtils.totalResults(
        messageCount,
        keyPairCount,
        timeResultsTotal,
        s"Total tries needed ${extraTriesTotal + messageCount}."
      )
    }
  }

  /**
    * Structural: Support Splitting Algorithm attack
    *
    * @param configuration McEliece PKC configuration
    * @param keyPairCount  McEliece PKC random public & private key pair count
    */
  def supportSplittingAlgorithm(configuration: Configuration, keyPairCount: Int): Unit = {
    throw new Exception("Currently not stable enough to attack, low chance of success")
  }

}
