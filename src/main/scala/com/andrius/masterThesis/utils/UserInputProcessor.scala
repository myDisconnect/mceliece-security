package com.andrius.masterThesis.utils

import com.andrius.masterThesis.attacks.Attack
import com.andrius.masterThesis.mceliece.McElieceCryptosystem.{Configuration, VerboseOptions}

import scala.io.StdIn

object UserInputProcessor {

  val consoleBooleanAnswer = Map(
    YesNoAnswer.Yes -> true,
    YesNoAnswer.No -> false
  )

  object YesNoAnswer {
    val Yes = "y"
    val No = "n"
  }

  def getMcElieceConfiguration: Configuration = {
    Console.println("[INFO] Press Enter if the default values suit you.")
    // Default options
    val defaultM = 5
    val defaultT = 2
    val defaultCustomVerbose = YesNoAnswer.No
    val defaultVerbose = VerboseOptions()

    Console.println(s"Enter Goppa code degree of the finite field - m ${printDefault(defaultM)}")
    val m = getIntOrDefault(StdIn.readLine(), defaultM)
    Console.println(s"Enter the error correction capability of the Goppa code - t ${printDefault(defaultT)}")
    val t = getIntOrDefault(StdIn.readLine(), defaultT)
    Console.println(s"${printDoYouWantToLog("custom logging", defaultCustomVerbose)}")
    val customVerbose = consoleBooleanAnswer(getStringOrDefault(StdIn.readLine(), defaultCustomVerbose))
    val verboseOptions = if (customVerbose) getVerboseOptions else defaultVerbose

    Configuration(m, t, verboseOptions)
  }

  def getVerboseOptions: VerboseOptions = {
    val defaultKeyPairGeneration = YesNoAnswer.No
    val defaultCipherGeneration = YesNoAnswer.No
    val defaultPartialResults = YesNoAnswer.Yes
    val defaultTotalResults = YesNoAnswer.Yes

    Console.println(s"${printDoYouWantToLog("public/private keys generation", defaultKeyPairGeneration)}")
    val keyPairGeneration = consoleBooleanAnswer(getStringOrDefault(StdIn.readLine(), defaultKeyPairGeneration))
    Console.println(s"${printDoYouWantToLog("cipher keys generation", defaultCipherGeneration)}")
    val cipherGeneration = consoleBooleanAnswer(getStringOrDefault(StdIn.readLine(), defaultCipherGeneration))
    Console.println(s"${printDoYouWantToLog("partial attack results", defaultPartialResults)}")
    val partialResults = consoleBooleanAnswer(getStringOrDefault(StdIn.readLine(), defaultPartialResults))
    Console.println(s"${printDoYouWantToLog("total attack results", defaultTotalResults)}")
    val totalResults = consoleBooleanAnswer(getStringOrDefault(StdIn.readLine(), defaultTotalResults))

    VerboseOptions(keyPairGeneration, cipherGeneration, partialResults, totalResults)
  }

  def getAttackOptions: (Int, Int) = {
    val defaultKeyPairCount = 10
    val defaultMessageCount = 1000
    Console.println(s"Enter the number of randomly generated McEliece keys to attack ${printDefault(defaultKeyPairCount)}")
    val keyPairCount = getIntOrDefault(StdIn.readLine(), defaultKeyPairCount)
    Console.println(s"Enter the number of messages to encrypt with single McEliece key pair ${printDefault(defaultMessageCount)}")
    val messageCount = getIntOrDefault(StdIn.readLine(), defaultMessageCount)
    (keyPairCount, messageCount)
  }

  def getKnownPartial(messageLength: Int): Int = {
    val defaultKnownRight = 0
    Console.println(s"Enter the number of known right bits of the plaintext, where $defaultKnownRight - " +
      s"execute for all 1..${messageLength - 1} ${printDefault(defaultKnownRight)}")
    val kRight = getIntOrDefault(StdIn.readLine(), defaultKnownRight)
    Console.println(s"[NOTE] This attack reduces security parameters and continues to decode with ${Attack.Name.GISD}")
    kRight
  }

  def getAttackId: Int = {
    Attack.map.foreach(attack => Console.println(s"${attack._1} - ${attack._2}"))
    StdIn.readInt
  }

  def printDefault[T](string: T): String = s"[Default $string]:"

  def printYesOrNo: String = s"Enter ${YesNoAnswer.Yes} or ${YesNoAnswer.No}"

  def printDoYouWantToLog[T](string: String, default: T): String =
    s"Do you want to log $string? $printYesOrNo ${printDefault(default)}"

  def getStringOrDefault(input: String, default: String): String = {
    if (input.isEmpty) {
      default
    } else {
      input
    }
  }

  def getIntOrDefault(input: String, default: Int): Int = {
    if (input.isEmpty) {
      default
    } else {
      input.toInt
    }
  }

}
