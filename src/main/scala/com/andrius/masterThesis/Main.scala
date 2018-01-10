package com.andrius.masterThesis

import com.andrius.masterThesis.attacks.noncritical.isd.LeeBrickell
import com.andrius.masterThesis.attacks.critical.{KnownPartialPlaintext, MessageResend, RelatedMessage}
import com.andrius.masterThesis.mceliece.McElieceCryptosystem
import com.andrius.masterThesis.mceliece.McElieceCryptosystem.{BasicConfiguration, DebugOptions}
import com.andrius.masterThesis.utils.Vector
import org.bouncycastle.crypto.InvalidCipherTextException
import org.bouncycastle.pqc.math.linearalgebra.GF2Vector

import scala.util.Random

/**
  * @author Andrius Versockas <andrius.versockas@gmail.com>
  * @todo Delete below:
  *       Great slides about McEliece: http://www-math.ucdenver.edu/~wcherowi/courses/m5410/mcleice.pdf
  *       Good conclusions on McEliece: http://re-search.info/sites/default/files/zajac_workshop_2016.pdf
  */
object Main {

  /**
    * Non-Critical: Generalized Information-Set Decoding (GISD) attack
    *
    * @param configuration McEliece PKC configuration
    */
  def generalizedInformationSetDecoding(configuration: BasicConfiguration): Unit = {
    val mcEliecePKC = new McElieceCryptosystem(configuration)

    val msg = Vector.generateMessageVector(mcEliecePKC.publicKey.getK)
    val cipher = mcEliecePKC.encryptVector(msg)

    val leeBrickell = new LeeBrickell(mcEliecePKC.publicKey)
    val result = leeBrickell.attack(cipher)

    println(result.equals(msg))
  }

  /**
    * Critical: Known Partial Plaintext Attack
    *
    * @param configuration McEliece PKC configuration
    */
  def knownPlainText(configuration: BasicConfiguration): Unit = {
    val mcEliecePKC = new McElieceCryptosystem(configuration)

    val msg = Vector.generateMessageVector(mcEliecePKC.publicKey.getK)
    val cipher = mcEliecePKC.encryptVector(msg)

    // How many places known
    val kRight = Random.nextInt(mcEliecePKC.publicKey.getK) + 1 // mcEliecePKC.publicKey.getK / 2
    val knownRight = msg.extractRightVector(kRight)

    val partial = new KnownPartialPlaintext(mcEliecePKC.publicKey)
    // Attack counts successful if security complexity was reduced
    val reducedParameters = partial.attack(knownRight, cipher)

    // Use any other decoding attack
    val leeBrickell = new LeeBrickell(reducedParameters.publicKey)
    val decodingResult = leeBrickell.attack(reducedParameters.cipher)
    val result = Vector.concat(decodingResult, knownRight)

    println(result.equals(msg))
  }

  /**
    * Critical: Message-Resend Attack
    *
    * @param configuration McEliece PKC configuration
    */
  def messageResend(configuration: BasicConfiguration): Unit = {
    val mcEliecePKC = new McElieceCryptosystem(configuration)

    val msg = Vector.generateMessageVector(mcEliecePKC.publicKey.getK)

    val cipher1 = mcEliecePKC.encryptVector(msg)
    val cipher2 = mcEliecePKC.encryptVector(msg)
    if (cipher1.equals(cipher2)) {
      throw new Exception("Attack cannot be successful, message m encoded with same error vectors (e1=e2)")
    }
    var found = false
    var tries = 0
    var result: GF2Vector = null
    val messageResend = new MessageResend(mcEliecePKC.publicKey)
    while (!found) {
      try {
        tries += 1
        result = messageResend.attack(cipher1, cipher2)
        // Test to see if received vector padding makes sense
        Vector.computeMessage(result)
        found = true
      } catch {
        case _: InvalidCipherTextException =>
        // Error vectors collision
      }
    }
    println(result.equals(msg), tries)
  }

  /**
    * Critical: Related-Message Attack
    *
    * @param configuration McEliece PKC configuration
    */
  def messageRelated(configuration: BasicConfiguration): Unit = {
    val mcEliecePKC = new McElieceCryptosystem(configuration)

    val msg1 = Vector.generateMessageVector(mcEliecePKC.publicKey.getK)
    // For example, we know that message vector always differ in every 32 position
    val mDelta = new GF2Vector(mcEliecePKC.publicKey.getK, Array.fill((mcEliecePKC.publicKey.getK - 1) / 32 + 1)(1))
    val msg2 = msg1.add(mDelta).asInstanceOf[GF2Vector]

    val cipher1 = mcEliecePKC.encryptVector(msg1)
    val cipher2 = mcEliecePKC.encryptVector(msg2)

    if (cipher1.equals(cipher2)) {
      throw new Exception("Attack cannot be successful, message m encoded with same error vectors (e1=e2)")
    }
    var found = false
    var tries = 0
    var result: GF2Vector = null
    val relatedMessage = new RelatedMessage(mcEliecePKC.publicKey)
    while (!found) {
      try {
        tries += 1
        result = relatedMessage.attack(cipher1, cipher2, mDelta)
        // Test to see if received vector padding makes sense
        Vector.computeMessage(result)
        found = true
      } catch {
        case _: InvalidCipherTextException =>
        // Error vectors collision
      }
    }
    println(result.equals(msg1), tries)
  }

  def main(args: Array[String]): Unit = {
    val configuration = BasicConfiguration(m = 5, t = 2)
    //generalizedInformationSetDecoding(configuration)
    //knownPlainText(configuration)
    //messageResend(configuration)
    //messageRelated(configuration)

    //for (i <- 0 until 10)
      //println(McElieceCryptosystem.computeMessageString(partial.attack(msgPartial)))

    /* Random
    val cipher = new McElieceCipher
    cipher.init(true, mcEliecePKC.publicKey)
    End Random*/
    //mcEliecePKC.publicKey.
    // We intercept user's cypher and prepare data
    //val encryptedVector = new GF2Vector(mcEliecePKC.publicKey.getN, LittleEndianConversions.toIntArray(encryptedMsg))
    //val parityCheckMatrixH = Matrix.convertGeneratorMatrixToParityCheckMatrix(mcEliecePKC.publicKey.getG)
    //val syndrome = parityCheckMatrixH.rightMultiply(encryptedVector).asInstanceOf[GF2Vector]
    //val oracle = new StdPlainPkcs1Oracle(keyPair.getPublic(), TestPkcs1Oracle.OracleType.MANGER_0x00, cipher.getBlockSize())
    /*(new BothMay).attack(
      syndrome,
      parityCheckMatrixH
    )*/

    /*
    Pkcs1Oracle oracle = new StdPlainPkcs1Oracle(keyPair.getPublic(), TestPkcs1Oracle.OracleType.TTT,
      cipher.getBlockSize());

    Bleichenbacher attacker = new Bleichenbacher(message, oracle, true);
    attacker.attack();
    BigInteger solution = attacker.getSolution();

    Assert.assertArrayEquals("The computed solution for Bleichenbacher must be equal to the original message",
      message, solution.toByteArray());
      */
    //
    //val start = System.currentTimeMillis
    //val msg = mcEliece.encryptRandomMessage
    //println(mcEliecePKC.decryptString(mcEliecePKC.encrypt(msg)), System.currentTimeMillis - start)

  }
}