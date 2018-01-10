package com.andrius.masterThesis

import java.nio.charset.StandardCharsets

import com.andrius.masterThesis.attacks.noncritical.isd.LeeBrickell
import com.andrius.masterThesis.attacks.critical.KnownPartialPlaintext
import com.andrius.masterThesis.mceliece.McElieceCryptosystem
import com.andrius.masterThesis.mceliece.McElieceCryptosystem.BasicConfiguration
import com.andrius.masterThesis.utils.Matrix
import org.bouncycastle.pqc.crypto.mceliece.{McElieceCipher, McElieceParameters, McEliecePublicKeyParameters}
import org.bouncycastle.pqc.jcajce.provider.mceliece.BCMcEliecePublicKey
import org.bouncycastle.pqc.math.linearalgebra.{GF2Matrix, GF2Vector}

object Main2 {

  def main(args: Array[String]): Unit = {
    //val configuration = BasicConfiguration(m = 5, t = 2)
    val configuration = BasicConfiguration(m = 5, t = 2)
    // Generate original McEliece cryptosystem public and private keys
    val mcEliecePKC = new McElieceCryptosystem(configuration)

    val privKey = mcEliecePKC.privateKey
    val pubKey = mcEliecePKC.publicKey
    val n = pubKey.getN
    val k = pubKey.getK

    val sInv = privKey.getSInv
    val p1 = privKey.getP1
    val p2 = privKey.getP2
    val p = p1.rightMultiply(p2)
    val pInv = p.computeInverse()
    // Gpub = S*G*P
    val gPub = pubKey.getG

    // G = S^-1*Gpub*P^-1
    val g = sInv.rightMultiply(gPub.rightMultiply(pInv).asInstanceOf[GF2Matrix])

    val msg = "ll"
    val encrypted = mcEliecePKC.encrypt(msg)
    GF2Vector.OS2VP(pubKey.getN, encrypted)

    val msg2 = "l"

    val nr = pubKey.getN/2
    val gr = Matrix.matrixFromColumns(pubKey.getG, Range(nr, pubKey.getN).toList)

    val pubKey2 = new BCMcEliecePublicKey(new McEliecePublicKeyParameters(nr, pubKey.getT, gr))
    val lee = new LeeBrickell(pubKey2)
    // encrypt
    val cipher = new McElieceCipher()
    new McElieceParameters()
    cipher.init(true, new McEliecePublicKeyParameters(pubKey2.getN, pubKey2.getT, pubKey2.getG))
    val c2 = cipher.messageEncrypt(msg2.getBytes(StandardCharsets.UTF_8))
    val v2 = GF2Vector.OS2VP(pubKey2.getN, c2)
    lee.attack(
      v2
    )
  }
}