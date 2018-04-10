package com.andrius.masterThesis.attacks

object Attack {

  val map: Map[Int, String] = Map(
    Id.GISD                  -> Name.GISD,
    Id.KnownPartialPlaintext -> Name.KnownPartialPlaintext,
    Id.MessageResend         -> Name.MessageResend,
    Id.RelatedMessage        -> Name.RelatedMessage,
    Id.SupportSplitting      -> Name.SupportSplitting
  )

  object Id {
    val GISD                  = 1
    val KnownPartialPlaintext = 2
    val MessageResend         = 3
    val RelatedMessage        = 4
    val SupportSplitting      = 5
  }

  object Name {
    val GISD                  = "Generalized Information Set Decoding"
    val KnownPartialPlaintext = "Known Partial Plaintext"
    val MessageResend         = "Message Resend"
    val RelatedMessage        = "Related Message"
    val SupportSplitting      = "Support Splitting"
  }

  object RelatedMessageAlgorithm {
    val ErrorVectorSearch        = 1
    val IndependentLinearColumns = 2
  }

}
