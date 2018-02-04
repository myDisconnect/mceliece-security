organization := "com.andrius"

name := "mceliece-security"

version := "0.1"

scalaVersion := "2.12.4"

val akkaVersion = "2.5.7"
val scalaTestVersion = "3.0.4"

libraryDependencies ++= Seq(
  //"com.typesafe.akka" %% "akka-actor" % akkaVersion, //@TODO use it
  "org.scalactic" %% "scalactic" % scalaTestVersion,
  "org.scalatest" %% "scalatest" % scalaTestVersion % Test,
  // https://mvnrepository.com/artifact/org.bouncycastle/bcprov-jdk15on
  "org.bouncycastle" % "bcprov-jdk15on" % "1.58"
)

mainClass := Some("com.andrius.masterThesis.Main")

assemblyJarName in assembly := "McEliece_attacks_v1.jar"