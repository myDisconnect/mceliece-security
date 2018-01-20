organization := "com.andrius"

name := "mceliece-security"

version := "0.1"

scalaVersion := "2.12.4"

val akkaVersion = "2.5.7"
val scalaTestVersion = "3.0.4"

libraryDependencies ++= Seq(
  "com.typesafe.akka" %% "akka-actor" % akkaVersion, //@TODO delete or use it
  // https://mvnrepository.com/artifact/org.bouncycastle/bcprov-jdk15on
  "org.scalactic" %% "scalactic" % scalaTestVersion,
  "com.typesafe.scala-logging" %% "scala-logging" % "3.7.2",
  "org.scalatest" %% "scalatest" % scalaTestVersion % Test,
  "org.bouncycastle" % "bcprov-jdk15on" % "1.58"
)
