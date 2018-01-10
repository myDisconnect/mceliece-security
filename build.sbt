organization := "com.andrius"

name := "mceliece-security"

version := "0.1"

scalaVersion := "2.12.4"

val akkaVersion = "2.5.7"

libraryDependencies ++= Seq(
  "com.typesafe.akka" %% "akka-actor" % akkaVersion,//@TODO delete or use it
  // https://mvnrepository.com/artifact/org.bouncycastle/bcprov-jdk15on
  "org.bouncycastle" % "bcprov-jdk15on" % "1.58"
)
