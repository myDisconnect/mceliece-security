# Master's thesis: Study of the security of McEliece public-key
This repository contains implementations of well known attacks against the original McEliece cryptosystem with binary Goppa codes.

## Structural attacks
- [ ] Support Splitting Algorithm (SSA) (In-Progress, currently unpredictable)

## Non-critical attacks
- [x] Generalized Information Set Decoding (GISD) (based on Lee-Brickell algorithm)
- [ ] Finding Low Weight Codewords in slightly larger code (maybe Both-May algorithm?)

## Critical attacks
- [x] Known Partial Plaintext
- [x] Message Resend
- [x] Related Message
- [ ] Malleability
- [ ] Reaction (Side-channel)
- [ ] Brute-force
- [ ] Statistical Decoding


# Requirements
* Java Runtime Environment 8 (JRE 8).

## Running the project
 > java -Xmx15g -Xms15g -jar McEliece_attacks_v1.jar

Here you need to specify the Xms and Xmx parameters according to your machine:
* `Xmx` - specifies the maximum memory allocation pool for a Java Virtual Machine (JVM).
* `Xms` - specifies the initial memory allocation pool for a Java Virtual Machine (JVM).
