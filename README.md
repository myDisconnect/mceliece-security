# Master's thesis: Study of the security of McEliece public-key cryptosystem
This repository contains implementations of well known attacks against the original McEliece cryptosystem with binary Goppa codes.

If you find any problems with the code, don't be afraid to open an issue or [e-mail me](mailto:andrius.versockas@gmail.com)

## Structural attacks
- [ ] Support Splitting Algorithm (SSA) (In-Progress)

## Non-critical attacks
- [x] Generalized Information Set Decoding (GISD) (based on Lee-Brickell algorithm)

## Critical attacks
- [x] Known Partial Plaintext
- [x] Message Resend
- [x] Related Message

# Requirements
* Java Runtime Environment 8 (JRE 8).

## Running the project
 > java -Xmx15g -Xms15g -jar McEliece_attacks_v1.jar

Here you need to specify the Xms and Xmx parameters according to your machine:
* `Xmx` - specifies the maximum memory allocation pool for a Java Virtual Machine (JVM).
* `Xms` - specifies the initial memory allocation pool for a Java Virtual Machine (JVM).

# Future work
- [ ] Finding Low Weight Codewords in slightly larger code (Both-May algorithm)
- [ ] Reaction (Side-channel)
- [ ] Brute-force
- [ ] Statistical Decoding
- [ ] Timing