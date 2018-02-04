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


## Prerequisites
Java 1.8

To run the project:
  > java -jar McEliece_attacks_v1.jar