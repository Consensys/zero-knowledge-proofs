# zk-snarks question #

This question will be based on a simple balance update example.  [This link provides a good background to the question](https://media.consensys.net/introduction-to-zksnarks-with-examples-3283b554fc3b)

Some additional background [Quadratic Arithmetic Programs: from Zero to Hero](https://medium.com/@VitalikButerin/quadratic-arithmetic-programs-from-zero-to-hero-f6d558cea649)

The question has a number of parts:

## Part 1: produce a zero knowledge proof that can be verified ##

Given the code here: (TBD), create a zero knowledge proof that takes the following inputs

* r1 (integer) = 2
* r2 (integer) = 3
* r3 (integer) = 5
* h1 = salted hash of r1
* h2 = salted hash of r2
* h3 = salted hash of r3

you will be provided with the following:

* salt1 = entropy (salt) for r1
* salt2 = entropy (salt) for r2
* salt3 = entropy (salt) for r3
* prover key for the proof generator

The proof generator should take the private inputs (r1,r2 & r3) and the public inputs (h1,h2 & h3) and output a proof.  The proof should be put into an output file.

The proof will be that r1 + r2 = r3

The proof will be validated using the validator key and the public inputs (h1,h2 and h3)

## Part 2: determine the level of security (in bits) that this solution provides ##

In a brute force attack, what is the level of security on private data (r1, r2 and r2) in this solution



