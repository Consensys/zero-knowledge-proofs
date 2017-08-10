# zk-snarks question #

This question will be based on a simple balance update example.  [This link provides a good background to the question](https://media.consensys.net/introduction-to-zksnarks-with-examples-3283b554fc3b)

The question has a number of parts:

## Part 1: produce a zero knowledge proof that can be verified ##

Given the code here: (TBD), create a zero knowledge proof that takes the following inputs

* r1 (integer) = 2
* r2 (integer) = 2
* h1 = salted hash of r1
* h2 = salted hash of r2

you will be provided with the following:

* e1 = entropy (salt) for r1
* e2 = entropy (salt) for r2
* prover key for the proof generator

The proof generator should take the private inputs (r1 and r2) and the public inputs (h1 and h2) and output a proof.  The proof should be put into an output file.

The proof will be that r1 * 2 = r2

The proof will be validated using the validator key and the public inputs (h1 and h2)

## Part 2: determine the level of security (in bits) that this solution provides ##

In a brute force attack, what is the level of security on private data (r1 and r2) in this solution



