# zk-snarks question #

Alice wants to prove to Bob that she knows the values r1, r2 and r3 which hash to 0x57603c1fbe46a14cf1ece9266fa6712c0f3fa5d79986a1502571f48fecf8c1b2, 
0x48e5963de6dc0867cf04b22c041b7fa5a5294a5ce1ab7cbacc845c4edc33a686 and 0xb554a51a5079403b181308909f887be8729a70cc727ebe723e985a64bea6fec1, respectively. 

However, Alice doesn't want to tell Bob the values of r1, r2 and r3. In an attempt to convice Bob that she knows the values for r1, r2 and r3, she mentions that r1 + r2 = r3.

Bob decided that the only way he can know for sure if Alice is telling the truth is if he constructs a zero knowledge circuit + proving key. Bob will then ask Alice to prove 
that she knows the values of r1, r2 and r3 by requesting her to construct a zero knowledge proof  + verification key.

Construct such a system for Bob. The system needs to take as input three values and their SHA256 hashes. The system will then generate a proof that the three values do hash to the 
given hashes, as well as that value1 + value2 = value3.

## Encoding of r1, r2 and r3 ##

The input values are 256 bit, big-endian binary encoded numbers. Bits 128 to 255 of the input values is used as a salt and bits 0 to 127 is used for the value itself.

## Getting started ##

1. Clone the repo here:
2. Install `sudo apt-get install build-essential git libgmp3-dev libprocps3-dev libgtest-dev python-markdown libboost-all-dev libssl-dev`
3. `./get-libsnark && make && ./test`

After changing any files, a simple `make && ./test` will run the test again.

## Files of interest ##

There are two files that are of interest:

1. `src/test.cpp`
2. `src/gadget.hpp`

The first file (the test file) contains sample test vectors for r1, r2 and r3, as well as their hashes. This file generates a new keypair (prover and verification) and makes a call to 
generate the zero knowledge proof (via `src/snark.hpp`) and then also verifies that the proof generated.

The second file has 3 steps with clearly marked TODO sections to complete. 

## The task ##

Once the three steps in the `src/gadget.hpp` file are filled in and correct, Bob will have a zero knowledge system which he can use to verify Alice's claims.

## Usefull links ##

1. For information on the general idea of zero knowledge proofs: https://media.consensys.net/introduction-to-zksnarks-with-examples-3283b554fc3b
2. For more information on R1CS: https://medium.com/@VitalikButerin/quadratic-arithmetic-programs-from-zero-to-hero-f6d558cea649


