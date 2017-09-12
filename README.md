# zero-knowledge-proofs
Zero Knowledge Proofs and how they can be implemented in Quorum

This is a SNARK implementation using libsnark for the following:

``ZkPoK{ (R1, R2, R3): Hi = sha256(Ri) and R3 = R1 + R2 }``

Read: given `H1`, `H2`, `H3`, prove you know `R1`, `R2`, `R3` such that `R1` is the preimage of `H1`, `R2` is the preimage of `H2`, `R3` is the preimage of `H3`, and `R3` is `R1 + R2`.

This is an implementation and benchmark of the "Receive" zk-SNARK in the Confidential Transaction scheme from this article: <https://media.consensys.net/introduction-to-zksnarks-with-examples-3283b554fc3b>.

Code based on <https://github.com/ebfull/lightning_circuit>.

## howto

### Required packages

* On Ubuntu 16.04 LTS:

        `$ sudo apt-get install build-essential cmake git libgmp3-dev libprocps4-dev python-markdown libboost-all-dev libssl-dev`

* On Ubuntu 14.04 LTS:

        `$ sudo apt-get install build-essential cmake git libgmp3-dev libprocps3-dev python-markdown libboost-all-dev libssl-dev`

### Installation

`./get-libsnark && make`

`npm install`

### Running  
`node index.js startBalance=10000`

Follow the prompts.  

1. Generate a key pair
2. Generate a multi-payment proof
4. Verify multi-payment proof
0. Quit

#### Generate a new key pair  
This creates a new proving key and verification key from the circuit.  They are saved to the files:  
* `provingKey`
* `verificationKey`

#### Generate a multi-payment proof  
This generates a proof using the proving key as well as the input values:

* `start balance`
* `incoming payments` (currently the user is prompted for 2 incoming payments)
* `outgoing payments` (currently the user is prompted for 2 outgoing payments)
* `intermediate balance` (start balance + incoming payments)
* `end balance` (intermediate balance - outgoing payments)

The proofs are:  
* `incoming1` + `incoming2` = `total incoming`
* `outgoing1` + `outgoing2` = `total outgoing`
* `start balance` + `total incoming` = `intermediate balance`
* `end balance` + `total outgoing` = `intermediate balance`

#### Verify multi-payment proof  
Verifies the above proofs

## anatomy

* `src/gadget.hpp` exposes the gadget, which is an abstraction of related constraint
and witness behavior in a circuit. This gadget uses other gadgets, creates its own
constraints, and exposes an interface for building input maps.

* `src/snark.hpp` exposes a loose wrapper around the constraint system and
key generation used by `test.cpp` to construct proofs and verify them as necessary.

# License
Copyright (C) 2017 The Quorum Zero Knowledge Proof Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
