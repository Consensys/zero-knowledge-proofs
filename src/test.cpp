#include <stdlib.h>
#include <iostream>
#include <boost/optional/optional_io.hpp>

#include "snark.hpp"
#include "test.h"

using namespace libsnark;
using namespace std;

int main()
{
    // Initialize the curve parameters.
    default_r1cs_ppzksnark_pp::init_public_params();
    // Generate the verifying/proving keys. (This is trusted setup!)
    auto keypair = generate_keypair<default_r1cs_ppzksnark_pp>();

    cout << "-----------Verification key start-----------" << endl;
    cout << keypair.vk << endl;
    cout << "-----------Verification key end-------------" << endl;

    // Run test vectors.
    assert(run_test(keypair, false, false, false));
    //assert(!run_test(keypair, true, false, false));
    //assert(!run_test(keypair, false, true, false));
    //assert(!run_test(keypair, false, false, true));
}

bool run_test(r1cs_ppzksnark_keypair<default_r1cs_ppzksnark_pp>& keypair,
              // These are just for changing behavior
              // for testing purposes:
              bool use_and_instead_of_xor,
              bool swap_r1_r2,
              bool goofy_verification_inputs
    ) {

    // Initialize bit_vectors for all of the variables involved.
    std::vector<bool> h1_bv(256);
    std::vector<bool> h2_bv(256);
    std::vector<bool> h3_bv(256);
    std::vector<bool> r1_bv(256);
    std::vector<bool> r2_bv(256);
    std::vector<bool> r3_bv(256);

    {
        // These are working test vectors. These vectors are 256 bits, where they are broken into
        // 32 x 8bit words. Each word is therefore respresented by an int ranging from 0 to 255.
        r1_bv = int_list_to_bits({0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 128, 202, 5, 190, 15, 140, 211, 75, 131, 62, 136, 12, 6, 17, 4, 10, 18}, 8);
        r2_bv = int_list_to_bits({0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 128, 6, 171, 218, 43, 241, 15, 217, 251, 205, 248, 0, 21, 86, 194, 100, 94}, 8);
        r3_bv = int_list_to_bits({0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 200, 1, 111, 160, 141, 10, 73, 36, 65, 16, 15, 6, 17, 2, 11, 8}, 8);
        // These are the sha256 hashes of r1, r2 and r3, also encoded in 32 x 8bit words. 
        h1_bv = int_list_to_bits({ 160, 95, 223, 120, 235, 188, 124, 111, 249, 78, 150, 221, 176, 18, 80, 39, 110, 174, 229, 79, 245, 125, 150, 234, 56, 106, 169, 104, 162, 33, 24, 153 }, 8);
        h2_bv = int_list_to_bits({ 161, 80, 151, 234, 94, 112, 26, 194, 211, 119, 229, 43, 151, 101, 159, 178, 59, 159, 64, 75, 24, 52, 126, 186, 38, 96, 213, 158, 190, 38, 112, 98 }, 8);
        h3_bv = int_list_to_bits({ 207, 66, 31, 102, 153, 84, 53, 105, 85, 76, 157, 56, 40, 35, 153, 34, 113, 21, 99, 253, 21, 174, 153, 8, 43, 60, 78, 229, 87, 25, 177, 165 }, 8);
    }

    if (swap_r1_r2) {
        // This swaps r1 and r2 which should test if the hashing
        // constraints work properly.
        auto tmp = r2_bv;
        r2_bv = r1_bv;
        r1_bv = tmp;
    }

    cout << "Trying to generate proof..." << endl;
    auto proof = generate_proof<default_r1cs_ppzksnark_pp>(keypair.pk, h1_bv, h2_bv, h3_bv, r1_bv, r2_bv, r3_bv);
    cout << "Proof generated!" << endl;
    cout << "Proof: " <<  proof << endl;

    if (!proof) {
        return false;
    } else {
        if (goofy_verification_inputs) {
            // [test] if we generated the proof but try to validate
            // with bogus inputs it shouldn't let us
            return verify_proof(keypair.vk, *proof, h2_bv, h1_bv, h3_bv);
        } else {
            // verification should not fail if the proof is generated!
            bool result = verify_proof(keypair.vk, *proof, h1_bv, h2_bv, h3_bv);
            if(result){
              cout << "Proof was verified!" << endl;
            } else {
              cout << "Proof could not be verified!" << endl;
            }
            assert(result);
            return result;
        }
    }
}
