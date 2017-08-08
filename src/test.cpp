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
        // These are working test vectors.
        h1_bv = int_list_to_bits({169, 231, 96, 189, 221, 234, 240, 85, 213, 187, 236, 114, 100, 185, 130, 86, 231, 29, 123, 196, 57, 225, 159, 216, 34, 190, 123, 97, 14, 57, 180, 120}, 8);
        h2_bv = int_list_to_bits({253, 199, 66, 55, 24, 155, 80, 121, 138, 60, 36, 201, 186, 221, 164, 65, 194, 53, 192, 159, 252, 7, 194, 24, 200, 217, 57, 55, 45, 204, 71, 9}, 8);
        h3_bv = int_list_to_bits({169, 231, 96, 189, 221, 234, 240, 85, 213, 187, 236, 114, 100, 185, 130, 86, 231, 29, 123, 196, 57, 225, 159, 216, 34, 190, 123, 97, 14, 57, 180, 120}, 8);
        r1_bv = int_list_to_bits({180, 34, 250, 166, 200, 177, 240, 137, 204, 219, 178, 17, 34, 14, 66, 65, 203, 6, 191, 16, 141, 210, 73, 136, 65, 136, 152, 60, 117, 24, 101, 18}, 8);
        r2_bv = int_list_to_bits({206, 64, 25, 10, 245, 205, 246, 107, 191, 157, 114, 181, 63, 40, 95, 134, 6, 178, 210, 43, 243, 10, 217, 251, 246, 248, 0, 21, 86, 194, 100, 94}, 8);
        r3_bv = int_list_to_bits({180, 34, 250, 166, 200, 177, 240, 137, 204, 219, 178, 17, 34, 14, 66, 65, 203, 6, 191, 16, 141, 210, 73, 136, 65, 136, 152, 60, 117, 24, 101, 18}, 8);
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
            assert(verify_proof(keypair.vk, *proof, h1_bv, h2_bv, h3_bv));
            return true;
        }
    }
}
