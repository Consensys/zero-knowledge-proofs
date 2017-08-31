#include <stdlib.h>
#include <iostream>
#include <boost/optional/optional_io.hpp>
#include <fstream>

#include "snark.hpp"

using namespace libsnark;
using namespace std;

int main(int argc, char *argv[])
{
  // Initialize the curve parameters.
  default_r1cs_ppzksnark_pp::init_public_params();

  // Read verifier key in from file
  r1cs_ppzksnark_verification_key<default_r1cs_ppzksnark_pp> verifierKey_in;
  ifstream fileIn("verifierKey");
  stringstream verifierKeyFromFile;
  if (fileIn) {
     verifierKeyFromFile << fileIn.rdbuf();
     fileIn.close();
  }
  verifierKeyFromFile >> verifierKey_in;
  
  // Read proof in from file
  boost::optional<r1cs_ppzksnark_proof<ppzksnark_ppT>> proof_in;
  ifstream proofFileIn("proof");
  stringstream proofFromFile;
  if (proofFileIn) {
     proofFromFile << proofFileIn.rdbuf();
     proofFileIn.close();
  }
  proofFromFile >> proof_in;
  
  // Hashes to validate against
  std::vector<bool> h1_bv(256);
  std::vector<bool> h2_bv(256);
  std::vector<bool> h3_bv(256);
  h1_bv = int_list_to_bits({78, 152, 23, 135, 180, 61, 171, 123, 58, 147, 215, 200, 83, 7, 198, 244, 58, 26, 58, 88, 150, 57, 69, 185, 62, 165, 253, 53, 112, 69, 80, 23}, 8);
  h2_bv = int_list_to_bits({182, 169, 95, 91, 248, 154, 156, 163, 104, 18, 251, 174, 68, 251, 237, 249, 215, 166, 135, 222, 50, 133, 48, 197, 197, 205, 182, 20, 56, 166, 108, 66}, 8);
  h3_bv = int_list_to_bits({101, 119, 48, 144, 165, 169, 249, 100, 249, 74, 13, 126, 39, 34, 64, 47, 238, 173, 29, 72, 31, 203, 7, 100, 179, 20, 220, 66, 172, 97, 252, 223}, 8);
 
  // Verify the proof
  //bool isVerified = verify_proof(verifierKey_in, proof_in, h1_bv, h2_bv, h3_bv);
  
  //cout << "isVerified:" << isVerified << endl;
  
  return 0;
}

