#include <stdlib.h>
#include <iostream>
#include <boost/optional/optional_io.hpp>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>

#include "snark.hpp"
#include "utils.cpp"

using namespace libsnark;
using namespace std;

int verifyProof(r1cs_ppzksnark_verification_key<default_r1cs_ppzksnark_pp> verificationKey_in, string proofFileName, string inputsFileName)
{
  // Read proof in from file
  //libsnark::r1cs_ppzksnark_proof<libff::alt_bn128_pp> proof_in;
  boost::optional<libsnark::r1cs_ppzksnark_proof<libff::alt_bn128_pp>> proof_in;
  //r1cs_ppzksnark_proof<default_r1cs_ppzksnark_pp> proof_in;
  
  cout << proofFileName << endl;
  ifstream proofFileIn(proofFileName);
  stringstream proofFromFile;
  if (proofFileIn) {
     proofFromFile << proofFileIn.rdbuf();
     proofFileIn.close();
  } else {
    cout << "Failed to read from proof file" << endl;
    return 1;
  }

  proofFromFile >> proof_in;
  
  // Hashes to validate against
  std::vector<bool> h1_bv(256);
  std::vector<bool> h2_bv(256);
  std::vector<bool> h3_bv(256);
  vector<vector<unsigned long int>> values = fillValuesFromfile(inputsFileName);
  h1_bv = int_list_to_bits_local(values[0], 8);
  h2_bv = int_list_to_bits_local(values[1], 8);
  h3_bv = int_list_to_bits_local(values[2], 8);

  cout << "proof read ... starting verification" << endl;
  // Verify the proof
  bool isVerified = verify_proof(verificationKey_in, *proof_in, h1_bv, h2_bv, h3_bv);

  if(isVerified){
    cout << "Proof was verified!!" << endl;
    return 0;
  } else {
    cout << "Proof was not verified!!" << endl;
    return 1;
  }

}


int main(int argc, char *argv[])
{
  // Initialize the curve parameters.
  default_r1cs_ppzksnark_pp::init_public_params();

  // Read verification key in from file
  r1cs_ppzksnark_verification_key<default_r1cs_ppzksnark_pp> verificationKey_in;
  ifstream fileIn("verificationKey");
  stringstream verificationKeyFromFile;
  if (fileIn) {
     verificationKeyFromFile << fileIn.rdbuf();
     fileIn.close();
  }
  verificationKeyFromFile >> verificationKey_in;

  int proof1 = verifyProof(verificationKey_in, "proof1", "proof1Inputs");
  int proof2 = verifyProof(verificationKey_in, "proof2", "proof2Inputs");
  return proof1 | proof2;
}


