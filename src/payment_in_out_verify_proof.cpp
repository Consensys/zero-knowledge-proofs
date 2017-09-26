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

int verifyProof(r1cs_ppzksnark_verification_key<default_r1cs_ppzksnark_pp> verificationKey_in, string proofFileName, string publicInputs)
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
  std::vector<bool> h_startBalance_bv(256);
  std::vector<bool> h_endBalance_bv(256);
  std::vector<bool> h_incoming_bv(256);
  std::vector<bool> h_outgoing_bv(256);
  vector<vector<unsigned long int>> values = fillValuesFromfile(publicInputs);
  h_startBalance_bv = int_list_to_bits_local(values[0], 8);
  h_endBalance_bv = int_list_to_bits_local(values[1], 8);
  h_incoming_bv = int_list_to_bits_local(values[2], 8);
  h_outgoing_bv = int_list_to_bits_local(values[3], 8);

  cout << "proof read ... starting verification" << endl;
  // Verify the proof
  bool isVerified = verify_payment_in_out_proof(verificationKey_in, *proof_in, h_startBalance_bv, h_endBalance_bv, h_incoming_bv, h_outgoing_bv);

  if(isVerified){
    cout << "Proof was verified!!" << proofFileName << endl;
    return 0;
  } else {
    cout << "Proof was not verified!!" << proofFileName << endl;
    return 1;
  }
}

int main(int argc, char *argv[])
{
  // Initialize the curve parameters.
  default_r1cs_ppzksnark_pp::init_public_params();

  // Read verification key in from file
  r1cs_ppzksnark_verification_key<default_r1cs_ppzksnark_pp> verificationKey_in;
  ifstream fileIn("verificationKey_single");
  stringstream verificationKeyFromFile;
  if (fileIn) {
     verificationKeyFromFile << fileIn.rdbuf();
     fileIn.close();
  }
  verificationKeyFromFile >> verificationKey_in;

  string proofName = "proof_single_";
  string proofNameWithId = proofName + argv[1];
  string publicInputs = "publicInputParameters_single_";
  string publicInputsWithId = publicInputs + argv[1];
  return verifyProof(verificationKey_in, proofNameWithId, publicInputsWithId);
}


