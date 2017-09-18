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


int verifyProof(r1cs_ppzksnark_verification_key<default_r1cs_ppzksnark_pp> verificationKey_in, string proofFileName)
{
  const int unsigned _noPayments = 2;
  int unsigned _counter;
  boost::optional<libsnark::r1cs_ppzksnark_proof<libff::alt_bn128_pp>> proof_in;
  
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
  bit_vector h_startBalance_bv;
  bit_vector h_endBalance_bv;
  bit_vector h_incoming_bv[_noPayments];
  bit_vector h_outgoing_bv[_noPayments];
  vector<vector<unsigned long int>> values = fillValuesFromfile("publicInputParameters_multi");
  h_startBalance_bv = int_list_to_bits_local(values[0], 8);
  h_endBalance_bv = int_list_to_bits_local(values[1], 8);
  
  for (_counter = 0; _counter < noPayments; _counter++)
  {
    h_incoming_bv[_counter] = int_list_to_bits_local(values[_counter+2], 8);
    h_outgoing_bv[_counter] = int_list_to_bits_local(values[_counter+2+_noPayments], 8);
  }

  cout << "proof read ... starting verification" << endl;
  // Verify the proof
  bool isVerified = verify_payment_multi_proof(verificationKey_in, *proof_in, h_startBalance_bv, h_endBalance_bv, h_incoming_bv, h_outgoing_bv);

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
  ifstream fileIn("verificationKey_multi");
  stringstream verificationKeyFromFile;
  if (fileIn) {
     verificationKeyFromFile << fileIn.rdbuf();
     fileIn.close();
  }
  verificationKeyFromFile >> verificationKey_in;

  return verifyProof(verificationKey_in, "proof1");
}


