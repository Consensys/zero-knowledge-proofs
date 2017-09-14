#include <stdlib.h>
#include <iostream>
#include <boost/optional/optional_io.hpp>
#include <boost/optional.hpp>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>

#include "snark.hpp"
#include "utils.cpp"

using namespace libsnark;
using namespace std;

int genProof(r1cs_ppzksnark_proving_key<default_r1cs_ppzksnark_pp> provingKey_in, string proofFileName)
{
  // Initialize bit_vectors for all of the variables involved.
  vector<bool> h1_bv(256);
  vector<bool> h2_bv(256);
  vector<bool> h3_bv(256);
  vector<bool> h4_bv(256);
  vector<bool> h5_bv(256);
  vector<bool> r1_bv(256);
  vector<bool> r2_bv(256);
  vector<bool> r3_bv(256);
  vector<bool> r4_bv(256);
  vector<bool> r5_bv(256);

  vector<vector<unsigned long int>> publicValues = fillValuesFromfile("publicInputParameters");
  h1_bv = int_list_to_bits_local(publicValues[0], 8);
  h2_bv = int_list_to_bits_local(publicValues[1], 8);
  h3_bv = int_list_to_bits_local(publicValues[2], 8);
  h4_bv = int_list_to_bits_local(publicValues[3], 8);
  h5_bv = int_list_to_bits_local(publicValues[4], 8);

  vector<vector<unsigned long int>> privateValues = fillValuesFromfile("privateInputParameters");
  r1_bv = int_list_to_bits_local(privateValues[0], 8);
  r2_bv = int_list_to_bits_local(privateValues[1], 8);
  r3_bv = int_list_to_bits_local(privateValues[2], 8);
  r4_bv = int_list_to_bits_local(privateValues[3], 8);
  r5_bv = int_list_to_bits_local(privateValues[4], 8);

  boost::optional<libsnark::r1cs_ppzksnark_proof<libff::alt_bn128_pp>> proof = generate_proof<default_r1cs_ppzksnark_pp>(provingKey_in, h1_bv, h2_bv, h3_bv, h4_bv, h5_bv, r1_bv, r2_bv, r3_bv, r4_bv, r5_bv);

  if(proof == boost::none)
  {
    return 1;
  } else {
    stringstream proofStream;
    proofStream << proof;

    ofstream fileOut;
    fileOut.open(proofFileName);

    fileOut << proofStream.rdbuf();
    fileOut.close();
    return 0;
  }
}

int main(int argc, char *argv[])
{
  string keyFileName = "provingKey";

  // Initialize the curve parameters.
  default_r1cs_ppzksnark_pp::init_public_params();

  r1cs_ppzksnark_proving_key<default_r1cs_ppzksnark_pp> provingKey_in;

  ifstream fileIn(keyFileName);
  stringstream provingKeyFromFile;
  if (fileIn) {
     provingKeyFromFile << fileIn.rdbuf();
     fileIn.close();
  }
 
  provingKeyFromFile >> provingKey_in;
 
  return genProof(provingKey_in, "proof1");
}
