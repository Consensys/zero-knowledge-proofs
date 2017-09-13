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
#include "test.h"

using namespace libsnark;
using namespace std;

int genProof(r1cs_ppzksnark_proving_key<default_r1cs_ppzksnark_pp> provingKey_in, string proofFileName, int r1_index, int r2_index, int r3_index)
{
  // Initialize bit_vectors for all of the variables involved.
  vector<bool> h1_bv(256);
  vector<bool> h2_bv(256);
  vector<bool> h3_bv(256);
  vector<bool> r1_bv(256);
  vector<bool> r2_bv(256);
  vector<bool> r3_bv(256);

  vector<vector<unsigned long int>> publicValues = fillValuesFromfile("publicInputParameters");
  h1_bv = int_list_to_bits_local(publicValues[r1_index], 8);
  h2_bv = int_list_to_bits_local(publicValues[r2_index], 8);
  h3_bv = int_list_to_bits_local(publicValues[r3_index], 8);

  vector<vector<unsigned long int>> privateValues = fillValuesFromfile("privateInputParameters");
  r1_bv = int_list_to_bits_local(privateValues[r1_index], 8);
  r2_bv = int_list_to_bits_local(privateValues[r2_index], 8);
  r3_bv = int_list_to_bits_local(privateValues[r3_index], 8);

  boost::optional<libsnark::r1cs_ppzksnark_proof<libff::alt_bn128_pp>> proof = generate_proof<default_r1cs_ppzksnark_pp>(provingKey_in, h1_bv, h2_bv, h3_bv, r1_bv, r2_bv, r3_bv);

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
 
  int proof1 = 1;
  int proof2 = 1;


  proof1 = genProof(provingKey_in, "proof1", 0, 3, 2);
  if(proof1 == 0){
    proof2 = genProof(provingKey_in, "proof2", 1, 4, 2);
  }

  return proof1 | proof2;
}
