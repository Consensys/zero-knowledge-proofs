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
 
  // Initialize bit_vectors for all of the variables involved.
  vector<bool> h1_bv(256);
  vector<bool> h2_bv(256);
  vector<bool> h3_bv(256);
  vector<bool> r1_bv(256);
  vector<bool> r2_bv(256);
  vector<bool> r3_bv(256);

  {
    vector<vector<unsigned long int>> values = fillValuesFromfile(argv[2]);
    h1_bv = int_list_to_bits_local(values[0], 8);
    h2_bv = int_list_to_bits_local(values[1], 8);
    h3_bv = int_list_to_bits_local(values[2], 8);
    // r = (num, salt)
    // Constraint is num3 = num1 + num2
    r1_bv = int_list_to_bits_local(values[3], 8);
    r2_bv = int_list_to_bits_local(values[4], 8);
    r3_bv = int_list_to_bits_local(values[5], 8);
  }

  boost::optional<libsnark::r1cs_ppzksnark_proof<libff::alt_bn128_pp>> proof = generate_proof<default_r1cs_ppzksnark_pp>(provingKey_in, h1_bv, h2_bv, h3_bv, r1_bv, r2_bv, r3_bv);

  stringstream proofStream;
  proofStream << proof;

  ofstream fileOut;
  fileOut.open(argv[1]);

  fileOut << proofStream.rdbuf();
  fileOut.close();
  return 0;
}
