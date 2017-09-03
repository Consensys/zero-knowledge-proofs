#include <stdlib.h>
#include <iostream>
#include <boost/optional/optional_io.hpp>
#include <boost/optional.hpp>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>

#include "snark.hpp"
#include "test.h"

using namespace libsnark;
using namespace std;

bit_vector int_list_to_bits_local(const vector<unsigned long> &l, const size_t wordsize)
{
    bit_vector res(wordsize*l.size());
    for (size_t i = 0; i < l.size(); ++i)
    {
        for (size_t j = 0; j < wordsize; ++j)
        {
            res[i*wordsize + j] = (*(l.begin()+i) & (1ul<<(wordsize-1-j)));
        }
    }
    return res;
}

vector<vector<unsigned long>> fillValuesFromfile(string fileName ) {
{
    string line;

    vector<vector<long unsigned int>> outputValues;
    ifstream inputParameters(fileName);
    while(getline(inputParameters, line)){

      cout << line << endl;

      stringstream iss( line );

      int number; 
      vector<long unsigned int> outputValue;
      while ( iss >> number )
        outputValue.push_back( number );

      outputValues.push_back(outputValue);
    }
    return outputValues;
  }
}

int main(int argc, char *argv[])
{
  std::string keyFileName = "provingKey";

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
  std::vector<bool> h1_bv(256);
  std::vector<bool> h2_bv(256);
  std::vector<bool> h3_bv(256);
  std::vector<bool> r1_bv(256);
  std::vector<bool> r2_bv(256);
  std::vector<bool> r3_bv(256);

  {
    std::vector<std::vector<unsigned long int>> values = fillValuesFromfile("inputParameters");
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
  fileOut.open("proof");

  fileOut << proofStream.rdbuf();
  fileOut.close();
/*
  // Read verifier key in from file
  r1cs_ppzksnark_verification_key<default_r1cs_ppzksnark_pp> verifierKey_in;
  ifstream verifierFileIn("verifierKey");
  stringstream verifierKeyFromFile;
  if (verifierFileIn) {
     verifierKeyFromFile << verifierFileIn.rdbuf();
     verifierFileIn.close();
  }
  verifierKeyFromFile >> verifierKey_in;

  // Verify the proof
  bool isVerified = verify_proof(verifierKey_in, *proof, h1_bv, h2_bv, h3_bv);

  cout << "isVerified: " << isVerified << endl;
*/
  return 0;
}
