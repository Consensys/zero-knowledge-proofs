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

bit_vector int_list_to_bits_local(const std::vector<unsigned long> &l, const size_t wordsize)
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
    string line1;

    ifstream inputParameters("inputParameters");
    getline(inputParameters, line1);

    cout << line1 << endl;
    inputParameters.close();

    stringstream iss( line1 );

    int number;
    vector<long unsigned int> myNumbers;
    while ( iss >> number )
      myNumbers.push_back( number );
    
    cout << myNumbers[0] << endl;
    // These are working test vectors.
    h1_bv = int_list_to_bits({78, 152, 23, 135, 180, 61, 171, 123, 58, 147, 215, 200, 83, 7, 198, 244, 58, 26, 58, 88, 150, 57, 69, 185, 62, 165, 253, 53, 112, 69, 80, 23}, 8);
    h2_bv = int_list_to_bits({182, 169, 95, 91, 248, 154, 156, 163, 104, 18, 251, 174, 68, 251, 237, 249, 215, 166, 135, 222, 50, 133, 48, 197, 197, 205, 182, 20, 56, 166, 108, 66}, 8);
    h3_bv = int_list_to_bits({101, 119, 48, 144, 165, 169, 249, 100, 249, 74, 13, 126, 39, 34, 64, 47, 238, 173, 29, 72, 31, 203, 7, 100, 179, 20, 220, 66, 172, 97, 252, 223}, 8);
    // r = (num, salt)
    // Constraint is num3 = num1 + num2
    r1_bv = int_list_to_bits_local(myNumbers, 8);
    r2_bv = int_list_to_bits({0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 6, 178, 210, 43, 243, 10, 217, 251, 246, 248, 0, 21, 86, 194, 100, 94}, 8);
    r3_bv = int_list_to_bits({0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5, 203, 6, 191, 16, 141, 210, 73, 136, 65, 136, 152, 60, 117, 24, 101, 18}, 8);
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
