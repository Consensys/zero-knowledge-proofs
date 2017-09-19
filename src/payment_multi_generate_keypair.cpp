#include <stdlib.h>
#include <iostream>
#include <boost/optional/optional_io.hpp>
#include <fstream>

#include "snark.hpp"

using namespace libsnark;
using namespace libff;
using namespace std;

int main(int argc, char *argv[])
{
  // Initialize the curve parameters.
default_r1cs_ppzksnark_pp::init_public_params();
  // Generate the verifying/proving keys. (This is trusted setup!)
  auto keypair = generate_keypair_multi<default_r1cs_ppzksnark_pp>();

  stringstream verificationKey;
  verificationKey << keypair.vk;

  ofstream fileOut;
  fileOut.open("verificationKey_multi");

  fileOut << verificationKey.rdbuf();
  fileOut.close();
 
  stringstream provingKey;
  provingKey << keypair.pk;

  fileOut.open("provingKey_multi");

  fileOut << provingKey.rdbuf();
  fileOut.close();

  return 0;
}

