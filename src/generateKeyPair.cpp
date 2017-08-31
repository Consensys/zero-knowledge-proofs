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
  auto keypair = generate_keypair<default_r1cs_ppzksnark_pp>();

  stringstream verifierKey;
  verifierKey << keypair.vk;

  ofstream fileOut;
  fileOut.open("verifierKey");

  fileOut << verifierKey.rdbuf();
  fileOut.close();
 
  stringstream proverKey;
  proverKey << keypair.pk;

  fileOut.open("proverKey");

  fileOut << proverKey.rdbuf();
  fileOut.close();

  return 0;
}

