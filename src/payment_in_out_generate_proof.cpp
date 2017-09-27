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

int genProof(r1cs_ppzksnark_proving_key<default_r1cs_ppzksnark_pp> provingKey_in, string startBalancePublic, string endBalancePublic, string incomingPublic, string outgoingPublic, string startBalancePrivate, string endBalancePrivate, string incomingPrivate, string outgoingPrivate)
{
  // Initialize bit_vectors for all of the variables involved.
  vector<bool> h_startBalance_bv(256);
  vector<bool> h_endBalance_bv(256);
  vector<bool> h_incoming_bv(256);
  vector<bool> h_outgoing_bv(256);
  vector<bool> r_startBalance_bv(256);
  vector<bool> r_endBalance_bv(256);
  vector<bool> r_incoming_bv(256);
  vector<bool> r_outgoing_bv(256);

  h_startBalance_bv = int_list_to_bits_local(fillValuesFromString(startBalancePublic), 8);
  h_endBalance_bv = int_list_to_bits_local(fillValuesFromString(endBalancePublic), 8);
  h_incoming_bv = int_list_to_bits_local(fillValuesFromString(incomingPublic), 8);
  h_outgoing_bv = int_list_to_bits_local(fillValuesFromString(outgoingPublic), 8);

  r_startBalance_bv = int_list_to_bits_local(fillValuesFromString(startBalancePrivate), 8);
  r_endBalance_bv = int_list_to_bits_local(fillValuesFromString(endBalancePrivate), 8);
  r_incoming_bv = int_list_to_bits_local(fillValuesFromString(incomingPrivate), 8);
  r_outgoing_bv = int_list_to_bits_local(fillValuesFromString(outgoingPrivate), 8);

  boost::optional<libsnark::r1cs_ppzksnark_proof<libff::alt_bn128_pp>> proof = generate_payment_in_out_proof<default_r1cs_ppzksnark_pp>(provingKey_in, h_startBalance_bv, h_endBalance_bv, h_incoming_bv, h_outgoing_bv, r_startBalance_bv, r_endBalance_bv, r_incoming_bv, r_outgoing_bv);

  if(proof == boost::none)
  {
    return 1;
  } else {
    stringstream proofStream;
    proofStream << proof;
    cout << proofStream.str();
    return 0;
  }
}

int getUserInput(r1cs_ppzksnark_proving_key<default_r1cs_ppzksnark_pp> provingKey_in)
{
  string inputTemp = "";
  int result=0;
  cout << "Press enter 'generate proof' to generate a proof or q to quit" << endl;
  getline(cin, inputTemp);
  cout << "Input from console: " << inputTemp << endl;
  if(inputTemp != "q")
  {
    if(inputTemp == "generate proof")
    {
      string startBalancePublic = "";
      string endBalancePublic = "";
      string incomingPublic = "";
      string outgoingPublic = "";
      string startBalancePrivate = "";
      string endBalancePrivate = "";
      string incomingPrivate = "";
      string outgoingPrivate = "";
      getline(cin, startBalancePublic);
      getline(cin, endBalancePublic);
      getline(cin, incomingPublic);
      getline(cin, outgoingPublic);
      getline(cin, startBalancePrivate);
      getline(cin, endBalancePrivate);
      getline(cin, incomingPrivate);
      getline(cin, outgoingPrivate);

      result = genProof(provingKey_in, startBalancePublic, endBalancePublic, incomingPublic, outgoingPublic, startBalancePrivate, endBalancePrivate, incomingPrivate, outgoingPrivate);
      if(result!=0)
      {
        cout << "There was an error generating the proof" << endl;
        return getUserInput(provingKey_in);
      }
      else
      {
        return getUserInput(provingKey_in);
      }
    } else {
      cout << "Unexpected input value" << endl;
      return getUserInput(provingKey_in);
    }
  }
  else
  {
    return 0;
  }
}


int main(int argc, char *argv[])
{
  string keyFileName = "provingKey_single";

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
 
  return getUserInput(provingKey_in);
}
