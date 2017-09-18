#include <fstream>
#include <sstream>
#include <vector>
#include <string>

std::vector<bool> int_list_to_bits_local(const vector<unsigned long> &l, const size_t wordsize)
{
    std::vector<bool> res(wordsize*l.size());
    for (size_t i = 0; i < l.size(); ++i)
    {
        for (size_t j = 0; j < wordsize; ++j)
        {
            res[i*wordsize + j] = (*(l.begin()+i) & (1ul<<(wordsize-1-j)));
        }
    }
    return res;
}

std::vector<std::vector<unsigned long>> fillValuesFromfile(string fileName ) {
{
    string line;

    std::vector<std::vector<long unsigned int>> outputValues;
    ifstream inputParameters(fileName);
    while(getline(inputParameters, line)){

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
