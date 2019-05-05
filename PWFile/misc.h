#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <string>
#include <vector>
using namespace std;

void Hex2Bin(const char *input, unsigned char* output, int &len);
void Bin2Hex(unsigned char* input, int len, string &output);

vector<unsigned char> GenerateRandom(unsigned int length);

