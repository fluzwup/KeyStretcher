#include <cstdlib>
#include <cstdio>
#include <string>
#include <vector>
#include <openssl/sha.h>
using namespace std;

#include "CryptKeeperPW.h"

// Test key stretcher against a set of PBKDF2 test cases
int main(int argc, char **argv)
{
	string filename = argv[1];
	string password = argv[2];
	
	CryptKeeperPW cc(password.c_str());

	// if the file ends in .enc, assume it's encrypted, and try to decrypt it
	if(filename.substr(filename.length() - 4, 4) == ".enc")
	{
		unsigned char buffer[4096];
		FILE *fp = fopen(filename.substr(0, filename.length() - 4).c_str(), "w");
		cc.Open(filename.c_str(), "r");
		int size = 4096;
		while(size == 4096)
		{
			size = cc.Read(buffer, 4096);
			fwrite((void *)buffer, 1, size, fp);
		}
		cc.Close();
		fclose(fp);
	}
	else
	{
		unsigned char buffer[4096];
		FILE *fp = fopen(filename.c_str(), "r");
		cc.Open((filename + ".enc").c_str(), "w");
		int size = 4096;
		while(size == 4096)
		{
			size = fread(buffer, 1, 4096, fp);
			cc.Write(buffer, size);
		}
		cc.Close();
		fclose(fp);
	}

	return 0;
}

