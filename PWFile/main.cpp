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
	const char *filename = "test.enc";
	const char *password = "This is my password.  There are many like it, but this one is mine.";
	const char *data = "This is some data to put in the encrypted file.\n";
	
	CryptKeeperPW cc(password);

	cc.Open(filename, "w");
	for(int i = 0; i < 10; ++i)
		cc.Write((void *)data, strlen(data));
	cc.Close();

	cc.Open(filename, "a");
	for(int i = 0; i < 10; ++i)
		cc.Write((void *)data, strlen(data));
	cc.Close();

	unsigned char buffer[64];
	FILE *fp = fopen("test.txt", "w");
	cc.Open(filename, "r");
	while(cc.Read(buffer, 64) == 64)
		fwrite((void *)buffer, 64, 1, fp);
	cc.Close();
	fclose(fp);

	return 0;
}

