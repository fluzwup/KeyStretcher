#ifndef CryptKeeper_h_included
#define CryptKeeper_h_included

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <memory.h>
#include <unistd.h>
#include <vector>
#include <string>
using namespace std;

/* Example of a file header:

0000000: 4372 7970 744b 6565 7065 7220 312e 3020  CryptKeeper 1.0 
0000010: 3230 3031 3820 3334 6532 6637 2036 3244  20018 34e2f7 62D
0000020: 3837 3132 3646 3431 3139 4435 4300 0000  87126F4119D5C...
0000030: 0000 0000 0000 0000 0000 0000 0000 0000  ................

*/

class CryptKeeper
{
protected:
	// 64 bytes is plenty for an 8 byte nonce, but we might need to bump it up 
	//  if we go to a 16 byte nonce.  
	int headerSize;
	// 8 byte block size for triple DES
	size_t blockSize;
	string fileVersion;

	FILE *fp;
	vector<unsigned char> blockBuffer;
	vector<unsigned char> nonce;
	vector<unsigned char> key;

	bool readOnly;
	int fileSize;
	int fileOffset;

	// we want these virtual so that derived classes will call the right encryption function
	virtual void DecryptBlock(vector<unsigned char> &data, int offset, int counter) = 0;
	virtual void EncryptBlock(vector<unsigned char> &data, int offset, int counter) = 0;
	// this will grab the first 6 hex digits resulting from encrypting a block of 0s (no nonce or counter)
	virtual string GetKCV() = 0;

	void InitFileHeader();
	bool ReadFileHeader();
	void ModifyNonce(size_t counter, vector<unsigned char> &modifiedNonce);

public:
	CryptKeeper(const char *key);
	~CryptKeeper();

	size_t Read(void *buffer, size_t count);
	size_t Write(void *buffer, size_t count);
	bool Open(const char *filename, const char *mode);
	void Close();
	void Seek(size_t offset, int origin);
	size_t Tell();
};

#endif
