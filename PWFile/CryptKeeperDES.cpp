#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <memory.h>
#include <unistd.h>
#include <assert.h>

#include <vector>
using namespace std;

#include "CryptKeeperDES.h"
#include "DES.h"
#include "misc.h"

// accepts the file encryption key in the clear; it's the caller's responsibility to 
//  handle providing the key from secure storage
CryptKeeperDES::CryptKeeperDES(const char *enckey) : CryptKeeper(enckey)
{
	// for DES
	blockSize = 8;
	headerSize = 64;
	fileVersion = "1.0";
}

CryptKeeperDES::~CryptKeeperDES()
{
}

void CryptKeeperDES::EncryptBlock(vector<unsigned char> &data, int offset, int counter)
{
	assert(offset + blockSize <= data.size());

	// add block counter to nonce
	static vector<unsigned char> modifiedNonce;
	ModifyNonce(counter, modifiedNonce);

	// XOR data with nonce
	for(int i = 0; i < blockSize; ++i)
	{
		data[offset + i] = data[offset + i] ^ modifiedNonce[i];
	}

	// encrypt data
	unsigned char output[blockSize];
	encryptECB(&key[0], key.size(), &data[offset], blockSize, output);
	memcpy(&data[offset], output, blockSize);

	return;
}

void CryptKeeperDES::DecryptBlock(vector<unsigned char> &data, int offset, int counter)
{
	assert(offset + blockSize <= data.size());

	// add block counter to nonce
	static vector<unsigned char> modifiedNonce;
	ModifyNonce(counter, modifiedNonce);
	
	// decrypt data
	unsigned char output[blockSize];
	decryptECB(&key[0], key.size(), &data[offset], blockSize, output);
	memcpy(&data[offset], output, blockSize);

	// XOR with nonce
	for(int i = 0; i < blockSize; ++i)
	{
		data[offset + i] = data[offset + i] ^ modifiedNonce[i];
	}

	return;
}

string CryptKeeperDES::GetKCV()
{
	unsigned char zeros[64] = {0};
	unsigned char output[64] = {0};

	encryptECB(&key[0], key.size(), zeros, blockSize, (unsigned char *)output);

	char kcv[16];
	sprintf(kcv, "%06x", (int)output[0] << 16 | (int)output[1] << 8 | (int)output[2]);

	return string(kcv);
}

