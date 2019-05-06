#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <memory.h>
#include <unistd.h>
#include <assert.h>
#include <openssl/sha.h>

#include <vector>
using namespace std;

#include "CryptKeeperPW.h"

// performs a SHA1 hash on a vector of unsigned chars, using OpenSSL SHA1 function
vector<unsigned char> CryptKeeperPW::SHA1(vector<unsigned char> input)
{
	vector<unsigned char> output;
	output.resize(20);

	::SHA1(&input[0], input.size(), &output[0]);

	return output;
}

// HMAC function using SHA1.  
// Test vector: HMAC_SHA1("", "") = fbdb1d1b18aa6c08324b7d64b71fb76370690e1d
vector<unsigned char> CryptKeeperPW::HMAC_SHA1(vector<unsigned char> key, vector<unsigned char> message)
{
	// trim keys longer than SHA1 block size (64 bytes) by hashing
	if(key.size() > 64) key = SHA1(key);
	
	// pad key up to SHA1 block size by adding zeros to the right
	key.resize(64, 0);
	
	// create inner and outer keys by XORing
	vector<unsigned char> outer;
	vector<unsigned char> inner;
	for(unsigned int i = 0; i < key.size(); ++i)
	{
		outer.push_back(0x5c ^ key[i]);
		inner.push_back(0x36 ^ key[i]);
	}

	// concatenate inner key with message and hash
	inner.insert(inner.end(), message.begin(), message.end());
	message = SHA1(inner);

	// concatenate outer key with previous step output and hash
	outer.insert(outer.end(), message.begin(), message.end());
	message = SHA1(outer);

	// result is the 20 byte HMAC
	return message;
}

// Key stretching function; takes a password and optional (but highly recommended) salt (128 bits 
// recommended by NIST), plus an iteration count (recommended 4096) and generates a key of the given
// length, which can then be used for a symmetric encryption algorithm such as 3DES or AES. 
vector<unsigned char> CryptKeeperPW::StretchKey(unsigned int length, unsigned int passes, string password, 
		vector<unsigned char> salt)
{
	// buffer to hold the hash input (and output), and the binary version of the password
	vector<unsigned char> input;
	vector<unsigned char> pwd;

	// vector to hold generated key
	vector<unsigned char> key;

	// convert password into unsigned chars
	for(unsigned int i = 0; i < password.length(); ++i)
		pwd.push_back((unsigned char)password[i]);
	
	int blockIndex = 1;
	while(key.size() < length)
	{
		// fill up input buffer with password + salt + block index
		input.resize(0);
	
		// put salt in hash input, converted to binary
		for(unsigned int i = 0; i < salt.size(); ++i)
			input.push_back(salt[i]);
		
		// add four bytes of block index, most significant bit first
		input.push_back((unsigned char)(blockIndex >> 24));
		input.push_back((unsigned char)(blockIndex >> 16 & 0xFF));
		input.push_back((unsigned char)(blockIndex >> 8 & 0xFF));
		input.push_back((unsigned char)(blockIndex & 0xFF));

		// zero out block accumulator
		vector<unsigned char> output;
		output.resize(20, 0);

		// now repeat hashing operation the desired number of times
		for(unsigned int i = passes; i > 0; --i)
		{
			// each pass will use the previous pass's output
			input = HMAC_SHA1(pwd, input);

			// XOR each step of the HMAC into output
			for(unsigned int j = 0; j < input.size(); ++j)
				output[j] ^= input[j];
		}

		// concatenate output onto key until we have enough bytes
		key.insert(key.end(), output.begin(), output.end());

		// increment the block index for the next block
		++blockIndex;
	}

	// trim key to desired length
	key.resize(length);

	return key;
}

// Store the password.  We can't create a key until we have a nonce to use as a 
// salt, so initialize CryptKeeperDES with a blank key.
CryptKeeperPW::CryptKeeperPW(const char *pw) : CryptKeeperDES("0000000000000000")
{
	password = pw;
}

CryptKeeperPW::~CryptKeeperPW()
{
}

bool CryptKeeperPW::Open(const char *filename, const char *mode)
{
	// go ahead and open the file with the base class
	// if the file exists, this will read the nonce, if it doesn't, it will create one
	if(!CryptKeeperDES::Open(filename, mode)) return false;

	// now the nonce is available; take that and the password and generate a triple-length
	//  DES key from it (24 bytes)
	// the one-block nonce for DES is only 64 bits, but it's truly random, so should be 
	//  pretty secure; certainly more entropy than most passwords
	key = StretchKey(24, 4096, password, nonce);

	return true;
}

