/* 
 * This program takes a password and a salt, and uses a hash operation to 
 * generate a key of a given length from the input data.  The password will
 % be ASCII data, the salt will be hexidecimal data.  An optional parameter
 * will be the number of hash passes, which will default to 4096.
 */

#include <cstdlib>
#include <cstdio>
#include <string>
#include <vector>
#include <openssl/sha.h>
using namespace std;

vector<unsigned char> SHA1(vector<unsigned char> input)
{
	vector<unsigned char> output;
	output.resize(20);

	::SHA1(&input[0], input.size(), &output[0]);

	return output;
}

// HMAC_SHA1("", "") = fbdb1d1b18aa6c08324b7d64b71fb76370690e1d
vector<unsigned char> HMAC_SHA1(vector<unsigned char> key, vector<unsigned char> message)
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

vector<unsigned char> StretchKey(unsigned int length, unsigned int passes, string password, string salt)
{
	vector<unsigned char> key;

	// make sure salt is an even number of hex digits; if not, pad with a leading zero
	if(salt.length() % 2 == 1) salt = "0" + salt;

	// buffer to hold the hash input (and output), and the binary version of the password
	vector<unsigned char> input;
	vector<unsigned char> pwd;
	
	int blockIndex = 1;
	while(key.size() < length)
	{
		// fill up input buffer with password + salt + block index
		input.resize(0);

		// convert password into unsigned chars
		for(unsigned int i = 0; i < password.length(); ++i)
		{
			pwd.push_back((unsigned char)password[i]);
		}
	
		// put salt in hash input, converted to binary
		for(unsigned int i = 0; i < salt.length(); i += 2)
		{
			// convert each pair of hex digits to a byte
			input.push_back((unsigned char)std::stoi(salt.substr(i, 2), NULL, 16));
		}
		
		// add four bytes of block index, most significant bit first
		input.push_back((unsigned char)(blockIndex >> 24));
		input.push_back((unsigned char)(blockIndex >> 16 && 0xFF));
		input.push_back((unsigned char)(blockIndex >> 8 && 0xFF));
		input.push_back((unsigned char)(blockIndex && 0xFF));

		// now repeat hashing operation the desired number of times
		for(unsigned int j = passes; j > 0; --j)
		{
			input = HMAC_SHA1(pwd, input);
		}

		// concatenate output onto key until we have enough bytes
		key.insert(key.end(), input.begin(), input.end());

		// increment the block index for the next block
		++blockIndex;
	}

	// trim key to desired length
	key.resize(length);

	return key;
}

int main(int argc, char **argv)
{
	vector<unsigned char> key;

	// test vectors for BPDKF2 from IETF RFC 6070
	unsigned char target1[] = 
	{
		0x0c, 0x60, 0xc8, 0x0f, 0x96, 0x1f, 0x0e, 0x71, 0xf3, 0xa9, 
		0xb5, 0x24, 0xaf, 0x60, 0x12, 0x06, 0x2f, 0xe0, 0x37, 0xa6 
	};

	// salt is hex for "salt"
	key = StretchKey(20, 1, "password", "73616c74");

	for(unsigned int i = 0; i < key.size(); ++i)
	{
		if(key[i] != target1[i])
		{
			printf("Failure 1\n");
			break;
		}
	}
	
	unsigned char target2[] = 
	{
		0x3d, 0x2e, 0xec, 0x4f, 0xe4, 0x1c, 0x84, 0x9b, 0x80, 0xc8,
		0xd8, 0x36, 0x62, 0xc0, 0xe4, 0x4a, 0x8b, 0x29, 0x1a, 0x96, 
		0x4c, 0xf2, 0xf0, 0x70, 0x38
	};

	// salt is hex for "saltSALTsaltSALTsaltSALTsaltSALTsalt"
	key = StretchKey(25, 4096, "passwordPASSWORDpassword", 
			"73616c7453414c5473616c7453414c5473616c7453414c5473616c7453414c54");

	for(unsigned int i = 0; i < key.size(); ++i)
	{
		if(key[i] != target2[i])
		{
			printf("Failure 2\n");
			break;
		}
	}
	
	return 0;
}

