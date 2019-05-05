#include "misc.h"

// converts a two digit hexidecimal character string into the binary byte it represents
unsigned char ByteFromStr(const char *input)
{
	unsigned char value = 0;
	switch (input[0])
	{
		case '0': break;
		case '1': value += 0x10; break;
		case '2': value += 0x20; break;
		case '3': value += 0x30; break;
		case '4': value += 0x40; break;
		case '5': value += 0x50; break;
		case '6': value += 0x60; break;
		case '7': value += 0x70; break;
		case '8': value += 0x80; break;
		case '9': value += 0x90; break;
		case 'A':
		case 'a': value += 0xA0; break;
		case 'B':
		case 'b': value += 0xB0; break;
		case 'C':
		case 'c': value += 0xC0; break;
		case 'D':
		case 'd': value += 0xD0; break;
		case 'E':
		case 'e': value += 0xE0; break;
		case 'F':
		case 'f': value += 0xF0; break;
		default:
			return 0;
	}

	switch (input[1])
	{
		case '0': break;
		case '1': value += 0x1; break;
		case '2': value += 0x2; break;
		case '3': value += 0x3; break;
		case '4': value += 0x4; break;
		case '5': value += 0x5; break;
		case '6': value += 0x6; break;
		case '7': value += 0x7; break;
		case '8': value += 0x8; break;
		case '9': value += 0x9; break;
		case 'A':
		case 'a': value += 0xA; break;
		case 'B':
		case 'b': value += 0xB; break;
		case 'C':
		case 'c': value += 0xC; break;
		case 'D':
		case 'd': value += 0xD; break;
		case 'E':
		case 'e': value += 0xE; break;
		case 'F':
		case 'f': value += 0xF; break;
		default:
			return 0;
	}

	return value;
}

void Hex2Bin(const char *input, unsigned char* output, int &len)
{
	len = strlen(input);

	// must be an even number of characters
	if (len % 2)
		return;

	for (int i = 0; i < len; i += 2)
    	output[i / 2] = ByteFromStr(&input[i]);
	len /= 2;
}


void Bin2Hex(unsigned char* input, int len, string &output)
{
	output = "";
	for(int i = 0; i < len; ++i)
	{
		char buff[8] = {(char)0};
		sprintf(buff, "%02X", input[i]);
		output += buff;
	}
	return;
}

// generates hex data, length is hex digits
vector<unsigned char> GenerateRandom(unsigned int length)
{
	vector<unsigned char> random;
	random.resize(length);

	FILE *fd = fopen("/dev/urandom", "r");
	size_t bytesRead = fread(&random[0], 1, length, fd);
	fclose(fd);

	return random;
}

