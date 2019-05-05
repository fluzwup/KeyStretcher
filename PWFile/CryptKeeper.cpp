#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <memory.h>
#include <unistd.h>
#include <assert.h>

#include <vector>
using namespace std;

#include "CryptKeeper.h"
#include "misc.h"

// accepts the file encryption key in the clear; it's the caller's responsibility to 
//  handle providing the key from secure storage
CryptKeeper::CryptKeeper(const char *enckey)
{
	// convert hex key into binary
	int keylen = strlen(enckey) / 2;
	key.resize(keylen);
	Hex2Bin(enckey, &key[0], keylen);

	fileOffset = 0;
	readOnly = false;
	fileSize = 0;
	fp = NULL;

	// for DES
	blockSize = 8;
	headerSize = 64;
	fileVersion = "1.0";
}

CryptKeeper::~CryptKeeper()
{
}

void CryptKeeper::ModifyNonce(size_t counter, vector<unsigned char> &modifiedNonce)
{
	// It doesn't really matter how we combine the nonce and counter, as long as
	//  it's consistent, and the output is unique for each value of counter.
	modifiedNonce = nonce;

	unsigned char *counterBytes = (unsigned char *)&counter;
	for(int i = 0; i < sizeof(size_t); ++i)
		modifiedNonce[blockSize - 1 - i] = counterBytes[i];

	return;
}

/*
 * Read the blocks containing the target data from the file
 * Decrypt the data using the block offset
 * Copy the target data into the read buffer
 */
size_t CryptKeeper::Read(void *buffer, size_t count)
{
	assert(fileOffset >= 0);

	size_t start = fileOffset;
	size_t end = fileOffset + count;

	// truncate to end of file
	if(end >= fileSize - 1) end = fileSize - 1;

	if(start >= end) return 0;

	size_t blockStart = start / blockSize;
	size_t blockEnd = (end + blockSize - 1) / blockSize;
	size_t blockCount = blockEnd - blockStart;
	size_t bytes = blockCount * blockSize;

	// resize buffer if needed; make it a bit bigger to allow partial blocks on each end
	if(blockBuffer.size() < (blockCount + 2) * blockSize)
	{
		blockBuffer.resize((blockCount + 2) * blockSize, 0);
	}

	fseek(fp, blockStart * blockSize + headerSize, SEEK_SET);
	fread((void *)&blockBuffer[0], 1, bytes, fp);

	// decrypt blockBuffer
	for(int i = 0; i < blockCount; ++i)
	{
		DecryptBlock(blockBuffer, i * blockSize, blockStart + i);
	}
	
	// copy relevant data from blockBuffer
	memcpy(buffer, (void *)&blockBuffer[start % blockSize], end - start);

	// upate file offset
	fileOffset = end;

	assert(fileOffset >= 0);
	return end - start;
}

/*
 * Read any existing data in the target blocks from the file and decrypt
 * Write the new data into the block buffer at the appropriate spot
 * Encrypt the blocks and write them back out.
 */
size_t CryptKeeper::Write(void *buffer, size_t count)
{
	assert(fileOffset >= 0);

	size_t start = fileOffset;
	size_t end = start + count;
	size_t blockStart = start / blockSize;
	size_t blockEnd = (end + blockSize - 1) / blockSize;
	size_t blockCount = blockEnd - blockStart;
	size_t bytes = 0;

	// resize buffer if needed; make it a bit bigger to allow partial blocks on each end
	if(blockBuffer.size() < (blockCount + 2) * blockSize)
	{
		blockBuffer.resize((blockCount + 2) * blockSize, 0);
	}
	
	// zero out buffer
	memset(&blockBuffer[0], 0, blockBuffer.size());
	
	// if we're writing into existing data blocks, fill the buffer with decrypted data to overlay onto
	if(blockStart * blockSize < fileSize)
	{
		// see how many bytes to read
		size_t readEnd = (end + blockSize - 1) / blockSize;
		
		// read existing data into blockBuffer and decrypt
		fseek(fp, blockStart * blockSize + headerSize, SEEK_SET);
		bytes = fread((void *)&blockBuffer[0], 1, blockSize * blockCount, fp);
	
		// decrypt data read into blockBuffer (but not any pad at the end)
		for(int i = 0; i < bytes / blockSize; ++i)
		{
			DecryptBlock(blockBuffer, i * blockSize, blockStart + i);
		}
	}
	
	// copy new data into blockBuffer
	memcpy((void *)&blockBuffer[start % blockSize], buffer, end - start);
	
	// encrypt blockBuffer here
	for(int i = 0; i < blockCount; ++i)
	{
		EncryptBlock(blockBuffer, i * blockSize, blockStart + i);
	}

	// write to file
	fseek(fp, blockStart * blockSize + headerSize, SEEK_SET);
	fwrite((void *)&blockBuffer[0], 1, blockCount * blockSize, fp);

	// update file offset
	fileOffset += count;

	// update the file size if we wrote past the end
	if(fileOffset > fileSize - 1) fileSize = fileOffset + 1;

	assert(fileOffset >= 0);

	return count;
}
/* Set the file size to zero, create a random nonce. */
void CryptKeeper::InitFileHeader()
{
	// set size to zero
	fileSize = 0;

	// create the nonce  
	nonce = GenerateRandom(blockSize);
}

// CryptKeeper 1.0 length KCVKCV noncenoncenoncen\n\0...
bool CryptKeeper::ReadFileHeader()
{
	fseek(fp, 0, SEEK_SET);

	char buffer[headerSize + 1];
	memset(buffer, 0, headerSize + 1);

	int bytes = fread(buffer, 1, headerSize, fp);

	// if there is no header, create one
	if(bytes != headerSize)
	{
		InitFileHeader();
		return true;
	}

	// validate header
	string name = strtok(buffer, " ");
	string version = strtok(NULL, " ");
	fileSize = atoi(strtok(NULL, " "));
	string kcv;
	if(version == "1.0")
	{
		kcv = strtok(NULL, "\n");
	}
	else
	{
		kcv = strtok(NULL, " ");
		string hexNonce = strtok(NULL, "\n");

		int len = blockSize;
		nonce.resize(blockSize);
		Hex2Bin(hexNonce.c_str(), &nonce[0], len);
	}

	if(name != "CryptKeeper") return false;
	if(version != fileVersion) return false;
	if(kcv != GetKCV()) return false;

	return false;
}

/* Open the file, using a subset of fopen modes.  We'll really open the file in
 * read-only or w+ mode, since any writes need to be able to update the file size
 * in the header.
 */
bool CryptKeeper::Open(const char *filename, const char *mode)
{
	fp = NULL;

	readOnly = false;

	// any write or append opens need to be able to seek to the beginning and
	// update the file header, so open in "w+" or "r+" mode
	// read-only "r" open will open the file in "r" mode
	if(strcmp(mode, "r") == 0)
	{
		fp = fopen(filename, "r");
		ReadFileHeader();
		fileOffset = 0;
		readOnly = true;
	}
	else if(strcmp(mode, "w") == 0)
	{
		fp = fopen(filename, "w+");
		InitFileHeader();
		fileOffset = 0;
	}	
	else if(strcmp(mode, "a") == 0)
	{
		fp = fopen(filename, "r+");	

		// fopen "r+" will fail if the file does not exist, but fopen "a" should not;
		//  create the file with fopen w+ if it doesn't exist
		if(fp == NULL)
		{
			fp = fopen(filename, "w+");
			InitFileHeader();
			fileOffset = 0;
		}
		else
		{
			ReadFileHeader();
			fileOffset = fileSize - 1;
		}
	}
	else if(strcmp(mode, "r+") == 0)
	{
		fp = fopen(filename, "r+");
		ReadFileHeader();
		fileOffset = 0;
	}
	else if(strcmp(mode, "w+") == 0)
	{
		fp = fopen(filename, "w+");
		InitFileHeader();
		fileOffset = 0;
	}
	else if(strcmp(mode, "a+") == 0)
	{
		fp = fopen(filename, "r+");
		ReadFileHeader();
		fileOffset = fileSize;
	}

	return (fp != NULL);
}

// CryptKeeper 1.0 length KCVKCV noncenoncenoncen\n\0...
void CryptKeeper::Close()
{
	if(!readOnly)
	{
		// update header
		string hexNonce;
		Bin2Hex(&nonce[0], blockSize, hexNonce);

		fseek(fp, 0, SEEK_SET);

		fprintf(fp, "Cryptkeeper %s %i %s %s\n", fileVersion.c_str(),
			fileSize, GetKCV().c_str(), hexNonce.c_str());
	}
	
	fclose(fp);
}

// set file offset to appropriate spot
void CryptKeeper::Seek(size_t offset, int origin)
{
	if(origin == SEEK_SET)
		fileOffset = offset;
	else if(origin == SEEK_END)
		fileOffset = fileSize + offset;
	else if(origin == SEEK_CUR)
		fileOffset += offset;
	else
		return;

	// offset should not go negative
	assert(fileOffset >= 0);
	// read-only should not seek past end of file
	assert(!readOnly || fileOffset <= fileSize);

	if(fileOffset < 0) fileOffset = 0;
	if(readOnly && fileOffset > fileSize) fileOffset = fileSize;
}

// return current spot in file
size_t CryptKeeper::Tell()
{
	return fileOffset;
}

