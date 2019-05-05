#ifndef CryptKeeperPW_h_included
#define CryptKeeperPW_h_included

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <memory.h>
#include <unistd.h>
#include <vector>
#include <string>
using namespace std;
#include "CryptKeeperDES.h"

class CryptKeeperPW : public CryptKeeperDES
{
protected:
	string password;
public:
	CryptKeeperPW(const char *key);
	~CryptKeeperPW();

	// nonce is created here, so here is where we generate the key
	bool Open(const char *filename, const char *mode);
};

#endif
