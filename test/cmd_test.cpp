#include "../libcryption/include/cryption/dog_cryption.h"

#include <iostream>
#include <print> 
#include <fstream>
#include <format>

int main()
{
	dog_cryption::CryptionConfig c("AES", 16, 32, true, "PKCS7", "PCBC", true, 16);

	return 0;
}

