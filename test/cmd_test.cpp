#include <chrono>

#include <format>
#include <fstream>
#include <iostream>
#include <print> 

#include <cmath>

#include "crypto/symmetric/algorithm/Rijndael.h"
#include "crypto/symmetric/base.h"
#include "crypto/symmetric/mode/CBC.h"
#include "crypto/symmetric/padding/PKCS7.h"

//#include <crtdbg.h>
//#define _CRTDBG_MAP_ALLOC
//#define _DEBUG
//_CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF);

int main()
{
	
	using namespace dog_torch::crypto::symmetric;
	using namespace dog_torch::crypto::symmetric::algorithm;
	using namespace dog_torch::crypto::symmetric::mode;
	using namespace dog_torch::crypto::symmetric::padding;

	Cipher cipher(AES(16), CBC(PKCS7(), utils::randiv(16)));
	std::cout << cipher.to_data().to_hex_string(true) << std::endl;

	return 0;
}