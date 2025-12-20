#include <chrono>
#include <format>
#include <fstream>
#include <iostream>
#include <print> 

#include <cmath>

#include "crypto/symmetric/algorithm/Rijndael.h"
#include "crypto/symmetric/mode/CBC.h"
#include "crypto/symmetric/padding/PKCS7.h"
#include "crypto/symmetric/symmetric_base.h"


int main()
{
	using namespace dog_torch::crypto::symmetric;
	using namespace dog_torch::crypto::symmetric::algorithm;
	using namespace dog_torch::crypto::symmetric::mode;
	using namespace dog_torch::crypto::symmetric::padding;

	CryptionConfig cryptor(AES(16), CBC(), PKCS7());
	std::cout << cryptor.to_data().to_hex_string(true) << std::endl;
	
}