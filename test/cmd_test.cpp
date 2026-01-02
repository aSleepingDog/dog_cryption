#include <chrono>

#include <format>
#include <fstream>
#include <future>
#include <iostream>
#include <print> 

#include <cmath>

#include "asyncion/pool/PollingPriorityTaskPool.h"
#include "asyncion/pool/PollingTaskPool.h"
#include "asyncion/pool/ThreadPool.h"
#include "crypto/symmetric/algorithm/Rijndael.h"
#include "crypto/symmetric/base.h"
#include "crypto/symmetric/mode/CBC.h"
#include "crypto/symmetric/mode/CFB.h"
#include "crypto/symmetric/mode/ECB.h"
#include "crypto/symmetric/padding/PKCS7.h"

//#include <crtdbg.h>
//#define _CRTDBG_MAP_ALLOC
//#define _DEBUG
//_CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF);

int main()
{

	using namespace dog_torch::crypto::symmetric;
	using namespace dog_torch::crypto::symmetric::mode;
	using namespace dog_torch::crypto::symmetric::padding;
	using namespace dog_torch::crypto::symmetric::algorithm;

	Data plain = "6D";
	Data iv = "8A045BB48C9E1E2B613C16E179C4EDE8";
	Data key = "A94C02C0116469AD465A909D824DDB89";

	std::cout << plain.to_hex_string() << std::endl;

	Cipher cipher(AES(16), CFBB(PKCS7(), iv, 10));
	cipher.set_key(key);
	Data crypt = cipher.encrypt(plain);
	std::cout << crypt.to_hex_string() << std::endl;
	std::cout << cipher.decrypt(crypt).to_hex_string() << std::endl;
	std::cout << std::boolalpha << (cipher.decrypt(crypt) == plain) << std::endl;

	return 0;
}