#include <chrono>

#include <filesystem>
#include <format>
#include <fstream>
#include <future>
#include <iostream>
#include <print>
#include <unordered_set>

#include <cmath>


//#include <crtdbg.h>
//#define _CRTDBG_MAP_ALLOC
//#define _DEBUG
//_CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF);

#include "crypto/symmetric/algorithm/Rijndael.h"
#include "crypto/symmetric/mode/ECB.h"
#include "crypto/symmetric/mode/CBC.h"
#include "crypto/symmetric/mode/CFB.h"
#include "crypto/symmetric/mode/CTR.h"
#include "crypto/symmetric/mode/OFB.h"
#include "crypto/symmetric/mode/PCBC.h"
#include "crypto/symmetric/padding/PKCS7.h"
#include "crypto/symmetric/base.h"





int main()
{
	using namespace dog_torch::crypto::symmetric;
	std::filesystem::path plain = "E:/project/crypher_cpp/test/plain/small_one";
	std::filesystem::path crypt = "E:/project/crypher_cpp/test/plain/small_one.crypt";
	std::filesystem::path plain_ = "E:/project/crypher_cpp/test/plain/small_one.plain";
	Data key = "0123456789ABCDEF0123456789ABCDEF";
	Cipher cipher(algorithm::AES(16), mode::CFBb(padding::PKCS7(), key, 10));
	cipher.set_key(key);
	cipher.encrypt(plain, crypt);
	std::cout << std::endl;
	cipher.decrypt(crypt, plain_);

	return 0;
}