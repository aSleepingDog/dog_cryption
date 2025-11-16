#include <iostream>
#include <fstream>
#include <format>
#include <print> 
#include <chrono>

#include <cmath>

#include "dog_torch.h"

int main()
{
	dog_torch::serialize::Data key = "00000000000000000000000000000000";
	key = dog_torch::crypto::symmetric::Twofish::extend_key(key, 16);

	dog_torch::serialize::Data plain = "00000000000000000000000000000000";
	plain = dog_torch::crypto::symmetric::Twofish::encoding(plain, 16, key, 16);
	std::cout << plain.to_hex_string() << std::endl;
	plain = dog_torch::crypto::symmetric::Twofish::decoding(plain, 16, key, 16);
	std::cout << plain.to_hex_string() << std::endl;

	//std::vector<uint32_t> l = { 0x61106645,0x4BBC55B2,0xF2F69FB8 };
	//uint32_t b = dog_torch::crypto::symmetric::Twofish::function_h(0x244A3938, l);
	//printf("%08X", b);
	//using dog_torch::crypto::symmetric::Twofish::mult169;

	return 0;
}