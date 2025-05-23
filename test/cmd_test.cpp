#include "../lib/dog_cryption.h"

#include <iostream>
#include <print>
#include <fstream>
#include <format>

int main()
{

	uint64_t key_size = 32;
	dog_data::Data d = "0123456789ABCDEFFEDCBA987654321000112233445566778899AABBCCDDEEFF";
	dog_data::Data key = dog_cryption::camellia::extend_key(d, key_size);
	dog_data::Data c = dog_cryption::camellia::encoding(d, 16, key, key_size);
	dog_data::print::space(c);
	dog_data::Data p = dog_cryption::camellia::decoding(c, 16, key, key_size);
	dog_data::print::space(p);

	return 0;
}