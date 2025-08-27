#include "../libcryption/include/cryption/dog_cryption.h"

#include <iostream>
#include <print> 
#include <fstream>
#include <format>

#include <cmath>

int main()
{
	dog_data::Data key = "0123456789ABCDEFFEDCBA987654321000112233445566778899AABBCCDDEEFF";
	dog_cryption::Twofish::extend_key(key, 32);

	double a = pow(1, 1);
	return 0;
}