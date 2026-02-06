#include "math/GaloisField.h"


uint8_t dog_torch::math::galois_field::GF2_mult(uint8_t a, uint8_t b, uint16_t n)
{
	uint16_t max = a >= b ? a : b;
	uint16_t min = a < b ? a : b;
	uint16_t res = 0;
	for (uint8_t i = 0; i < 8; i++)
	{
		if ((min >> i) & 0x01)
		{
			res ^= max << i;
		}
	}
	for (uint8_t i = 0; i < 8; i++)
	{
		if (res >> (8 + i) & 0x01)
		{
			res ^= n << i;
		}
	}
	return res;
}
