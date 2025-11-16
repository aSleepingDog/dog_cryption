#pragma once
#ifdef SHARED
	#include "export.h"
#else
	#define DOG_CRYPTION_API
#endif
#include <any>
#include <mutex>
#include <regex>
#include <print>
#include <thread>
#include <atomic>
#include <bitset>
#include <string>
#include <random>
#include <format>
#include <cstdlib>
#include <exception>
#include <functional>
#include <unordered_map>
#include <condition_variable>

#include "serialize/serialize.h"
#include "math/math.h"
#include "symmetric_base.h"

namespace dog_torch { namespace crypto {namespace symmetric
{
	using Data = dog_torch::serialize::Data;
    namespace camellia
	{
		//unit单位:uint8_t字节
		extern const DOG_CRYPTION_API AlgorithmConfig CONFIG;

		extern const DOG_CRYPTION_API uint8_t Sbox[256];

		extern const DOG_CRYPTION_API uint64_t sigma[6];

		DOG_CRYPTION_API std::pair<uint64_t, uint64_t> CLMB(uint64_t l, uint64_t r, uint64_t i);

		DOG_CRYPTION_API uint8_t s1(uint8_t n);
		DOG_CRYPTION_API uint8_t s2(uint8_t n);
		DOG_CRYPTION_API uint8_t s3(uint8_t n);
		DOG_CRYPTION_API uint8_t s4(uint8_t n);

		DOG_CRYPTION_API uint64_t s(uint64_t n);
		DOG_CRYPTION_API uint64_t p(uint64_t n);
		DOG_CRYPTION_API uint64_t FL(uint64_t x, uint64_t kl);
		DOG_CRYPTION_API uint64_t FL_inv(uint64_t y, uint64_t kl);
		DOG_CRYPTION_API uint64_t F(uint64_t x, uint64_t k);

		DOG_CRYPTION_API Data extend_key(Data key, uint64_t key_size = 16);

		DOG_CRYPTION_API Data encoding(Data& plain, uint64_t block_size, const Data& key, uint64_t key_size);
		DOG_CRYPTION_API Data decoding(Data& crypt, uint64_t block_size, const Data& key, uint64_t key_size);

		DOG_CRYPTION_API void encoding_self(Data& plain, uint64_t block_size, const Data& key, uint64_t key_size);
		DOG_CRYPTION_API void decoding_self(Data& crypt, uint64_t block_size, const Data& key, uint64_t key_size);

	}
}}}