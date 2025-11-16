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
    namespace SM4
	{
		//unit单位:uint8_t字节
		extern const DOG_CRYPTION_API AlgorithmConfig CONFIG;

		extern const DOG_CRYPTION_API uint8_t SBox[16][16];

		extern const DOG_CRYPTION_API uint32_t FK[4];
		extern const DOG_CRYPTION_API uint32_t CK[32];

		DOG_CRYPTION_API uint32_t TMixChange1(uint32_t n);
		DOG_CRYPTION_API uint32_t TMixChange2(uint32_t n);

		DOG_CRYPTION_API Data extend_key(Data key, uint64_t key_size = 16);

		DOG_CRYPTION_API Data encoding(Data& plain, uint64_t block_size, const Data& key, uint64_t key_size);
		DOG_CRYPTION_API Data decoding(Data& crypt, uint64_t block_size, const Data& key, uint64_t key_size);

		DOG_CRYPTION_API void encoding_self(Data& plain, uint64_t block_size, const Data& key, uint64_t key_size);
		DOG_CRYPTION_API void decoding_self(Data& crypt, uint64_t block_size, const Data& key, uint64_t key_size);
	}

}}}