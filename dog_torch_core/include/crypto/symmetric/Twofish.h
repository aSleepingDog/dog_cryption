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
    namespace Twofish
	{
		//unit单位:uint8_t字节
		extern const DOG_CRYPTION_API dog_torch::crypto::symmetric::AlgorithmConfig CONFIG;

		extern const DOG_CRYPTION_API uint8_t P8x8[2][256];

		extern const DOG_CRYPTION_API uint8_t GF14D[255];
		extern const DOG_CRYPTION_API uint8_t GFi14D[255];
		DOG_CRYPTION_API uint8_t mult14D(uint8_t a, uint8_t b);

		DOG_CRYPTION_API uint8_t mult169(uint8_t a, uint8_t b);

		extern const DOG_CRYPTION_API uint8_t MDS[16];
		extern const DOG_CRYPTION_API uint8_t RS[32];

		DOG_CRYPTION_API uint32_t multMDS(uint32_t n);
		DOG_CRYPTION_API uint32_t multRS(uint64_t n);
		DOG_CRYPTION_API uint32_t function_h(uint32_t x, std::vector<uint32_t> l);
		DOG_CRYPTION_API Data extend_key(Data& key, uint64_t key_size = 16);

		DOG_CRYPTION_API Data encoding(Data& plain, uint64_t block_size, const Data& key, uint64_t key_size);
		DOG_CRYPTION_API Data decoding(Data& plain, uint64_t block_size, const Data& key, uint64_t key_size);

		DOG_CRYPTION_API void encoding_self(Data& plain, uint64_t block_size, const Data& key, uint64_t key_size);
		DOG_CRYPTION_API void decoding_self(Data& crypt, uint64_t block_size, const Data& key, uint64_t key_size);
	}
}}}