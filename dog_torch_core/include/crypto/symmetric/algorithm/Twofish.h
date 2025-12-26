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
#include "crypto/symmetric/base.h"

namespace dog_torch { namespace crypto { namespace symmetric { namespace algorithm
{
	using Data = dog_torch::serialize::Data;
	class Twofish : public Algorithm
	{
		//unit单位:uint8_t字节
		static const Config CONFIG;

		static const uint8_t P8x8[2][256];

		static const uint8_t GF14D[255];
		static const uint8_t GFi14D[255];
		static uint8_t mult14D(uint8_t a, uint8_t b);

		static uint8_t mult169(uint8_t a, uint8_t b);

		static const uint8_t MDS[16];
		static const uint8_t RS[32];

		static uint32_t multMDS(uint32_t n);
		static uint32_t multRS(uint64_t n);
		static uint32_t function_h(uint32_t x, std::vector<uint32_t> l);
		static Data extend_key(const Data& key, uint64_t block_size, uint64_t key_size);

		static Data encoding(const Data& plain, uint64_t block_size, const Data& key, uint64_t key_size);
		static Data decoding(const Data& plain, uint64_t block_size, const Data& key, uint64_t key_size);

		static void encoding_self(Data& plain, uint64_t block_size, const Data& key, uint64_t key_size);
		static void decoding_self(Data& crypt, uint64_t block_size, const Data& key, uint64_t key_size);

		std::unique_ptr<Algorithm> clone() const override;

		Extend_key_func           get_extend_key()    const override;
		Block_cryption_func       get_encrypt()       const override;
		Block_cryption_func       get_decrypt()       const override;
		Block_self_cryption_func  get_encrypt_self()  const override;
		Block_self_cryption_func  get_decrypt_self()  const override;
	};
}}}}