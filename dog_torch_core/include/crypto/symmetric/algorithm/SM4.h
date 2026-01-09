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

namespace dog_torch::crypto::symmetric::algorithm
{
	using Data = dog_torch::serialize::BinaryData;
	class SM4 : public Algorithm
	{
	public:
		//unit单位:uint8_t字节
		static const Config CONFIG;

		static const uint8_t SBox[16][16];

		static const uint32_t FK[4];
		static const uint32_t CK[32];

		static uint32_t TMixChange1(uint32_t n);
		static uint32_t TMixChange2(uint32_t n);

		static Data extend_key(const Data& key, uint64_t block_size, uint64_t key_size);

		static Data encoding(const Data& plain, uint64_t block_size, const Data& key, uint64_t key_size);
		static Data decoding(const Data& crypt, uint64_t block_size, const Data& key, uint64_t key_size);

		static void encoding_self(Data& plain, uint64_t block_size, const Data& key, uint64_t key_size);
		static void decoding_self(Data& crypt, uint64_t block_size, const Data& key, uint64_t key_size);

		SM4(const uint64_t key_size) : Algorithm(CONFIG.name, 16, key_size) {}

		std::unique_ptr<Algorithm> clone() const override;

		extend_key_func           get_extend_key()    const override;
		block_cryption_func       get_encrypt()       const override;
		block_cryption_func       get_decrypt()       const override;
		block_self_cryption_func  get_encrypt_self()  const override;
		block_self_cryption_func  get_decrypt_self()  const override;
	};

}