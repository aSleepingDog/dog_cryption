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

	class DOG_CRYPTION_API camellia : public Algorithm
	{
	public:
		static const Config CONFIG;
		static const uint8_t Sbox[256];
		static const uint64_t sigma[6];
		static std::pair<uint64_t, uint64_t> CLMB(uint64_t l, uint64_t r, uint64_t i);
		static uint8_t s1(uint8_t n);
		static uint8_t s2(uint8_t n);
		static uint8_t s3(uint8_t n);
		static uint8_t s4(uint8_t n);

		static uint64_t s(uint64_t n);
		static uint64_t p(uint64_t n);
		static uint64_t FL(uint64_t x, uint64_t kl);
		static uint64_t FL_inv(uint64_t y, uint64_t kl);
		static uint64_t F(uint64_t x, uint64_t k);

		static Data extend_key(const Data& key, uint64_t block_size, uint64_t key_size);

		static Data encoding(const Data& plain, uint64_t block_size, const Data& key, uint64_t key_size);
		static Data decoding(const Data& crypt, uint64_t block_size, const Data& key, uint64_t key_size);

		static void encoding_self(Data& plain, uint64_t block_size, const Data& key, uint64_t key_size);
		static void decoding_self(Data& crypt, uint64_t block_size, const Data& key, uint64_t key_size);


		camellia(const uint64_t key_size) : Algorithm(CONFIG.name, 16, key_size) {};

		std::unique_ptr<Algorithm> clone() const override;

		extend_key_func           get_extend_key()    const override;
		block_cryption_func       get_encrypt()       const override;
		block_cryption_func       get_decrypt()       const override;
		block_self_cryption_func  get_encrypt_self()  const override;
		block_self_cryption_func  get_decrypt_self()  const override;
	};
}