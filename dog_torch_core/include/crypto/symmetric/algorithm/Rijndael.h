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

	class DOG_CRYPTION_API Rijndael : public Algorithm
	{
	public:
		static const Config CONFIG;

		static const uint8_t SBox[16][16];
		static const uint8_t InvSBox[16][16];
		static const uint8_t MixTable[16];
		static const uint8_t UMixTable[16];
		static const uint8_t round[16];

		static uint8_t Xtime(uint8_t a, uint8_t b);

		static Data extend_key(const Data& key, uint64_t block_size, uint64_t key_size);

		static Data encoding(const Data& plain, uint64_t block_size, const Data& key, uint64_t key_size);
		static Data decoding(const Data& crypt, uint64_t block_size, const Data& key, uint64_t key_size);

		static void encoding_self(Data& plain, uint64_t block_size, const Data& key, uint64_t key_size);
		static void decoding_self(Data& crypt, uint64_t block_size, const Data& key, uint64_t key_size);

		Rijndael(const uint64_t block_size, const uint64_t key_size);

		//extend_key_func           get_extend_key()    const override;
		//block_cryption_func       get_encrypt()       const override;
		//block_cryption_func       get_decrypt()       const override;
		//block_self_cryption_func  get_encrypt_self()  const override;
		//block_self_cryption_func  get_decrypt_self()  const override;
	};
	

	//2025.12.14 由于AES的相关算法实现比Rijndael更早,所以使用原本的实现,但是常量使用Rijndael的
	class DOG_CRYPTION_API AES : public Rijndael
	{
	public:
		static const Config CONFIG;

		static void middle_encryption(Data& datablock, uint64_t flag, uint64_t mode);
		static void middle_decryption(Data& datablock, uint64_t flag, uint64_t mode);

		static Data extend_key(const Data& key, uint64_t block_size, uint64_t key_size);

		static Data encoding(const Data& plain, uint64_t block_size, const Data& key, uint64_t key_size);
		static Data decoding(const Data& crypt, uint64_t block_size, const Data& key, uint64_t key_size);

		static void encoding_self(Data& plain, uint64_t block_size, const Data& key, uint64_t key_size);
		static void decoding_self(Data& crypt, uint64_t block_size, const Data& key, uint64_t key_size);

		AES(const uint64_t key_size);

		std::unique_ptr<Algorithm> clone() const override;

		extend_key_func           get_extend_key()    const override;
		block_cryption_func       get_encrypt()       const override;
		block_cryption_func       get_decrypt()       const override;
		block_self_cryption_func  get_encrypt_self()  const override;
		block_self_cryption_func  get_decrypt_self()  const override;
	};

}