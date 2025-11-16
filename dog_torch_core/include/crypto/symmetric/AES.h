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

	namespace Rijndael
	{
		DOG_CRYPTION_API Data extend_key(Data& key, uint64_t key_size);

		//Rijndael加解密中 字节代还 行移位 列混合混合方法
		DOG_CRYPTION_API Data middle_encryption(Data datablock, uint64_t flag, uint64_t mode);
		DOG_CRYPTION_API Data middle_decryption(Data datablock, uint64_t flag, uint64_t mode);

		DOG_CRYPTION_API Data encoding(Data& plain, uint64_t block_size, const Data& key, uint64_t key_size);
		DOG_CRYPTION_API Data decoding(Data& crypt, uint64_t block_size, const Data& key, uint64_t key_size);

		DOG_CRYPTION_API void encoding_self(Data& plain, uint64_t block_size, const Data& key, uint64_t key_size);
		DOG_CRYPTION_API void decoding_self(Data& crypt, uint64_t block_size, const Data& key, uint64_t key_size);
	};

    namespace AES
	{
		//unit单位:uint8_t字节
		extern const DOG_CRYPTION_API AlgorithmConfig CONFIG;
		extern const DOG_CRYPTION_API uint8_t SBox[16][16];
		extern const DOG_CRYPTION_API uint8_t InvSBox[16][16];

		extern const DOG_CRYPTION_API uint8_t MixTable[16];
		extern const DOG_CRYPTION_API uint8_t UMixTable[16];

		extern const DOG_CRYPTION_API uint8_t round[10];
		DOG_CRYPTION_API Data extendKey128(Data& key);
		DOG_CRYPTION_API Data extendKey192(Data& key);
		DOG_CRYPTION_API Data extendKey256(Data& key);
		DOG_CRYPTION_API Data extend_key(Data& key, uint64_t key_size);

		//the value of a must be 0x01 0x02 0x03 a的值只能为0x01,0x02,0x03
		DOG_CRYPTION_API uint8_t Xtime(uint8_t a, uint8_t b);

		//each block encrypt and using funcation 区块加密及内部算法

		//AES加解密中 字节代还 行移位 列混合混合方法
		DOG_CRYPTION_API Data middle_encryption(Data datablock, uint64_t flag, uint64_t mode);
        DOG_CRYPTION_API Data middle_decryption(Data datablock, uint64_t flag, uint64_t mode);

		DOG_CRYPTION_API Data encoding(Data& plain, uint64_t block_size, const Data& key, uint64_t key_size);
		DOG_CRYPTION_API Data decoding(Data& crypt, uint64_t block_size, const Data& key, uint64_t key_size);

		DOG_CRYPTION_API void encoding_self(Data& plain, uint64_t block_size, const Data& key, uint64_t key_size);
		DOG_CRYPTION_API void decoding_self(Data& crypt, uint64_t block_size, const Data& key, uint64_t key_size);
	}

}}}