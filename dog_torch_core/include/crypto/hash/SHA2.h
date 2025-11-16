#pragma once
#ifdef SHARED
	#include "export.h"
#else
	#define DOG_CRYPTION_API
#endif
#include <mutex>
#include <thread>
#include <atomic>
#include <iostream>
#include <condition_variable>

#include "math/math.h"
#include "serialize/serialize.h"
#include "utils/exception.h"
#include "hash_base.h"

namespace dog_torch { namespace crypto { namespace hash{

	namespace SHA2
	{
		DOG_CRYPTION_API extern const std::string name;
		DOG_CRYPTION_API extern const std::string effective_region;
		DOG_CRYPTION_API extern const HashConfig config;

		DOG_CRYPTION_API std::string get_config(std::string name, uint64_t effective);

		DOG_CRYPTION_API extern const uint32_t k_256[64];

		DOG_CRYPTION_API uint32_t tick4B(Data& data, uint64_t size, uint64_t index);
		//circle right move by bits循环右移
		DOG_CRYPTION_API uint32_t CRMB(uint32_t i, uint64_t n);
		DOG_CRYPTION_API uint32_t function1_64(uint32_t e, uint32_t f, uint32_t g, uint32_t h, Data& block, int size, int n);
		DOG_CRYPTION_API uint32_t function2_64(uint32_t a, uint32_t b, uint32_t c);

		namespace b256
		{
			DOG_CRYPTION_API extern const Data IV;
			DOG_CRYPTION_API extern const dog_torch::math::number::BigInteger MAX;
			DOG_CRYPTION_API extern const uint64_t EFFECTIVE_SIZE;
			DOG_CRYPTION_API extern const uint64_t BLOCK_SIZE;
			DOG_CRYPTION_API extern const uint64_t NUMBER_SIZE;
			DOG_CRYPTION_API void single_update(Data plain, Data& change_value);
		}
		namespace b224
		{
			DOG_CRYPTION_API extern const Data IV;
			DOG_CRYPTION_API extern const dog_torch::math::number::BigInteger MAX;
			DOG_CRYPTION_API extern const uint64_t EFFECTIVE_SIZE;
			DOG_CRYPTION_API extern const uint64_t BLOCK_SIZE;
			DOG_CRYPTION_API extern const uint64_t NUMBER_SIZE;
			DOG_CRYPTION_API void single_update(Data plain, Data& change_value);
		}
		DOG_CRYPTION_API extern const uint64_t k_512[80];

		DOG_CRYPTION_API uint64_t tick8B(Data& data, uint64_t size, uint64_t index);
		//circleRightMoveBit
		DOG_CRYPTION_API uint64_t CRMB(uint64_t i, uint64_t n);
		DOG_CRYPTION_API uint64_t function1_128(uint64_t e, uint64_t f, uint64_t g, uint64_t h, Data& block, int size, int n);
		DOG_CRYPTION_API uint64_t function2_128(uint64_t a, uint64_t b, uint64_t c);

		namespace b384
		{
			DOG_CRYPTION_API extern const Data IV;
			DOG_CRYPTION_API extern const dog_torch::math::number::BigInteger MAX;
			DOG_CRYPTION_API extern const uint64_t EFFECTIVE_SIZE;
			DOG_CRYPTION_API extern const uint64_t BLOCK_SIZE;
			DOG_CRYPTION_API extern const uint64_t NUMBER_SIZE;
			DOG_CRYPTION_API void single_update(Data plain, Data& change_value);
		}

		namespace b512
		{
			DOG_CRYPTION_API extern const Data IV;
			DOG_CRYPTION_API extern const dog_torch::math::number::BigInteger MAX;
			DOG_CRYPTION_API extern const uint64_t EFFECTIVE_SIZE;
			DOG_CRYPTION_API extern const uint64_t BLOCK_SIZE;
			DOG_CRYPTION_API extern const uint64_t NUMBER_SIZE;
			void single_update(Data plain, Data& change_value);
		}
	};

}}}