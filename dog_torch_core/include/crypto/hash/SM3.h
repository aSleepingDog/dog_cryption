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

namespace dog_torch { namespace crypto { namespace hash
{
    using HashException = dog_torch::utils::Exception;
	using Data = dog_torch::serialize::Data;
	namespace SM3
	{
		DOG_CRYPTION_API extern const std::string name;
		DOG_CRYPTION_API extern const std::string effective_region;
		DOG_CRYPTION_API extern const HashConfig config;

		DOG_CRYPTION_API std::string get_config(std::string name, uint64_t effective);

		//circleLeftMoveBit
		DOG_CRYPTION_API uint32_t CLMB(uint32_t i, uint64_t n);
		DOG_CRYPTION_API uint32_t SM3tick4B(Data& data, uint64_t index);
		DOG_CRYPTION_API uint32_t functionP1_SM3(Data& data, uint64_t index);
		DOG_CRYPTION_API uint32_t functionFF1_SM3(uint32_t a, uint32_t b, uint32_t c, int i);
		DOG_CRYPTION_API uint32_t functionGG1_SM3(uint32_t a, uint32_t b, uint32_t c, int i);

		namespace b256
		{
			DOG_CRYPTION_API extern const Data IV;
			DOG_CRYPTION_API extern const dog_torch::math::number::BigInteger MAX;
			DOG_CRYPTION_API extern const uint64_t EFFECTIVE_SIZE;
			DOG_CRYPTION_API extern const uint64_t BLOCK_SIZE;
			DOG_CRYPTION_API extern const uint64_t NUMBER_SIZE;
			DOG_CRYPTION_API void single_update(Data plain, Data& change_value);
		}
	}

}}}