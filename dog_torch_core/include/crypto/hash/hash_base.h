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

namespace dog_torch { namespace crypto { namespace hash
{
	using HashException = dog_torch::utils::Exception;
	using Data = dog_torch::serialize::Data;

	/*
	* BLAKE2b, BLAKE2s, Keccack (F1600), SHA-1, SHA-3, SHAKE (128/256), SipHash, LSH (128/256), Tiger, RIPEMD (128/160/256/320), WHIRLPOOL
	*/

	class DOG_CRYPTION_API HashConfig
	{
	public:
		std::string name;
		std::string region;
		HashConfig(std::string name, std::string region);
	};
}}}