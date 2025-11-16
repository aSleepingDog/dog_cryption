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

namespace dog_torch { namespace crypto {namespace symmetric
{
    using Data = dog_torch::serialize::Data;

	namespace utils
	{
		DOG_CRYPTION_API uint8_t rand_byte();

		DOG_CRYPTION_API bool is_integer(std::any a);
		DOG_CRYPTION_API uint64_t get_integer(std::any a);

		DOG_CRYPTION_API Data squareXOR(Data& a, Data& b, uint64_t size);
		DOG_CRYPTION_API void squareXOR_self(Data& a, Data& b, uint64_t size);
		DOG_CRYPTION_API Data randiv(uint8_t block_size);

		DOG_CRYPTION_API Data get_sequence(uint64_t lenght);
	}

	class DOG_CRYPTION_API CryptionException : public dog_torch::utils::Exception
	{
	public:
		CryptionException(DOG_EXCEPTION_MSG_PARAMS) : dog_torch::utils::Exception(DOG_EXCEPTION_MSG_OPINION(msg)) {}
	};

	class DOG_CRYPTION_API WrongKeyException : public dog_torch::utils::Exception
	{
	public:
		WrongKeyException(DOG_EXCEPTION_PARAMS) : dog_torch::utils::Exception(DOG_EXCEPTION_MSG_OPINION("wrong key")) {}
	};

	class DOG_CRYPTION_API WrongConfigException : public dog_torch::utils::Exception
	{
	public:
		WrongConfigException(DOG_EXCEPTION_PARAMS) : dog_torch::utils::Exception(DOG_EXCEPTION_MSG_OPINION("invalid cryption algorithm")) {}
	};

    class DOG_CRYPTION_API AlgorithmConfig
	{
	public:
		std::string name;
		std::string block_size_region;
		std::string key_size_region;
		AlgorithmConfig(std::string name, std::string block_size_region, std::string key_size_region);
	};


}}}