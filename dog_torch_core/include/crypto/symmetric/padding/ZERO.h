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
#include "crypto/symmetric/symmetric_base.h"

namespace dog_torch { namespace crypto { namespace symmetric { namespace padding
{
	using Data = dog_torch::serialize::Data;

	class ZERO : public Padding
	{
	public:
		static void padding(Data& data, uint64_t block_size);
		static void unpadding(Data& data, uint64_t block_size);
		ZERO() : Padding("ZERO") {};
		padding_func get_padding() const override;
		padding_func get_unpadding() const override;
	};

}}}}