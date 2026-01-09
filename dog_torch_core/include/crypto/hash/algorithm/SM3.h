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
#include "crypto/hash/base.h"

namespace dog_torch::crypto::hash::algorithm
{
	class DOG_CRYPTION_API SM3 : public Hash
	{
	private:
		bool is_padding_ = false;
		dog_torch::math::number::BigInteger max_ = 0;
	public:
		static const Config CONFIG;

		static uint32_t CLMB(uint32_t i, uint64_t n);
		static uint32_t SM3tick4B(Data& data, uint64_t index);
		static uint32_t functionP1_SM3(Data& data, uint64_t index);
		static uint32_t functionFF1_SM3(uint32_t a, uint32_t b, uint32_t c, int i);
		static uint32_t functionGG1_SM3(uint32_t a, uint32_t b, uint32_t c, int i);
		static void single_update(Data block, Data& value);
		static const Data IV;

		SM3(uint64_t effective);
		void init() override;
		Data init_data() const override;
		bool have_next_block(const BigInt& pos, const BigInt& total) const override;
		Data next_block(const Data& data, BigInt& pos, const BigInt& total) override;
		Data next_block(std::istream& data, BigInt& pos, const BigInt& total) override;
		update_func get_update() const override;
		trims_func get_trims() const override;
		std::unique_ptr<Hash> clone() const override;

	};
}