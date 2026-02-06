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
#include "utils/Exception.h"
#include "crypto/hash/hash.h"

namespace dog_torch::crypto::hash::algorithm
{
	class DOG_CRYPTION_API SHA2 : public Hash
	{
	private:
		bool is_padding_80_ = false;
		bool is_padding_num_ = false;
		dog_torch::math::number::BigInteger max_ = 0;
	public:
		static const Config get_config();
		static const uint32_t k_256[64];
		static uint32_t tick4B(Data& data, uint64_t size, uint64_t index); 
		//circle right move by bits循环右移
		static uint32_t CRMB(uint32_t i, uint64_t n);
		static uint32_t function1_64(uint32_t e, uint32_t f, uint32_t g, uint32_t h, Data& block, int size, int n);
		static uint32_t function2_64(uint32_t a, uint32_t b, uint32_t c);
		static const Data IV_256;
		static const Data IV_224;
		static void single_256_update(Data block, Data& value);
		static const uint64_t k_512[80];
		static uint64_t tick8B(Data& data, uint64_t size, uint64_t index);
		//circleRightMoveBit
		static uint64_t CRMB(uint64_t i, uint64_t n);
		static uint64_t function1_128(uint64_t e, uint64_t f, uint64_t g, uint64_t h, Data& block, int size, int n);
		static uint64_t function2_128(uint64_t a, uint64_t b, uint64_t c);
		static const Data IV_512;
		static const Data IV_384;
		static void single_512_update(Data block, Data& value);

		SHA2(uint64_t effective);
		void init() override;
		Data init_data() const override;

		update_func get_update() const override;
		trims_func get_trims() const override;
		std::unique_ptr<Hash> clone() const override;
		uint64_t get_block_size() const override;

		bool have_next_block(uint64_t data_pos, uint64_t data_total) override;
		bool have_next_block_big(const BigInt& data_pos, const BigInt& data_total) override;

		Data next_block(const Data& data, uint64_t start, uint64_t& data_pos, uint64_t data_total) override;
		Data next_block(std::istream& data, uint64_t& data_pos, uint64_t data_total) override;
		Data next_block_big(std::istream& data, BigInt& data_pos, const BigInt& data_total) override;
	};
}