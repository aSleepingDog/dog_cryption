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

namespace dog_torch::crypto::symmetric::mode
{

	class PCBC : public Mode
	{
	private:
		std::unique_ptr<padding::Padding> padding_;
		Data iv_;
	public:
		static Data encrypt(const Data& plain, const Data& available_key, const algorithm::Algorithm& algorithm, const Data& iv, padding::padding_func padding);
		static Data decrypt(const Data& crypt, const Data& available_key, const algorithm::Algorithm& algorithm, const Data& iv, padding::padding_func unpadding);

		static void encrypt_stream(std::istream& plain, uint64_t max, std::ostream& crypt, const Data& available_key, const algorithm::Algorithm& algorithm, const Data& iv, padding::padding_func padding);
		static void decrypt_stream(std::istream& crypt, uint64_t max, std::ostream& plain, const Data& available_key, const algorithm::Algorithm& algorithm, const Data& iv, padding::padding_func unpadding);

		PCBC(const padding::Padding& padding, const Data& iv);
		PCBC(const PCBC& other);

		std::unique_ptr<Mode> clone() const override;
		bool check(const algorithm::Algorithm& algorithm) const override;

		const Data& get_iv() const;
		const padding::Padding& get_padding() const;

		bool set_data_param(const std::string& param, const Data& value) override;
		bool set_Padding(const padding::Padding& value) override;

		crypt_func get_mult_encrypt() const override;
		crypt_func get_mult_decrypt() const override;

		stream_crypt_func get_stream_encrypt() const override;
		stream_crypt_func get_stream_decrypt() const override;

	};



}