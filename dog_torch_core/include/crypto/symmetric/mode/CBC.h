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
#include "crypto/symmetric/symmetric.h"
#include "asyncion/thread/thread.h"

namespace dog_torch::crypto::symmetric::mode
{
	class DOG_CRYPTION_API CBC : public Mode
	{
	private:
		std::unique_ptr<padding::Padding>  padding_;
		Data                               iv_;
	public:
		
		static Config get_config();

		static Data encrypt(const Data& plain, const Data& available_key, const algorithm::Algorithm& algorithm, const Data& iv, padding::padding_func padding);
		static Data decrypt(const Data& crypt, const Data& available_key, const algorithm::Algorithm& algorithm, const Data& iv, padding::padding_func unpadding);
		static void encrypt_stream(std::istream& plain, uint64_t max, std::ostream& crypt, const Data& available_key, const algorithm::Algorithm& algorithm, const Data& iv, padding::padding_func padding);
		static void decrypt_stream(std::istream& crypt, uint64_t max, std::ostream& plain, const Data& available_key, const algorithm::Algorithm& algorithm, const Data& iv, padding::padding_func unpadding);
		static void encryptp_stream(PauseableChannel& pchannel, std::istream& plain, uint64_t max, std::ostream& crypt, const Data& available_key, const algorithm::Algorithm& algorithm, const Data& iv, padding::padding_func padding);
		static void decryptp_stream(PauseableChannel& pchannel, std::istream& crypt, uint64_t max, std::ostream& plain, const Data& available_key, const algorithm::Algorithm& algorithm, const Data& iv, padding::padding_func unpadding);

		CBC(const padding::Padding& padding, const Data& iv);
		CBC(const CBC& other);

		const Data& get_iv() const;
		const padding::Padding& get_padding() const;

		std::unique_ptr<Mode> clone() const override;
		bool check(const algorithm::Algorithm& algorithm) const override;

		bool set_data_param(const std::string& param, const Data& value) override;
		bool set_Padding(const padding::Padding& value) override;
		
		Data to_data() const override;

		crypt_func get_mult_encrypt() const override;
		crypt_func get_mult_decrypt() const override;

		stream_crypt_func get_stream_encrypt() const override;
		stream_crypt_func get_stream_decrypt() const override;

		streamp_crypt_func get_streamp_encrypt() const override;
		streamp_crypt_func get_streamp_decrypt() const override;
	};


}