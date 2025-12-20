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

namespace dog_torch { namespace crypto { namespace symmetric { namespace mode {

	class CBC : public Mode
	{
	public:
		static Data encrypt(const Data& plain, const Data& iv, Cryptor& cryptor);
		static Data decrypt(const Data& crypt, const Data& iv, Cryptor& cryptor);

		static void encrypt_stream(std::istream& plain, const Data& iv, std::ostream& crypt, Cryptor& cryptor);
		static void decrypt_stream(std::istream& crypt, const Data& iv, std::ostream& plain, Cryptor& cryptor);

		static void encrypt_streamp(std::istream& plain, const Data& iv, std::ostream& crypt, Cryptor& cryptor,
			std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress_, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_);
		static void decrypt_streamp(std::istream& crypt, const Data& iv, std::ostream& plain, Cryptor& cryptor,
			std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress_, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_);

		CBC() : Mode("CBC", true, true) {};

		crypt_func get_mult_encrypt() const override;
		crypt_func get_mult_decrypt() const override;

		stream_crypt_func get_stream_encrypt() const override;
		stream_crypt_func get_stream_decrypt() const override;

		stream_cryptp_func get_stream_encryptp() const override;
		stream_cryptp_func get_stream_decryptp() const override;
	};



}}}} 