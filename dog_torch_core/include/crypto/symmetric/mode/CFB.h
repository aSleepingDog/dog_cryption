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

	class CFBB : public Mode
	{
	private:
		uint64_t shift;
	public:
		static Data encrypt(const Data& plain, const Data& iv, Cryptor& cryptor);
		static Data decrypt(const Data& crypt, const Data& iv, Cryptor& cryptor);

		static void encrypt_stream(std::istream& plain, const Data& iv, std::ostream& crypt, Cryptor& cryptor);
		static void decrypt_stream(std::istream& crypt, const Data& iv, std::ostream& plain, Cryptor& cryptor);

		static void encrypt_streamp(std::istream& plain, const Data& iv, std::ostream& crypt, Cryptor& cryptor,
			std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress_, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_);
		static void decrypt_streamp(std::istream& crypt, const Data& iv, std::ostream& plain, Cryptor& cryptor,
			std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress_, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_);

		static Data encrypt_CFB8(const Data& plain, const Data& iv, Cryptor& cryptor);
		static Data decrypt_CFB8(const Data& crypt, const Data& iv, Cryptor& cryptor);

		static void encrypt_CFB8_stream(std::istream& plain, const Data& iv, std::ostream& crypt, Cryptor& cryptor);
		static void decrypt_CFB8_stream(std::istream& crypt, const Data& iv, std::ostream& plain, Cryptor& cryptor);

		static void encrypt_CFB8_streamp(std::istream& plain, const Data& iv, std::ostream& crypt, Cryptor& cryptor,
			std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress_, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_);
		static void decrypt_CFB8_streamp(std::istream& crypt, const Data& iv, std::ostream& plain, Cryptor& cryptor,
			std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress_, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_);

		static Data encrypt_CFB128(const Data& plain, const Data& iv, Cryptor& cryptor);
		static Data decrypt_CFB128(const Data& crypt, const Data& iv, Cryptor& cryptor);

		static void encrypt_CFB128_stream(std::istream& plain, const Data& iv, std::ostream& crypt, Cryptor& cryptor);
		static void decrypt_CFB128_stream(std::istream& crypt, const Data& iv, std::ostream& plain, Cryptor& cryptor);

		static void encrypt_CFB128_streamp(std::istream& plain, const Data& iv, std::ostream& crypt, Cryptor& cryptor,
			std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress_, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_);
		static void decrypt_CFB128_streamp(std::istream& crypt, const Data& iv, std::ostream& plain, Cryptor& cryptor,
			std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress_, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_);

		CFBB(uint64_t shitf, bool using_padding);

		uint64_t get_shift() const;

		crypt_func get_mult_encrypt() const override;
		crypt_func get_mult_decrypt() const override;

		stream_crypt_func get_stream_encrypt() const override;
		stream_crypt_func get_stream_decrypt() const override;

		stream_cryptp_func get_stream_encryptp() const override;
		stream_cryptp_func get_stream_decryptp() const override;
	};

	class CFBb : public Mode
	{
	private:
		uint64_t shift;
	public:
		static Data encrypt(const Data& plain, const Data& iv, Cryptor& cryptor);
		static Data decrypt(const Data& crypt, const Data& iv, Cryptor& cryptor);

		static void encrypt_stream(std::istream& plain, const Data& iv, std::ostream& crypt, Cryptor& cryptor);
		static void decrypt_stream(std::istream& crypt, const Data& iv, std::ostream& plain, Cryptor& cryptor);

		static void encrypt_streamp(std::istream& plain, const Data& iv, std::ostream& crypt, Cryptor& cryptor,
			std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress_, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_);
		static void decrypt_streamp(std::istream& crypt, const Data& iv, std::ostream& plain, Cryptor& cryptor,
			std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress_, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_);

		static Data encrypt_CFB1(const Data& plain, const Data& iv, Cryptor& cryptor);
		static Data decrypt_CFB1(const Data& crypt, const Data& iv, Cryptor& cryptor);

		static void encrypt_CFB1_stream(std::istream& plain, const Data& iv, std::ostream& crypt, Cryptor& cryptor);
		static void decrypt_CFB1_stream(std::istream& crypt, const Data& iv, std::ostream& plain, Cryptor& cryptor);

		static void encrypt_CFB1_streamp(std::istream& plain, const Data& iv, std::ostream& crypt, Cryptor& cryptor,
			std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress_, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_);
		static void decrypt_CFB1_streamp(std::istream& crypt, const Data& iv, std::ostream& plain, Cryptor& cryptor,
			std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress_, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_);

		CFBb(uint64_t shitf, bool using_padding);

		uint64_t get_shift() const;

		crypt_func get_mult_encrypt() const override;
		crypt_func get_mult_decrypt() const override;

		stream_crypt_func get_stream_encrypt() const override;
		stream_crypt_func get_stream_decrypt() const override;

		stream_cryptp_func get_stream_encryptp() const override;
		stream_cryptp_func get_stream_decryptp() const override;
	};

}}}} 