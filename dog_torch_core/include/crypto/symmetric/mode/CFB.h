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
	/*
	* CFB模式默认不使用填充 只有处于CFBB(按字节分组)且反馈长度大于1时才使用填充
	*/


	class CFBB : public Mode
	{
	private:
		std::unique_ptr<padding::Padding> padding_;
		Data iv_;
		uint64_t shift_;
	public:
		static Data encrypt(const Data& plain, const Cipher& cipher);
		static Data decrypt(const Data& crypt, const Cipher& cipher);

		static void encrypt_stream(std::istream& plain, std::ostream& crypt, const Cipher& cipher);
		static void decrypt_stream(std::istream& crypt, std::ostream& plain, const Cipher& cipher);

		static void encrypt_streamp(std::istream& plain, std::ostream& crypt, const Cipher& cipher,
			std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress_, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_);
		static void decrypt_streamp(std::istream& crypt, std::ostream& plain, const Cipher& cipher,
			std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress_, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_);

		static Data encrypt_CFB8(const Data& plain, const Cipher& cipher);
		static Data decrypt_CFB8(const Data& crypt, const Cipher& cipher);

		static void encrypt_CFB8_stream(std::istream& plain, std::ostream& crypt, const Cipher& cipher);
		static void decrypt_CFB8_stream(std::istream& crypt, std::ostream& plain, const Cipher& cipher);

		static void encrypt_CFB8_streamp(std::istream& plain, std::ostream& crypt, const Cipher& cipher,
			std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress_, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_);
		static void decrypt_CFB8_streamp(std::istream& crypt, std::ostream& plain, const Cipher& cipher,
			std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress_, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_);

		static Data encrypt_CFB128(const Data& plain, const Cipher& cipher);
		static Data decrypt_CFB128(const Data& crypt, const Cipher& cipher);

		static void encrypt_CFB128_stream(std::istream& plain, std::ostream& crypt, const Cipher& cipher);
		static void decrypt_CFB128_stream(std::istream& crypt, std::ostream& plain, const Cipher& cipher);

		static void encrypt_CFB128_streamp(std::istream& plain, std::ostream& crypt, const Cipher& cipher,
			std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress_, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_);
		static void decrypt_CFB128_streamp(std::istream& crypt, std::ostream& plain, const Cipher& cipher,
			std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress_, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_);

		CFBB(const padding::Padding& padding, const Data& iv, uint64_t shift);
		CFBB(const Data& iv, uint64_t shift) : CFBB(padding::Padding(), iv, shift) {}
		CFBB(const CFBB& other);

		std::unique_ptr<Mode> clone() const override;

		uint64_t get_shift() const;

		const Data& get_iv() const;
		const padding::Padding& get_padding() const;

		bool set_uint64_param(const std::string& param, uint64_t value) override;
		bool set_data_param(const std::string& param, const Data& value) override;
		bool set_Padding(const padding::Padding& value) override;
		
		std::string fmt_config() const override;

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
		std::unique_ptr<padding::Padding> padding_;
		Data iv_;
		uint64_t shift_;
	public:
		static Data encrypt(const Data& plain, const Cipher& cipher);
		static Data decrypt(const Data& crypt, const Cipher& cipher);

		static void encrypt_stream(std::istream& plain, std::ostream& crypt, const Cipher& cipher);
		static void decrypt_stream(std::istream& crypt, std::ostream& plain, const Cipher& cipher);

		static void encrypt_streamp(std::istream& plain, std::ostream& crypt, const Cipher& cipher,
			std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress_, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_);
		static void decrypt_streamp(std::istream& crypt, std::ostream& plain, const Cipher& cipher,
			std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress_, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_);

		static Data encrypt_CFB1(const Data& plain, const Cipher& cipher);
		static Data decrypt_CFB1(const Data& crypt, const Cipher& cipher);

		static void encrypt_CFB1_stream(std::istream& plain, std::ostream& crypt, const Cipher& cipher);
		static void decrypt_CFB1_stream(std::istream& crypt, std::ostream& plain, const Cipher& cipher);

		static void encrypt_CFB1_streamp(std::istream& plain, std::ostream& crypt, const Cipher& cipher,
			std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress_, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_);
		static void decrypt_CFB1_streamp(std::istream& crypt, std::ostream& plain, const Cipher& cipher,
			std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress_, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_);

		CFBb(const padding::Padding& padding, const Data& iv, uint64_t shift);
		CFBb(const Data& iv, uint64_t shift) : CFBb(padding::Padding(), iv, shift) {}
		CFBb(const CFBb& other);

		uint64_t get_shift() const;

		const Data& get_iv() const;
		const padding::Padding& get_padding() const;

		std::string fmt_config() const override;

		std::unique_ptr<Mode> clone() const override;
		
		bool set_uint64_param(const std::string& param, uint64_t value) override;
		bool set_data_param(const std::string& param, const Data& value) override;
		bool set_Padding(const padding::Padding& value) override;

		crypt_func get_mult_encrypt() const override;
		crypt_func get_mult_decrypt() const override;

		stream_crypt_func get_stream_encrypt() const override;
		stream_crypt_func get_stream_decrypt() const override;

		stream_cryptp_func get_stream_encryptp() const override;
		stream_cryptp_func get_stream_decryptp() const override;
	};

}