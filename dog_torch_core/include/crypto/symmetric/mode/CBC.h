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

namespace dog_torch { namespace crypto { namespace symmetric { namespace mode {

	class CBC : public Mode
	{
	private:
		std::unique_ptr<padding::Padding>  padding_;
		Data                               iv_;
	public:
		static Data encrypt(const Data& plain, const Cipher& cipher);
		static Data decrypt(const Data& crypt, const Cipher& cipher);

		static void encrypt_stream(std::istream& plain, std::ostream& crypt, const Cipher& cipher);
		static void decrypt_stream(std::istream& crypt, std::ostream& plain, const Cipher& cipher);

		static void encrypt_streamp(std::istream& plain, std::ostream& crypt, const Cipher& cipher,
			std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress_, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_);
		static void decrypt_streamp(std::istream& crypt, std::ostream& plain, const Cipher& cipher,
			std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress_, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_);

		CBC(const padding::Padding& padding, const Data& iv);
		CBC(const CBC& other);

		const Data& get_iv() const;
		const padding::Padding& get_padding() const;

		std::unique_ptr<Mode> clone() const override;

		Data to_data() const override;

		crypt_func get_mult_encrypt() const override;
		crypt_func get_mult_decrypt() const override;

		stream_crypt_func get_stream_encrypt() const override;
		stream_crypt_func get_stream_decrypt() const override;

		stream_cryptp_func get_stream_encryptp() const override;
		stream_cryptp_func get_stream_decryptp() const override;
	};



}}}} 