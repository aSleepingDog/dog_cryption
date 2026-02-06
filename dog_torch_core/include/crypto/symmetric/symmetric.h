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
#include <fstream>
#include <unordered_map>
#include <filesystem>
#include <condition_variable>

#include "asyncion/thread/thread.h"
#include "serialize/serialize.h"
#include "math/math.h"

namespace dog_torch::crypto::symmetric
{
    using Data = dog_torch::serialize::BinaryData;

	namespace utils
	{
		DOG_CRYPTION_API uint8_t rand_byte();

		DOG_CRYPTION_API Data randiv(uint8_t block_size);

		DOG_CRYPTION_API Data get_sequence(uint64_t lenght);
	}

	class DOG_CRYPTION_API CryptionException : public dog_torch::utils::Exception
	{
	public:
		CryptionException(DOG_EXCEPTION_MSG_PARAMS) : dog_torch::utils::Exception(DOG_EXCEPTION_MSG_OPINION(msg)) {}
	};

	namespace algorithm
	{
		/**
		* 密钥扩展方法
		* @param const Data& 原始密钥
		* @param uint64_t    分组长度
		* @param uint64_t    密钥长度
		*/
		using extend_key_func = std::function<Data(const Data&, uint64_t, uint64_t)>;
		/**
		* 块自加密/解密方法
		* @param Data&       待处理分块
		* @param uint64_t    分组长度
		* @param const Data& 扩展后密钥
		* @param uint64_t    密钥长度
		*/
		using block_self_cryption_func = std::function<void(Data&, uint64_t, const Data&, uint64_t)>;
		/**
		* 块加密/解密方法
		* @param Data&       待处理分块
		* @param uint64_t    分组长度
		* @param const Data& 扩展后密钥
		* @param uint64_t    密钥长度
		* @return Data       结果分款
		*/
		using block_cryption_func = std::function<Data(const Data&, uint64_t, const Data&, uint64_t)>;

		struct DOG_CRYPTION_API Config
		{
			std::string name;
			std::string block_size_region;
			std::string key_size_region;
			Config(const std::string& name, const std::string& block_size_region, const std::string& key_size_region) :
				name(name), block_size_region(block_size_region), key_size_region(key_size_region) {};
		};

		/*
		RC6, MARS,  Serpent, CAST-256,ARIA, Blowfish, CHAM, HIGHT, IDEA, Kalyna (128/256/512), LEA, SEED, RC5, SHACAL-2, SIMECK, SIMON (64/128), Skipjack, SPECK (64/128), Simeck,Threefish (256/512/1024), Triple-DES (DES-EDE2 and DES-EDE3), TEA, XTEA
		*/

		class DOG_CRYPTION_API Algorithm
		{
		protected:
			//static const AlgorithmConfig CONFIG;//在子类中实现
			std::string name;
			uint64_t block_size;
			uint64_t key_size;
		public:
			/*
			以下具体函数在子类中实现
			static Data extend_key(const Data& key, uint64_t block_size, uint64_t key_size);

			static Data encoding(const Data& plain, uint64_t block_size, const Data& key, uint64_t key_size);
			static Data decoding(const Data& crypt, uint64_t block_size, const Data& key, uint64_t key_size);

			static void encoding_self(Data& plain, uint64_t block_size, const Data& key, uint64_t key_size);
			static void decoding_self(Data& crypt, uint64_t block_size, const Data& key, uint64_t key_size);
			*/
			Algorithm(const std::string& name, const uint64_t block_size, const uint64_t key_size);
			virtual ~Algorithm() = default;
			virtual std::unique_ptr<Algorithm> clone() const;
			virtual Data to_data() const;
			virtual std::string fmt_config() const;
			virtual std::string get_name() const;
			virtual uint64_t get_block_size() const;
			virtual uint64_t get_key_size() const;
			virtual extend_key_func           get_extend_key() const;
			virtual block_cryption_func       get_encrypt() const;
			virtual block_cryption_func       get_decrypt() const;
			virtual block_self_cryption_func  get_encrypt_self() const;
			virtual block_self_cryption_func  get_decrypt_self() const;
		};
	}

	namespace padding
	{
		using padding_func = std::function<void(Data&, uint64_t)>;

		class DOG_CRYPTION_API Padding
		{
		protected:
			std::string name;
		public:
			/*
			以下具体函数在子类实现
			void padding(Data& data, uint64_t block_size);
			void unpadding(Data& data, uint64_t block_size);
			*/
			Padding(const std::string& name);
			Padding();
			
			Padding(const Padding& padding);
			Padding operator=(const Padding& padding);
			Padding(Padding&& padding) noexcept;
			Padding operator=(Padding&& padding) noexcept;

			virtual ~Padding() = default;
			virtual std::unique_ptr<Padding> clone() const;
			virtual Data to_data() const;
			virtual std::string fmt_config() const;
			virtual std::string get_name() const;
			virtual padding_func get_padding() const;
			virtual padding_func get_unpadding() const;
		};

		class DOG_CRYPTION_API None : public Padding
		{
		public:
			None();
			~None() = default;
			std::unique_ptr<Padding> clone() const override;
			Data to_data() const override;
			std::string fmt_config() const override;
			std::string get_name() const override;
			padding_func get_padding() const override;
			padding_func get_unpadding() const override;
		};
	}

	namespace mode
	{
		using dog_torch::asyncion::thread::PauseableChannel;
		using crypt_func           =    std::function<Data(const Data&, const Data&, const algorithm::Algorithm&)>;
		using streamp_crypt_func   =    std::function<void(PauseableChannel&, std::istream&, uint64_t, std::ostream&, const Data&, const algorithm::Algorithm&)>;
		using stream_crypt_func    =    std::function<void(std::istream&, uint64_t, std::ostream&, const Data&, const algorithm::Algorithm&)>;

		double update_progress(double progress, double progress_step, double progress_max);

		struct DOG_CRYPTION_API Config
		{
			std::string name;
			std::unordered_map<std::string, std::string> params;
			Config(const std::string& name, const std::unordered_map<std::string, std::string> params);
		};

		class DOG_CRYPTION_API Mode
		{
		protected:
			std::string name;
		public:
			Mode(const std::string& name) : name(name) {};
			
			virtual ~Mode() = default;
			virtual std::unique_ptr<Mode> clone() const;

			virtual std::string fmt_config() const;
			virtual Data to_data() const;

			virtual bool set_uint64_param(const std::string& param, uint64_t value);
			virtual bool set_string_param(const std::string& param,const std::string& value);
			virtual bool set_data_param(const std::string& param,const Data& value);
			virtual bool set_Padding(const padding::Padding& value);

			virtual bool check(const algorithm::Algorithm& algorithm) const;

			virtual crypt_func get_mult_encrypt() const;
			virtual crypt_func get_mult_decrypt() const;

			virtual stream_crypt_func get_stream_encrypt() const;
			virtual stream_crypt_func get_stream_decrypt() const;

			virtual streamp_crypt_func get_streamp_encrypt() const;
			virtual streamp_crypt_func get_streamp_decrypt() const;
		};
	}

	class DOG_CRYPTION_API CryptionConfig
	{
	public:
		std::unique_ptr<algorithm::Algorithm>   algorithm_;
		std::unique_ptr<mode::Mode>             mode_;

		CryptionConfig(const algorithm::Algorithm& algorithm, const mode::Mode& mode);
		CryptionConfig(algorithm::Algorithm&& algorithm, mode::Mode&& mode);
		CryptionConfig(const CryptionConfig& other);
		CryptionConfig(CryptionConfig&& other);
		void swap(CryptionConfig& other);
		Data to_data() const;
		std::string to_string() const;
	};

	class DOG_CRYPTION_API Cipher
	{
	private:
		CryptionConfig    config_;
		bool              is_setting_key_ = false;
		Data              original_key_;
		Data              available_key_;
	public:
		Cipher(const algorithm::Algorithm& algorithm, const mode::Mode& mode);
		Cipher(const Cipher& other) noexcept;
		Cipher(Cipher&& other) noexcept;
		
		void set_key(Data key);
		bool is_available() const;

 		void swap(Cipher& other);
 		void swap_config(Cipher& other);

		uint64_t get_block_size() const;
		uint64_t get_key_size() const;

		Data& get_original_key();
		Data& get_available_key();

 		const Data& get_original_key() const;
		const Data& get_available_key() const;

		const algorithm::block_self_cryption_func get_block_self_encryption() const;
		const algorithm::block_self_cryption_func get_block_self_decryption() const;

		const algorithm::block_cryption_func get_block_encryption() const;
		const algorithm::block_cryption_func get_block_decryption() const;

		algorithm::block_self_cryption_func get_block_self_encryption();
		algorithm::block_self_cryption_func get_block_self_decryption();

		algorithm::block_cryption_func get_block_encryption();
		algorithm::block_cryption_func get_block_decryption();

		Data to_data() const;
		std::string to_string() const;
		const algorithm::Algorithm& get_algorithm() const;
		const mode::Mode& get_mode() const;

		algorithm::Algorithm& get_algorithm();
		mode::Mode& get_mode();

		bool set_mode_uint64_param(const std::string& param, uint64_t value);
		bool set_mode_string_param(const std::string& param, const std::string& value);
		bool set_mode_data_param(const std::string& param, const Data& value);
		bool set_mode_Padding(const padding::Padding& value);

		using PauseableChannel = dog_torch::asyncion::thread::PauseableChannel;

 		Data encrypt(const Data& plain);
		void encrypt(std::istream& plain, uint64_t max, std::ostream& crypt);
		void encrypt(std::filesystem::path plain, std::filesystem::path crypt);

		Data decrypt(const Data& crypt);
 		void decrypt(std::istream& crypt, uint64_t max, std::ostream& plain);
		void decrypt(std::filesystem::path crypt, std::filesystem::path plain);
	};

}