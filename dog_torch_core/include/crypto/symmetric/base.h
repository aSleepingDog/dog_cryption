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

namespace dog_torch { namespace crypto {namespace symmetric
{
    using Data = dog_torch::serialize::Data;

	namespace utils
	{
		DOG_CRYPTION_API uint8_t rand_byte();

		/*
		* @Params a: Data
		* @Params b: Data
		* @Params size: uint64_t
		* @Return: Data = a[0 -> size-1] XOR b[0 -> size-1]
		*/
		DOG_CRYPTION_API Data squareXOR(const Data& a, const Data& b, uint64_t size);
		/*
		* @Params a: Data
		* @Params b: Data
		* @Params size: uint64_t
		* @Return: a[0 -> size-1] = a[0 -> size-1] XOR b[0 -> size-1]
		*/
		DOG_CRYPTION_API void squareXOR_self(Data& a, Data& b, uint64_t size);
		DOG_CRYPTION_API Data randiv(uint8_t block_size);

		DOG_CRYPTION_API Data get_sequence(uint64_t lenght);
	}

	class DOG_CRYPTION_API CryptionException : public dog_torch::utils::Exception
	{
	public:
		CryptionException(DOG_EXCEPTION_MSG_PARAMS) : dog_torch::utils::Exception(DOG_EXCEPTION_MSG_OPINION(msg)) {}
	};

	class DOG_CRYPTION_API WrongKeyException : public dog_torch::utils::Exception
	{
	public:
		WrongKeyException(DOG_EXCEPTION_PARAMS) : dog_torch::utils::Exception(DOG_EXCEPTION_MSG_OPINION("wrong key")) {}
	};

	class DOG_CRYPTION_API WrongConfigException : public dog_torch::utils::Exception
	{
	public:
		WrongConfigException(DOG_EXCEPTION_PARAMS) : dog_torch::utils::Exception(DOG_EXCEPTION_MSG_OPINION("invalid cryption algorithm")) {}
	};

	namespace algorithm
	{
		using Extend_key_func = std::function<Data(const Data&, uint64_t, uint64_t)>;
		using Block_self_cryption_func = std::function<void(Data&, uint64_t, const Data&, uint64_t)>;
		using Block_cryption_func = std::function<Data(const Data&, uint64_t, const Data&, uint64_t)>;

		class DOG_CRYPTION_API Config
		{
		public:
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

			Algorithm(const std::string& name, const uint64_t block_size, const uint64_t key_size) : 
				name(name), block_size(block_size), key_size(key_size) {};
			virtual ~Algorithm() = default;
			virtual std::unique_ptr<Algorithm> clone() const;
			virtual Data to_data() const;
			virtual std::string fmt_config() const;
			virtual std::string get_name() const;
			virtual uint64_t get_block_size() const;
			virtual uint64_t get_key_size() const;
			virtual Extend_key_func           get_extend_key() const;
			virtual Block_cryption_func       get_encrypt() const;
			virtual Block_cryption_func       get_decrypt() const;
			virtual Block_self_cryption_func  get_encrypt_self() const;
			virtual Block_self_cryption_func  get_decrypt_self() const;
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
			virtual ~Padding() = default;
			virtual std::unique_ptr<Padding> clone() const;
			virtual Data to_data() const;
			virtual std::string fmt_config() const;
			virtual std::string get_name() const;
			virtual padding_func get_padding() const;
			virtual padding_func get_unpadding() const;
		};
	}
	class Cipher;
	namespace mode
	{
		using crypt_func           =    std::function<Data(const Data&, const Cipher&)>;
		using stream_crypt_func    =    std::function<void(std::istream&, std::ostream&, const Cipher&)>;
		using stream_cryptp_func   =    std::function<void(std::istream&, std::ostream&, const Cipher&,
			std::mutex*, std::condition_variable*, std::atomic<double>*, std::atomic<bool>*, std::atomic<bool>*, std::atomic<bool>*)>;

		double update_progress(double progress, double progress_step, double progress_max);

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

			virtual crypt_func get_mult_encrypt() const;
			virtual crypt_func get_mult_decrypt() const;

			virtual stream_crypt_func get_stream_encrypt() const;
			virtual stream_crypt_func get_stream_decrypt() const;

			virtual stream_cryptp_func get_stream_encryptp() const;
			virtual stream_cryptp_func get_stream_decryptp() const;
		};
	}

	class DOG_CRYPTION_API CryptionConfig
	{
	public:
		std::unique_ptr<algorithm::Algorithm>   algorithm_;
		std::unique_ptr<mode::Mode>             mode_;

		CryptionConfig(const algorithm::Algorithm& algorithm, const mode::Mode& mode);
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

		const algorithm::Block_self_cryption_func get_block_self_encryption() const;
		const algorithm::Block_self_cryption_func get_block_self_decryption() const;

		const algorithm::Block_cryption_func get_block_encryption() const;
		const algorithm::Block_cryption_func get_block_decryption() const;

		algorithm::Block_self_cryption_func get_block_self_encryption();
		algorithm::Block_self_cryption_func get_block_self_decryption();

		algorithm::Block_cryption_func get_block_encryption();
		algorithm::Block_cryption_func get_block_decryption();

 		//CryptionConfig get_config();
		const algorithm::Algorithm& get_algorithm() const;
		const mode::Mode& get_mode() const;

		algorithm::Algorithm& get_algorithm();
		mode::Mode& get_mode();

 		Data encrypt(const Data& plain);
 		void encrypt(std::istream& plain, std::ostream& crypt);
 		void encryptp(std::istream& plain, std::ostream& crypt,
 			std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress_, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_);
 		Data decrypt(const Data& crypt);
 		void decrypt(std::istream& crypt, std::ostream& plain);
 		void decryptp(std::istream& plain, std::ostream& crypt,
 			std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress_, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_);

	};

}}}