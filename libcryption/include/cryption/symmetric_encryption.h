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

#include "data_bytes.h"

namespace dog_cryption
{
	namespace utils
	{
		DOG_CRYPTION_API uint8_t rand_byte();

		DOG_CRYPTION_API bool is_integer(std::any a);
		DOG_CRYPTION_API uint64_t get_integer(std::any a);

		DOG_CRYPTION_API dog_data::Data squareXOR(dog_data::Data& a, dog_data::Data& b, uint64_t size);
		DOG_CRYPTION_API void squareXOR_self(dog_data::Data& a, dog_data::Data& b, uint64_t size);
		DOG_CRYPTION_API dog_data::Data randiv(uint8_t block_size);

		DOG_CRYPTION_API dog_data::Data get_sequence(uint64_t lenght);
	}

	class DOG_CRYPTION_API CryptionException : public std::exception
	{
	private:
		std::string msg;
	public:
		CryptionException(const char* msg, const char* file, const char* function, uint64_t line);
		~CryptionException() = default;
		virtual const char* what() const throw();
	};

	class DOG_CRYPTION_API WrongKeyException : public std::exception
	{
	public:
		const char* what() const throw();
	};

	class DOG_CRYPTION_API WrongConfigException : public std::exception
	{
	public:
		const char* what() const throw();
	};

	class DOG_CRYPTION_API CryptionConfig
	{
	public:
		std::string cryption_algorithm;//算法名
		uint64_t block_size = 0;//块大小
		uint64_t key_size = 0;//密钥大小
        
        std::string mult_function;//多块加密函数
		uint64_t shift = 0;//CFB模式下偏移量
		bool using_iv = false;//是否使用iv
		bool using_padding = false;//是否使用填充
		std::string padding_function;//填充函数

		std::unordered_map<std::string, std::any> extra_config;//额外配置

		CryptionConfig() = default;
		CryptionConfig(
			const std::string& cryption_algorithm, const uint64_t block_size, const uint64_t key_size,
			bool using_padding, const std::string& padding_function,
			const std::string& mult_function, bool using_iv, uint64_t shift,
			std::vector<std::pair<std::string, std::any>> extra_config = std::vector<std::pair<std::string, std::any>>()
		);
		CryptionConfig(
			const std::string& cryption_algorithm, const uint64_t block_size, const uint64_t key_size,
			bool using_padding, const std::string& padding_function,
			const std::string& mult_function, bool using_iv, uint64_t shift,
			std::unordered_map<std::string, std::any> extra_config
		);
		dog_data::Data to_data() const;
		std::string to_string() const;
		/*
		* @param config_stream 带有配置信息头的流
		* @param return_start 是否返回流指针到开始处(默认回到)
		* @throw CryptionException
		* @return 配置信息
		*/
		static CryptionConfig get_cryption_config(std::istream& config_stream, bool return_start = true);
		static CryptionConfig get_cryption_config(dog_data::Data& config_data, bool is_cut);
	};

	class DOG_CRYPTION_API Cryptor
	{
	private:
		bool is_valid_ = false;//加密器是否有效
		CryptionConfig config_;//加密配置信息

		//密钥加工
		bool is_setting_key_ = false;//是否设置密钥
		dog_data::Data key_;//可用密钥
		dog_data::Data original_key_;//原始密钥
		std::function<dog_data::Data(dog_data::Data&, uint64_t)> extend_key_;//密钥扩展方法

		//填充/去填充方法
		std::function<void(dog_data::Data&, uint8_t)> padding_;
		std::function<void(dog_data::Data&, uint8_t)> unpadding_;
		
		//单块加密/解密方法
		std::function<void(dog_data::Data&, uint8_t, const dog_data::Data&, uint8_t)> block_encryption_self_;
		std::function<void(dog_data::Data&, uint8_t, const dog_data::Data&, uint8_t)> block_decryption_self_;

		std::function<dog_data::Data(dog_data::Data&, uint8_t, const dog_data::Data&, uint8_t)> block_encryption_;
		std::function<dog_data::Data(dog_data::Data&, uint8_t, const dog_data::Data&, uint8_t)> block_decryption_;
		
		//模式加密/解密方法
		std::function<dog_data::Data(dog_data::Data, dog_data::Data, dog_cryption::Cryptor&)> mult_encrypt_;
		std::function<dog_data::Data(dog_data::Data, dog_data::Data, dog_cryption::Cryptor&)> mult_decrypt_;

		std::function<void(std::istream&, dog_data::Data, std::ostream&, dog_cryption::Cryptor&)> stream_encrypt_;
		std::function<void(std::istream&, dog_data::Data, std::ostream&, dog_cryption::Cryptor&)> stream_decrypt_;

		std::function<void(std::istream&, dog_data::Data, std::ostream&, dog_cryption::Cryptor&,
			std::mutex*, std::condition_variable*, std::atomic<double>*, std::atomic<bool>*, std::atomic<bool>*, std::atomic<bool>*)> stream_encryptp_;
		std::function<void(std::istream&, dog_data::Data, std::ostream&, dog_cryption::Cryptor&, 
			std::mutex*, std::condition_variable*, std::atomic<double>*, std::atomic<bool>*, std::atomic<bool>*, std::atomic<bool>*)> stream_decryptp_;

	public:
		static bool is_config_available(const CryptionConfig& config);
		static std::unordered_map<std::string, std::any> turn_map(std::vector<std::pair<std::string, std::any>> vec);
		static std::vector<std::pair<std::string, std::any>> turn_vec(std::unordered_map<std::string, std::any> map);

		/*
		* 构造函数
		* @param cryption_algorithm 加密算法名
		* @param block_size 块大小
		* @param key_size 密钥大小
		* @param padding_function 填充函数
		* @param mult_function 多块加密函数
		* @param using_iv 是否使用iv
		* @param using_padding 是否使用填充
		* @param using_parallelism 是否使用并行
		*/
		Cryptor(
			const std::string& cryption_algorithm, const uint64_t block_size, const uint64_t key_size,
			bool using_padding, const std::string& padding_function,
			const std::string& mult_function, bool using_iv, uint64_t shift,
			std::vector<std::pair<std::string, std::any>> extra_config = std::vector<std::pair<std::string, std::any>>()
		);
		Cryptor(
			const std::string& cryption_algorithm, const uint64_t block_size, const uint64_t key_size,
			bool using_padding, const std::string& padding_function,
			const std::string& mult_function, bool using_iv, uint64_t shift,
			std::unordered_map<std::string, std::any> extra_config_
		) : 
			Cryptor(cryption_algorithm, block_size, key_size, using_padding, padding_function, mult_function, using_iv, shift, turn_vec(extra_config_)) {};
		Cryptor(const CryptionConfig& config) : 
			Cryptor(
				config.cryption_algorithm, config.block_size, config.key_size, 
				config.using_padding, config.padding_function, 
				config.mult_function, config.using_iv, config.shift,
				config.extra_config
			) {}
		void set_key(dog_data::Data key);

		void swap(Cryptor& other);
		void swap_config(Cryptor& other);
		
		uint64_t get_block_size() const;
        uint64_t get_key_size() const;

		bool get_using_iv() const;
		bool get_using_padding() const;
		
		dog_data::Data get_original_key() const;
		dog_data::Data get_available_key() const;

		std::function<void(dog_data::Data&, uint8_t)> get_padding() const;
		std::function<void(dog_data::Data&, uint8_t)> get_unpadding() const;

		std::function<void(dog_data::Data&, uint8_t, const dog_data::Data&, uint8_t)> get_block_self_encryption() const;
		std::function<void(dog_data::Data&, uint8_t, const dog_data::Data&, uint8_t)> get_block_self_decryption() const;

		std::function<dog_data::Data(dog_data::Data&, uint8_t, const dog_data::Data&, uint8_t)> get_block_encryption() const;
		std::function<dog_data::Data(dog_data::Data&, uint8_t, const dog_data::Data&, uint8_t)> get_block_decryption() const;

		dog_cryption::CryptionConfig get_config();
		uint64_t get_reback_size() const;
		bool is_available() const;

		dog_data::Data encrypt(dog_data::Data plain, bool with_config, bool with_iv, dog_data::Data iv, bool with_check);
		void encrypt(std::istream& plain, std::ostream& crypt, bool with_config, bool with_iv, dog_data::Data iv, bool with_check);
		void encryptp(std::istream& plain, std::ostream& crypt, bool with_config, bool with_iv, dog_data::Data iv, bool with_check,
			std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_);
		dog_data::Data decrypt(dog_data::Data crypt, bool with_config, bool with_iv, dog_data::Data iv, bool with_check);
		void decrypt(std::istream& crypt, std::ostream& plain,bool with_config, bool with_iv, dog_data::Data iv, bool with_check);
		void decryptp(std::istream& plain, std::ostream& crypt, bool with_config, bool with_iv, dog_data::Data iv, bool with_check,
			std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_);
	};

	namespace padding
	{
		/*
		    0 NONE        no fill                                                                       不填充
			1 PKCS7       all fill value of length less than 16B                                        全部填充少于16B的长度值
			2 ZERO        all fill 0 -- not suggestion                                                  全部填充0--不建议使用
			3 ANSIX923    all fill 0 but the last one fill value of length less than 16B                全部填充0，但是最后一个填充的是少于16B的长度值
			4 ISO7816_4   all fill 0 but the first one fill value 0x80                                  全部填充0，但是第一个填充的是0x80
			5 ISO10126    all fill randon value but the last one fill value of length less than 16B     全部填充随机数，但是最后一个填充的是少于16B的长度值
		*/

		class DOG_CRYPTION_API Config
		{
		public:
			std::string name_;
			uint8_t code_;
			Config(std::string name, uint8_t code);
		};

		extern const DOG_CRYPTION_API std::string NONE;
		extern const DOG_CRYPTION_API uint8_t NONE_CODE;
		extern const DOG_CRYPTION_API Config NONE_CONFIG;
		DOG_CRYPTION_API void NONE_padding(dog_data::Data& data, uint8_t block_size);
		DOG_CRYPTION_API void NONE_unpadding(dog_data::Data& data, uint8_t block_size);

		extern const DOG_CRYPTION_API std::string PKCS7;
		extern const DOG_CRYPTION_API uint8_t PKCS7_CODE;
		extern const DOG_CRYPTION_API Config PKCS7_CONFIG;
		DOG_CRYPTION_API void PKCS7_padding(dog_data::Data& data,uint8_t block_size);
		DOG_CRYPTION_API void PKCS7_unpadding(dog_data::Data& data, uint8_t block_size);
        
		extern const DOG_CRYPTION_API std::string ZERO;
		extern const DOG_CRYPTION_API uint8_t ZERO_CODE;
		extern const DOG_CRYPTION_API Config ZERO_CONFIG;
		DOG_CRYPTION_API void ZERO_padding(dog_data::Data& data, uint8_t block_size);
		DOG_CRYPTION_API void ZERO_unpadding(dog_data::Data& data, uint8_t block_size);

		extern const DOG_CRYPTION_API std::string ANSIX923;
		extern const DOG_CRYPTION_API uint8_t ANSIX923_CODE;
		extern const DOG_CRYPTION_API Config ANSIX923_CONFIG;
		DOG_CRYPTION_API void ANSIX923_padding(dog_data::Data& data, uint8_t block_size);
		DOG_CRYPTION_API void ANSIX923_unpadding(dog_data::Data& data, uint8_t block_size);

		extern const DOG_CRYPTION_API std::string ISO7816_4;
		extern const DOG_CRYPTION_API uint8_t ISO7816_4_CODE;
		extern const DOG_CRYPTION_API Config ISO7816_4_CONFIG;
		DOG_CRYPTION_API void ISO7816_4_padding(dog_data::Data& data, uint8_t block_size);
		DOG_CRYPTION_API void ISO7816_4_unpadding(dog_data::Data& data, uint8_t block_size);

		extern const DOG_CRYPTION_API std::string ISO10126;
		extern const DOG_CRYPTION_API uint8_t ISO10126_CODE;
		extern const DOG_CRYPTION_API Config ISO10126_CONFIG;
		DOG_CRYPTION_API void ISO10126_padding(dog_data::Data& data, uint8_t block_size);
		DOG_CRYPTION_API void ISO10126_unpadding(dog_data::Data& data, uint8_t block_size);

		extern const DOG_CRYPTION_API std::vector<Config> list;
	}

	namespace mode
	{
		/*
		   vx:不强制 v:强制
		          iv|填充|
			ECB  |vx|v |
			CBC  |v |v |
			PCBC |v |v |
			OFB  |v |vx|
			CTR  |v |vx|
			CFB  |v |vx|
		*/

		class DOG_CRYPTION_API Config
		{
		public:
			std::string name_;
			uint8_t code_;
			bool force_iv_;
			bool force_padding_;
			bool force_shift_;
			Config(std::string name, uint8_t code, bool force_iv, bool force_padding, bool force_shift_);
		};

		double update_progress(double progress, double progress_step, double progress_max);

		namespace ECB
		{
			extern const DOG_CRYPTION_API std::string name;
			extern const DOG_CRYPTION_API uint8_t CODE;
			extern const DOG_CRYPTION_API Config CONFIG;
			DOG_CRYPTION_API dog_data::Data encrypt(dog_data::Data plain, dog_data::Data iv, dog_cryption::Cryptor& cryptor);
			DOG_CRYPTION_API dog_data::Data decrypt(dog_data::Data crypt, dog_data::Data iv, dog_cryption::Cryptor& cryptor);
			DOG_CRYPTION_API void encrypt_stream(std::istream& plain, dog_data::Data iv, std::ostream& crypt, dog_cryption::Cryptor& cryptor);
			DOG_CRYPTION_API void decrypt_stream(std::istream& crypt, dog_data::Data iv, std::ostream& plain, dog_cryption::Cryptor& cryptor);
			DOG_CRYPTION_API void encrypt_streamp(std::istream& plain, dog_data::Data iv, std::ostream& crypt, dog_cryption::Cryptor& cryptor,
				std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress_, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_);
			DOG_CRYPTION_API void decrypt_streamp(std::istream& crypt, dog_data::Data iv, std::ostream& plain, dog_cryption::Cryptor& cryptor,
				std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress_, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_);
		};

		namespace CBC
		{
			extern const DOG_CRYPTION_API std::string name;
			extern const DOG_CRYPTION_API uint8_t CODE;
			extern const DOG_CRYPTION_API Config CONFIG;
			DOG_CRYPTION_API dog_data::Data encrypt(dog_data::Data plain, dog_data::Data iv, dog_cryption::Cryptor& cryptor);
			DOG_CRYPTION_API dog_data::Data decrypt(dog_data::Data crypt, dog_data::Data iv, dog_cryption::Cryptor& cryptor);
			DOG_CRYPTION_API void encrypt_stream(std::istream& plain, dog_data::Data iv, std::ostream& crypt, dog_cryption::Cryptor& cryptor);
			DOG_CRYPTION_API void decrypt_stream(std::istream& crypt, dog_data::Data iv, std::ostream& plain, dog_cryption::Cryptor& cryptor);
			DOG_CRYPTION_API void encrypt_streamp(std::istream& plain, dog_data::Data iv, std::ostream& crypt, dog_cryption::Cryptor& cryptor,
				std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress_, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_);
			DOG_CRYPTION_API void decrypt_streamp(std::istream& crypt, dog_data::Data iv, std::ostream& plain, dog_cryption::Cryptor& cryptor,
				std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress_, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_);
		};

		namespace PCBC
		{
			extern const DOG_CRYPTION_API std::string name;
			extern const DOG_CRYPTION_API uint8_t CODE;
			extern const DOG_CRYPTION_API Config CONFIG;
			DOG_CRYPTION_API dog_data::Data encrypt(dog_data::Data plain, dog_data::Data iv, dog_cryption::Cryptor& cryptor);
			DOG_CRYPTION_API dog_data::Data decrypt(dog_data::Data crypt, dog_data::Data iv, dog_cryption::Cryptor& cryptor);
			DOG_CRYPTION_API void encrypt_stream(std::istream& plain, dog_data::Data iv, std::ostream& crypt, dog_cryption::Cryptor& cryptor);
			DOG_CRYPTION_API void decrypt_stream(std::istream& crypt, dog_data::Data iv, std::ostream& plain, dog_cryption::Cryptor& cryptor);
			DOG_CRYPTION_API void encrypt_streamp(std::istream& plain, dog_data::Data iv, std::ostream& crypt, dog_cryption::Cryptor& cryptor,
				std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress_, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_);
			DOG_CRYPTION_API void decrypt_streamp(std::istream& crypt, dog_data::Data iv, std::ostream& plain, dog_cryption::Cryptor& cryptor,
				std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress_, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_);
		};

		namespace OFB
		{
			extern const DOG_CRYPTION_API std::string name;
			extern const DOG_CRYPTION_API uint8_t CODE;
			extern const DOG_CRYPTION_API Config CONFIG;
			DOG_CRYPTION_API dog_data::Data encrypt(dog_data::Data plain, dog_data::Data iv, dog_cryption::Cryptor& cryptor);
			DOG_CRYPTION_API dog_data::Data decrypt(dog_data::Data crypt, dog_data::Data iv, dog_cryption::Cryptor& cryptor);
			DOG_CRYPTION_API void encrypt_stream(std::istream& plain, dog_data::Data iv, std::ostream& crypt, dog_cryption::Cryptor& cryptor);
			DOG_CRYPTION_API void decrypt_stream(std::istream& crypt, dog_data::Data iv, std::ostream& plain, dog_cryption::Cryptor& cryptor);
			DOG_CRYPTION_API void encrypt_streamp(std::istream& plain, dog_data::Data iv, std::ostream& crypt, dog_cryption::Cryptor& cryptor,
				std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress_, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_);
			DOG_CRYPTION_API void decrypt_streamp(std::istream& crypt, dog_data::Data iv, std::ostream& plain, dog_cryption::Cryptor& cryptor,
				std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress_, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_);
		};
				
		namespace CTR
		{
			extern const DOG_CRYPTION_API std::string name;
			extern const DOG_CRYPTION_API uint8_t CODE;
			extern const DOG_CRYPTION_API Config CONFIG;
			DOG_CRYPTION_API dog_data::Data encrypt(dog_data::Data plain, dog_data::Data iv, dog_cryption::Cryptor& cryptor);
			DOG_CRYPTION_API dog_data::Data decrypt(dog_data::Data crypt, dog_data::Data iv, dog_cryption::Cryptor& cryptor);
			DOG_CRYPTION_API void encrypt_stream(std::istream& plain, dog_data::Data iv, std::ostream& crypt, dog_cryption::Cryptor& cryptor);
			DOG_CRYPTION_API void decrypt_stream(std::istream& crypt, dog_data::Data iv, std::ostream& plain, dog_cryption::Cryptor& cryptor);
			DOG_CRYPTION_API void encrypt_streamp(std::istream& plain, dog_data::Data iv, std::ostream& crypt, dog_cryption::Cryptor& cryptor,
				std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress_, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_);
			DOG_CRYPTION_API void decrypt_streamp(std::istream& crypt, dog_data::Data iv, std::ostream& plain, dog_cryption::Cryptor& cryptor,
				std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress_, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_);

		};
		
		namespace CFBB
		{
			extern const DOG_CRYPTION_API std::string name;
			extern const DOG_CRYPTION_API uint8_t CODE;
			extern const DOG_CRYPTION_API Config CONFIG;
			DOG_CRYPTION_API dog_data::Data encrypt(dog_data::Data plain, dog_data::Data iv, dog_cryption::Cryptor& cryptor);
			DOG_CRYPTION_API dog_data::Data decrypt(dog_data::Data crypt, dog_data::Data iv, dog_cryption::Cryptor& cryptor);
			DOG_CRYPTION_API void encrypt_stream(std::istream& plain, dog_data::Data iv, std::ostream& crypt, dog_cryption::Cryptor& cryptor);
			DOG_CRYPTION_API void decrypt_stream(std::istream& crypt, dog_data::Data iv, std::ostream& plain, dog_cryption::Cryptor& cryptor);
			DOG_CRYPTION_API void encrypt_streamp(std::istream& plain, dog_data::Data iv, std::ostream& crypt, dog_cryption::Cryptor& cryptor,
				std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress_, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_);
			DOG_CRYPTION_API void decrypt_streamp(std::istream& crypt, dog_data::Data iv, std::ostream& plain, dog_cryption::Cryptor& cryptor,
				std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress_, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_);

			DOG_CRYPTION_API dog_data::Data encrypt_CFB8(dog_data::Data plain, dog_data::Data iv, dog_cryption::Cryptor& cryptor);
			DOG_CRYPTION_API dog_data::Data decrypt_CFB8(dog_data::Data crypt, dog_data::Data iv, dog_cryption::Cryptor& cryptor);
			DOG_CRYPTION_API void encrypt_CFB8_stream(std::istream& plain, dog_data::Data iv, std::ostream& crypt, dog_cryption::Cryptor& cryptor);
			DOG_CRYPTION_API void decrypt_CFB8_stream(std::istream& crypt, dog_data::Data iv, std::ostream& plain, dog_cryption::Cryptor& cryptor);
			DOG_CRYPTION_API void encrypt_CFB8_streamp(std::istream& plain, dog_data::Data iv, std::ostream& crypt, dog_cryption::Cryptor& cryptor,
				std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress_, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_);
			DOG_CRYPTION_API void decrypt_CFB8_streamp(std::istream& crypt, dog_data::Data iv, std::ostream& plain, dog_cryption::Cryptor& cryptor,
				std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress_, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_);

			DOG_CRYPTION_API dog_data::Data encrypt_CFB128(dog_data::Data plain, dog_data::Data iv, dog_cryption::Cryptor& cryptor);
			DOG_CRYPTION_API dog_data::Data decrypt_CFB128(dog_data::Data crypt, dog_data::Data iv, dog_cryption::Cryptor& cryptor);
			DOG_CRYPTION_API void encrypt_CFB128_stream(std::istream& plain, dog_data::Data iv, std::ostream& crypt, dog_cryption::Cryptor& cryptor);
			DOG_CRYPTION_API void decrypt_CFB128_stream(std::istream& crypt, dog_data::Data iv, std::ostream& plain, dog_cryption::Cryptor& cryptor);
			DOG_CRYPTION_API void encrypt_CFB128_streamp(std::istream& plain, dog_data::Data iv, std::ostream& crypt, dog_cryption::Cryptor& cryptor,
				std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress_, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_);
			DOG_CRYPTION_API void decrypt_CFB128_streamp(std::istream& crypt, dog_data::Data iv, std::ostream& plain, dog_cryption::Cryptor& cryptor,
				std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress_, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_);
		};

		namespace CFBb
		{
			extern const DOG_CRYPTION_API std::string name;
			extern const DOG_CRYPTION_API uint8_t CODE;
			extern const DOG_CRYPTION_API Config CONFIG;
			DOG_CRYPTION_API dog_data::Data encrypt(dog_data::Data plain, dog_data::Data iv, dog_cryption::Cryptor& cryptor);
			DOG_CRYPTION_API dog_data::Data decrypt(dog_data::Data crypt, dog_data::Data iv, dog_cryption::Cryptor& cryptor);
			DOG_CRYPTION_API void encrypt_stream(std::istream& plain, dog_data::Data iv, std::ostream& crypt, dog_cryption::Cryptor& cryptor);
			DOG_CRYPTION_API void decrypt_stream(std::istream& crypt, dog_data::Data iv, std::ostream& plain, dog_cryption::Cryptor& cryptor);
			DOG_CRYPTION_API void encrypt_streamp(std::istream& plain, dog_data::Data iv, std::ostream& crypt, dog_cryption::Cryptor& cryptor,
				std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress_, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_);
			DOG_CRYPTION_API void decrypt_streamp(std::istream& crypt, dog_data::Data iv, std::ostream& plain, dog_cryption::Cryptor& cryptor,
				std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress_, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_);

			DOG_CRYPTION_API dog_data::Data encrypt_CFB1(dog_data::Data plain, dog_data::Data iv, dog_cryption::Cryptor& cryptor);
			DOG_CRYPTION_API dog_data::Data decrypt_CFB1(dog_data::Data crypt, dog_data::Data iv, dog_cryption::Cryptor& cryptor);
			DOG_CRYPTION_API void encrypt_CFB1_stream(std::istream& plain, dog_data::Data iv, std::ostream& crypt, dog_cryption::Cryptor& cryptor);
			DOG_CRYPTION_API void decrypt_CFB1_stream(std::istream& crypt, dog_data::Data iv, std::ostream& plain, dog_cryption::Cryptor& cryptor);
			DOG_CRYPTION_API void encrypt_CFB1_streamp(std::istream& plain, dog_data::Data iv, std::ostream& crypt, dog_cryption::Cryptor& cryptor,
				std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress_, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_);
			DOG_CRYPTION_API void decrypt_CFB1_streamp(std::istream& crypt, dog_data::Data iv, std::ostream& plain, dog_cryption::Cryptor& cryptor,
				std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress_, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_);
		};

		extern const DOG_CRYPTION_API std::vector<Config> list;
	}

	/*
	namespace <加密算法>
	{
		const std::string name = "加密算法名";
		const std::string BLOCK_REGION = "分组范围";
		const std::string KEY_REGION = "密钥范围";

		<!--
		中间函数和常量
		-->

		//密钥加工
		const dog_data::Data extend_key(dog_data::Data& key, uint64_t key_size);
		//加密有返回
		dog_data::Data encoding(dog_data::Data& plain, uint8_t block_size, const dog_data::Data& key, uint8_t key_size);
		dog_data::Data decoding(dog_data::Data& crypt, uint8_t block_size, const dog_data::Data& key, uint8_t key_size);
		//加密无返回
		void encoding_self(dog_data::Data& plain, uint8_t block_size, const dog_data::Data& key, uint8_t key_size);
		void decoding_self(dog_data::Data& crypt, uint8_t block_size, const dog_data::Data& key, uint8_t key_size);
	}
	*/

	/*
	RC6, MARS, Twofish, Serpent, CAST-256,ARIA, Blowfish, CHAM, HIGHT, IDEA, Kalyna (128/256/512), LEA, SEED, RC5, SHACAL-2, SIMECK, SIMON (64/128), Skipjack, SPECK (64/128), Simeck,Threefish (256/512/1024), Triple-DES (DES-EDE2 and DES-EDE3), TEA, XTEA
	*/

	class DOG_CRYPTION_API AlgorithmConfig
	{
	public:
		std::string name;
		std::string block_size_region;
		std::string key_size_region;
		AlgorithmConfig(std::string name, std::string block_size_region, std::string key_size_region);
	};

	namespace AES
	{
		//unit单位:uint8_t字节
		extern const DOG_CRYPTION_API std::string name;
		
		extern const DOG_CRYPTION_API std::string BLOCK_REGION;
		extern const DOG_CRYPTION_API uint8_t BLOCK_128;
		
		extern const DOG_CRYPTION_API std::string KEY_REGION;
		extern const DOG_CRYPTION_API uint64_t KEY_128;
        extern const DOG_CRYPTION_API uint64_t KEY_192;
		extern const DOG_CRYPTION_API uint64_t KEY_256;
		extern const DOG_CRYPTION_API AlgorithmConfig CONFIG;
		extern const DOG_CRYPTION_API uint8_t SBox[16][16];
		extern const DOG_CRYPTION_API uint8_t InvSBox[16][16];

		extern const DOG_CRYPTION_API uint8_t MixTable[16];
		extern const DOG_CRYPTION_API uint8_t UMixTable[16];

		extern const DOG_CRYPTION_API uint8_t round[10];
		DOG_CRYPTION_API dog_data::Data extendKey128(dog_data::Data& key);
		DOG_CRYPTION_API dog_data::Data extendKey192(dog_data::Data& key);
		DOG_CRYPTION_API dog_data::Data extendKey256(dog_data::Data& key);
		DOG_CRYPTION_API dog_data::Data extend_key(dog_data::Data& key, uint64_t key_size);

		//the value of a must be 0x01 0x02 0x03 a的值只能为0x01,0x02,0x03
		DOG_CRYPTION_API uint8_t Xtime(uint8_t a, uint8_t b);

		//each block encrypt and using funcation 区块加密及内部算法

		//AES加解密中 字节代还 行移位 列混合混合方法
		DOG_CRYPTION_API dog_data::Data middle_encryption(dog_data::Data datablock, int flag, int mode);
        DOG_CRYPTION_API dog_data::Data middle_decryption(dog_data::Data datablock, int flag, int mode);

		DOG_CRYPTION_API dog_data::Data encoding(dog_data::Data& plain, uint8_t block_size, const dog_data::Data& key, uint8_t key_size);
		DOG_CRYPTION_API dog_data::Data decoding(dog_data::Data& crypt, uint8_t block_size, const dog_data::Data& key, uint8_t key_size);

		DOG_CRYPTION_API void encoding_self(dog_data::Data& plain, uint8_t block_size, const dog_data::Data& key, uint8_t key_size);
		DOG_CRYPTION_API void decoding_self(dog_data::Data& crypt, uint8_t block_size, const dog_data::Data& key, uint8_t key_size);
	}

	namespace SM4
	{
		//unit单位:uint8_t字节
		extern const DOG_CRYPTION_API std::string name;

		extern const DOG_CRYPTION_API std::string BLOCK_REGION;
		extern const DOG_CRYPTION_API uint8_t BLOCK_128; 
		
		extern const DOG_CRYPTION_API std::string KEY_REGION;
		extern const DOG_CRYPTION_API uint64_t KEY_128;
		extern const DOG_CRYPTION_API AlgorithmConfig CONFIG;

		extern const DOG_CRYPTION_API uint8_t SBox[16][16];

		extern const DOG_CRYPTION_API uint32_t FK[4];
		extern const DOG_CRYPTION_API uint32_t CK[32];

		DOG_CRYPTION_API uint32_t TMixChange1(uint32_t n);
		DOG_CRYPTION_API uint32_t TMixChange2(uint32_t n);

		DOG_CRYPTION_API dog_data::Data extend_key(dog_data::Data key, uint64_t key_size = 16);

		DOG_CRYPTION_API dog_data::Data encoding(dog_data::Data& plain, uint8_t block_size, const dog_data::Data& key, uint8_t key_size);
		DOG_CRYPTION_API dog_data::Data decoding(dog_data::Data& crypt, uint8_t block_size, const dog_data::Data& key, uint8_t key_size);

		DOG_CRYPTION_API void encoding_self(dog_data::Data& plain, uint8_t block_size, const dog_data::Data& key, uint8_t key_size);
		DOG_CRYPTION_API void decoding_self(dog_data::Data& crypt, uint8_t block_size, const dog_data::Data& key, uint8_t key_size);
	}

	namespace camellia
	{
		//unit单位:uint8_t字节
		extern const DOG_CRYPTION_API std::string name;

		extern const DOG_CRYPTION_API std::string BLOCK_REGION;
		extern const DOG_CRYPTION_API uint8_t BLOCK_128;

		extern const DOG_CRYPTION_API std::string KEY_REGION;
		extern const DOG_CRYPTION_API uint64_t KEY_128;
		extern const DOG_CRYPTION_API uint64_t KEY_192;
		extern const DOG_CRYPTION_API uint64_t KEY_256;
		extern const DOG_CRYPTION_API AlgorithmConfig CONFIG;

		extern const DOG_CRYPTION_API uint8_t Sbox[256];

		extern const DOG_CRYPTION_API uint64_t sigma[6];

		DOG_CRYPTION_API std::pair<uint64_t, uint64_t> CLMB(uint64_t l, uint64_t r, uint64_t i);

		DOG_CRYPTION_API uint8_t s1(uint8_t n);
		DOG_CRYPTION_API uint8_t s2(uint8_t n);
		DOG_CRYPTION_API uint8_t s3(uint8_t n);
		DOG_CRYPTION_API uint8_t s4(uint8_t n);

		DOG_CRYPTION_API uint64_t s(uint64_t n);
		DOG_CRYPTION_API uint64_t p(uint64_t n);
		DOG_CRYPTION_API uint64_t FL(uint64_t x, uint64_t kl);
		DOG_CRYPTION_API uint64_t FL_inv(uint64_t y, uint64_t kl);
		DOG_CRYPTION_API uint64_t F(uint64_t x, uint64_t k);

		DOG_CRYPTION_API dog_data::Data extend_key(dog_data::Data key, uint64_t key_size = 16);

		DOG_CRYPTION_API dog_data::Data encoding(dog_data::Data& plain, uint8_t block_size, const dog_data::Data& key, uint8_t key_size);
		DOG_CRYPTION_API dog_data::Data decoding(dog_data::Data& crypt, uint8_t block_size, const dog_data::Data& key, uint8_t key_size);

		DOG_CRYPTION_API void encoding_self(dog_data::Data& plain, uint8_t block_size, const dog_data::Data& key, uint8_t key_size);
		DOG_CRYPTION_API void decoding_self(dog_data::Data& crypt, uint8_t block_size, const dog_data::Data& key, uint8_t key_size);

	}

	namespace Twofish
	{

	}

	extern const DOG_CRYPTION_API std::vector<AlgorithmConfig> Algorithm_list;
}
