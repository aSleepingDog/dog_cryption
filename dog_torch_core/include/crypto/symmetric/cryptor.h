// #pragma once
// #ifdef SHARED
// 	#include "export.h"
// #else
// 	#define DOG_CRYPTION_API
// #endif
// #include <any>
// #include <mutex>
// #include <regex>
// #include <print>
// #include <thread>
// #include <atomic>
// #include <bitset>
// #include <string>
// #include <random>
// #include <format>
// #include <cstdlib>
// #include <exception>
// #include <functional>
// #include <unordered_map>
// #include <condition_variable>

// #include "serialize/serialize.h"
// #include "math/math.h"
// #include "symmetric_base.h"
// #include "AES.h"
// #include "SM4.h"
// #include "camellia.h"
// #include "Twofish.h"




// namespace dog_torch { namespace crypto {namespace symmetric
// {
// 	class Cryptor;
// 	class CryptionConfig;
// 	extern const DOG_CRYPTION_API std::vector<AlgorithmConfig> Algorithm_list;
	    	
// 	namespace padding
// 	{
// 		/*
// 		    0 NONE        no fill                                                                       不填充
// 			1 PKCS7       all fill value of length less than 16B                                        全部填充少于16B的长度值
// 			2 ZERO        all fill 0 -- not suggestion                                                  全部填充0--不建议使用
// 			3 ANSIX923    all fill 0 but the last one fill value of length less than 16B                全部填充0，但是最后一个填充的是少于16B的长度值
// 			4 ISO7816_4   all fill 0 but the first one fill value 0x80                                  全部填充0，但是第一个填充的是0x80
// 			5 ISO10126    all fill randon value but the last one fill value of length less than 16B     全部填充随机数，但是最后一个填充的是少于16B的长度值
// 		*/

// 		class DOG_CRYPTION_API Config
// 		{
// 		public:
// 			std::string name;
// 			uint64_t code;
// 			Config(std::string name, uint64_t code);
// 		};

// 		extern const DOG_CRYPTION_API Config NONE_CONFIG;
// 		DOG_CRYPTION_API void NONE_padding(Data& data, uint64_t block_size);
// 		DOG_CRYPTION_API void NONE_unpadding(Data& data, uint64_t block_size);

// 		extern const DOG_CRYPTION_API Config PKCS7_CONFIG;
// 		DOG_CRYPTION_API void PKCS7_padding(Data& data,uint64_t block_size);
// 		DOG_CRYPTION_API void PKCS7_unpadding(Data& data, uint64_t block_size);
        
// 		extern const DOG_CRYPTION_API Config ZERO_CONFIG;
// 		DOG_CRYPTION_API void ZERO_padding(Data& data, uint64_t block_size);
// 		DOG_CRYPTION_API void ZERO_unpadding(Data& data, uint64_t block_size);

// 		extern const DOG_CRYPTION_API Config ANSIX923_CONFIG;
// 		DOG_CRYPTION_API void ANSIX923_padding(Data& data, uint64_t block_size);
// 		DOG_CRYPTION_API void ANSIX923_unpadding(Data& data, uint64_t block_size);

// 		extern const DOG_CRYPTION_API Config ISO7816_4_CONFIG;
// 		DOG_CRYPTION_API void ISO7816_4_padding(Data& data, uint64_t block_size);
// 		DOG_CRYPTION_API void ISO7816_4_unpadding(Data& data, uint64_t block_size);

// 		extern const DOG_CRYPTION_API Config ISO10126_CONFIG;
// 		DOG_CRYPTION_API void ISO10126_padding(Data& data, uint64_t block_size);
// 		DOG_CRYPTION_API void ISO10126_unpadding(Data& data, uint64_t block_size);

// 		extern const DOG_CRYPTION_API std::vector<Config> list;
// 	}

// 	namespace mode
// 	{
// 		/*
// 		   vx:不强制 v:强制
// 		          iv|填充|
// 			ECB  |vx|v |
// 			CBC  |v |v |
// 			PCBC |v |v |
// 			OFB  |v |vx|
// 			CTR  |v |vx|
// 			CFB  |v |vx|
// 		*/

// 		class DOG_CRYPTION_API Config
// 		{
// 		public:
// 			std::string name;
// 			uint64_t code;
// 			bool force_iv;
// 			bool force_padding;
// 			bool force_shift;
// 			Config(std::string name, uint64_t code, bool force_iv, bool force_padding, bool force_shift);
// 		};

// 		double update_progress(double progress, double progress_step, double progress_max);

// 		namespace ECB
// 		{
// 			extern const DOG_CRYPTION_API Config CONFIG;
// 			DOG_CRYPTION_API Data encrypt(Data plain, Data iv, Cryptor& cryptor);
// 			DOG_CRYPTION_API Data decrypt(Data crypt, Data iv, Cryptor& cryptor);
// 			DOG_CRYPTION_API void encrypt_stream(std::istream& plain, Data iv, std::ostream& crypt, Cryptor& cryptor);
// 			DOG_CRYPTION_API void decrypt_stream(std::istream& crypt, Data iv, std::ostream& plain, Cryptor& cryptor);
// 			DOG_CRYPTION_API void encrypt_streamp(std::istream& plain, Data iv, std::ostream& crypt, Cryptor& cryptor,
// 				std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress_, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_);
// 			DOG_CRYPTION_API void decrypt_streamp(std::istream& crypt, Data iv, std::ostream& plain, Cryptor& cryptor,
// 				std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress_, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_);
// 		};

// 		namespace CBC
// 		{
// 			extern const DOG_CRYPTION_API Config CONFIG;
// 			DOG_CRYPTION_API Data encrypt(Data plain, Data iv, Cryptor& cryptor);
// 			DOG_CRYPTION_API Data decrypt(Data crypt, Data iv, Cryptor& cryptor);
// 			DOG_CRYPTION_API void encrypt_stream(std::istream& plain, Data iv, std::ostream& crypt, Cryptor& cryptor);
// 			DOG_CRYPTION_API void decrypt_stream(std::istream& crypt, Data iv, std::ostream& plain, Cryptor& cryptor);
// 			DOG_CRYPTION_API void encrypt_streamp(std::istream& plain, Data iv, std::ostream& crypt, Cryptor& cryptor,
// 				std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress_, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_);
// 			DOG_CRYPTION_API void decrypt_streamp(std::istream& crypt, Data iv, std::ostream& plain, Cryptor& cryptor,
// 				std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress_, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_);
// 		};

// 		namespace PCBC
// 		{
// 			extern const DOG_CRYPTION_API Config CONFIG;
// 			DOG_CRYPTION_API Data encrypt(Data plain, Data iv, Cryptor& cryptor);
// 			DOG_CRYPTION_API Data decrypt(Data crypt, Data iv, Cryptor& cryptor);
// 			DOG_CRYPTION_API void encrypt_stream(std::istream& plain, Data iv, std::ostream& crypt, Cryptor& cryptor);
// 			DOG_CRYPTION_API void decrypt_stream(std::istream& crypt, Data iv, std::ostream& plain, Cryptor& cryptor);
// 			DOG_CRYPTION_API void encrypt_streamp(std::istream& plain, Data iv, std::ostream& crypt, Cryptor& cryptor,
// 				std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress_, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_);
// 			DOG_CRYPTION_API void decrypt_streamp(std::istream& crypt, Data iv, std::ostream& plain, Cryptor& cryptor,
// 				std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress_, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_);
// 		};

// 		namespace OFB
// 		{
// 			extern const DOG_CRYPTION_API Config CONFIG;
// 			DOG_CRYPTION_API Data encrypt(Data plain, Data iv, Cryptor& cryptor);
// 			DOG_CRYPTION_API Data decrypt(Data crypt, Data iv, Cryptor& cryptor);
// 			DOG_CRYPTION_API void encrypt_stream(std::istream& plain, Data iv, std::ostream& crypt, Cryptor& cryptor);
// 			DOG_CRYPTION_API void decrypt_stream(std::istream& crypt, Data iv, std::ostream& plain, Cryptor& cryptor);
// 			DOG_CRYPTION_API void encrypt_streamp(std::istream& plain, Data iv, std::ostream& crypt, Cryptor& cryptor,
// 				std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress_, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_);
// 			DOG_CRYPTION_API void decrypt_streamp(std::istream& crypt, Data iv, std::ostream& plain, Cryptor& cryptor,
// 				std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress_, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_);
// 		};
				
// 		namespace CTR
// 		{
// 			extern const DOG_CRYPTION_API Config CONFIG;
// 			DOG_CRYPTION_API Data encrypt(Data plain, Data iv, Cryptor& cryptor);
// 			DOG_CRYPTION_API Data decrypt(Data crypt, Data iv, Cryptor& cryptor);
// 			DOG_CRYPTION_API void encrypt_stream(std::istream& plain, Data iv, std::ostream& crypt, Cryptor& cryptor);
// 			DOG_CRYPTION_API void decrypt_stream(std::istream& crypt, Data iv, std::ostream& plain, Cryptor& cryptor);
// 			DOG_CRYPTION_API void encrypt_streamp(std::istream& plain, Data iv, std::ostream& crypt, Cryptor& cryptor,
// 				std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress_, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_);
// 			DOG_CRYPTION_API void decrypt_streamp(std::istream& crypt, Data iv, std::ostream& plain, Cryptor& cryptor,
// 				std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress_, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_);

// 		};
		
// 		namespace CFBB
// 		{
// 			extern const DOG_CRYPTION_API Config CONFIG;
// 			DOG_CRYPTION_API Data encrypt(Data plain, Data iv, Cryptor& cryptor);
// 			DOG_CRYPTION_API Data decrypt(Data crypt, Data iv, Cryptor& cryptor);
// 			DOG_CRYPTION_API void encrypt_stream(std::istream& plain, Data iv, std::ostream& crypt, Cryptor& cryptor);
// 			DOG_CRYPTION_API void decrypt_stream(std::istream& crypt, Data iv, std::ostream& plain, Cryptor& cryptor);
// 			DOG_CRYPTION_API void encrypt_streamp(std::istream& plain, Data iv, std::ostream& crypt, Cryptor& cryptor,
// 				std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress_, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_);
// 			DOG_CRYPTION_API void decrypt_streamp(std::istream& crypt, Data iv, std::ostream& plain, Cryptor& cryptor,
// 				std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress_, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_);

// 			DOG_CRYPTION_API Data encrypt_CFB8(Data plain, Data iv, Cryptor& cryptor);
// 			DOG_CRYPTION_API Data decrypt_CFB8(Data crypt, Data iv, Cryptor& cryptor);
// 			DOG_CRYPTION_API void encrypt_CFB8_stream(std::istream& plain, Data iv, std::ostream& crypt, Cryptor& cryptor);
// 			DOG_CRYPTION_API void decrypt_CFB8_stream(std::istream& crypt, Data iv, std::ostream& plain, Cryptor& cryptor);
// 			DOG_CRYPTION_API void encrypt_CFB8_streamp(std::istream& plain, Data iv, std::ostream& crypt, Cryptor& cryptor,
// 				std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress_, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_);
// 			DOG_CRYPTION_API void decrypt_CFB8_streamp(std::istream& crypt, Data iv, std::ostream& plain, Cryptor& cryptor,
// 				std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress_, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_);

// 			DOG_CRYPTION_API Data encrypt_CFB128(Data plain, Data iv, Cryptor& cryptor);
// 			DOG_CRYPTION_API Data decrypt_CFB128(Data crypt, Data iv, Cryptor& cryptor);
// 			DOG_CRYPTION_API void encrypt_CFB128_stream(std::istream& plain, Data iv, std::ostream& crypt, Cryptor& cryptor);
// 			DOG_CRYPTION_API void decrypt_CFB128_stream(std::istream& crypt, Data iv, std::ostream& plain, Cryptor& cryptor);
// 			DOG_CRYPTION_API void encrypt_CFB128_streamp(std::istream& plain, Data iv, std::ostream& crypt, Cryptor& cryptor,
// 				std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress_, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_);
// 			DOG_CRYPTION_API void decrypt_CFB128_streamp(std::istream& crypt, Data iv, std::ostream& plain, Cryptor& cryptor,
// 				std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress_, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_);
// 		};

// 		namespace CFBb
// 		{
// 			extern const DOG_CRYPTION_API Config CONFIG;
// 			DOG_CRYPTION_API Data encrypt(Data plain, Data iv, Cryptor& cryptor);
// 			DOG_CRYPTION_API Data decrypt(Data crypt, Data iv, Cryptor& cryptor);
// 			DOG_CRYPTION_API void encrypt_stream(std::istream& plain, Data iv, std::ostream& crypt, Cryptor& cryptor);
// 			DOG_CRYPTION_API void decrypt_stream(std::istream& crypt, Data iv, std::ostream& plain, Cryptor& cryptor);
// 			DOG_CRYPTION_API void encrypt_streamp(std::istream& plain, Data iv, std::ostream& crypt, Cryptor& cryptor,
// 				std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress_, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_);
// 			DOG_CRYPTION_API void decrypt_streamp(std::istream& crypt, Data iv, std::ostream& plain, Cryptor& cryptor,
// 				std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress_, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_);

// 			DOG_CRYPTION_API Data encrypt_CFB1(Data plain, Data iv, Cryptor& cryptor);
// 			DOG_CRYPTION_API Data decrypt_CFB1(Data crypt, Data iv, Cryptor& cryptor);
// 			DOG_CRYPTION_API void encrypt_CFB1_stream(std::istream& plain, Data iv, std::ostream& crypt, Cryptor& cryptor);
// 			DOG_CRYPTION_API void decrypt_CFB1_stream(std::istream& crypt, Data iv, std::ostream& plain, Cryptor& cryptor);
// 			DOG_CRYPTION_API void encrypt_CFB1_streamp(std::istream& plain, Data iv, std::ostream& crypt, Cryptor& cryptor,
// 				std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress_, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_);
// 			DOG_CRYPTION_API void decrypt_CFB1_streamp(std::istream& crypt, Data iv, std::ostream& plain, Cryptor& cryptor,
// 				std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress_, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_);
// 		};

// 		extern const DOG_CRYPTION_API std::vector<Config> list;
// 	}

// 	class DOG_CRYPTION_API CryptionConfig
// 	{
// 	public:
// 		std::string cryption_algorithm;//算法名
// 		uint64_t block_size = 0;//块大小
// 		uint64_t key_size = 0;//密钥大小
        
//         std::string mult_function;//多块加密函数
// 		uint64_t shift = 0;//CFB模式下偏移量
// 		bool using_iv = false;//是否使用iv
// 		bool using_padding = false;//是否使用填充
// 		std::string padding_function;//填充函数

// 		std::unordered_map<std::string, std::any> extra_config;//额外配置

// 		CryptionConfig() = default;
// 		CryptionConfig(
// 			const std::string& cryption_algorithm, const uint64_t block_size, const uint64_t key_size,
// 			bool using_padding, const std::string& padding_function,
// 			const std::string& mult_function, bool using_iv, uint64_t shift,
// 			std::vector<std::pair<std::string, std::any>> extra_config = std::vector<std::pair<std::string, std::any>>()
// 		);
// 		CryptionConfig(
// 			const std::string& cryption_algorithm, const uint64_t block_size, const uint64_t key_size,
// 			bool using_padding, const std::string& padding_function,
// 			const std::string& mult_function, bool using_iv, uint64_t shift,
// 			std::unordered_map<std::string, std::any> extra_config
// 		);
// 		Data to_data() const;
// 		std::string to_string() const;
// 		/*
// 		* @param config_stream 带有配置信息头的流
// 		* @param return_start 是否返回流指针到开始处(默认回到)
// 		* @throw CryptionException
// 		* @return 配置信息
// 		*/
// 		static CryptionConfig get_cryption_config(std::istream& config_stream, bool return_start = true);
// 		static CryptionConfig get_cryption_config(Data& config_data, bool is_cut);
// 	};

// 	class DOG_CRYPTION_API Cryptor
// 	{
// 	private:
// 		bool is_valid_ = false;//加密器是否有效
// 		CryptionConfig config_;//加密配置信息

// 		//密钥加工
// 		bool is_setting_key_ = false;//是否设置密钥
// 		Data key_;//可用密钥
// 		Data original_key_;//原始密钥

// 		using padding_func             = std::function<void(Data&, uint64_t)>;
// 		using extend_key_func          = std::function<Data(const Data&, uint64_t, uint64_t)>;
// 		using block_self_cryption_func = std::function<void(Data&, uint64_t, const Data&, uint64_t)>;
// 		using block_cryption_func      = std::function<Data(const Data&, uint64_t, const Data&, uint64_t)>;

// 		extend_key_func extend_key_;//密钥扩展方法

// 		//填充/去填充方法
// 		padding_func padding_;
// 		padding_func unpadding_;
		
// 		//单块加密/解密方法
// 		block_self_cryption_func block_encryption_self_;
// 		block_self_cryption_func block_decryption_self_;

// 		block_cryption_func block_encryption_;
// 		block_cryption_func block_decryption_;
		
// 		//模式加密/解密方法
// 		std::function<Data(Data, Data, Cryptor&)> mult_encrypt_;
// 		std::function<Data(Data, Data, Cryptor&)> mult_decrypt_;

// 		std::function<void(std::istream&, Data, std::ostream&, Cryptor&)> stream_encrypt_;
// 		std::function<void(std::istream&, Data, std::ostream&, Cryptor&)> stream_decrypt_;

// 		std::function<void(std::istream&, Data, std::ostream&, Cryptor&,
// 			std::mutex*, std::condition_variable*, std::atomic<double>*, std::atomic<bool>*, std::atomic<bool>*, std::atomic<bool>*)> stream_encryptp_;
// 		std::function<void(std::istream&, Data, std::ostream&, Cryptor&, 
// 			std::mutex*, std::condition_variable*, std::atomic<double>*, std::atomic<bool>*, std::atomic<bool>*, std::atomic<bool>*)> stream_decryptp_;

// 	public:
// 		static bool is_config_available(const CryptionConfig& config);
// 		static std::unordered_map<std::string, std::any> turn_map(std::vector<std::pair<std::string, std::any>> vec);
// 		static std::vector<std::pair<std::string, std::any>> turn_vec(std::unordered_map<std::string, std::any> map);

// 		/*
// 		* 构造函数
// 		* @param cryption_algorithm  加密算法名
// 		* @param block_size          块大小
// 		* @param key_size            密钥大小
// 		* @param padding_function    填充函数
// 		* @param mult_function       多块加密函数
// 		* @param using_iv            是否使用iv
// 		* @param using_padding       是否使用填充
// 		* @param extra_config        额外参数
// 		*/
// 		Cryptor(
// 			const std::string& cryption_algorithm, const uint64_t block_size, const uint64_t key_size,
// 			bool using_padding, const std::string& padding_function,
// 			const std::string& mult_function, bool using_iv, uint64_t shift,
// 			std::vector<std::pair<std::string, std::any>> extra_config = std::vector<std::pair<std::string, std::any>>()
// 		);
// 		Cryptor(
// 			const std::string& cryption_algorithm, const uint64_t block_size, const uint64_t key_size,
// 			bool using_padding, const std::string& padding_function,
// 			const std::string& mult_function, bool using_iv, uint64_t shift,
// 			std::unordered_map<std::string, std::any> extra_config_
// 		) : 
// 			Cryptor(
// 				cryption_algorithm, block_size, key_size, 
// 				using_padding, padding_function, 
// 				mult_function, using_iv, shift, 
// 				turn_vec(extra_config_)) {};
// 		Cryptor(const CryptionConfig& config) : 
// 			Cryptor(
// 				config.cryption_algorithm, config.block_size, config.key_size, 
// 				config.using_padding, config.padding_function, 
// 				config.mult_function, config.using_iv, config.shift,
// 				config.extra_config
// 			) {}
// 		void set_key(Data key);

// 		void swap(Cryptor& other);
// 		void swap_config(Cryptor& other);
		
// 		uint64_t get_block_size() const;
//         uint64_t get_key_size() const;

// 		bool get_using_iv() const;
// 		bool get_using_padding() const;
		
// 		Data get_original_key() const;
// 		Data get_available_key() const;

// 		padding_func get_padding() const;
// 		padding_func get_unpadding() const;

// 		block_self_cryption_func get_block_self_encryption() const;
// 		block_self_cryption_func get_block_self_decryption() const;

// 		block_cryption_func get_block_encryption() const;
// 		block_cryption_func get_block_decryption() const;

// 		CryptionConfig get_config();
// 		uint64_t get_reback_size() const;
// 		bool is_available() const;

// 		Data encrypt(Data plain, bool with_config, bool with_iv, Data iv, bool with_check);
// 		void encrypt(std::istream& plain, std::ostream& crypt, bool with_config, bool with_iv, Data iv, bool with_check);
// 		void encryptp(std::istream& plain, std::ostream& crypt, bool with_config, bool with_iv, Data iv, bool with_check,
// 			std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_);
// 		Data decrypt(Data crypt, bool with_config, bool with_iv, Data iv, bool with_check);
// 		void decrypt(std::istream& crypt, std::ostream& plain,bool with_config, bool with_iv, Data iv, bool with_check);
// 		void decryptp(std::istream& plain, std::ostream& crypt, bool with_config, bool with_iv, Data iv, bool with_check,
// 			std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_);
// 	};

// 	/*
// 	namespace <加密算法>
// 	{
// 		const std::string name = "加密算法名";
// 		const std::string BLOCK_REGION = "分组范围";
// 		const std::string KEY_REGION = "密钥范围";

// 		<!--
// 		中间函数和常量
// 		-->

// 		//密钥加工
// 		Data extend_key(const Data& key, uint64_t block_size, uint64_t key_size);
// 		//加密有返回
// 		Data encoding(const Data& plain, uint64_t block_size, const Data& key, uint64_t key_size);
// 		Data decoding(const Data& crypt, uint64_t block_size, const Data& key, uint64_t key_size);
// 		//加密无返回
// 		void encoding_self(Data& plain, uint64_t block_size, const Data& key, uint64_t key_size);
// 		void decoding_self(Data& crypt, uint64_t block_size, const Data& key, uint64_t key_size);
// 	}
// 	*/

	
// }}}
