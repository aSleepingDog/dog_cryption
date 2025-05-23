#pragma once
#include <exception>
#include <string>
#include <random>
#include <format>
#include <functional>
#include <thread>
#include <cstdlib>
#include <any>
#include <unordered_map>
#include <regex>
#include <bitset>
#include <print>

#include "data_bytes.h"
#include "big_number.h"


namespace dog_cryption
{
	namespace utils
	{
		uint8_t rand_byte();
		bool is_in_region(std::string region_str, uint64_t num);

		bool is_integer(std::any a);
		uint64_t get_integer(std::any a);

		template<class T>
		uint8_t get_type_size(T value) 
		{
			if constexpr (std::is_same_v<T, bool>)
			{
				return value ? 0b00001111 : 0b00000000;
			}
			else if constexpr (std::is_unsigned_v<T> && std::is_integral_v<T>)
			{
				uint8_t size = dog_number::integer::available_size((uint64_t)value);
				return 0b01000000 | size;
			}
			else if constexpr (std::is_signed_v<T> && std::is_integral_v<T>)
			{
				uint8_t size = dog_number::integer::available_size((uint64_t)(value < 0 ? -value : value));
				uint8_t sign_bit = (value < 0) ? 0b00010000 : 0b00000000;
				return 0b01100000 | sign_bit | size;
			}
			else if constexpr (std::is_same_v<T, float>)
			{
				return 0b10000100;
			}
			else if constexpr (std::is_same_v<T, double>)
			{
				return 0b10001000;
			}
			else if constexpr (std::is_same_v<T, const char*>)
			{
				size_t tmp_size = strlen(value);
				if (tmp_size == 0 || tmp_size > 127) 
				{
					throw dog_number::NumberException("String length invalid", __FILE__, __func__, __LINE__);
				}
				return 0b11000000 | static_cast<uint8_t>(tmp_size);
			}
			else if constexpr (std::is_same_v<T, std::string>)
			{
				size_t tmp_size = value.size();
				if (tmp_size == 0 || tmp_size > 127)
				{
					throw dog_number::NumberException("String length invalid", __FILE__, __func__, __LINE__);
				}
				return 0b11000000 | static_cast<uint8_t>(tmp_size);
			}
			else
			{
				static_assert(!std::is_same_v<T, T>, "Unsupported type");
			}
		}

		dog_data::Data squareXOR(dog_data::Data& a, dog_data::Data& b, uint64_t size);
		void squareXOR_self(dog_data::Data& a, dog_data::Data& b, uint64_t size);
		dog_data::Data randiv(uint8_t block_size);
	}

	class CryptionException : public std::exception
	{
	private:
		std::string msg;
	public:
		CryptionException(const char* msg, const char* file, const char* function, uint64_t line);
		~CryptionException() = default;
		virtual const char* what() const throw();
	};

	class CryptionConfig
	{
	public:
		std::string cryption_algorithm_;//算法名
		uint64_t block_size_;//块大小
		uint64_t key_size_;//密钥大小
        std::string padding_function_;//填充函数
        std::string mult_function_;//多块加密函数
		bool using_iv_;//是否使用iv
		bool with_iv_;//是否携带iv 加密时自动加上iv解密时自动解析iv仅在using_iv_为true时有效
		bool using_padding_;//是否使用填充
		std::unordered_map<std::string, std::any> extra_config_;//额外配置

		CryptionConfig() = default;
		CryptionConfig(
			const std::string& cryption_algorithm, const uint64_t block_size, const uint64_t key_size,
			bool using_padding, const std::string& padding_function,
			const std::string& mult_function, bool using_iv,bool with_iv,
			std::vector<std::pair<std::string, std::any>> extra_config = std::vector<std::pair<std::string, std::any>>()
		);
		CryptionConfig(
			const std::string& cryption_algorithm, const uint64_t block_size, const uint64_t key_size,
			bool using_padding, const std::string& padding_function,
			const std::string& mult_function, bool using_iv, bool with_iv,
			std::unordered_map<std::string, std::any> extra_config = std::unordered_map<std::string, std::any>()
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
		static CryptionConfig get_cryption_config(const dog_data::Data& config_data);
	};

	class Cryptor
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

		std::function<void(std::istream&, dog_data::Data, std::ostream&, dog_cryption::Cryptor&, std::atomic<double>* progress)> stream_encryptp_;
		std::function<void(std::istream&, dog_data::Data, std::ostream&, dog_cryption::Cryptor&, std::atomic<double>* progress)> stream_decryptp_;

	public:
		static bool is_config_available(const CryptionConfig& config);

		/*
		* 构造函数
		* @param cryption_algorithm 加密算法名
		* @param block_size 块大小
		* @param key_size 密钥大小
		* @param padding_function 填充函数
		* @param mult_function 多块加密函数
		* @param using_iv 是否使用iv
		* @param with_iv 是否携带iv
		* @param using_padding 是否使用填充
		* @param using_parallelism 是否使用并行
		*/
		Cryptor(
			const std::string& cryption_algorithm, const uint64_t block_size, const uint64_t key_size,
			bool using_padding, const std::string& padding_function,
			const std::string& mult_function, bool using_iv, bool with_iv,
			std::vector<std::pair<std::string, std::any>> extra_config = std::vector<std::pair<std::string, std::any>>()
		);
		Cryptor(
			const std::string& cryption_algorithm, const uint64_t block_size, const uint64_t key_size,
			bool using_padding, const std::string& padding_function,
			const std::string& mult_function, bool using_iv, bool with_iv,
			std::unordered_map<std::string, std::any> extra_config_ = std::unordered_map<std::string, std::any>()
		);
		Cryptor(const CryptionConfig& config) : 
			Cryptor(
				config.cryption_algorithm_, config.block_size_, config.key_size_, 
				config.using_padding_, config.padding_function_, 
				config.mult_function_, config.using_iv_, config.with_iv_, 
				config.extra_config_
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

		std::function<void(dog_data::Data&, uint8_t, const dog_data::Data&, uint8_t)> get_block_encryption() const;
		std::function<void(dog_data::Data&, uint8_t, const dog_data::Data&, uint8_t)> get_block_decryption() const;

		dog_cryption::CryptionConfig get_config();
		uint64_t get_reback_size() const;
		bool is_available() const;

		/*
         文本加密时
		 加密时iv和密文crypt情况
                                                    start开始
                                                        |
                                 ---true是-----using_iv加密时是否需要iv----false否---
                                 |                                                 |
                    --true是---是否传参iv--false否---                           <"", crypt密文>
                    |                              |
        出错<------选取iv------------------------随机iv
                                  |
                   --true是---with_iv是否携带iv--false否--
                   |                                    |
              <iv, iv|crypt密文>                    <iv, crypt密文>

         解密是iv和明文crypt情况
                                                    start开始
                                                        |
                                 ---true是-----using_iv加密时是否需要iv----false否---
                                 |                                                 |
                --true是---with_iv是否携带iv--false否--                          忽略参数iv
                |                                    |                             |
    出错<------选取iv                    --true是---是否传参iv--false否-->出错     plain明文 
                |                       |
              plain明文       出错<----选取iv
                                        |
                                     plain明文

		*/

		/*
		 加密时iv和密文crypt情况
													start开始
														|
								 ---true是-----using_iv加密时是否需要iv----false否---
								 |                                                 |
					--true是---是否传参iv--false否---                           <"", crypt密文>
					|                              |
		出错<------选取iv------------------------随机iv
								  |
				   --true是---with_iv是否携带iv--false否--
				   |                                    |
			  <iv, iv|crypt密文>                    <iv, crypt密文>
		*
		* @param iv 加密所需随机数据(若算法不需要使用则忽略此项,若过长则截取前部所需范围(如需要16B,输入24B则截取前16B))
		* @param plain 明文数据
		* 
		* @throws 无效的cryptor,可能是cryptor未正确配置或未设置密钥
		* @throws 无效的iv,可能是iv长度不够
		* 
		* @return std::pair<iv,crypt> 如果using_iv为false则iv为空容器,反之则包含参数iv的数据.如果with_iv为true则crypt前部包含iv,反之则不包含.
		*/
		std::pair<dog_data::Data, dog_data::Data> encrypt(dog_data::Data iv, dog_data::Data plain);

		/*
		 加密时iv和密文crypt情况
													start开始
														|
								 ---true是-----using_iv加密时是否需要iv----false否---
								 |                                                 |
					--true是---是否传参iv--false否---                           <"", crypt密文>
					|                              |
		出错<------选取iv------------------------随机iv
								  |
				   --true是---with_iv是否携带iv--false否--
				   |                                    |
			  <iv, iv|crypt密文>                    <iv, crypt密文>

		* @param plain 密文数据
		* 
		* @throws 无效的cryptor,可能是cryptor未正确配置或未设置密钥
		* @throws 当using_iv为true时使用抛出异常
		* 
		* @return std::pair<iv,crypt> 如果using_iv为false则iv为空容器,反之则包含随机生成的iv数据.如果with_iv为true则crypt前部包含iv,反之则不包含.
		*/
		std::pair<dog_data::Data, dog_data::Data> encrypt(dog_data::Data plain);

		/*
		 解密是iv和明文crypt情况
													start开始
														|
								 ---true是-----using_iv加密时是否需要iv----false否---
								 |                                                 |
				--true是---with_iv是否携带iv--false否--                          忽略参数iv
				|                                    |                             |
	出错<------选取iv                    --true是---是否传参iv--false否-->出错     plain明文
				|                       |
			  plain明文       出错<----选取iv
										|
									 plain明文

		* 
		* @param iv_crypt 加密所需随机数据(若算法不需要使用则忽略此项,若过长则截取前部所需范围(如需要16B,输入24B则截取前16B))和密文数据
		* 
		* @throws 无效的cryptor,可能是cryptor未正确配置或未设置密钥
		* @throws 无效的iv,可能是iv长度不够
		* 
		* @return 明文数据
		*/
        dog_data::Data decrypt(std::pair<dog_data::Data, dog_data::Data> iv_crypt);

		/*
		 解密是iv和明文crypt情况
													start开始
														|
								 ---true是-----using_iv加密时是否需要iv----false否---
								 |                                                 |
				--true是---with_iv是否携带iv--false否--                          忽略参数iv
				|                                    |                             |
	出错<------选取iv                    --true是---是否传参iv--false否-->出错     plain明文
				|                       |
			  plain明文       出错<----选取iv
										|
									 plain明文

		*/
		dog_data::Data decrypt(dog_data::Data iv, dog_data::Data crypt);

		/*
		 解密是iv和明文crypt情况
													start开始
														|
								 ---true是-----using_iv加密时是否需要iv----false否---
								 |                                                 |
				--true是---with_iv是否携带iv--false否--                          忽略参数iv
				|                                    |                             |
	出错<------选取iv                    --true是---是否传参iv--false否-->出错     plain明文
				|                       |
			  plain明文       出错<----选取iv
										|
									 plain明文

		*/
		dog_data::Data decrypt(dog_data::Data crypt);

		/*
		* @param plain 明文输入流引用
		* @param crypt 密文输出流引用
		* @param iv 加密所需随机数据(若算法不需要使用则忽略此项,若过长则截取前部所需范围(如需要16B,输入24B则截取前16B))
		* @param with_config 是否将配置信息写入密文流头部
		* 
		* @throws 无效的cryptor,可能是cryptor未正确配置或未设置密钥
		* @throws 无效的iv,可能是iv长度不够
		*/
		void encrypt(std::istream& plain, std::ostream& crypt, dog_data::Data iv, bool with_config);

		/*
		* @param plain 明文输入流引用
		* @param crypt 密文输出流引用
		* @param iv 加密所需随机数据(若算法不需要使用则忽略此项,若过长则截取前部所需范围(如需要16B,输入24B则截取前16B))
		* @param with_config=false 默认不将配置信息写入密文流头部
		* 
		* @throws 无效的cryptor,可能是cryptor未正确配置或未设置密钥
		* @throws 无效的iv,可能是iv长度不够
		*/
		void encrypt(std::istream& plain, std::ostream& crypt, dog_data::Data iv);

		/*
		* @param plain 明文输入流引用
		* @param crypt 密文输出流引用
		* @param iv (此项无需输入)若必须则随机生成,若不需要则留空
		* @param with_config 是否将配置信息写入密文流头部
		*
		* @throws 无效的cryptor,可能是cryptor未正确配置或未设置密钥
		* @throws 无效的iv,可能是iv长度不够
		* 
		* @return 若必须则返回随机生成的iv,若不需要则返回空容器
		*/
		dog_data::Data encrypt(std::istream& plain, std::ostream& crypt, bool with_config);
		dog_data::Data encryptp(std::istream& plain, std::ostream& crypt, bool with_config, std::atomic<double>* progress);
		
		/*
		* @param plain 明文输入流引用
		* @param crypt 密文输出流引用
		* @param iv 若必须则随机生成,若不需要则留空
		* @param with_config=false 默认不将配置信息写入密文流头部
		*
		* @throws 无效的cryptor,可能是cryptor未正确配置或未设置密钥
		* @throws 无效的iv,可能是iv长度不够
		* 
		* @return 若必须则返回随机生成的iv,若不需要则返回空容器
		*/
		dog_data::Data encrypt(std::istream& plain, std::ostream& crypt);
		dog_data::Data encryptp(std::istream& plain, std::ostream& crypt, std::atomic<double>* progress);
		
		/*
		* @param crypt 密文输入流引用
		* @param plain 明文输出流引用
		* @param with_config 是否从密文流头部读取并自动临时更改配置
		* 
		* @throws 无效的config,可能是从密文流头部读取的配置不正确
		* @throws 无效的cryptor,可能是cryptor未正确配置或未设置密钥
		* @throws 无效的iv,可能是iv长度不够
		*/
		void decrypt(std::istream& crypt, std::ostream& plain, bool with_config);
		void decryptp(std::istream& crypt, std::ostream& plain, bool with_config, std::atomic<double>* progress);

		/*
		* @param crypt 密文输入流引用
		* @param plain 明文输出流引用
		* @param with_config=false 不从密文流头部读取并自动临时更改配置
		* 
		* @throws 无效的cryptor,可能是cryptor未正确配置或未设置密钥
		* @throws 无效的iv,可能是iv长度不够
		*/
		void decrypt(std::istream& crypt, std::ostream& plain);
		void decryptp(std::istream& crypt, std::ostream& plain, std::atomic<double>* progress);
	};

	namespace padding
	{
		/*
		    0 NONE        no fill                                                                       不填充
			1 PKCS7       all fill value of length less than 16B                                        全部填充少于16B的长度值
			2 ZERO        all fill 0 -- not suggestion                                                  全部填充0--不建议使用
			3 ANSI923     all fill 0 but the last one fill value of length less than 16B                全部填充0，但是最后一个填充的是少于16B的长度值
			4 ISO7816_4   all fill 0 but the first one fill value 0x80                                  全部填充0，但是第一个填充的是0x80
			5 ISO10126    all fill randon value but the last one fill value of length less than 16B     全部填充随机数，但是最后一个填充的是少于16B的长度值
		*/

		const bool USING_PADDING = true;
		const bool NOT_USING_PADDING = false;

		const std::string NONE = "NONE";
		const uint8_t NONE_CODE = 0;
		void NONE_padding(dog_data::Data& data, uint8_t block_size);
		void NONE_unpadding(dog_data::Data& data, uint8_t block_size);

		const std::string PKCS7 = "PKCS7";
		const uint8_t PKCS7_CODE = 1;
		void PKCS7_padding(dog_data::Data& data,uint8_t block_size);
		void PKCS7_unpadding(dog_data::Data& data, uint8_t block_size);
        
		const std::string ZERO = "ZERO";
		const uint8_t ZERO_CODE = 2;
		void ZERO_padding(dog_data::Data& data, uint8_t block_size);
		void ZERO_unpadding(dog_data::Data& data, uint8_t block_size);

		const std::string ANSIX923 = "ANSIX923";
		const uint8_t ANSIX923_CODE = 3;
		void ANSIX923_padding(dog_data::Data& data, uint8_t block_size);
		void ANSIX923_unpadding(dog_data::Data& data, uint8_t block_size);

		const std::string ISO7816_4 = "ISO7816_4";
		const uint8_t ISO7816_4_CODE = 4;
		void ISO7816_4_padding(dog_data::Data& data, uint8_t block_size);
		void ISO7816_4_unpadding(dog_data::Data& data, uint8_t block_size);

		const std::string ISO10126 = "ISO10126";
		const uint8_t ISO10126_CODE = 5;
		void ISO10126_padding(dog_data::Data& data, uint8_t block_size);
		void ISO10126_unpadding(dog_data::Data& data, uint8_t block_size);
	}

	namespace mode
	{
		/*
		   vx:不强制 v:强制
		         iv|填充|
			ECB |vx|v |
			CBC |v |v |
			OFB |v |vx|
			CTR |v |vx|
			CFB |v |vx|

			0 ECB
			1 CBC
			2 OFB
			3 CTR
			4 CFBB
			5 CFBb

		*/

		double update_progress(double progress, double progress_step, double progress_max);

		namespace ECB
		{
			const std::string name = "ECB";
			const uint8_t CODE = 0;
			dog_data::Data encrypt(dog_data::Data plain, dog_data::Data iv, dog_cryption::Cryptor& cryptor);
			dog_data::Data decrypt(dog_data::Data crypt, dog_data::Data iv, dog_cryption::Cryptor& cryptor);
			void encrypt_stream(std::istream& plain, dog_data::Data iv, std::ostream& crypt, dog_cryption::Cryptor& cryptor);
			void decrypt_stream(std::istream& crypt, dog_data::Data iv, std::ostream& plain, dog_cryption::Cryptor& cryptor);
			void encrypt_streamp(std::istream& plain, dog_data::Data iv, std::ostream& crypt, dog_cryption::Cryptor& cryptor, std::atomic<double>* progress);
			void decrypt_streamp(std::istream& crypt, dog_data::Data iv, std::ostream& plain, dog_cryption::Cryptor& cryptor, std::atomic<double>* progress);
		}

		namespace CBC
		{
			const std::string name = "CBC";
			const uint8_t CODE = 1;
			dog_data::Data encrypt(dog_data::Data plain, dog_data::Data iv, dog_cryption::Cryptor& cryptor);
			dog_data::Data decrypt(dog_data::Data crypt, dog_data::Data iv, dog_cryption::Cryptor& cryptor);
			void encrypt_stream(std::istream& plain, dog_data::Data iv, std::ostream& crypt, dog_cryption::Cryptor& cryptor);
			void decrypt_stream(std::istream& crypt, dog_data::Data iv, std::ostream& plain, dog_cryption::Cryptor& cryptor);
			void encrypt_streamp(std::istream& plain, dog_data::Data iv, std::ostream& crypt, dog_cryption::Cryptor& cryptor, std::atomic<double>* progress);
			void decrypt_streamp(std::istream& crypt, dog_data::Data iv, std::ostream& plain, dog_cryption::Cryptor& cryptor, std::atomic<double>* progress);
		}

		namespace OFB
		{
			const std::string name = "OFB";
			const uint8_t CODE = 2;
			dog_data::Data encrypt(dog_data::Data plain, dog_data::Data iv, dog_cryption::Cryptor& cryptor);
			dog_data::Data decrypt(dog_data::Data crypt, dog_data::Data iv, dog_cryption::Cryptor& cryptor);
			void encrypt_stream(std::istream& plain, dog_data::Data iv, std::ostream& crypt, dog_cryption::Cryptor& cryptor);
			void decrypt_stream(std::istream& crypt, dog_data::Data iv, std::ostream& plain, dog_cryption::Cryptor& cryptor);
			void encrypt_streamp(std::istream& plain, dog_data::Data iv, std::ostream& crypt, dog_cryption::Cryptor& cryptor, std::atomic<double>* progress);
			void decrypt_streamp(std::istream& crypt, dog_data::Data iv, std::ostream& plain, dog_cryption::Cryptor& cryptor, std::atomic<double>* progress);
		}
				
		namespace CTR
		{
			const std::string name = "CTR";
			const uint8_t CODE = 3;
			dog_data::Data encrypt(dog_data::Data plain, dog_data::Data iv, dog_cryption::Cryptor& cryptor);
			dog_data::Data decrypt(dog_data::Data crypt, dog_data::Data iv, dog_cryption::Cryptor& cryptor);
			void encrypt_stream(std::istream& plain, dog_data::Data iv, std::ostream& crypt, dog_cryption::Cryptor& cryptor);
			void decrypt_stream(std::istream& crypt, dog_data::Data iv, std::ostream& plain, dog_cryption::Cryptor& cryptor);
			void encrypt_streamp(std::istream& plain, dog_data::Data iv, std::ostream& crypt, dog_cryption::Cryptor& cryptor, std::atomic<double>* progress);
			void decrypt_streamp(std::istream& crypt, dog_data::Data iv, std::ostream& plain, dog_cryption::Cryptor& cryptor, std::atomic<double>* progress);
		}
		
		namespace CFBB
		{
			const std::string name = "CFBB";
			const uint8_t CODE = 4;
			dog_data::Data encrypt(dog_data::Data plain, dog_data::Data iv, dog_cryption::Cryptor& cryptor);
			dog_data::Data decrypt(dog_data::Data crypt, dog_data::Data iv, dog_cryption::Cryptor& cryptor);
			void encrypt_stream(std::istream& plain, dog_data::Data iv, std::ostream& crypt, dog_cryption::Cryptor& cryptor);
			void decrypt_stream(std::istream& crypt, dog_data::Data iv, std::ostream& plain, dog_cryption::Cryptor& cryptor);
			void encrypt_streamp(std::istream& plain, dog_data::Data iv, std::ostream& crypt, dog_cryption::Cryptor& cryptor, std::atomic<double>* progress);
			void decrypt_streamp(std::istream& crypt, dog_data::Data iv, std::ostream& plain, dog_cryption::Cryptor& cryptor, std::atomic<double>* progress);

			dog_data::Data encrypt_CFB8(dog_data::Data plain, dog_data::Data iv, dog_cryption::Cryptor& cryptor);
			dog_data::Data decrypt_CFB8(dog_data::Data crypt, dog_data::Data iv, dog_cryption::Cryptor& cryptor);
			void encrypt_CFB8_stream(std::istream& plain, dog_data::Data iv, std::ostream& crypt, dog_cryption::Cryptor& cryptor);
			void decrypt_CFB8_stream(std::istream& crypt, dog_data::Data iv, std::ostream& plain, dog_cryption::Cryptor& cryptor);
			void encrypt_CFB8_streamp(std::istream& plain, dog_data::Data iv, std::ostream& crypt, dog_cryption::Cryptor& cryptor, std::atomic<double>* progress);
			void decrypt_CFB8_streamp(std::istream& crypt, dog_data::Data iv, std::ostream& plain, dog_cryption::Cryptor& cryptor, std::atomic<double>* progress);

			dog_data::Data encrypt_CFB128(dog_data::Data plain, dog_data::Data iv, dog_cryption::Cryptor& cryptor);
			dog_data::Data decrypt_CFB128(dog_data::Data crypt, dog_data::Data iv, dog_cryption::Cryptor& cryptor);
			void encrypt_CFB128_stream(std::istream& plain, dog_data::Data iv, std::ostream& crypt, dog_cryption::Cryptor& cryptor);
			void decrypt_CFB128_stream(std::istream& crypt, dog_data::Data iv, std::ostream& plain, dog_cryption::Cryptor& cryptor);
			void encrypt_CFB128_streamp(std::istream& plain, dog_data::Data iv, std::ostream& crypt, dog_cryption::Cryptor& cryptor, std::atomic<double>* progress);
			void decrypt_CFB128_streamp(std::istream& crypt, dog_data::Data iv, std::ostream& plain, dog_cryption::Cryptor& cryptor, std::atomic<double>* progress);
		}

		namespace CFBb
		{
			const std::string name = "CFBb";
			const uint8_t CODE = 5;
			//此处6个方法未实现
			dog_data::Data encrypt(dog_data::Data plain, dog_data::Data iv, dog_cryption::Cryptor& cryptor);
			dog_data::Data decrypt(dog_data::Data crypt, dog_data::Data iv, dog_cryption::Cryptor& cryptor);
			void encrypt_stream(std::istream& plain, dog_data::Data iv, std::ostream& crypt, dog_cryption::Cryptor& cryptor);
			void decrypt_stream(std::istream& crypt, dog_data::Data iv, std::ostream& plain, dog_cryption::Cryptor& cryptor);
			void encrypt_streamp(std::istream& plain, dog_data::Data iv, std::ostream& crypt, dog_cryption::Cryptor& cryptor, std::atomic<double>* progress);
			void decrypt_streamp(std::istream& crypt, dog_data::Data iv, std::ostream& plain, dog_cryption::Cryptor& cryptor, std::atomic<double>* progress);
			
			dog_data::Data encrypt_CFB1(dog_data::Data plain, dog_data::Data iv, dog_cryption::Cryptor& cryptor);
			dog_data::Data decrypt_CFB1(dog_data::Data crypt, dog_data::Data iv, dog_cryption::Cryptor& cryptor);
			void encrypt_CFB1_stream(std::istream& plain, dog_data::Data iv, std::ostream& crypt, dog_cryption::Cryptor& cryptor);
			void decrypt_CFB1_stream(std::istream& crypt, dog_data::Data iv, std::ostream& plain, dog_cryption::Cryptor& cryptor);
			void encrypt_CFB1_streamp(std::istream& plain, dog_data::Data iv, std::ostream& crypt, dog_cryption::Cryptor& cryptor, std::atomic<double>* progress);
			void decrypt_CFB1_streamp(std::istream& crypt, dog_data::Data iv, std::ostream& plain, dog_cryption::Cryptor& cryptor, std::atomic<double>* progress);

		}
			
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

	namespace AES
	{
		//unit单位:uint8_t字节
		const std::string name = "AES";

		const std::string BLOCK_REGION = "[16,32]:8";
		const uint8_t BLOCK_128 = 16;
		
		const std::string KEY_REGION = "[16,32]:8";
		const uint64_t KEY_128 = 16;
        const uint64_t KEY_192 = 24;
		const uint64_t KEY_256 = 32;

		const uint8_t SBox[16][16] = {
			//0     1     2     3     4     5     6     7     8     9     A     B     C     D     E     F
			{0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76},//0
			{0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0},//1
			{0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15},//2
			{0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75},//3
			{0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84},//4
			{0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf},//5
			{0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8},//6
			{0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2},//7
			{0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73},//8
			{0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb},//9
			{0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79},//A
			{0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08},//B
			{0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a},//C
			{0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e},//D
			{0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf},//E
			{0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16} };//
		const uint8_t InvSBox[16][16] = {
			//0     1     2     3     4     5     6     7     8     9     A     B     C     D     E     F
			{0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb},//0
			{0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb},//1
			{0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e},//2
			{0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25},//3
			{0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92},//4
			{0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84},//5
			{0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06},//6
			{0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b},//7
			{0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73},//8
			{0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e},//9
			{0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b},//A
			{0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4},//B
			{0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f},//C
			{0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef},//D
			{0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61},//E
			{0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d} };//F

		const uint8_t MixTable[16] = { 0x02,0x03,0x01,0x01, 0x01,0x02,0x03,0x01, 0x01,0x01,0x02,0x03, 0x03,0x01,0x01,0x02 };
		const uint8_t UMixTable[16] = { 0x0E,0x0B,0x0D,0x09, 0x09,0x0E,0x0B,0x0D, 0x0D,0x09,0x0E,0x0B, 0x0B,0x0D,0x09,0x0E };

		const uint8_t round[10] = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };
		dog_data::Data extendKey128(dog_data::Data& key);
		dog_data::Data extendKey192(dog_data::Data& key);
		dog_data::Data extendKey256(dog_data::Data& key);
		dog_data::Data extend_key(dog_data::Data& key, uint64_t key_size);

		//the value of a must be 0x01 0x02 0x03 a的值只能为0x01,0x02,0x03
		uint8_t Xtime(uint8_t a, uint8_t b);

		//each block encrypt and using funcation 区块加密及内部算法

		//AES加解密中 字节代还 行移位 列混合混合方法
		dog_data::Data middle_encryption(dog_data::Data datablock, int flag, int mode);
        dog_data::Data middle_decryption(dog_data::Data datablock, int flag, int mode);

		dog_data::Data encoding(dog_data::Data& plain, uint8_t block_size, const dog_data::Data& key, uint8_t key_size);
		dog_data::Data decoding(dog_data::Data& crypt, uint8_t block_size, const dog_data::Data& key, uint8_t key_size);

		void encoding_self(dog_data::Data& plain, uint8_t block_size, const dog_data::Data& key, uint8_t key_size);
		void decoding_self(dog_data::Data& crypt, uint8_t block_size, const dog_data::Data& key, uint8_t key_size);
	}

	namespace SM4
	{
		//unit单位:uint8_t字节
		const std::string name = "SM4";

		const std::string BLOCK_REGION = "[16,16]:0";
		const uint8_t BLOCK_128 = 16; 

		const std::string KEY_REGION = "[16,16]:0";
		const uint64_t KEY_128 = 16;

		const uint8_t SBox[16][16] = {
			//0     1     2     3     4     5     6     7     8     9     A     B     C     D     E     F
			{0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05},//0
			{0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99},//1
			{0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62},//2
			{0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6},//3
			{0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8},//4
			{0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35},//5
			{0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87},//6
			{0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e},//7
			{0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1},//8
			{0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3},//9
			{0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f},//A
			{0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51},//B
			{0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8},//C
			{0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0},//D
			{0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84},//E
			{0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d/*这里*/, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48}};//F
		//2024.10.10把F6的4d错打成了4b导致结果错误一直没发现，调试了10h。第二天才解决
		//此事在 https://github.com/aSleepingDog/simpleTextHashAndEncryption 亦有记载
		const uint32_t FK[4] = { 0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc };
		const uint32_t CK[32] = { 0x00070e15,0x1c232a31,0x383f464d,0x545b6269,0x70777e85,0x8c939aa1,0xa8afb6bd,0xc4cbd2d9,
							  0xe0e7eef5,0xfc030a11,0x181f262d,0x343b4249,0x50575e65,0x6c737a81,0x888f969d,0xa4abb2b9,
							  0xc0c7ced5,0xdce3eaf1,0xf8ff060d,0x141b2229,0x30373e45,0x4c535a61,0x686f767d,0x848b9299,
							  0xa0a7aeb5,0xbcc3cad1,0xd8dfe6ed,0xf4fb0209,0x10171e25,0x2c333a41,0x484f565d,0x646b7279 };

		uint32_t TMixChange1(uint32_t n);
		uint32_t TMixChange2(uint32_t n);

		dog_data::Data extend_key(dog_data::Data key, uint64_t key_size = 16);

		dog_data::Data encoding(dog_data::Data& plain, uint8_t block_size, const dog_data::Data& key, uint8_t key_size);
		dog_data::Data decoding(dog_data::Data& crypt, uint8_t block_size, const dog_data::Data& key, uint8_t key_size);

		void encoding_self(dog_data::Data& plain, uint8_t block_size, const dog_data::Data& key, uint8_t key_size);
		void decoding_self(dog_data::Data& crypt, uint8_t block_size, const dog_data::Data& key, uint8_t key_size);
		

	}

	namespace camellia
	{
		const std::string name = "camellia";

		const std::string BLOCK_REGION = "[16,32]:8";
		const uint8_t BLOCK_128 = 16;

		const std::string KEY_REGION = "[16,32]:8";
		const uint64_t KEY_128 = 16;
		const uint64_t KEY_192 = 24;
		const uint64_t KEY_256 = 32;

		const uint8_t Sbox[256] =
		{
			//   0     1     2     3     4     5     6     7     8     9     A     B     C     D     E     F
				0x70, 0x82, 0x2c, 0xec, 0xb3, 0x27, 0xc0, 0xe5, 0xe4, 0x85, 0x57, 0x35, 0xea, 0x0c, 0xae, 0x41,//0
				0x23, 0xef, 0x6b, 0x93, 0x45, 0x19, 0xa5, 0x21, 0xed, 0x0e, 0x4f, 0x4e, 0x1d, 0x65, 0x92, 0xbd,//1
				0x86, 0xb8, 0xaf, 0x8f, 0x7c, 0xeb, 0x1f, 0xce, 0x3e, 0x30, 0xdc, 0x5f, 0x5e, 0xc5, 0x0b, 0x1a,//2
				0xa6, 0xe1, 0x39, 0xca, 0xd5, 0x47, 0x5d, 0x3d, 0xd9, 0x01, 0x5a, 0xd6, 0x51, 0x56, 0x6c, 0x4d,//3
				0x8b, 0x0d, 0x9a, 0x66, 0xfb, 0xcc, 0xb0, 0x2d, 0x74, 0x12, 0x2b, 0x20, 0xf0, 0xb1, 0x84, 0x99,//4
				0xdf, 0x4c, 0xcb, 0xc2, 0x34, 0x7e, 0x76, 0x05, 0x6d, 0xb7, 0xa9, 0x31, 0xd1, 0x17, 0x04, 0xd7,//5
				0x14, 0x58, 0x3a, 0x61, 0xde, 0x1b, 0x11, 0x1c, 0x32, 0x0f, 0x9c, 0x16, 0x53, 0x18, 0xf2, 0x22,//5
				0xfe, 0x44, 0xcf, 0xb2, 0xc3, 0xb5, 0x7a, 0x91, 0x24, 0x08, 0xe8, 0xa8, 0x60, 0xfc, 0x69, 0x50,//7
				0xaa, 0xd0, 0xa0, 0x7d, 0xa1, 0x89, 0x62, 0x97, 0x54, 0x5b, 0x1e, 0x95, 0xe0, 0xff, 0x64, 0xd2,//8
				0x10, 0xc4, 0x00, 0x48, 0xa3, 0xf7, 0x75, 0xdb, 0x8a, 0x03, 0xe6, 0xda, 0x09, 0x3f, 0xdd, 0x94,//9
				0x87, 0x5c, 0x83, 0x02, 0xcd, 0x4a, 0x90, 0x33, 0x73, 0x67, 0xf6, 0xf3, 0x9d, 0x7f, 0xbf, 0xe2,//A
				0x52, 0x9b, 0xd8, 0x26, 0xc8, 0x37, 0xc6, 0x3b, 0x81, 0x96, 0x6f, 0x4b, 0x13, 0xbe, 0x63, 0x2e,//B
				0xe9, 0x79, 0xa7, 0x8c, 0x9f, 0x6e, 0xbc, 0x8e, 0x29, 0xf5, 0xf9, 0xb6, 0x2f, 0xfd, 0xb4, 0x59,//C
				0x78, 0x98, 0x06, 0x6a, 0xe7, 0x46, 0x71, 0xba, 0xd4, 0x25, 0xab, 0x42, 0x88, 0xa2, 0x8d, 0xfa,//D
				0x72, 0x07, 0xb9, 0x55, 0xf8, 0xee, 0xac, 0x0a, 0x36, 0x49, 0x2a, 0x68, 0x3c, 0x38, 0xf1, 0xa4,//E
				0x40, 0x28, 0xd3, 0x7b, 0xbb, 0xc9, 0x43, 0xc1, 0x15, 0xe3, 0xad, 0xf4, 0x77, 0xc7, 0x80, 0x9e //F
		};

		const uint64_t sigma[6] =
		{
			0xa09e667f3bcc908b,
			0xb67ae8584caa73b2,
			0xc6ef372fe94f82be,
			0x54ff53a5f1d36f1c,
			0x10e527fade682d1d,
			0xb05688c2b3e6c1fd
		};

		std::pair<uint64_t, uint64_t> CLMB(uint64_t l, uint64_t r, uint64_t i);

		uint8_t s1(uint8_t n);
		uint8_t s2(uint8_t n);
		uint8_t s3(uint8_t n);
		uint8_t s4(uint8_t n);

		uint64_t s(uint64_t n);
		uint64_t p(uint64_t n);
		uint64_t FL(uint64_t x, uint64_t kl);
		uint64_t FL_inv(uint64_t y, uint64_t kl);
		uint64_t F(uint64_t x, uint64_t k);

		dog_data::Data extend_key(dog_data::Data key, uint64_t key_size = 16);

		dog_data::Data encoding(dog_data::Data& plain, uint8_t block_size, const dog_data::Data& key, uint8_t key_size);
		dog_data::Data decoding(dog_data::Data& crypt, uint8_t block_size, const dog_data::Data& key, uint8_t key_size);

		void encoding_self(dog_data::Data& plain, uint8_t block_size, const dog_data::Data& key, uint8_t key_size);
		void decoding_self(dog_data::Data& crypt, uint8_t block_size, const dog_data::Data& key, uint8_t key_size);

	}
}