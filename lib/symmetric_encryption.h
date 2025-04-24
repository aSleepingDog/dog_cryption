#pragma once
#include <exception>
#include <string>
#include <random>
#include <format>
#include <functional>
#include <thread>
#include <cstdlib>

#include "data_bytes.h"
#include "big_number.h"


namespace DogCryption
{
	typedef uint64_t Ullong;
	typedef uint32_t Uint;
	typedef uint16_t Ushort;
	typedef uint8_t byte;

	class cryption_config
	{
	public:
		bool is_valid = false;

		std::string cryption_algorithm;//算法名
		Ullong block_size;//块大小
		Ullong key_size;//密钥大小
        std::string padding_function;//填充函数
        std::string mult_function;//多块加密函数
		bool using_iv;//是否使用iv
		//bool with_iv;//是否携带iv
		bool using_padding;//是否使用填充
		bool using_parallelism;//是否使用并行

		cryption_config(
			const std::string& cryption_algorithm, const Ullong block_size, const Ullong key_size,
			const std::string& padding_function,
			const std::string& mult_function, bool using_iv, bool using_padding, bool using_parallelism
		);
		DogData::Data to_data() const;
		std::string to_string() const;
		/*
		* @param config_stream 带有配置信息头的流
		* @param return_start 是否返回流指针到开始处(默认回到)
		* @return 配置信息
		*/
		static cryption_config get_cryption_config(std::istream& config_stream, bool return_start = true);
		static cryption_config get_cryption_config(const DogData::Data& config_data);
	};

	class cryption_exception : public std::exception
	{
	private:
		std::string msg;
	public:
		cryption_exception(const char* msg, const char* file, const char* function, uint64_t line);
		~cryption_exception() = default;
		virtual const char* what() const throw();
	};

	class cryptor
	{
	private:
		bool is_valid = false;
		std::string cryption_algorithm;//算法名
		Ullong block_size;//块大小
		Ullong key_size;//密钥大小
		std::string padding_function;//填充函数
		std::string mult_function;//多块加密函数
		bool using_iv;//是否使用iv
		//bool with_iv;//是否携带iv
		bool using_padding;//是否使用填充
		bool using_parallelism;//是否使用并行

		//以下属性仅在CFB模式下有效 
		Ullong reback_size = 0;//反馈数据长度大小
		
		//密钥加工
		bool is_setting_key = false;
		DogData::Data key;
		DogData::Data original_key;
		std::function<DogData::Data(DogData::Data&, Ullong)> extend_key;

		//填充/去填充方法
		std::function<void(DogData::Data&, byte)> padding;
		std::function<void(DogData::Data&, byte)> unpadding;
		
		//单块加密/解密方法
		std::function<void(DogData::Data&, byte, const DogData::Data&, byte)> block_encryption;
		std::function<void(DogData::Data&, byte, const DogData::Data&, byte)> block_decryption;
		
		//模式加密/解密方法
		std::function<DogData::Data(DogData::Data, DogData::Data, DogCryption::cryptor&)> mult_encrypt;
		std::function<DogData::Data(DogData::Data, DogData::Data, DogCryption::cryptor&)> mult_decrypt;

		std::function<void(std::istream&, DogData::Data, std::ostream&, DogCryption::cryptor&)> stream_encrypt;
		std::function<void(std::istream&, DogData::Data, std::ostream&, DogCryption::cryptor&)> stream_decrypt;

		std::function<void(std::istream&, DogData::Data, std::ostream&, DogCryption::cryptor&, std::atomic<double>* progress)> stream_encryptp;
		std::function<void(std::istream&, DogData::Data, std::ostream&, DogCryption::cryptor&, std::atomic<double>* progress)> stream_decryptp;

	public:
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
		cryptor(
			const std::string& cryption_algorithm, const Ullong block_size, const Ullong key_size,
			const std::string& padding_function,
			const std::string& mult_function, bool using_iv, bool using_padding, bool using_parallelism
		);
		cryptor(const cryption_config& config) : 
			cryptor(config.cryption_algorithm, config.block_size, config.key_size, 
				config.padding_function, 
				config.mult_function, config.using_iv, config.using_padding, config.using_parallelism) {}
		void set_key(DogData::Data key);

		void swap(cryptor& other);
		void swap_config(cryptor& other);
		
		Ullong get_block_size() const;
        Ullong get_key_size() const;

		bool get_using_iv() const;
		bool get_using_padding() const;
		bool get_using_parallelism() const;

		Ullong get_reback_size() const;
		
		DogData::Data get_original_key() const;
		DogData::Data get_available_key() const;

		std::function<void(DogData::Data&, byte)> get_padding() const;
		std::function<void(DogData::Data&, byte)> get_unpadding() const;

		std::function<void(DogData::Data&, byte, const DogData::Data&, byte)> get_block_encryption() const;
		std::function<void(DogData::Data&, byte, const DogData::Data&, byte)> get_block_decryption() const;

		DogCryption::cryption_config get_config();

		std::pair<DogData::Data, DogData::Data> encrypt(DogData::Data iv, DogData::Data data);
		std::pair<DogData::Data, DogData::Data> encrypt(DogData::Data data);
        DogData::Data decrypt(std::pair<DogData::Data, DogData::Data> datas);
		DogData::Data decrypt(DogData::Data iv, DogData::Data data);

		/*
		* @param plain 明文输入流引用
		* @param crypt 密文输出流引用
		* @param iv 加密所需随机数据(若算法不需要使用则忽略此项,若过长则截取前部所需范围(如需要16B,输入24B则截取前16B))
		* @param with_config 是否将配置信息写入密文流头部
		* 
		* @throws 无效的cryptor,可能是cryptor未正确配置或未设置密钥
		* @throws 无效的iv,可能是iv长度不够
		*/
		void encrypt(std::istream& plain, std::ostream& crypt, DogData::Data iv, bool with_config);

		/*
		* @param plain 明文输入流引用
		* @param crypt 密文输出流引用
		* @param iv 加密所需随机数据(若算法不需要使用则忽略此项,若过长则截取前部所需范围(如需要16B,输入24B则截取前16B))
		* @param with_config=false 默认不将配置信息写入密文流头部
		* 
		* @throws 无效的cryptor,可能是cryptor未正确配置或未设置密钥
		* @throws 无效的iv,可能是iv长度不够
		*/
		void encrypt(std::istream& plain, std::ostream& crypt, DogData::Data iv);

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
		DogData::Data encrypt(std::istream& plain, std::ostream& crypt, bool with_config);
		DogData::Data encryptp(std::istream& plain, std::ostream& crypt, bool with_config, std::atomic<double>* progress);
		
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
		DogData::Data encrypt(std::istream& plain, std::ostream& crypt);
		DogData::Data encryptp(std::istream& plain, std::ostream& crypt, std::atomic<double>* progress);
		
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

	namespace utils
	{
		byte rand_byte();
		
		DogData::Data squareXOR(DogData::Data& a, DogData::Data& b, Ullong size);
		void squareXOR_self(DogData::Data& a, DogData::Data& b, Ullong size);
		DogData::Data randiv(byte block_size);
	}

	namespace padding
	{
		/*
		PKCS7 all fill value of length less than 16B 全部填充少于16B的长度值
		ZERO all fill 0 全部填充0
		ANSI923 all fill 0 but the last one fill value of length less than 16B 全部填充0，但是最后一个填充的是少于16B的长度值
		ISO7816_4 all fill 0 but the first one fill value 0x80 全部填充0，但是第一个填充的是0x80
		ISO10126 all fill randon value but the last one fill value of length less than 16B 全部填充随机数，但是最后一个填充的是少于16B的长度值
		*/

		const bool USING_PADDING = true;
		const bool NOT_USING_PADDING = false;

		const std::string NONE = "NONE";
		void NONE_padding(DogData::Data& data, byte block_size);
		void NONE_unpadding(DogData::Data& data, byte block_size);

		const std::string PKCS7 = "PKCS7";
		void PKCS7_padding(DogData::Data& data,byte block_size);
		void PKCS7_unpadding(DogData::Data& data, byte block_size);
        
		const std::string ZERO = "ZERO";
		void ZERO_padding(DogData::Data& data, byte block_size);
		void ZERO_unpadding(DogData::Data& data, byte block_size);

		const std::string ANSI923 = "ANSI923";
		void ANSI923_padding(DogData::Data& data, byte block_size);
		void ANSI923_unpadding(DogData::Data& data, byte block_size);

		const std::string ISO7816_4 = "ISO7816_4";
		void ISO7816_4_padding(DogData::Data& data, byte block_size);
		void ISO7816_4_unpadding(DogData::Data& data, byte block_size);

		const std::string ISO10126 = "ISO10126";
		void ISO10126_padding(DogData::Data& data, byte block_size);
		void ISO10126_unpadding(DogData::Data& data, byte block_size);
	}

	namespace mode
	{
		/*
			ECB no use iv 不使用iv
			CBC use iv 使用iv
			OFB use iv 使用iv
			CTR use iv 使用iv
			CFB1 use iv 使用iv
			CFB8 use iv 使用iv
			CFB128 use iv使用iv使用填充
		*/

		const bool USING_IV = true;
		const bool NOT_USING_IV = false;

		const bool USING_PARALLELISM = true;
		const bool NOT_USING_PARALLELISM = false;

		double update_progress(double progress, double progress_step, double progress_max);

        const std::string ECB = "ECB";
		DogData::Data encrypt_ECB(DogData::Data plain, DogData::Data iv, DogCryption::cryptor& cryptor);
		DogData::Data decrypt_ECB(DogData::Data crypt, DogData::Data iv, DogCryption::cryptor& cryptor);
		void encrypt_ECB_stream(std::istream& plain, DogData::Data iv, std::ostream& crypt, DogCryption::cryptor& cryptor);
		void decrypt_ECB_stream(std::istream& crypt, DogData::Data iv, std::ostream& plain, DogCryption::cryptor& cryptor);
		void encrypt_ECB_streamp(std::istream& plain, DogData::Data iv, std::ostream& crypt, DogCryption::cryptor& cryptor, std::atomic<double>* progress);
		void decrypt_ECB_streamp(std::istream& crypt, DogData::Data iv, std::ostream& plain, DogCryption::cryptor& cryptor, std::atomic<double>* progress);

		const std::string CBC = "CBC";
		DogData::Data encrypt_CBC(DogData::Data plain, DogData::Data iv, DogCryption::cryptor& cryptor);
		DogData::Data decrypt_CBC(DogData::Data crypt, DogData::Data iv, DogCryption::cryptor& cryptor);
		void encrypt_CBC_stream(std::istream& plain, DogData::Data iv, std::ostream& crypt, DogCryption::cryptor& cryptor);
		void decrypt_CBC_stream(std::istream& crypt, DogData::Data iv, std::ostream& plain, DogCryption::cryptor& cryptor);
		void encrypt_CBC_streamp(std::istream& plain, DogData::Data iv, std::ostream& crypt, DogCryption::cryptor& cryptor, std::atomic<double>* progress);
		void decrypt_CBC_streamp(std::istream& crypt, DogData::Data iv, std::ostream& plain, DogCryption::cryptor& cryptor, std::atomic<double>* progress);

		const std::string OFB = "OFB";
		DogData::Data encrypt_OFB(DogData::Data plain, DogData::Data iv, DogCryption::cryptor& cryptor);
		DogData::Data decrypt_OFB(DogData::Data crypt, DogData::Data iv, DogCryption::cryptor& cryptor);
		void encrypt_OFB_stream(std::istream& plain, DogData::Data iv, std::ostream& crypt, DogCryption::cryptor& cryptor);
		void decrypt_OFB_stream(std::istream& crypt, DogData::Data iv, std::ostream& plain, DogCryption::cryptor& cryptor);
		void encrypt_OFB_streamp(std::istream& plain, DogData::Data iv, std::ostream& crypt, DogCryption::cryptor& cryptor, std::atomic<double>* progress);
		void decrypt_OFB_streamp(std::istream& crypt, DogData::Data iv, std::ostream& plain, DogCryption::cryptor& cryptor, std::atomic<double>* progress);
		
		const std::string CTR = "CTR";
		DogData::Data encrypt_CTR(DogData::Data plain, DogData::Data iv, DogCryption::cryptor& cryptor);
		DogData::Data decrypt_CTR(DogData::Data crypt, DogData::Data iv, DogCryption::cryptor& cryptor);
		void encrypt_CTR_stream(std::istream& plain, DogData::Data iv, std::ostream& crypt, DogCryption::cryptor& cryptor);
		void decrypt_CTR_stream(std::istream& crypt, DogData::Data iv, std::ostream& plain, DogCryption::cryptor& cryptor);
		void encrypt_CTR_streamp(std::istream& plain, DogData::Data iv, std::ostream& crypt, DogCryption::cryptor& cryptor, std::atomic<double>* progress);
		void decrypt_CTR_streamp(std::istream& crypt, DogData::Data iv, std::ostream& plain, DogCryption::cryptor& cryptor, std::atomic<double>* progress);

		const std::string CFBbyte = "CFBbyte";
		DogData::Data encrypt_CFBbyte(DogData::Data plain, DogData::Data iv, DogCryption::cryptor& cryptor);
		DogData::Data decrypt_CFBbyte(DogData::Data crypt, DogData::Data iv, DogCryption::cryptor& cryptor);
		void encrypt_CFBbyte_stream(std::istream& plain, DogData::Data iv, std::ostream& crypt, DogCryption::cryptor& cryptor);
		void decrypt_CFBbyte_stream(std::istream& crypt, DogData::Data iv, std::ostream& plain, DogCryption::cryptor& cryptor);
		void encrypt_CFBbyte_streamp(std::istream& plain, DogData::Data iv, std::ostream& crypt, DogCryption::cryptor& cryptor, std::atomic<double>* progress);
		void decrypt_CFBbyte_streamp(std::istream& crypt, DogData::Data iv, std::ostream& plain, DogCryption::cryptor& cryptor, std::atomic<double>* progress);

		const std::string CFBbit = "CFBbit";
		DogData::Data encrypt_CFBbit(DogData::Data plain, DogData::Data iv, DogCryption::cryptor& cryptor);
		DogData::Data decrypt_CFBbit(DogData::Data crypt, DogData::Data iv, DogCryption::cryptor& cryptor);
		void encrypt_CFBbit_stream(std::istream& plain, DogData::Data iv, std::ostream& crypt, DogCryption::cryptor& cryptor);
		void decrypt_CFBbit_stream(std::istream& crypt, DogData::Data iv, std::ostream& plain, DogCryption::cryptor& cryptor);
		void encrypt_CFBbit_streamp(std::istream& plain, DogData::Data iv, std::ostream& crypt, DogCryption::cryptor& cryptor, std::atomic<double>* progress);
		void decrypt_CFBbit_streamp(std::istream& crypt, DogData::Data iv, std::ostream& plain, DogCryption::cryptor& cryptor, std::atomic<double>* progress);

		const std::string CFB8 = "CFB8";
		DogData::Data encrypt_CFB8(DogData::Data plain, DogData::Data iv, DogCryption::cryptor& cryptor);
		DogData::Data decrypt_CFB8(DogData::Data crypt, DogData::Data iv, DogCryption::cryptor& cryptor);
		void encrypt_CFB8_stream(std::istream& plain, DogData::Data iv, std::ostream& crypt, DogCryption::cryptor& cryptor);
		void decrypt_CFB8_stream(std::istream& crypt, DogData::Data iv, std::ostream& plain, DogCryption::cryptor& cryptor);
		void encrypt_CFB8_streamp(std::istream& plain, DogData::Data iv, std::ostream& crypt, DogCryption::cryptor& cryptor, std::atomic<double>* progress);
		void decrypt_CFB8_streamp(std::istream& crypt, DogData::Data iv, std::ostream& plain, DogCryption::cryptor& cryptor, std::atomic<double>* progress);

		const std::string CFB1 = "CFB1";
		DogData::Data encrypt_CFB1(DogData::Data plain, DogData::Data iv, DogCryption::cryptor& cryptor);
		DogData::Data decrypt_CFB1(DogData::Data crypt, DogData::Data iv, DogCryption::cryptor& cryptor);
		void encrypt_CFB1_stream(std::istream& plain, DogData::Data iv, std::ostream& crypt, DogCryption::cryptor& cryptor);
		void decrypt_CFB1_stream(std::istream& crypt, DogData::Data iv, std::ostream& plain, DogCryption::cryptor& cryptor);
		void encrypt_CFB1_streamp(std::istream& plain, DogData::Data iv, std::ostream& crypt, DogCryption::cryptor& cryptor, std::atomic<double>* progress);
		void decrypt_CFB1_streamp(std::istream& crypt, DogData::Data iv, std::ostream& plain, DogCryption::cryptor& cryptor, std::atomic<double>* progress);

		const std::string CFB128 = "CFB128";
		DogData::Data encrypt_CFB128(DogData::Data plain, DogData::Data iv, DogCryption::cryptor& cryptor);
		DogData::Data decrypt_CFB128(DogData::Data crypt, DogData::Data iv, DogCryption::cryptor& cryptor);
		void encrypt_CFB128_stream(std::istream& plain, DogData::Data iv, std::ostream& crypt, DogCryption::cryptor& cryptor);
		void decrypt_CFB128_stream(std::istream& crypt, DogData::Data iv, std::ostream& plain, DogCryption::cryptor& cryptor);
		void encrypt_CFB128_streamp(std::istream& plain, DogData::Data iv, std::ostream& crypt, DogCryption::cryptor& cryptor, std::atomic<double>* progress);
		void decrypt_CFB128_streamp(std::istream& crypt, DogData::Data iv, std::ostream& plain, DogCryption::cryptor& cryptor, std::atomic<double>* progress);

	}

	namespace AES
	{
		const std::string AES = "AES";

		const byte AES_BLOCK_SIZE = 16;
		
		const Ullong AES128_KEY_SIZE = 16;
        const Ullong AES192_KEY_SIZE = 24;
		const Ullong AES256_KEY_SIZE = 32;

		const byte SBox[16][16] = {
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
			{0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16} };//F
		const byte InvSBox[16][16] = {
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

		const byte MixTable[16] = { 0x02,0x03,0x01,0x01, 0x01,0x02,0x03,0x01, 0x01,0x01,0x02,0x03, 0x03,0x01,0x01,0x02 };
		const byte UMixTable[16] = { 0x0E,0x0B,0x0D,0x09, 0x09,0x0E,0x0B,0x0D, 0x0D,0x09,0x0E,0x0B, 0x0B,0x0D,0x09,0x0E };

		const byte round[10] = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };
		DogData::Data extendKey128(DogData::Data& key);
		DogData::Data extendKey192(DogData::Data& key);
		DogData::Data extendKey256(DogData::Data& key);
		DogData::Data AES_extend_key(DogData::Data& key, Ullong mode);

		//the value of a must be 0x01 0x02 0x03 a的值只能为0x01,0x02,0x03
		byte Xtime(byte a, byte b);

		//each block encrypt and using funcation 区块加密及内部算法

		//AES加解密中 字节代还 行移位 列混合混合方法
		DogData::Data AESMiddleEncryptionMethod(DogData::Data datablock, int flag, int mode);
        DogData::Data AESMiddleDecryptionMethod(DogData::Data datablock, int flag, int mode);

		void AESEncodingMachine(DogData::Data& plain, byte block_size, const DogData::Data& key, byte key_size);
		void AESDecodingMachine(DogData::Data& cipher, byte block_size, const DogData::Data& key, byte key_size);
	}

	namespace SM4
	{
		const std::string SM4 = "SM4";

		const byte SM4_BLOCK_SIZE = 16;

		const Ullong SM4_KEY_SIZE = 16;

		const byte SBox[16][16] = {
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
		const Uint FK[4] = { 0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc };
		const Uint CK[32] = { 0x00070e15,0x1c232a31,0x383f464d,0x545b6269,0x70777e85,0x8c939aa1,0xa8afb6bd,0xc4cbd2d9,
							  0xe0e7eef5,0xfc030a11,0x181f262d,0x343b4249,0x50575e65,0x6c737a81,0x888f969d,0xa4abb2b9,
							  0xc0c7ced5,0xdce3eaf1,0xf8ff060d,0x141b2229,0x30373e45,0x4c535a61,0x686f767d,0x848b9299,
							  0xa0a7aeb5,0xbcc3cad1,0xd8dfe6ed,0xf4fb0209,0x10171e25,0x2c333a41,0x484f565d,0x646b7279 };

		//循环左移
		Uint CLMB(Uint i, int n);

		Uint TMixChange1(Uint n);
		Uint TMixChange2(Uint n);

		DogData::Data SM4_extend_key(DogData::Data key, Ullong mode = 16);

		void SM4EncodingMachine(DogData::Data& plain, byte block_size, const DogData::Data& key, byte key_size);
		
		void SM4DecodingMachine(DogData::Data& crypt, byte block_size, const DogData::Data& key, byte key_size);
		

	}

	namespace camelia
	{
		const std::string camelia = "camelia";

		const byte camelia_BLOCK_SIZE = 16;

		const Ullong camelia128_KEY_SIZE = 16;
		const Ullong camelia192_KEY_SIZE = 24;
		const Ullong camelia256_KEY_SIZE = 32;
	}
}