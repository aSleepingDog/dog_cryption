#pragma once
#ifdef SHARED
	#include "export.h"
#else
	#define DOG_CRYPTION_API
#endif
#include <mutex>
#include <thread>
#include <atomic>
#include <iostream>
#include <fstream>
#include <condition_variable>
#include <filesystem>

#include "asyncion/thread/thread.h"
#include "math/math.h"
#include "serialize/serialize.h"
#include "utils/Exception.h"

namespace dog_torch::crypto::hash
{
	using Data = dog_torch::serialize::BinaryData;
	using BigInt = dog_torch::math::number::BigInteger;
	using PauseableChannel = dog_torch::asyncion::thread::PauseableChannel;

	class HashException : public dog_torch::utils::Exception
	{
	public:
		HashException(DOG_EXCEPTION_MSG_PARAMS) : dog_torch::utils::Exception(DOG_EXCEPTION_MSG_OPINION(msg)) {};
	};

	/*
	* BLAKE2b, BLAKE2s, Keccack (F1600), SHA-1, SHA-3, SHAKE (128/256), SipHash, LSH (128/256), Tiger, RIPEMD (128/160/256/320), WHIRLPOOL
	*/
	namespace algorithm
	{
		/**
		* 散列基本配置结构体
		*/
		struct DOG_CRYPTION_API Config
		{
			/**
			* 散列算法名
			*/
			std::string name;
			/**
			* 散列支持版本
			*/
			std::string region;
			Config(const std::string& name, const std::string& region) : name(name), region(region) {};
		};

		using update_func = std::function<void(Data, Data&)>;
		using trims_func = std::function<Data(const Data&)>;

		/**
		* 散列算法类
		*/
		class DOG_CRYPTION_API Hash
		{
		protected:
			/**
			* 散列算法名
			*/
			std::string name_;
			/**
			* 生效算法版本
			*/
			uint64_t effective_;
		public:
			Hash(const std::string& name, uint64_t effective) : name_(name), effective_(effective) {};

			Hash(const Hash& other);
			Hash operator=(const Hash& other);
			Hash(Hash&& other) noexcept;
			Hash operator=(Hash&& other) noexcept;


			virtual ~Hash() = default;
			/**
			* 初始化函数
			*/
			virtual void init();
			/**
			* 获得初始值
			*/
			virtual Data init_data() const;
			/**
			* 获得更新函数
			*/
			virtual update_func get_update() const;
			/**
			* 获得修剪函数
			*/
			virtual trims_func get_trims() const;
			/**
			* 获得副本
			*/
			virtual std::unique_ptr<Hash> clone() const;
			/**
			* 获得分组大小
			*/
			virtual uint64_t get_block_size() const;
			/**
			* 获得名字
			*/
			virtual std::string get_name() const;
			/**
			* 获得版本
			*/
			virtual uint64_t get_effective() const;


			/**
			* 判断是否还有下一个分组
			* @param data_pos 分组计算当前位置
			* @param data_total 分组计算总长度
			*/
			virtual bool have_next_block(uint64_t data_pos, uint64_t data_total);
			/**
			* 判断是否还有下一个分组
			* @param data_pos 分组计算当前位置
			* @param data_total 分组计算总长度
			*/
			virtual bool have_next_block_big(const BigInt& data_pos, const BigInt& data_total);

			/**
			* 获得下一个分组
			* @param data 原始数据
			* @param start 原始数据截取位置
			* @param data_pos 分组计算当前位置
			* @param data_total 分组计算总长度
			*/
			virtual Data next_block(const Data& data, uint64_t start, uint64_t& data_pos, uint64_t data_total);
			/**
			* 获得下一个分组
			* @param data 原始数据流
			* @param data_pos 分组计算当前位置
			* @param data_total 分组计算总长度
			*/
			virtual Data next_block(std::istream& data, uint64_t& data_pos, uint64_t data_total);
			/**
			* 获得下一个分组
			* @param data 原始数据流
			* @param data_pos 分组计算当前位置
			* @param data_total 分组计算总长度
			*/
			virtual Data next_block_big(std::istream& data, BigInt& data_pos, const BigInt& data_total);

		};
	}

	/**
	* 自动化散列生成器
	* ```
	* //how to use (base on SHA-256)
	* auto obj = HashGenerator(SHA2(32));                  //the unit is byte
	* obj.init();                                          //remember using init() to reset()
	* BinaryData res = obj.calculate(path("exm.txt"));
	* obj.init();                                          //remember using init() to reset before next calculating
	* ```
	*/
	class DOG_CRYPTION_API HashGenerator
	{
	private:
		std::unique_ptr<algorithm::Hash> hash_;
		Data value_;
		BigInt pos_;
		BigInt total_;
	public:
		HashGenerator(const algorithm::Hash& hash);

		HashGenerator(const HashGenerator& other);
		HashGenerator operator=(const HashGenerator& other);
		HashGenerator(HashGenerator&& other) noexcept;
		HashGenerator operator=(HashGenerator&& other) noexcept;

		/**
		* 获得内部散列算法的只读引用
		*/
		const algorithm::Hash& get_hash() const;

		/**
		* 初始化函数 在一次计算任务完成后调用 第一次构造后自动调用
		*/
		void init();
		/**
		* 计算字节序的散列值
		*/
		Data calculate(const Data& data);
		/**
		* 计算最多max个字节的流的散列值
		*/
		Data calculate(std::istream& data, uint64_t max);
		/**
		* 计算最多max个字节的流的散列值
		*/
		Data calculate(std::istream& data, const BigInt& max);
		/**
		* 带线程控制的计算最多max个字节的流的散列值
		*/
		Data calculate(PauseableChannel& pc, std::istream& data, uint64_t max);
		/**
		* 计算最多max个字节的流的散列值
		*/
		Data calculate(PauseableChannel& pc, std::istream& data, const BigInt& max);

		/**
		* 计算文件的散列值
		*/
		Data calculate(const std::filesystem::path& path);
		/**
		* 带线程控制的计算文件的散列值()
		*/
		Data calculate(PauseableChannel& pc, const std::filesystem::path& path);
	};
}