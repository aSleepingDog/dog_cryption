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
#include "utils/exception.h"

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
		struct DOG_CRYPTION_API Config
		{
			std::string name;
			std::string region;
			Config(const std::string& name, const std::string& region) : name(name), region(region) {};
		};

		using update_func = std::function<void(Data, Data&)>;
		using trims_func = std::function<Data(const Data&)>;

		class DOG_CRYPTION_API Hash
		{
		protected:
			std::string name_;
			uint64_t effective_;
		public:
			Hash(const std::string& name, uint64_t effective) : name_(name), effective_(effective) {};
			virtual ~Hash() = default;
			virtual void init();
			virtual Data init_data() const;
			virtual bool have_next_block(const BigInt& pos, const BigInt& total) const;
			virtual Data next_block(const Data& data, BigInt& pos, const BigInt& total);
			virtual Data next_block(std::istream& data, BigInt& pos, const BigInt& total);
			virtual update_func get_update() const;
			virtual trims_func get_trims() const;
			virtual std::unique_ptr<Hash> clone() const;
		};
	}

	class DOG_CRYPTION_API HashGenerator
	{
	private:
		std::unique_ptr<algorithm::Hash> hash_;
		Data value_;
		BigInt pos_;
		BigInt total_;
	public:
		HashGenerator(const algorithm::Hash& hash);
		void init();
		Data calculate(const Data& data);
		Data calculate(std::istream& data, const BigInt& max);
		Data calculate(PauseableChannel& pc, std::istream& data, const BigInt& max);

		Data calculate(const std::filesystem::path& path);
		Data calculate(PauseableChannel& pc, const std::filesystem::path& path);
	};
}