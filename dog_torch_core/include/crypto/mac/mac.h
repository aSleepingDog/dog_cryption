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
#include "crypto/hash/hash.h"

namespace dog_torch::crypto::mac
{
	using BinaryData = dog_torch::serialize::BinaryData;
	using HashGenerator = dog_torch::crypto::hash::HashGenerator;
	using PauseableChannel = dog_torch::asyncion::thread::PauseableChannel;

	class MacGenerator
	{
	protected:
		BinaryData key_;
	public:
		MacGenerator(const BinaryData& key);
		virtual ~MacGenerator();
		virtual BinaryData generate(const BinaryData& data);
		virtual BinaryData generate(std::istream& input, uint64_t size);
		virtual BinaryData generate(PauseableChannel& pc, std::istream& input, uint64_t size);
		virtual BinaryData generate(std::filesystem::path path);
		virtual BinaryData generate(PauseableChannel& pc, std::filesystem::path path);
	};

	class HMacGenerator : public MacGenerator
	{
	private:
		std::unique_ptr<hash::algorithm::Hash> hasher_;
	public:
		HMacGenerator(const BinaryData& key, const hash::algorithm::Hash& hasher);
		BinaryData generate(const BinaryData& data) override;
		BinaryData generate(std::istream& input, uint64_t size) override;
		BinaryData generate(PauseableChannel& pc, std::istream& input, uint64_t size) override;
		BinaryData generate(std::filesystem::path path) override;
		BinaryData generate(PauseableChannel& pc, std::filesystem::path path) override;
	};
}
