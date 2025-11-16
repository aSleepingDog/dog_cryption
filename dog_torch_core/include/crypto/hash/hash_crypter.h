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
#include <condition_variable>

#include "math/math.h"
#include "serialize/serialize.h"
#include "utils/exception.h"
#include "hash_base.h"
#include "SHA2.h"
#include "SM3.h"

namespace dog_torch { namespace crypto { namespace hash
{
	using HashException = dog_torch::utils::Exception;
	using Data = dog_torch::serialize::Data;
	
	class DOG_CRYPTION_API HashCrypher
	{
	private:
		std::string type_;
		uint64_t effective_;

		dog_torch::math::number::BigInteger total_ = 0;
		dog_torch::math::number::BigInteger max_ = 0;

		bool is_effective_ = false;

		Data initial_value_;
		uint64_t effective_size_ = 0;
		
		uint64_t block_size_ = 0;
		uint64_t number_size_ = 0;

		std::function<void(Data, Data&)> hash_function_;
		std::function<std::string(std::string, uint64_t)> config_fmt_;

	public:
		HashCrypher(std::string type, uint64_t effective);
		void update(Data data);
		void init();
		void finish();
		Data get_hash();	

		std::string get_type() const;
		uint64_t get_effective() const;
		std::string get_config() const;

		std::function<void(Data, Data&)> get_update() const;

		Data get_data_hash(Data data);
		Data get_string_hash(std::string data);
		
		static Data streamHash(HashCrypher& crypher, std::istream& data);
		static void streamHashp(HashCrypher& crypher, std::istream& data, Data* result,
			std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_);
	};

	DOG_CRYPTION_API extern const std::vector<HashConfig> list;
}}}