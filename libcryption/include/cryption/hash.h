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

#include "data_bytes.h"
namespace dog_hash
{
	class DOG_CRYPTION_API HashException : public std::exception
	{
	private:
		std::string msg;
	public:
		HashException(const char* msg, const char* file, const char* function, uint64_t line);
		~HashException() = default;
		virtual const char* what() const throw();
	};

	class DOG_CRYPTION_API HashConfig
	{
	public:
		std::string name;
		std::string region;
		HashConfig(std::string name, std::string region);
	};
	
	class DOG_CRYPTION_API HashCrypher
	{
	private:
		std::string type_;
		uint64_t effective_;

		dog_number::BigInteger total_ = 0;
		dog_number::BigInteger max_ = 0;

		bool is_effective_ = false;

		dog_data::Data initial_value_;
		uint64_t effective_size_ = 0;
		
		uint64_t block_size_ = 0;
		uint64_t number_size_ = 0;

		std::function<void(dog_data::Data, dog_data::Data&)> hash_function_;
		std::function<std::string(std::string, uint64_t)> config_fmt_;

	public:
		HashCrypher(std::string type, uint64_t effective);
		void update(dog_data::Data data);
		void init();
		void finish();
		dog_data::Data get_hash();	

		std::string get_type() const;
		uint64_t get_effective() const;
		std::string get_config() const;

		std::function<void(dog_data::Data, dog_data::Data&)> get_update() const;

		dog_data::Data getDataHash(dog_data::Data data);
		dog_data::Data getStringHash(std::string data);
		
		static dog_data::Data streamHash(HashCrypher& crypher, std::istream& data);
		static void streamHashp(HashCrypher& crypher, std::istream& data, dog_data::Data* result,
			std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_);
	};

	namespace SHA2
	{
		DOG_CRYPTION_API extern const std::string name;
		DOG_CRYPTION_API extern const std::string effective_region;
		DOG_CRYPTION_API extern const HashConfig config;

		DOG_CRYPTION_API std::string get_config(std::string name, uint64_t effective);

		DOG_CRYPTION_API extern const uint32_t k_256[64];

		DOG_CRYPTION_API uint32_t tick4B(dog_data::Data& data, uint64_t size, uint64_t index);
		//circle right move by bits循环右移
		DOG_CRYPTION_API uint32_t CRMB(uint32_t i, uint64_t n);
		DOG_CRYPTION_API uint32_t function1_64(uint32_t e, uint32_t f, uint32_t g, uint32_t h, dog_data::Data& block, int size, int n);
		DOG_CRYPTION_API uint32_t function2_64(uint32_t a, uint32_t b, uint32_t c);

		namespace b256
		{
			DOG_CRYPTION_API extern const dog_data::Data IV;
			DOG_CRYPTION_API extern const dog_number::BigInteger MAX;
			DOG_CRYPTION_API extern const uint64_t EFFECTIVE_SIZE;
			DOG_CRYPTION_API extern const uint64_t BLOCK_SIZE;
			DOG_CRYPTION_API extern const uint64_t NUMBER_SIZE;
			DOG_CRYPTION_API void single_update(dog_data::Data plain, dog_data::Data& change_value);
		}
		namespace b224
		{
			DOG_CRYPTION_API extern const dog_data::Data IV;
			DOG_CRYPTION_API extern const dog_number::BigInteger MAX;
			DOG_CRYPTION_API extern const uint64_t EFFECTIVE_SIZE;
			DOG_CRYPTION_API extern const uint64_t BLOCK_SIZE;
			DOG_CRYPTION_API extern const uint64_t NUMBER_SIZE;
			DOG_CRYPTION_API void single_update(dog_data::Data plain, dog_data::Data& change_value);
		}
		DOG_CRYPTION_API extern const uint64_t k_512[80];

		DOG_CRYPTION_API uint64_t tick8B(dog_data::Data& data, uint64_t size, uint64_t index);
		//circleRightMoveBit
		DOG_CRYPTION_API uint64_t CRMB(uint64_t i, uint64_t n);
		DOG_CRYPTION_API uint64_t function1_128(uint64_t e, uint64_t f, uint64_t g, uint64_t h, dog_data::Data& block, int size, int n);
		DOG_CRYPTION_API uint64_t function2_128(uint64_t a, uint64_t b, uint64_t c);

		namespace b384
		{
			DOG_CRYPTION_API extern const dog_data::Data IV;
			DOG_CRYPTION_API extern const dog_number::BigInteger MAX;
			DOG_CRYPTION_API extern const uint64_t EFFECTIVE_SIZE;
			DOG_CRYPTION_API extern const uint64_t BLOCK_SIZE;
			DOG_CRYPTION_API extern const uint64_t NUMBER_SIZE;
			DOG_CRYPTION_API void single_update(dog_data::Data plain, dog_data::Data& change_value);
		}

		namespace b512
		{
			DOG_CRYPTION_API extern const dog_data::Data IV;
			DOG_CRYPTION_API extern const dog_number::BigInteger MAX;
			DOG_CRYPTION_API extern const uint64_t EFFECTIVE_SIZE;
			DOG_CRYPTION_API extern const uint64_t BLOCK_SIZE;
			DOG_CRYPTION_API extern const uint64_t NUMBER_SIZE;
			void single_update(dog_data::Data plain, dog_data::Data& change_value);
		}
	};

	namespace SM3
	{
		DOG_CRYPTION_API extern const std::string name;
		DOG_CRYPTION_API extern const std::string effective_region;
		DOG_CRYPTION_API extern const HashConfig config;

		DOG_CRYPTION_API std::string get_config(std::string name, uint64_t effective);

		//circleLeftMoveBit
		DOG_CRYPTION_API uint32_t CLMB(uint32_t i, uint64_t n);
		DOG_CRYPTION_API uint32_t SM3tick4B(dog_data::Data& data, uint64_t index);
		DOG_CRYPTION_API uint32_t functionP1_SM3(dog_data::Data& data, uint64_t index);
		DOG_CRYPTION_API uint32_t functionFF1_SM3(uint32_t a, uint32_t b, uint32_t c, int i);
		DOG_CRYPTION_API uint32_t functionGG1_SM3(uint32_t a, uint32_t b, uint32_t c, int i);

		namespace b256
		{
			DOG_CRYPTION_API extern const dog_data::Data IV;
			DOG_CRYPTION_API extern const dog_number::BigInteger MAX;
			DOG_CRYPTION_API extern const uint64_t EFFECTIVE_SIZE;
			DOG_CRYPTION_API extern const uint64_t BLOCK_SIZE;
			DOG_CRYPTION_API extern const uint64_t NUMBER_SIZE;
			DOG_CRYPTION_API void single_update(dog_data::Data plain, dog_data::Data& change_value);
		}
	}

	DOG_CRYPTION_API extern const std::vector<HashConfig> list;
}