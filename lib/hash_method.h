#pragma once
#include <iostream>
#include <thread>
#include "big_number.h"
#include "data_bytes.h"
namespace dog_hash
{
	class HashException : public std::exception
	{
	private:
		std::string msg;
	public:
		HashException(const char* msg, const char* file, const char* function, uint64_t line);
		~HashException() = default;
		virtual const char* what() const throw();
	};
	
	class hash_crypher
	{
	private:
		std::string type;

		dog_number::BigInteger total = 0;
		dog_number::BigInteger max = 0;

		bool is_effective = false;

		dog_data::Data initial_value;
		uint64_t effective_size = 0;
		
		uint64_t block_size = 0;
		uint64_t number_size = 0;

		std::function<void(dog_data::Data, dog_data::Data&)> hash_function;

	public:
		hash_crypher(std::string sign);
		void update(dog_data::Data data);
		void init();
		void finish();
		dog_data::Data get_hash();	

		std::string get_type() const;

		dog_data::Data getDataHash(dog_data::Data data);
		dog_data::Data getStringHash(std::string data);
		
		static dog_data::Data streamHash(hash_crypher& crypher, std::istream& data);
		static void streamHashp(hash_crypher& crypher, std::istream& data, std::atomic<double>* progress, dog_data::Data* result);
	};

	namespace SHA2
	{
		const std::string SHA256 = "SHA2_256";
		const std::string SHA224 = "SHA2_224";

		const uint32_t k_256[64] = { 
				0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
				0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
				0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
				0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
				0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
				0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
				0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
				0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2 };

		uint32_t tick4B(dog_data::Data& data, uint64_t size, uint64_t index);
		//circle right move by bits循环右移
		uint32_t CRMB(uint32_t i, uint64_t n);
		uint32_t function1_64(uint32_t e, uint32_t f, uint32_t g, uint32_t h, dog_data::Data& block, int size, int n);
		uint32_t function2_64(uint32_t a, uint32_t b, uint32_t c);

		//                               ________--------________--------________--------________--------
		const dog_data::Data SHA256_IV = "6A09E667BB67AE853C6EF372A54FF53A510E527F9B05688C1F83D9AB5BE0CD19";
		const dog_number::BigInteger SHA256_MAX = "18446744073709551616";
		const uint64_t SHA256_EFFECTIVE_SIZE = 32;
		const uint64_t SHA256_BLOCK_SIZE = 64;
        const uint64_t SHA256_NUMBER_SIZE = 8;
		void SHA256_update(dog_data::Data plain, dog_data::Data& change_value);

		//                               ________--------________--------________--------________--------
		const dog_data::Data SHA224_IV = "C1059ED8367CD5073070DD17F70E5939FFC00B316858151164F98FA7BEFA4FA4";
        const dog_number::BigInteger SHA224_MAX = "18446744073709551616";
        const uint64_t SHA224_EFFECTIVE_SIZE = 28;
        const uint64_t SHA224_BLOCK_SIZE = 64;
        const uint64_t SHA224_NUMBER_SIZE = 8;
        void SHA224_update(dog_data::Data plain, dog_data::Data& change_value);

		const std::string SHA384 = "SHA2_384";
		const std::string SHA512 = "SHA2_512";

		const uint64_t k_512[80] = { 
			0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
			0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
			0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
			0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
			0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
			0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
			0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
			0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
			0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
			0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
			0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
			0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
			0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
			0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
			0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
			0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
			0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
			0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
			0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
			0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817 };

		uint64_t tick8B(dog_data::Data& data, uint64_t size, uint64_t index);
		//circleRightMoveBit
		uint64_t CRMB(uint64_t i, uint64_t n);
		uint64_t function1_128(uint64_t e, uint64_t f, uint64_t g, uint64_t h, dog_data::Data& block, int size, int n);
		uint64_t function2_128(uint64_t a, uint64_t b, uint64_t c);

		//                               ________________----------------________________----------------________________----------------________________----------------
		const dog_data::Data SHA512_IV = "6A09E667F3BCC908BB67AE8584CAA73B3C6EF372FE94F82BA54FF53A5F1D36F1510E527FADE682D19B05688C2B3E6C1F1F83D9ABFB41BD6B5BE0CD19137E2179";
		const dog_number::BigInteger SHA512_MAX = "340282366920938463463374607431768211455";
		const uint64_t SHA512_EFFECTIVE_SIZE = 64;
		const uint64_t SHA512_BLOCK_SIZE = 128;
		const uint64_t SHA512_NUMBER_SIZE = 16;
        void SHA512_update(dog_data::Data plain, dog_data::Data& change_value);
		//                               ________________----------------________________----------------________________----------------________________----------------
		const dog_data::Data SHA384_IV = "CBBB9D5DC1059ED8629A292A367CD5079159015A3070DD17152FECD8F70E593967332667FFC00B318EB44A8768581511DB0C2E0D64F98FA747B5481DBEFA4FA4";
		const dog_number::BigInteger SHA384_MAX = "340282366920938463463374607431768211455";
        const uint64_t SHA384_EFFECTIVE_SIZE = 48;
        const uint64_t SHA384_BLOCK_SIZE = 128;
        const uint64_t SHA384_NUMBER_SIZE = 16;
        void SHA384_update(dog_data::Data plain, dog_data::Data& change_value);
	};

	namespace SM3
	{
		//circleLeftMoveBit
		uint32_t CLMB(uint32_t i, uint64_t n);
		uint32_t SM3tick4B(dog_data::Data& data, uint64_t index);
		uint32_t functionP1_SM3(dog_data::Data& data, uint64_t index);
		uint32_t functionFF1_SM3(uint32_t a, uint32_t b, uint32_t c, int i);
		uint32_t functionGG1_SM3(uint32_t a, uint32_t b, uint32_t c, int i);

		const std::string SM3 = "SM3";
		const dog_data::Data SM3_IV = "7380166F4914B2B9172442D7DA8A0600A96F30BC163138AAE38DEE4DB0FB0E4E";
		const dog_number::BigInteger SM3_MAX = "18446744073709551616";
        const uint64_t SM3_EFFECTIVE_SIZE = 32;
        const uint64_t SM3_BLOCK_SIZE = 64;
        const uint64_t SM3_NUMBER_SIZE = 8;
		void SM3_update(dog_data::Data plain, dog_data::Data& change_value);
	}
}