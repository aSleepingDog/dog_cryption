#include "crypto/hash/algorithm/SHA2.h"

#define NSROOT dog_torch::crypto::hash::algorithm
#define DOG_DATA dog_torch::serialize::BinaryData

#define DOG_ERROR_WRONG_BLOCK_SHA2_256 "Error:block size is not 64 when SHA2-256 or SHA2-224"
#define DOG_ERROR_WRONG_BLOCK_SHA2_512 "Error:block size is not 128 when SHA2-512 or SHA2-384"
#define DOG_ERROR_WRONG_SIZE "Error:effective must be 32 28 64 48"
#define DOG_ERROR_LARGE_SIZE "Error:input size is too large"

const NSROOT::Config dog_torch::crypto::hash::algorithm::SHA2::get_config()
{
	return Config("SHA2", "32,28|64,48");
}

const uint32_t NSROOT::SHA2::k_256[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2 };

uint32_t NSROOT::SHA2::tick4B(Data& data, uint64_t size, uint64_t index)
{
	return (uint32_t)(data[size - index * 4] << 24) + (data[size - index * 4 + 1] << 16) + (data[size - index * 4 + 2] << 8) + (data[size - index * 4 + 3]);
}
uint32_t NSROOT::SHA2::CRMB(uint32_t i, uint64_t n)
{
	//circleRightMoveBit
	int temp = n % 32;
	return (i >> temp) | (i << (32 - temp));
}
uint32_t NSROOT::SHA2::function1_64(uint32_t e, uint32_t f, uint32_t g, uint32_t h, Data& block, int size, int n)
{
	uint32_t S1 = CRMB(e, 6) ^ CRMB(e, 11) ^ CRMB(e, 25);
	//printf("%0x\n", S1);
	uint32_t ch = (e & f) ^ ((~e) & g);
	uint32_t k = k_256[n];
	uint32_t w = tick4B(block, size, (64 - n));
	//printf("%0x\n", w);
	return h + S1 + ch + k + w;
}
uint32_t NSROOT::SHA2::function2_64(uint32_t a, uint32_t b, uint32_t c)
{
	uint32_t S0 = CRMB(a, 2) ^ CRMB(a, 13) ^ CRMB(a, 22);
	uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
	return S0 + maj;
}

const DOG_DATA NSROOT::SHA2::IV_256 = "6A09E667BB67AE853C6EF372A54FF53A510E527F9B05688C1F83D9AB5BE0CD19";
void NSROOT::SHA2::single_256_update(Data block, Data& value)
{
	if (block.size() != 64)
	{
		throw HashException(DOG_EXCEPTION_MSG_OPINION(DOG_ERROR_WRONG_BLOCK_SHA2_256));
	}
	uint32_t tempN[9], tempH[8];
	for (int i = 0; i < 8; i++)
	{
		uint32_t tempInt = 0;
		tempInt |= (uint32_t)value[i * 4] << 24;
		tempInt |= (uint32_t)value[i * 4 + 1] << 16;
		tempInt |= (uint32_t)value[i * 4 + 2] << 8;
		tempInt |= (uint32_t)value[i * 4 + 3];
		tempN[i] = tempInt;
		tempH[i] = tempInt;
	}
	tempN[8] = 0;

	uint64_t size = block.size();
	while (size < 256)
	{
		uint32_t s0 = tick4B(block, size, 15);
		uint32_t s1 = tick4B(block, size, 2);
		uint32_t s2 = tick4B(block, size, 16);
		uint32_t s3 = tick4B(block, size, 7);
		s0 = CRMB(s0, 7) ^ CRMB(s0, 18) ^ (s0 >> 3);
		s1 = CRMB(s1, 17) ^ CRMB(s1, 19) ^ (s1 >> 10);
		uint32_t append = s0 + s1 + s2 + s3;
		for (int i0 = 0; i0 < 4; i0++)
		{
			block.push_back((uint8_t)(append << i0 * 8 >> 24));
		}
		size += 4;
	}
	for (int i0 = 0; i0 < 64; i0++)
	{
		uint32_t T1 = function1_64(tempN[4], tempN[5], tempN[6], tempN[7], block, size, i0);
		uint32_t T2 = function2_64(tempN[0], tempN[1], tempN[2]);
		tempN[3] += T1;
		tempN[7] = T1 + T2;
		for (int j = 8; j > 0; j--)
		{
			tempN[j] = tempN[j - 1];
		}
		tempN[0] = tempN[8];
	}
	for (int i1 = 0; i1 < 8; i1++)
	{
		tempH[i1] += tempN[i1];
		tempN[i1] = tempH[i1];
	}

	for (int i = 0; i < 8; i++)
	{
		for (int i0 = 0; i0 < 4; i0++)
		{
			value[i * 4 + i0] = (uint8_t)((tempH[i] >> (24 - i0 * 8)) & 0xFF);
		}
	}
}
const DOG_DATA NSROOT::SHA2::IV_224 = "C1059ED8367CD5073070DD17F70E5939FFC00B316858151164F98FA7BEFA4FA4";

const uint64_t NSROOT::SHA2::k_512[80] = {
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
uint64_t NSROOT::SHA2::tick8B(dog_torch::serialize::BinaryData& data, uint64_t size, uint64_t index)
{
	uint64_t res = 0;
	res += ((uint64_t)data[size - index * 8 + 0] << (56 - 8 * 0));
	res += ((uint64_t)data[size - index * 8 + 1] << (56 - 8 * 1));
	res += ((uint64_t)data[size - index * 8 + 2] << (56 - 8 * 2));
	res += ((uint64_t)data[size - index * 8 + 3] << (56 - 8 * 3));
	res += ((uint64_t)data[size - index * 8 + 4] << (56 - 8 * 4));
	res += ((uint64_t)data[size - index * 8 + 5] << (56 - 8 * 5));
	res += ((uint64_t)data[size - index * 8 + 6] << (56 - 8 * 6));
	res += ((uint64_t)data[size - index * 8 + 7] << (56 - 8 * 7));
	return res;
}
uint64_t NSROOT::SHA2::CRMB(uint64_t i, uint64_t n)
{
	int temp = n % 64;
	return (i >> temp) | (i << (64 - temp));
}
uint64_t NSROOT::SHA2::function1_128(uint64_t e, uint64_t f, uint64_t g, uint64_t h, dog_torch::serialize::BinaryData& block, int size, int n)
{
	uint64_t S1 = CRMB(e, 14) ^ CRMB(e, 18) ^ CRMB(e, 41);
	uint64_t ch = (e & f) ^ ((~e) & g);
	uint64_t temp = h + S1 + ch + k_512[n] + tick8B(block, size, (80 - n));
	return temp;
}
uint64_t NSROOT::SHA2::function2_128(uint64_t a, uint64_t b, uint64_t c)
{
	uint64_t S0 = CRMB(a, 28) ^ CRMB(a, 34) ^ CRMB(a, 39);
	uint64_t maj = (a & b) ^ (a & c) ^ (b & c);
	return S0 + maj;
}

const DOG_DATA NSROOT::SHA2::IV_512 = "6A09E667F3BCC908BB67AE8584CAA73B3C6EF372FE94F82BA54FF53A5F1D36F1510E527FADE682D19B05688C2B3E6C1F1F83D9ABFB41BD6B5BE0CD19137E2179";
void NSROOT::SHA2::single_512_update(Data block, Data& value)
{
	if (block.size() != 128)
	{
		throw HashException(DOG_EXCEPTION_MSG_OPINION(DOG_ERROR_WRONG_BLOCK_SHA2_512));
	}
	uint64_t tempN[9], tempH[8];
	for (int i = 0; i < 8; i++)
	{
		uint64_t tempInt = 0;
		tempInt |= (uint64_t)value[i * 8] << 56;
		tempInt |= (uint64_t)value[i * 8 + 1] << 48;
		tempInt |= (uint64_t)value[i * 8 + 2] << 40;
		tempInt |= (uint64_t)value[i * 8 + 3] << 32;
		tempInt |= (uint64_t)value[i * 8 + 4] << 24;
		tempInt |= (uint64_t)value[i * 8 + 5] << 16;
		tempInt |= (uint64_t)value[i * 8 + 6] << 8;
		tempInt |= (uint64_t)value[i * 8 + 7];
		tempN[i] = tempInt;
		tempH[i] = tempInt;
	}
	tempN[8] = 0;
	uint64_t size = block.size();
	while (size < 640)
	{
		uint64_t s0 = tick8B(block, size, 15);
		uint64_t s1 = tick8B(block, size, 2);
		uint64_t s2 = tick8B(block, size, 16);
		uint64_t s3 = tick8B(block, size, 7);
		s0 = CRMB(s0, 1) ^ CRMB(s0, 8) ^ (s0 >> 7);
		s1 = CRMB(s1, 19) ^ CRMB(s1, 61) ^ (s1 >> 6);
		uint64_t append = s0 + s1 + s2 + s3;
		for (int i0 = 0; i0 < 8; i0++)
		{
			block.push_back((uint8_t)(append << i0 * 8 >> 56));
		}
		size += 8;
	}
	for (int i0 = 0; i0 < 80; i0++)
	{
		uint64_t T1 = function1_128(tempN[4], tempN[5], tempN[6], tempN[7], block, size, i0);
		uint64_t T2 = function2_128(tempN[0], tempN[1], tempN[2]);
		tempN[3] += T1;
		tempN[7] = T1 + T2;
		for (int j = 8; j > 0; j--)
		{
			tempN[j] = tempN[j - 1];
		}
		tempN[0] = tempN[8];
	}
	for (int i1 = 0; i1 < 8; i1++)
	{
		tempH[i1] += tempN[i1];
		tempN[i1] = tempH[i1];
	}
	for (int i = 0; i < 8; i++)
	{
		for (int i0 = 0; i0 < 8; i0++)
		{
			value[i * 8 + i0] = (uint8_t)((tempH[i] >> (56 - i0 * 8)) & 0xFF);
		}
	}
}
const DOG_DATA NSROOT::SHA2::IV_384 = "CBBB9D5DC1059ED8629A292A367CD5079159015A3070DD17152FECD8F70E593967332667FFC00B318EB44A8768581511DB0C2E0D64F98FA747B5481DBEFA4FA4";

NSROOT::SHA2::SHA2(uint64_t effective) : Hash("SHA2", effective)
{
	if (this->effective_ != 32 && this->effective_ != 28 && this->effective_ != 64 && this->effective_ != 48)
	{
		throw HashException(DOG_EXCEPTION_MSG_OPINION(DOG_ERROR_WRONG_SIZE));
	}
	if (this->effective_ == 32 || this->effective_ == 28)
	{
		this->max_ = dog_torch::math::number::BIG_UINT64_MAX;
	}
	else if (this->effective_ == 64 || this->effective_ == 48)
	{
		this->max_ = dog_torch::math::number::BIG_UINT128_MAX;
	}
}
void NSROOT::SHA2::init()
{
	this->is_padding_num_ = false;
	this->is_padding_80_ = false;
	if (this->effective_ == 32 || this->effective_ == 28)
	{
		this->max_ = dog_torch::math::number::BIG_UINT64_MAX;
	}
	else if (this->effective_ == 64 || this->effective_ == 48)
	{
		this->max_ = dog_torch::math::number::BIG_UINT128_MAX;
	}
}
DOG_DATA NSROOT::SHA2::init_data() const
{
	switch (this->effective_)
	{
	case 32: return IV_256;
	case 28: return IV_224;
	case 64: return IV_512;
	case 48: return IV_384;
	}
}
bool NSROOT::SHA2::have_next_block(uint64_t data_pos, uint64_t data_total)
{
	if (data_total > this->max_)
	{
		throw HashException(DOG_EXCEPTION_MSG_OPINION(DOG_ERROR_LARGE_SIZE));
	}
	if (this->effective_ == 32 || this->effective_ == 28)
	{
		auto dur = (data_total - data_pos);
		return dur >= 64 ? true : !this->is_padding_num_;
	}
	else if (this->effective_ == 64 || this->effective_ == 48)
	{
		auto dur = (data_total - data_pos);
		return dur >= 128 ? true : !this->is_padding_num_;
	}
}
bool NSROOT::SHA2::have_next_block_big(const BigInt& data_pos, const BigInt& data_total)
{
	if (data_total > this->max_)
	{
		throw HashException(DOG_EXCEPTION_MSG_OPINION(DOG_ERROR_LARGE_SIZE));
	}
	if (this->effective_ == 32 || this->effective_ == 28)
	{
		auto dur = (data_total - data_pos);
		return dur >= 64 ? true : !this->is_padding_num_;
	}
	else if (this->effective_ == 64 || this->effective_ == 48)
	{
		auto dur = (data_total - data_pos);
		return dur >= 128 ? true : !this->is_padding_num_;
	}
}
DOG_DATA NSROOT::SHA2::next_block(const Data& data, uint64_t start, uint64_t& pos, uint64_t total)
{
	if (total > this->max_)
	{
		throw HashException(DOG_EXCEPTION_MSG_OPINION(DOG_ERROR_LARGE_SIZE));
	}
	if (this->effective_ == 32 || this->effective_ == 28)
	{
		auto res = data.sub_bytes_by_len(start, 64);
		pos += res.size();
		if (res.size() >= 64) return res;
		else
		{
			if (!this->is_padding_80_)
			{
				res.push_back(0x80);
				this->is_padding_80_ = true;
			}
			if (res.size() > (64 - 8))
			{
				while (res.size() < 64) res.push_back(0x00);
				return res;
			}
			else
			{
				while (res.size() < (64 - 8)) res.push_back(0x00);
				Data num = BigInt(total * 8).to_byte_vector();
				for (uint64_t i = 0; i < (8 - num.size()); i++) res.push_back(0x00);
				this->is_padding_num_ = true;
				return res + num;
			}
		}
	}
	else if (this->effective_ == 64 || this->effective_ == 48)
	{
		auto res = data.sub_bytes_by_len(start, 128);
		pos += res.size();
		if (res.size() >= 128) return res;
		else
		{
			if (!this->is_padding_80_)
			{
				res.push_back(0x80);
				this->is_padding_80_ = true;
			}
			if (res.size() > (128 - 16))
			{
				while (res.size() < 128) res.push_back(0x00);
				return res;
			}
			else
			{
				while (res.size() < (128 - 16)) res.push_back(0x00);
				Data num = BigInt(total * 8).to_byte_vector();
				for (uint64_t i = 0; i < (16 - num.size()); i++) res.push_back(0x00);
				this->is_padding_num_ = true;
				return res + num;
			}
		}

	}
	else
	{
		throw HashException(DOG_EXCEPTION_MSG_OPINION(DOG_ERROR_WRONG_SIZE));
	}
}
DOG_DATA NSROOT::SHA2::next_block(std::istream& data, uint64_t& data_pos, uint64_t data_total)
{
	if (data_total > this->max_)
	{
		throw HashException(DOG_EXCEPTION_MSG_OPINION(DOG_ERROR_LARGE_SIZE));
	}
	if (this->effective_ == 32 || this->effective_ == 28)
	{
		Data res(64);
		data.read((char*)res.data(), 64);
		for (uint64_t i = data.gcount(); i < 64; i++) res.pop_back();
		data_pos += data.gcount();
		if (res.size() >= 64) return res;
		else
		{
			if (!this->is_padding_80_)
			{
				res.push_back(0x80);
				this->is_padding_80_ = true;
			}
			if (res.size() > (64 - 8))
			{
				while (res.size() < 64) res.push_back(0x00);
				return res;
			}
			else
			{
				while (res.size() < (64 - 8)) res.push_back(0x00);
				Data num = BigInt(data_total * 8).to_byte_vector();
				for (uint64_t i = 0; i < (8 - num.size()); i++) res.push_back(0x00);
				this->is_padding_num_ = true;
				return res + num;
			}
		}
	}
	else if (this->effective_ == 64 || this->effective_ == 48)
	{
		Data res(64);
		data.read((char*)res.data(), 64);
		for (uint64_t i = data.gcount(); i < 64; i++) res.pop_back();
		data_pos += data.gcount();
		if (res.size() >= 128) return res;
		else
		{
			if (!this->is_padding_80_)
			{
				res.push_back(0x80);
				this->is_padding_80_ = true;
			}
			if (res.size() > (128 - 16))
			{
				while (res.size() < 128) res.push_back(0x00);
				return res;
			}
			else
			{
				while (res.size() < (128 - 16)) res.push_back(0x00);
				Data num = BigInt(data_total * 8).to_byte_vector();
				for (uint64_t i = 0; i < (16 - num.size()); i++) res.push_back(0x00);
				this->is_padding_num_ = true;
				return res + num;
			}
		}

	}
	else
	{
		throw HashException(DOG_EXCEPTION_MSG_OPINION(DOG_ERROR_WRONG_SIZE));
	}
}
DOG_DATA NSROOT::SHA2::next_block_big(std::istream& data, BigInt& data_pos, const BigInt& data_total)
{
	if (data_total > this->max_)
	{
		throw HashException(DOG_EXCEPTION_MSG_OPINION(DOG_ERROR_LARGE_SIZE));
	}
	if (this->effective_ == 32 || this->effective_ == 28)
	{
		Data res(64);
		data.read((char*)res.data(), 64);
		for (uint64_t i = data.gcount(); i < 64; i++) res.pop_back();
		data_pos += data.gcount();
		if (res.size() >= 64) return res;
		else
		{
			if (!this->is_padding_80_)
			{
				res.push_back(0x80);
				this->is_padding_80_ = true;
			}
			if (res.size() > (64 - 8))
			{
				while (res.size() < 64) res.push_back(0x00);
				return res;
			}
			else
			{
				while (res.size() < (64 - 8)) res.push_back(0x00);
				Data num = (data_total * 8).to_byte_vector();
				for (uint64_t i = 0; i < (8 - num.size()); i++) res.push_back(0x00);
				this->is_padding_num_ = true;
				return res + num;
			}
		}
	}
	else if (this->effective_ == 64 || this->effective_ == 48)
	{
		Data res(64);
		data.read((char*)res.data(), 64);
		for (uint64_t i = data.gcount(); i < 64; i++) res.pop_back();
		data_pos += data.gcount();
		if (res.size() >= 128) return res;
		else
		{
			if (!this->is_padding_80_)
			{
				res.push_back(0x80);
				this->is_padding_80_ = true;
			}
			if (res.size() > (128 - 16))
			{
				while (res.size() < 128) res.push_back(0x00);
				return res;
			}
			else
			{
				while (res.size() < (128 - 16)) res.push_back(0x00);
				Data num = (data_total * 8).to_byte_vector();
				for (uint64_t i = 0; i < (16 - num.size()); i++) res.push_back(0x00);
				this->is_padding_num_ = true;
				return res + num;
			}
		}

	}
	else
	{
		throw HashException(DOG_EXCEPTION_MSG_OPINION(DOG_ERROR_WRONG_SIZE));
	}
}
NSROOT::update_func NSROOT::SHA2::get_update() const
{
	using dog_torch::math::number::BigInteger;
	switch (this->effective_)
	{
	case 28:
	case 32:
		return single_256_update;
	case 48:
	case 64:
		return single_512_update;
	}
	throw HashException(DOG_EXCEPTION_MSG_OPINION(DOG_ERROR_WRONG_SIZE));
}
NSROOT::trims_func NSROOT::SHA2::get_trims() const
{
	switch (this->effective_)
	{
	case 32:
	case 64:
	{
		return [](const Data& value) -> Data
			{
				return value;
			};
	}
	case 28:
	{
		return [](const Data& value) -> Data
			{
				return value.sub_bytes_by_len(0, 28);
			};
	}
	case 48:
	{
		return [](const Data& value) -> Data
			{
				return value.sub_bytes_by_len(0, 48);
			};
	}
	}
	throw HashException(DOG_EXCEPTION_MSG_OPINION(DOG_ERROR_WRONG_SIZE));
}
std::unique_ptr<NSROOT::Hash> NSROOT::SHA2::clone() const
{
	return std::move(std::make_unique<SHA2>(*this));
}

uint64_t dog_torch::crypto::hash::algorithm::SHA2::get_block_size() const
{
	if (this->effective_ == 32 || this->effective_ == 28) return 64;
	else if (this->effective_ == 64 || this->effective_ == 48) return 128;
}

#undef NSROOT
#undef DOG_DATA

#undef DOG_ERROR_WRONG_BLOCK_SHA2_256
#undef DOG_ERROR_WRONG_BLOCK_SHA2_512
#undef DOG_ERROR_WRONG_SIZE
#undef DOG_ERROR_LARGE_SIZE