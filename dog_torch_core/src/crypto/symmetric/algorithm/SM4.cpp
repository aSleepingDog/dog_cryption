#include "crypto/symmetric/algorithm/SM4.h"//SM4

#define NSROOT dog_torch::crypto::symmetric //NSROOT = namespace root
#define DOG_DATA dog_torch::serialize::Data

//unit单位:uint8_t字节
const NSROOT::algorithm::Config NSROOT::algorithm::SM4::CONFIG = Config("SM4", "[16,16]0", "[16,16]0");

const uint8_t NSROOT::algorithm::SM4::SBox[16][16] = {
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
	{0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d/*这里*/, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48} };//F
    //2024.10.10把F6的4d错打成了4b导致结果错误一直没发现，调试了10h。第二天才解决
	//此事在 https://github.com/aSleepingDog/simpleTextHashAndEncryption 亦有记载
const uint32_t NSROOT::algorithm::SM4::FK[4] = { 0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc };
const uint32_t NSROOT::algorithm::SM4::CK[32] = { 
	0x00070e15,0x1c232a31,0x383f464d,0x545b6269,0x70777e85,0x8c939aa1,0xa8afb6bd,0xc4cbd2d9,
	0xe0e7eef5,0xfc030a11,0x181f262d,0x343b4249,0x50575e65,0x6c737a81,0x888f969d,0xa4abb2b9,
	0xc0c7ced5,0xdce3eaf1,0xf8ff060d,0x141b2229,0x30373e45,0x4c535a61,0x686f767d,0x848b9299,
	0xa0a7aeb5,0xbcc3cad1,0xd8dfe6ed,0xf4fb0209,0x10171e25,0x2c333a41,0x484f565d,0x646b7279 };

uint32_t NSROOT::algorithm::SM4::TMixChange1(uint32_t n)
{
	uint32_t res = 0;
	for (int i = 0; i < 4; i++)
	{
		uint8_t bs = (n >> (24 - i * 8)) & 0xff;
		bs = SBox[bs >> 4][(bs & 0x0f)];
		res += (uint32_t)bs << (24 - i * 8);
	}
	return res ^ dog_torch::math::integer::CLMB(res, 13) ^ dog_torch::math::integer::CLMB(res, 23);
}
uint32_t NSROOT::algorithm::SM4::TMixChange2(uint32_t n)
{
	uint32_t res = 0;
	for (int i0 = 0; i0 < 4; ++i0)
	{
		uint8_t bs = (n >> (24 - i0 * 8)) & 0xff;
		bs = SBox[bs >> 4][(bs & 0x0f)];
		res += (uint32_t)bs << (24 - i0 * 8);
	}
	uint32_t e = res ^ dog_torch::math::integer::CLMB(res, 2) ^ dog_torch::math::integer::CLMB(res, 10) ^ dog_torch::math::integer::CLMB(res, 18) ^ dog_torch::math::integer::CLMB(res, 24);
	return e;
}
DOG_DATA NSROOT::algorithm::SM4::extend_key(const Data& key, uint64_t block_size, uint64_t key_size)
{
	DOG_DATA res; res.reserve(128);
	uint32_t K[36];
	for (uint64_t i = 0; i < 16; i += 4)
	{
		K[i / 4] = (uint32_t)key[i] << 24 | (uint32_t)key[i + 1] << 16 | (uint32_t)key[i + 2] << 8 | (uint32_t)key[i + 3];
		K[i / 4] ^= FK[i / 4];
	}
	for (uint64_t i = 4; i < 36; i++)
	{
		K[i] = K[i - 4] ^ TMixChange1(K[i - 3] ^ K[i - 2] ^ K[i - 1] ^ CK[i - 4]);
		for (int i0 = 0; i0 < 4; i0++)
		{
			res.push_back((uint8_t)(K[i] >> (24 - i0 * 8) & 0xff));
		}
	}
	return res;
}
DOG_DATA NSROOT::algorithm::SM4::encoding(const Data& plain, uint64_t block_size, const DOG_DATA& key, uint64_t key_size)
{
	uint32_t temp[4] = { 0,0,0,0 };
	for (int i = 0; i < 16; i += 4)
	{
		for (int i0 = 0; i0 < 4; i0++)
		{
			temp[i / 4] += (uint32_t)plain[i + i0] << (24 - i0 * 8);
		}
	}
	for (int i = 0; i < 128; i += 4)
	{
		uint32_t tempRK = 0;
		//printf("%d\n", i);
		for (int j = 0; j < 4; j++)
		{
			tempRK += (uint32_t)key[i + j] << (24 - j * 8);
		}
		int n0 = (i / 4) % 4;// 2025/03/07-23:40 int n0 = (i / 4) % 4改成int n0=(i>>2)&0xff 出现i从108跃至-439497484 原因不明
		int n1 = (n0 + 1) % 4;
		int n2 = (n0 + 2) % 4;
		int n3 = (n0 + 3) % 4;
		temp[n0] = temp[n0] ^ TMixChange2(temp[n1] ^ temp[n2] ^ temp[n3] ^ tempRK);// 2025/03/07-23:40 发生上句修改后 此句执行后 出现i从108跃至-439497484 原因不明
	}
	DOG_DATA res; res.reserve(16);
	for (int i = 0; i < 4; i++)
	{
		for (int j = 0; j < 4; j++)
		{
			res.push_back((uint8_t)(temp[3 - i] >> (24 - j * 8) & 0xff));
		}
	}
	return res;
}
DOG_DATA NSROOT::algorithm::SM4::decoding(const Data& crypt, uint64_t block_size, const DOG_DATA& key, uint64_t key_size)
{
	uint32_t temp[4] = { 0,0,0,0 };
	for (int i = 0; i < 16; i += 4)
	{
		for (int i0 = 0; i0 < 4; i0++)
		{
			temp[i / 4] += (uint32_t)crypt[i + i0] << (24 - i0 * 8);
		}
	}
	for (int i = 0; i < 128; i += 4)
	{
		uint32_t tempRK = 0;
		for (int j = 0; j < 4; j++)
		{
			tempRK += (uint32_t)key[124 - i + j] << (24 - j * 8);
		}
		int n0 = (i / 4) % 4;
		int n1 = (n0 + 1) % 4;
		int n2 = (n0 + 2) % 4;
		int n3 = (n0 + 3) % 4;
		temp[n0] = temp[n0] ^ TMixChange2(temp[n1] ^ temp[n2] ^ temp[n3] ^ tempRK);
	}
	DOG_DATA res; res.reserve(16);
	for (int i = 0; i < 4; i++)
	{
		for (int j = 0; j < 4; j++)
		{
			res.push_back((uint8_t)(temp[3 - i] >> (24 - j * 8) & 0xff));
		}
	}
	return res;
}
void NSROOT::algorithm::SM4::encoding_self(Data& plain, uint64_t block_size, const DOG_DATA& key, uint64_t key_size)
{
	uint32_t temp[4] = { 0,0,0,0 };
	for (int i = 0; i < 16; i += 4)
	{
		for (int i0 = 0; i0 < 4; i0++)
		{
			temp[i / 4] += (uint32_t)plain[i + i0] << (24 - i0 * 8);
		}
	}
	for (int i = 0; i < 128; i += 4)
	{
		uint32_t tempRK = 0;
		//printf("%d\n", i);
		for (int j = 0; j < 4; j++)
		{
			tempRK += (uint32_t)key[i + j] << (24 - j * 8);
		}
		int n0 = (i / 4) % 4;// 2025/03/07-23:40 int n0 = (i / 4) % 4改成int n0=(i>>2)&0xff 出现i从108跃至-439497484 原因不明
		int n1 = (n0 + 1) % 4;
		int n2 = (n0 + 2) % 4;
		int n3 = (n0 + 3) % 4;
		temp[n0] = temp[n0] ^ TMixChange2(temp[n1] ^ temp[n2] ^ temp[n3] ^ tempRK);// 2025/03/07-23:40 发生上句修改后 此句执行后 出现i从108跃至-439497484 原因不明
	}
	for (int i = 0; i < 4; i++)
	{
		for (int j = 0; j < 4; j++)
		{
			plain[i * 4 + j] = (uint8_t)(temp[3 - i] >> (24 - j * 8) & 0xff);
		}
	}
}
void NSROOT::algorithm::SM4::decoding_self(Data& crypt, uint64_t block_size, const DOG_DATA& key, uint64_t key_size)
{
	uint32_t temp[4] = { 0,0,0,0 };
	for (int i = 0; i < 16; i += 4)
	{
		for (int i0 = 0; i0 < 4; i0++)
		{
			temp[i / 4] += (uint32_t)crypt[i + i0] << (24 - i0 * 8);
		}
	}
	for (int i = 0; i < 128; i += 4)
	{
		uint32_t tempRK = 0;
		for (int j = 0; j < 4; j++)
		{
			tempRK += (uint32_t)key[124 - i + j] << (24 - j * 8);
		}
		int n0 = (i / 4) % 4;
		int n1 = (n0 + 1) % 4;
		int n2 = (n0 + 2) % 4;
		int n3 = (n0 + 3) % 4;
		temp[n0] = temp[n0] ^ TMixChange2(temp[n1] ^ temp[n2] ^ temp[n3] ^ tempRK);
	}
	for (int i = 0; i < 4; i++)
	{
		for (int j = 0; j < 4; j++)
		{
			crypt[i * 4 + j] = (uint8_t)(temp[3 - i] >> (24 - j * 8) & 0xff);
		}
	}
}

NSROOT::algorithm::extend_key_func NSROOT::algorithm::SM4::get_extend_key() const
{
	return extend_key;
}
NSROOT::algorithm::block_cryption_func NSROOT::algorithm::SM4::get_encrypt() const
{
	return encoding;
}
NSROOT::algorithm::block_cryption_func NSROOT::algorithm::SM4::get_decrypt() const
{
	return decoding;
}
NSROOT::algorithm::block_self_cryption_func NSROOT::algorithm::SM4::get_encrypt_self() const
{
	return encoding_self;
}
NSROOT::algorithm::block_self_cryption_func NSROOT::algorithm::SM4::get_decrypt_self() const
{
	return decoding_self;
}

#undef DOG_DATA
#undef NSROOT