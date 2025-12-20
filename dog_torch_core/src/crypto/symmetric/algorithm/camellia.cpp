#include "crypto/symmetric/algorithm/camellia.h"//camellia
#define NSROOT dog_torch::crypto::symmetric //NSROOT = namespace root 
#define DOG_DATA dog_torch::serialize::Data

const NSROOT::algorithm::Config NSROOT::algorithm::camellia::CONFIG = Config("camellia", "[16,16]0", "[16,32]8");

const uint8_t NSROOT::algorithm::camellia::Sbox[256] = 
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
const uint64_t NSROOT::algorithm::camellia::sigma[6] =
{
	0xa09e667f3bcc908b,
	0xb67ae8584caa73b2,
	0xc6ef372fe94f82be,
	0x54ff53a5f1d36f1c,
	0x10e527fade682d1d,
	0xb05688c2b3e6c1fd
};
std::pair<uint64_t, uint64_t> NSROOT::algorithm::camellia::CLMB(uint64_t l, uint64_t r, uint64_t i)
{
	i %= 128;
	if (i == 0)
	{
		return std::make_pair(l, r);
	}
	else if (i == 64)
	{
		return std::make_pair(r, l);
	}
	else if (i < 64)
	{
		uint64_t l_ = (l << i) | (r >> (64 - i));
		uint64_t r_ = (r << i) | (l >> (64 - i));
		return std::make_pair(l_, r_);
	}
	else
	{
		return CLMB(r, l, i - 64);
	}
}
uint8_t NSROOT::algorithm::camellia::s1(uint8_t n)
{
	return Sbox[n];
}
uint8_t NSROOT::algorithm::camellia::s2(uint8_t n)
{
	return ((Sbox[n] << 1) + (Sbox[n] >> 7));
}
uint8_t NSROOT::algorithm::camellia::s3(uint8_t n)
{
	return ((Sbox[n] << 7) + (Sbox[n] >> 1));
}
uint8_t NSROOT::algorithm::camellia::s4(uint8_t n)
{
	return Sbox[(uint8_t)(((n) << 1) + ((n) >> 7))];
}
uint64_t NSROOT::algorithm::camellia::s(uint64_t n)
{
	typedef uint8_t byte;
	byte a1 = (n >> 56) & 0xff;
	byte a2 = (n >> 48) & 0xff;
	byte a3 = (n >> 40) & 0xff;
	byte a4 = (n >> 32) & 0xff;
	byte a5 = (n >> 24) & 0xff;
	byte a6 = (n >> 16) & 0xff;
	byte a7 = (n >> 8) & 0xff;
	byte a8 = n & 0xff;

	byte l1 = s1(a1);
	byte l2 = s2(a2);
	byte l3 = s3(a3);
	byte l4 = s4(a4);
	byte l5 = s2(a5);
	byte l6 = s3(a6);
	byte l7 = s4(a7);
	byte l8 = s1(a8);

	return ((uint64_t)l1 << 56) | 
		((uint64_t)l2 << 48) | 
		((uint64_t)l3 << 40) | 
		((uint64_t)l4 << 32) | 
		((uint64_t)l5 << 24) | 
		((uint64_t)l6 << 16) | 
		((uint64_t)l7 << 8) | 
		((uint64_t)l8);
}
uint64_t NSROOT::algorithm::camellia::p(uint64_t n)
{
	typedef uint8_t byte;

	byte z1 = (n >> 56) & 0xff;
	byte z2 = (n >> 48) & 0xff;
	byte z3 = (n >> 40) & 0xff;
	byte z4 = (n >> 32) & 0xff;
	byte z5 = (n >> 24) & 0xff;
	byte z6 = (n >> 16) & 0xff;
	byte z7 = (n >> 8) & 0xff;
	byte z8 = n & 0xff;

	byte z_1 = z1 ^ z3 ^ z4 ^ z6 ^ z7 ^ z8;
	byte z_2 = z1 ^ z2 ^ z4 ^ z5 ^ z7 ^ z8;
	byte z_3 = z1 ^ z2 ^ z3 ^ z5 ^ z6 ^ z8;
	byte z_4 = z2 ^ z3 ^ z4 ^ z5 ^ z6 ^ z7;
	byte z_5 = z1 ^ z2 ^ z6 ^ z7 ^ z8;
	byte z_6 = z2 ^ z3 ^ z5 ^ z7 ^ z8;
	byte z_7 = z3 ^ z4 ^ z5 ^ z6 ^ z8;
	byte z_8 = z1 ^ z4 ^ z5 ^ z6 ^ z7;

	return (
		(uint64_t)z_1 << 56) |
		((uint64_t)z_2 << 48) |
		((uint64_t)z_3 << 40) |
		((uint64_t)z_4 << 32) |
		((uint64_t)z_5 << 24) |
		((uint64_t)z_6 << 16) |
		((uint64_t)z_7 << 8) |
		((uint64_t)z_8);
}
uint64_t NSROOT::algorithm::camellia::FL(uint64_t x, uint64_t kl)
{
	uint32_t xl = (x >> 32) & 0xffffffff;
	uint32_t xr = x & 0xffffffff;
	uint32_t kll = (kl >> 32) & 0xffffffff;
	uint32_t klr = kl & 0xffffffff;
	uint32_t yr = (dog_torch::math::integer::CLMB(xl & kll, 1)) ^ xr;
	uint32_t yl = (yr | klr) ^ xl;
	//2025.5.22 原语句(uint64_t)yr << 32 | (uint64_t)yl;
	//把yr(y_right放左边),yl(y_left放右边)
	return (uint64_t)yl << 32 | (uint64_t)yr;
}
uint64_t NSROOT::algorithm::camellia::FL_inv(uint64_t y, uint64_t kl)
{
	uint32_t yl = (y >> 32) & 0xffffffff;
	uint32_t yr = y & 0xffffffff;
	uint32_t kll = (kl >> 32) & 0xffffffff;
	uint32_t klr = kl & 0xffffffff;
	uint32_t xl = (yr | klr) ^ yl;
	uint32_t xr = (dog_torch::math::integer::CLMB(xl & kll, 1)) ^ yr;
	//2025.5.22 (uint64_t)xr << 32 | (uint64_t)xl
	//把xr(x_right放左边),xl(x_left放右边)
	return (uint64_t)xl << 32 | (uint64_t)xr;
}
uint64_t NSROOT::algorithm::camellia::F(uint64_t x, uint64_t k)
{
	return p(s(x ^ k));
}
DOG_DATA NSROOT::algorithm::camellia::extend_key(const Data& key, uint64_t block_size, uint64_t key_size)
{
	DOG_DATA res;
	if (key.size() < 16)
	{
		throw CryptionException(DOG_EXCEPTION_MSG_OPINION(std::format("Error:key is to short need {} now {}\n错误：密钥过短 需要 {} 当前 {}", 16, key.size(), 16, key.size())));
	}
	uint64_t kll = 0, klr = 0, krl = 0, krr = 0;
	for (uint64_t i = 0; i < 8; i++)
	{
		kll |= ((uint64_t)key[i]) << (56 - i * 8);
		klr |= ((uint64_t)key[i + 8]) << (56 - i * 8);
	}
	uint64_t kal = kll, kar = klr;
	if (key_size == 24)
	{
		if (key.size() < 24)
		{
			throw CryptionException(DOG_EXCEPTION_MSG_OPINION(std::format("Error:key is to short need 24 now {}\n错误：密钥过短 需要 24 当前 {} ", key.size(), key.size())));
		}
		for (uint64_t i = 0; i < 8; i++)
		{
			krl |= (uint64_t)(key[i + 16]) << (56 - i * 8);
			krr |= ((0xFF) << (56 - i * 8)) & (uint64_t)(~key[i + 16]) << (56 - i * 8);
		}
	}
	else if (key_size == 32)
	{
		if (key.size() < 32)
		{
			throw CryptionException(DOG_EXCEPTION_MSG_OPINION(std::format("Error:key is to short need 32 now {}\n错误：密钥过短 需要 32 当前 {} ", key.size(), key.size())));
		}
		for (uint64_t i = 0; i < 8; i++)
		{
			krl |= ((uint64_t)key[i + 16]) << (56 - i * 8);
			krr |= ((uint64_t)key[i + 24]) << (56 - i * 8);
		}
	}
	else if (key_size != 16)
	{
		throw CryptionException(DOG_EXCEPTION_MSG_OPINION("Error:key size is not 16, 24 or 32\n错误：密钥长度不是16，24或32"));
	}
	auto add_uint64 = [&res](uint64_t n) -> void
		{
			for (uint64_t i = 0; i < 8; i++)
			{
				res.push_back((n >> (56 - i * 8)) & 0xff);
			}
		};

	kal ^= krl; kar ^= krr;
	kar ^= F(sigma[0], kal);
	std::swap(kal, kar);
	kar ^= F(sigma[1], kal);
	std::swap(kal, kar);

	kal ^= kll; kar ^= klr;
	kar ^= F(sigma[2], kal);
	std::swap(kal, kar);
	kar ^= F(sigma[3], kal);
	std::swap(kal, kar);

	uint64_t shift[8] = { 0,15,30,45,60,77,94,111 };
	if (key_size == 16)
	{
		res.reserve(208);
		for (uint64_t i = 0; i < 8; i++)
		{
			auto kl_ = NSROOT::algorithm::camellia::CLMB(kll, klr, shift[i]);
			auto ka_ = NSROOT::algorithm::camellia::CLMB(kal, kar, shift[i]);
			switch (shift[i])
			{
			case 0:
			{
				add_uint64(kl_.first);//kw1
				add_uint64(kl_.second);//kw2
				add_uint64(ka_.first);//k1
				add_uint64(ka_.second);//k2
				break;
			}
			case 15:
			{
				add_uint64(kl_.first);//k3
				add_uint64(kl_.second);//k4
				add_uint64(ka_.first);//k5
				add_uint64(ka_.second);//k6
				break;
			}
			case 30:
			{
				add_uint64(ka_.first);//kl1
				add_uint64(ka_.second);//kl2
				break;
			}
			case 45:
			{
				add_uint64(kl_.first);//k7
				add_uint64(kl_.second);//k8
				add_uint64(ka_.first);//k9
				break;
			}
			case 60:
			{
				add_uint64(kl_.second);//k10
				add_uint64(ka_.first);//k11
				add_uint64(ka_.second);//k12
				break;
			}
			case 77:
			{
				add_uint64(kl_.first);//kl3
				add_uint64(kl_.second);//kl4
				break;
			}
			case 94:
			{
				add_uint64(kl_.first);//k13
				add_uint64(kl_.second);//k14
				add_uint64(ka_.first);//k15
				add_uint64(ka_.second);//k16
				break;
			}
			case 111:
			{
				add_uint64(kl_.first);//k17
				add_uint64(kl_.second);//k18
				add_uint64(ka_.first);//kw3
				add_uint64(ka_.second);//kw4
				break;
			}
			}
		}
		return res;
	}
	else if (key_size != 16)
	{

		uint64_t kbl = kal, kbr = kar;
		kbl ^= krl; kbr ^= krr;
		kbr ^= F(sigma[4], kbl);
		std::swap(kbl, kbr);
		kbr ^= F(sigma[5], kbl);
		std::swap(kbl, kbr);
		for (uint64_t i = 0; i < 8; i++)
		{
			auto kl_ = NSROOT::algorithm::camellia::CLMB(kll, klr, shift[i]);
			auto kr_ = NSROOT::algorithm::camellia::CLMB(krl, krr, shift[i]);
			auto ka_ = NSROOT::algorithm::camellia::CLMB(kal, kar, shift[i]);
			auto kb_ = NSROOT::algorithm::camellia::CLMB(kbl, kbr, shift[i]);
			switch (shift[i])
			{
			case 0:
			{
				add_uint64(kl_.first);//kw1
				add_uint64(kl_.second);//kw2
				add_uint64(kb_.first);//k1
				add_uint64(kb_.second);//k2
				break;
			}
			case 15:
			{
				add_uint64(kr_.first);//k3
				add_uint64(kr_.second);//k4
				add_uint64(ka_.first);//k5
				add_uint64(ka_.second);//k6
				break;
			}
			case 30:
			{
				add_uint64(kr_.first);//kl1
				add_uint64(kr_.second);//kl2
				add_uint64(kb_.first);//k7
				add_uint64(kb_.second);//k8
				break;
			}
			case 45:
			{
				add_uint64(kl_.first);//k9
				add_uint64(kl_.second);//k10
				add_uint64(ka_.first);//k11
				add_uint64(ka_.second);//k12

				break;
			}
			case 60:
			{
				add_uint64(kl_.first);//kl3
				add_uint64(kl_.second);//kl4
				add_uint64(kr_.first);//k13
				add_uint64(kr_.second);//k14
				add_uint64(kb_.first);//k15
				add_uint64(kb_.second);//k16
				break;
			}
			case 77:
			{
				add_uint64(kl_.first);//k17
				add_uint64(kl_.second);//k18
				add_uint64(ka_.first);//kl5
				add_uint64(ka_.second);//kl6
				break;
			}
			case 94:
			{
				add_uint64(kr_.first);//k19
				add_uint64(kr_.second);//k20
				add_uint64(ka_.first);//k21
				add_uint64(ka_.second);//k22
				break;
			}
			case 111:
			{
				add_uint64(kl_.first);//k23
				add_uint64(kl_.second);//k24
				add_uint64(kb_.first);//kw3
				add_uint64(kb_.second);//kw4
				break;
			}
			}
		}
		return res;
	}


}
DOG_DATA NSROOT::algorithm::camellia::encoding(const Data& plain, uint64_t block_size, const Data& key, uint64_t key_size)
{
	auto take_uint64 = [](const DOG_DATA& data, uint64_t pos) -> uint64_t
		{
			uint64_t res = 0;
			for (uint64_t i = 0; i < 8; i++)
			{
				res |= (uint64_t)(data[pos + i]) << (56 - 8 * i);
			}
			return res;
		};
	uint64_t pl = take_uint64(plain, 0), pr = take_uint64(plain, 8);
	uint64_t pos = 16;
	auto round = [&take_uint64, &key, &pos, &pl, &pr]()->void
		{
			for (uint64_t i = 0; i < 6; i++)
			{
				uint64_t kn = take_uint64(key, pos);
				pos += 8;
				pr ^= F(kn, pl);
				std::swap(pl, pr);
			}
		};
	//std::println("{:0>16x} {:0>16x}", pl, pr);

	uint64_t kw1 = take_uint64(key, 0), kw2 = take_uint64(key, 8);
	pl ^= kw1, pr ^= kw2;
	//16-2 24/32-3
	for (uint64_t j = 0; j < 2; j++)
	{
		round();
		uint64_t kl_1 = take_uint64(key, pos), kl_2 = take_uint64(key, pos + 8);
		pos += 16;
		pl = FL(pl, kl_1); pr = FL_inv(pr, kl_2);
	}
	if (key_size != 16)
	{
		round();
		uint64_t kl_1 = take_uint64(key, pos), kl_2 = take_uint64(key, pos + 8);
		pos += 16;
		pl = FL(pl, kl_1); pr = FL_inv(pr, kl_2);
	}
	round();
	std::swap(pl, pr);
	uint64_t kw3 = take_uint64(key, pos), kw4 = take_uint64(key, pos + 8);
	pl ^= kw3, pr ^= kw4;
	//std::println("{:0>16x} {:0>16x}", pl, pr);
	DOG_DATA crypt(16);
	for (uint64_t i = 0; i < 8; i++)
	{
		crypt[i] = pl >> (56 - 8 * i) & 0xff;
		crypt[i + 8] = pr >> (56 - 8 * i) & 0xff;
	}
	return crypt;

}
DOG_DATA NSROOT::algorithm::camellia::decoding(const Data& crypt, uint64_t block_size, const Data& key, uint64_t key_size)
{
	auto take_uint64 = [](const DOG_DATA& data, uint64_t pos) -> uint64_t
		{
			uint64_t res = 0;
			for (uint64_t i = 0; i < 8; i++)
			{
				res |= (uint64_t)(data[pos + i]) << (56 - 8 * i);
			}
			return res;
		};
	uint64_t cr = take_uint64(crypt, 0), cl = take_uint64(crypt, 8);
	uint64_t pos = key_size == 16 ? 200 : 264;
	uint64_t kw4 = take_uint64(key, pos), kw3 = take_uint64(key, pos - 8);
	pos -= 16;
	cl ^= kw4, cr ^= kw3;
	auto round = [&take_uint64, &key, &pos, &cl, &cr]()->void
		{
			for (uint64_t i = 0; i < 6; i++)
			{
				uint64_t kn = take_uint64(key, pos);
				pos -= 8;
				cl ^= F(kn, cr);
				std::swap(cl, cr);
			}
		};
	for (int j = 0; j < 2; j++)
	{
		round();
		uint64_t kl_1 = take_uint64(key, pos), kl_2 = take_uint64(key, pos - 8);
		pos -= 16;
		cr = FL(cr, kl_1); cl = FL_inv(cl, kl_2);
	}
	if (key_size != 16)
	{
		round();
		uint64_t kl_1 = take_uint64(key, pos), kl_2 = take_uint64(key, pos - 8);
		pos -= 16;
		cr = FL(cr, kl_1); cl = FL_inv(cl, kl_2);
	}
	round();
	std::swap(cl, cr);
	uint64_t kw1 = take_uint64(key, 0), kw2 = take_uint64(key, 8);
	cr ^= kw1, cl ^= kw2;
	//std::println("{:0>16x} {:0>16x}", cr, cl);
	DOG_DATA plain(16);
	for (uint64_t i = 0; i < 8; i++)
	{
		plain[i] = cr >> (56 - 8 * i) & 0xff;
		plain[i + 8] = cl >> (56 - 8 * i) & 0xff;
	}
	return plain;
}
void NSROOT::algorithm::camellia::encoding_self(Data& plain, uint64_t block_size, const Data& key, uint64_t key_size)
{
	auto take_uint64 = [](const DOG_DATA& data, uint64_t pos) -> uint64_t
		{
			uint64_t res = 0;
			for (uint64_t i = 0; i < 8; i++)
			{
				res |= (uint64_t)(data[pos + i]) << (56 - 8 * i);
			}
			return res;
		};
	uint64_t pl = take_uint64(plain, 0), pr = take_uint64(plain, 8);
	uint64_t pos = 16;
	auto round = [&take_uint64, &key, &pos, &pl, &pr]()->void
		{
			for (uint64_t i = 0; i < 6; i++)
			{
				uint64_t kn = take_uint64(key, pos);
				pos += 8;
				pr ^= F(kn, pl);
				std::swap(pl, pr);
			}
		};
	//std::println("{:0>16x} {:0>16x}", pl, pr);

	uint64_t kw1 = take_uint64(key, 0), kw2 = take_uint64(key, 8);
	pl ^= kw1, pr ^= kw2;
	//16-2 24/32-3
	for (uint64_t j = 0; j < 2; j++)
	{
		round();
		uint64_t kl_1 = take_uint64(key, pos), kl_2 = take_uint64(key, pos + 8);
		pos += 16;
		pl = FL(pl, kl_1); pr = FL_inv(pr, kl_2);
	}
	if (key_size != 16)
	{
		round();
		uint64_t kl_1 = take_uint64(key, pos), kl_2 = take_uint64(key, pos + 8);
		pos += 16;
		pl = FL(pl, kl_1); pr = FL_inv(pr, kl_2);
	}
	round();
	std::swap(pl, pr);
	uint64_t kw3 = take_uint64(key, pos), kw4 = take_uint64(key, pos + 8);
	pl ^= kw3, pr ^= kw4;
	//std::println("{:0>16x} {:0>16x}", pl, pr);
	for (uint64_t i = 0; i < 8; i++)
	{
		plain[i] = pl >> (56 - 8 * i) & 0xff;
		plain[i + 8] = pr >> (56 - 8 * i) & 0xff;
	}
}
void NSROOT::algorithm::camellia::decoding_self(Data& crypt, uint64_t block_size, const Data& key, uint64_t key_size)
{
	auto take_uint64 = [](const DOG_DATA& data, uint64_t pos) -> uint64_t
		{
			uint64_t res = 0;
			for (uint64_t i = 0; i < 8; i++)
			{
				res |= (uint64_t)(data[pos + i]) << (56 - 8 * i);
			}
			return res;
		};
	uint64_t cr = take_uint64(crypt, 0), cl = take_uint64(crypt, 8);
	uint64_t pos = key_size == 16 ? 200 : 264;
	uint64_t kw4 = take_uint64(key, pos), kw3 = take_uint64(key, pos - 8);
	pos -= 16;
	cl ^= kw4, cr ^= kw3;
	auto round = [&take_uint64, &key, &pos, &cl, &cr]()->void
		{
			for (uint64_t i = 0; i < 6; i++)
			{
				uint64_t kn = take_uint64(key, pos);
				pos -= 8;
				cl ^= F(kn, cr);
				std::swap(cl, cr);
			}
		};
	for (int j = 0; j < 2; j++)
	{
		round();
		uint64_t kl_1 = take_uint64(key, pos), kl_2 = take_uint64(key, pos - 8);
		pos -= 16;
		cr = FL(cr, kl_1); cl = FL_inv(cl, kl_2);
	}
	if (key_size != 16)
	{
		round();
		uint64_t kl_1 = take_uint64(key, pos), kl_2 = take_uint64(key, pos - 8);
		pos -= 16;
		cr = FL(cr, kl_1); cl = FL_inv(cl, kl_2);
	}
	round();
	std::swap(cl, cr);
	uint64_t kw1 = take_uint64(key, 0), kw2 = take_uint64(key, 8);
	cr ^= kw1, cl ^= kw2;
	//std::println("{:0>16x} {:0>16x}", cr, cl);
	for (uint64_t i = 0; i < 8; i++)
	{
		crypt[i] = cr >> (56 - 8 * i) & 0xff;
		crypt[i + 8] = cl >> (56 - 8 * i) & 0xff;
	}
}

NSROOT::algorithm::extend_key_func NSROOT::algorithm::camellia::get_extend_key() const
{
	return extend_key;
}
NSROOT::algorithm::block_cryption_func NSROOT::algorithm::camellia::get_encrypt() const
{
	return encoding;
}
NSROOT::algorithm::block_cryption_func NSROOT::algorithm::camellia::get_decrypt() const
{
	return decoding;
}
NSROOT::algorithm::block_self_cryption_func NSROOT::algorithm::camellia::get_encrypt_self() const
{
	return encoding_self;
}
NSROOT::algorithm::block_self_cryption_func NSROOT::algorithm::camellia::get_decrypt_self() const
{
	return decoding_self;
}


#undef NSROOT
#undef DOG_DATA