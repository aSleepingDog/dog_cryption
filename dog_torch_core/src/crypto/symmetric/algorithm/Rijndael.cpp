#include "crypto/symmetric/algorithm/Rijndael.h"//Rijndael & AES

#define NSROOT dog_torch::crypto::symmetric //NSROOT = namespace root

const uint8_t NSROOT::algorithm::Rijndael::SBox[16][16] = {
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
const uint8_t NSROOT::algorithm::Rijndael::InvSBox[16][16] = {
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
	{0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d} };//F;
const uint8_t NSROOT::algorithm::Rijndael::MixTable[16] = { 0x02,0x03,0x01,0x01, 0x01,0x02,0x03,0x01, 0x01,0x01,0x02,0x03, 0x03,0x01,0x01,0x02 };
const uint8_t NSROOT::algorithm::Rijndael::UMixTable[16] = { 0x0E,0x0B,0x0D,0x09, 0x09,0x0E,0x0B,0x0D, 0x0D,0x09,0x0E,0x0B, 0x0B,0x0D,0x09,0x0E };
const uint8_t NSROOT::algorithm::Rijndael::round[16] = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };//todo 使用循环元0x011b填充后续元素……

uint8_t NSROOT::algorithm::Rijndael::Xtime(uint8_t a, uint8_t b)
{
	//1 2 4 8
	if (a == 0x01)
	{
		return b;
	}
	else if (a == 0x02)
	{
		if (b >> 7 == 0)
		{
			return b << 1;
		}
		else//  <==> else if (b >> 7 == 1)
		{
			return (b << 1) ^ 0x1b;
		}
	}
	else if (a == 0x04)
	{
		return Xtime(0x02, Xtime(0x02, b));
	}
	else if (a == 0x08)
	{
		return Xtime(0x02, Xtime(0x02, Xtime(0x02, b)));
	}
	else if (a == 0x03) //02+01
	{
		return Xtime(0x02, b) ^ b;
	}
	else if (a == 0x09) //08+01=09
	{
		return Xtime(0x08, b) ^ b;
	}
	else if (a == 0x0b) //08+02+01=13=0b
	{
		return Xtime(0x08, b) ^ Xtime(0x02, b) ^ b;
	}
	else if (a == 0x0d) //08+04+01
	{
		return Xtime(0x08, b) ^ Xtime(0x04, b) ^ b;
	}
	else if (a == 0x0e) //08+04+02=0e=14
	{
		return Xtime(0x08, b) ^ Xtime(0x04, b) ^ Xtime(0x02, b);
	}
	else
	{
		throw CryptionException(DOG_EXCEPTION_MSG_OPINION("Error:AES wrong value of a\n错误,AES a值错误"));
	}
}

//Rijndael
const NSROOT::algorithm::Config NSROOT::algorithm::Rijndael::CONFIG = Config("Rijndael","[16,32]4","[16,32]4");
NSROOT::algorithm::Rijndael::Rijndael(const uint64_t block_size, const uint64_t key_size) : Algorithm(CONFIG.name, block_size, key_size)
{
	this->name = CONFIG.name;
	using namespace dog_torch::math::region;
	if (!is_fall(CONFIG.block_size_region, block_size))
	{
		throw CryptionException(
			DOG_EXCEPTION_MSG_OPINION(std::format("Error:Invalid Block Size {},it must fall in {}  < 16\n错误：无效分钟大小 {} 合适的范围{}", 
				block_size, CONFIG.block_size_region, block_size, CONFIG.block_size_region))
		);
	}
	if (!is_fall(CONFIG.key_size_region, key_size))
	{
		throw CryptionException(
			DOG_EXCEPTION_MSG_OPINION(std::format("Error:Invalid Key Size {},it must fall in {}  < 16\n错误：无效密钥大小 {} 合适的范围{}",
				key_size, CONFIG.key_size_region, block_size, CONFIG.block_size_region))
		);
	}
}

//AES
const NSROOT::algorithm::Config NSROOT::algorithm::AES::CONFIG = Config("AES","[16,16]0","[16,32]8");

dog_torch::serialize::Data NSROOT::algorithm::AES::extend_key(const Data& key, uint64_t block_size, uint64_t key_size)
{
	if (key_size == 16)
    {
        dog_torch::serialize::Data res;
        res.reserve(176);

        if (key.size() < 16)
        {
            throw CryptionException(DOG_EXCEPTION_MSG_OPINION(std::format("Error:Invalid Key Size {}  < 16\n错误：密钥长度过短 {} < 16", key.size(), key.size())));
        }
        for (int i = 0; i < 16; i++)
        {
            res.push_back(key.at(i));
        }
        for (int i = 16; i < 176; i += 4)
        {
            if (i % 16 == 0)
            {
                //取当前列-1
                uint8_t temp1[4] = { res.at(i - 4), res.at(i - 3), res.at(i - 2), res.at(i - 1) };
                //列位移
                uint8_t typeB = temp1[0];
                for (int i = 0; i < 3; i++)
                {
                    temp1[i] = temp1[i + 1];
                }
                temp1[3] = typeB;
                //字节代还
                for (int i = 0; i < 4; i++)
                {
                    temp1[i] = SBox[temp1[i] >> 4][temp1[i] & 0x0f];
                }
                //轮常量异或
                temp1[0] = temp1[0] ^ round[(i / 16) - 1];
                //取当前列-4并异或
                uint8_t temp2[4] = { res.at(i - 16), res.at(i - 15), res.at(i - 14), res.at(i - 13) };
                for (int i = 0; i < 4; i++)
                {
                    res.push_back(temp1[i] ^ temp2[i]);
                }
            }
            else
            {
                //取当前列-1
                uint8_t temp1[4] = { res.at(i - 4), res.at(i - 3), res.at(i - 2), res.at(i - 1) };
                //取当前列-4并异或
                uint8_t temp2[4] = { res.at(i - 16), res.at(i - 15), res.at(i - 14), res.at(i - 13) };
                for (int i = 0; i < 4; i++)
                {
                    res.push_back(temp1[i] ^ temp2[i]);
                }
            }
        }
        return res;
    }
    else if (key_size == 24)
    {
        dog_torch::serialize::Data res;
        res.reserve(208);
        if (key.size() < 24)
        {
            throw CryptionException(DOG_EXCEPTION_MSG_OPINION(std::format("Error:Invalid Key Size {}  < 24\n错误：密钥长度过短 {} < 24", key.size(), key.size())));
        }
        for (int i = 0; i < 24; i++)
        {
            res.push_back(key.at(i));
        }
        for (int i = 24; i < 208; i += 4)
        {
            if (i % 24 == 0)
            {
                //取当前列-1
                uint8_t temp1[4] = { res.at(i - 4), res.at(i - 3), res.at(i - 2), res.at(i - 1) };
                //列位移
                uint8_t typeB = temp1[0];
                for (int i = 0; i < 3; i++)
                {
                    temp1[i] = temp1[i + 1];
                }
                temp1[3] = typeB;
                //字节代还
                for (int i = 0; i < 4; i++)
                {
                    temp1[i] = SBox[temp1[i] >> 4][temp1[i] & 0x0f];
                }
                //轮常量异或
                temp1[0] = temp1[0] ^ round[(i / 24) - 1];
                //取当前列-6并异或
                uint8_t temp2[4] = { res.at(i - 24), res.at(i - 23), res.at(i - 22), res.at(i - 21) };
                for (int i = 0; i < 4; i++)
                {
                    res.push_back(temp1[i] ^ temp2[i]);
                }
            }
            else
            {
                //取当前列-1
                uint8_t temp1[4] = { res.at(i - 4), res.at(i - 3), res.at(i - 2), res.at(i - 1) };
                //取当前列-6并异或
                uint8_t temp2[4] = { res.at(i - 24), res.at(i - 23), res.at(i - 22), res.at(i - 21) };
                for (int i = 0; i < 4; i++)
                {
                    res.push_back(temp1[i] ^ temp2[i]);
                }
            }
        }
        return res;
    }
	else if (key_size == 32)
	{
        dog_torch::serialize::Data res;
        res.reserve(240);
        if (key.size() < 32)
        {
            throw CryptionException(DOG_EXCEPTION_MSG_OPINION(std::format("Error:Invalid Key Size {}  < 32\n错误：密钥长度过短 {} < 32", key.size(), key.size())));
        }
        for (int i = 0; i < 32; i++)
        {
            res.push_back(key.at(i));
        }
        for (int i = 32; i < 240; i += 4)
        {
            if (i % 32 == 0)
            {
                //取当前列-1
                uint8_t temp1[4] = { res.at(i - 4), res.at(i - 3), res.at(i - 2), res.at(i - 1) };
                //列位移
                uint8_t typeB = temp1[0];
                for (int i0 = 0; i0 < 3; i0++)
                {
                    temp1[i0] = temp1[i0 + 1];
                }
                temp1[3] = typeB;
                //字节代还
                for (int i0 = 0; i0 < 4; i0++)
                {
                    temp1[i0] = SBox[temp1[i0] >> 4][temp1[i0] & 0x0f];
                }
                //轮常量异或
                temp1[0] = temp1[0] ^ round[(i / 32) - 1];
                //取当前列-8并异或
                uint8_t temp2[4] = { res.at(i - 32), res.at(i - 31), res.at(i - 30), res.at(i - 29) };
                for (int i0 = 0; i0 < 4; i0++)
                {
                    res.push_back(temp1[i0] ^ temp2[i0]);
                }
            }
            else if (i % 16 == 0)
            {
                //取当前列-1
                uint8_t temp1[4] = { res.at(i - 4), res.at(i - 3), res.at(i - 2), res.at(i - 1) };
                for (int i0 = 0; i0 < 4; i0++)
                {
                    temp1[i0] = SBox[temp1[i0] >> 4][temp1[i0] & 0x0f];
                }
                //取当前列-8并异或
                uint8_t temp2[4] = { res.at(i - 32), res.at(i - 31), res.at(i - 30), res.at(i - 29) };
                for (int i0 = 0; i0 < 4; i0++)
                {
                    res.push_back(temp1[i0] ^ temp2[i0]);
                }
            }
            else
            {
                //取当前列-1
                uint8_t temp1[4] = { res.at(i - 4), res.at(i - 3), res.at(i - 2), res.at(i - 1) };
                //取当前列-8并异或
                uint8_t temp2[4] = { res.at(i - 32), res.at(i - 31), res.at(i - 30), res.at(i - 29) };
                for (int i0 = 0; i0 < 4; i0++)
                {
                    res.push_back(temp1[i0] ^ temp2[i0]);
                }
            }
        }
        return res;
    }
	else
	{
		throw CryptionException(DOG_EXCEPTION_MSG_OPINION("Error:AES wrong value of key_size\n错误,AES key_size值错误"));
	}
}

void NSROOT::algorithm::AES::middle_encryption(Data& datablock, uint64_t flag, uint64_t mode)
{
	dog_torch::serialize::Data res;
	res.reserve(16);
	//字节代换(00 04 08 12)
	for (int i = 0; i < 16; i++)
	{
		datablock[i] = AES::SBox[datablock.at(i) >> 4][datablock.at(i) & 0x0f];
	}

	/*printf("字节代换后数据\n");
	ShowBlock(datablock);*/

	//行位移
	//01 05 09 13 左移1位
	uint8_t b1, b2;
	b1 = datablock[1];
	datablock[1] = datablock[5];
	datablock[5] = datablock[9];
	datablock[9] = datablock[13];
	datablock[13] = b1;
	//02 06 10 14 左移2位
	b1 = datablock[2];
	b2 = datablock[6];
	datablock[2] = datablock[10];
	datablock[6] = datablock[14];
	datablock[10] = b1;
	datablock[14] = b2;
	//03 07 11 15 右移1位代替左移3位
	b1 = datablock[15];
	datablock[15] = datablock[11];
	datablock[11] = datablock[7];
	datablock[7] = datablock[3];
	datablock[3] = b1;

	/*printf("行移位后数据\n");
	ShowBlock(datablock);*/

	//列混合
	if ((mode == 128 && flag != 9) || (mode == 192 && flag != 11) || (mode == 256 && flag != 13))
	{
		for (int i0 = 0; i0 < 16; i0 += 4)
		{
			for (int i1 = 0; i1 < 16; i1 += 4)
			{
				uint8_t tempB = 0;
				for (int i2 = 0; i2 < 4; i2++)
				{
					tempB ^= NSROOT::algorithm::AES::Xtime(MixTable[i1 + i2], datablock[i0 + i2]);
				}
				res.push_back(tempB);
			}
		}
	}
	else
	{
		for (int i0 = 0; i0 < 16; i0++)
		{
			res.push_back(datablock[i0]);
		}
	}
    std::copy(res.begin(), res.end(), datablock.begin());
}
void NSROOT::algorithm::AES::middle_decryption(Data& datablock, uint64_t flag, uint64_t mode)
{
	dog_torch::serialize::Data res;
	res.reserve(16);
	//列混合
	if (flag != 0)
	{
		for (int i0 = 0; i0 < 16; i0 += 4)
		{
			for (int i1 = 0; i1 < 16; i1 += 4)
			{
				uint8_t tempB = 0;
				for (int i2 = 0; i2 < 4; i2++)
				{
					tempB ^= NSROOT::algorithm::AES::Xtime(UMixTable[i1 + i2], datablock[i0 + i2]);
				}
				res.push_back(tempB);
			}
		}
	}
	else
	{
		for (int i0 = 0; i0 < 16; i0++)
		{
			res.push_back(datablock[i0]);
		}
	}

	/*printf("列混合后数据\n");
	ShowBlock(res);*/

	//行位移
	uint8_t b1, b2;
	//01 05 09 13 右移1位
	b1 = res[13];
	res[13] = res[9];
	res[9] = res[5];
	res[5] = res[1];
	res[1] = b1;
	//02 06 10 14 右移2位
	b1 = res[14];
	b2 = res[10];
	res[14] = res[6];
	res[10] = res[2];
	res[2] = b2;
	res[6] = b1;
	//03 07 11 15 左移1位代替右移3位
	b1 = res[3];
	res[3] = res[7];
	res[7] = res[11];
	res[11] = res[15];
	res[15] = b1;

	/*printf("行移位后数据\n");
	ShowBlock(res);*/

	//字节代换
	for (int i = 0; i < 16; i++)
	{
		res[i] = AES::InvSBox[res[i] >> 4][res[i] & 0x0f];
	}

	/*printf("字节代换后数据\n");
	ShowBlock(res);*/
    std::copy(res.begin(), res.end(), datablock.begin());
}

dog_torch::serialize::Data NSROOT::algorithm::AES::encoding(const Data& plain, uint64_t block_size, const Data& key, uint64_t key_size)
{
	Data temp_key = key.sub_by_pos(0, 16);
	Data mid_block = NSROOT::utils::squareXOR(plain, temp_key, 16);
	for (int i = 0; i < ((key_size / 4) + 6); i++)
	{
		AES::middle_encryption(mid_block, i, key_size << 3);
		temp_key = key.sub_by_pos(16 * (i + 1), 16 * (i + 2));
		mid_block = NSROOT::utils::squareXOR(mid_block, temp_key, 16);
	}
	return mid_block;
}
dog_torch::serialize::Data NSROOT::algorithm::AES::decoding(const Data& crypt, uint64_t block_size, const Data& key, uint64_t key_size)
{
	Data tempKey = key.sub_by_pos((key_size * 4) + 96, (key_size * 4) + 112);
	Data mid_block = dog_torch::crypto::symmetric::utils::squareXOR(crypt, tempKey, 16);
	for (int i = 0; i < ((key_size / 4) + 6); i++)
	{
		AES::middle_decryption(mid_block, i, key_size << 3);
		tempKey = key.sub_by_pos(16 * ((key_size / 4) + 5 - i), 16 * ((key_size / 4) + 6 - i));
		mid_block = NSROOT::utils::squareXOR(mid_block, tempKey, 16);
	}
	return mid_block;
}
void NSROOT::algorithm::AES::encoding_self(Data& plain, uint64_t block_size, const Data& key, uint64_t key_size)
{
	Data tempKey = key.sub_by_pos(0, 16);
	plain = dog_torch::crypto::symmetric::utils::squareXOR(plain, tempKey, 16);
	for (int i = 0; i < ((key_size / 4) + 6); i++)
	{
		AES::middle_encryption(plain, i, key_size << 3);
		tempKey = key.sub_by_pos(16 * (i + 1), 16 * (i + 2));
		plain = dog_torch::crypto::symmetric::utils::squareXOR(plain, tempKey, 16);
	}
}
void NSROOT::algorithm::AES::decoding_self(Data& crypt, uint64_t block_size, const Data& key, uint64_t key_size)
{
	dog_torch::serialize::Data tempKey = key.sub_by_pos((key_size * 4) + 96, (key_size * 4) + 112);
	crypt = dog_torch::crypto::symmetric::utils::squareXOR(crypt, tempKey, 16);
	for (int i = 0; i < ((key_size / 4) + 6); i++)
	{
		middle_decryption(crypt, i, key_size << 3);
		tempKey = key.sub_by_pos(16 * ((key_size / 4) + 5 - i), 16 * ((key_size / 4) + 6 - i));//取当前轮密钥
		crypt = dog_torch::crypto::symmetric::utils::squareXOR(crypt, tempKey, 16);//轮密钥加
	}
}
NSROOT::algorithm::AES::AES(const uint64_t key_size) : Rijndael(16, key_size)
{
	this->name = CONFIG.name;
	using namespace dog_torch::math::region;
	if (!is_fall(CONFIG.key_size_region, key_size))
	{
		throw CryptionException(
			DOG_EXCEPTION_MSG_OPINION(std::format("Error:Invalid Key Size {},it must fall in {}  < 16\n错误：无效密钥大小 {} 合适的范围{}",
				key_size, CONFIG.key_size_region, key_size, CONFIG.key_size_region))
		);
	}
}
std::unique_ptr<NSROOT::algorithm::Algorithm> NSROOT::algorithm::AES::clone() const
{
	return std::move(std::make_unique<AES>(*this));
}
NSROOT::algorithm::Extend_key_func NSROOT::algorithm::AES::get_extend_key() const
{
	return extend_key;
}
NSROOT::algorithm::Block_cryption_func NSROOT::algorithm::AES::get_encrypt() const
{
	return encoding;
}
NSROOT::algorithm::Block_cryption_func NSROOT::algorithm::AES::get_decrypt() const
{
	return decoding;
}
NSROOT::algorithm::Block_self_cryption_func NSROOT::algorithm::AES::get_encrypt_self() const
{
	return encoding_self;
}
NSROOT::algorithm::Block_self_cryption_func NSROOT::algorithm::AES::get_decrypt_self() const
{
	return decoding_self;
}

#undef NSROOT


