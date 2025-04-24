#define _CRT_SECURE_NO_WARNINGS

#include "../../lib/dog_cryption.h"

#include <iostream>
#include <fstream>

#include <iomanip>

#include <thread>
#include <chrono>

class Working : std::jthread
{
	std::ofstream fcout;
	std::ofstream fpout;
	std::ifstream fp;
	std::ifstream fk;
	DogCryption::cryptor* cryptor;

	std::string cryption_algorithm;
	uint64_t block_size;
	uint64_t key_size;
	std::string padding;
	std::string mult_function;
	bool using_iv;
	bool using_padding;
	std::string config_str;

	double en_time = 0;
	double de_time = 0;

public:
	static std::string now_time();
	Working(const std::string fp_name, const std::string fk_name,
		const std::string cryption_name, const uint64_t block_size, const uint64_t key_size,
		const std::string padding,
		const std::string mult_function, const bool using_iv, const bool using_padding);
	void doing();
	~Working();
	void join_();
};


std::string Working::now_time()
{
	auto now = std::chrono::system_clock::now();
	std::time_t now_time_t = std::chrono::system_clock::to_time_t(now);
	struct tm now_tm;
	localtime_s(&now_tm, &now_time_t);
	auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
		now.time_since_epoch()) % 1000;
	std::string res = std::format("{:04d}-{:02d}-{:02d} {:02d}:{:02d}:{:02d} ",
		now_tm.tm_year + 1900,
		now_tm.tm_mon + 1,
		now_tm.tm_mday,
		now_tm.tm_hour,
		now_tm.tm_min,
		now_tm.tm_sec);
	return res;
}

Working::Working(const std::string fp_name, const std::string fk_name,
	const std::string cryption_name, const uint64_t block_size, const uint64_t key_size,
	const std::string padding,
	const std::string mult_function, const bool using_iv, const bool using_padding)
{
	this->cryption_algorithm = cryption_name;
	this->padding = padding;
	this->mult_function = mult_function;
	this->cryptor = new DogCryption::cryptor(
		cryption_name, block_size, key_size,
		padding,
		mult_function, using_iv, using_padding, false);
	this->config_str = std::format("{}_{}_{}_{}_{}_{}_{}",
		cryption_name, block_size, key_size,
		padding, (using_padding ? "UsingPadding" : "NotUsingPadding"),
		mult_function, (using_iv ? "UsingIV" : "NotUsingIV"));

	this->fcout.open("crypt\\" + this->config_str + "_crypt.txt", std::ios::binary);
	this->fpout.open("plain\\" + this->config_str + "_plain.txt", std::ios::binary);
	this->fp.open(fp_name, std::ios::binary);
	this->fk.open(fk_name, std::ios::binary);
	jthread(&Working::doing, this).swap(*this);
	//std::cout << std::format("{} {} {} {} start", );
	printf("%s-%s start\n", Working::now_time().c_str(), this->config_str.c_str());
}

void Working::doing()
{
	try
	{
		std::string ori_plain;
		std::string key;

		DogData::Data ori_plain_data;
		DogData::Data key_data;

		std::chrono::steady_clock::time_point start, end;
		std::chrono::duration<double, std::milli> duration;

		uint64_t size = 0;

		while (std::getline(this->fp, ori_plain) && std::getline(this->fk, key))
		{
			size += 2;

			while (ori_plain.size() > size)
			{
				ori_plain.pop_back();
			}
			ori_plain_data = DogData::Data(ori_plain);

			key_data = DogData::Data(key);
			this->cryptor->set_key(key_data);

			start = std::chrono::steady_clock::now();
			std::pair<DogData::Data, DogData::Data> res = this->cryptor->encrypt(ori_plain_data);
			end = std::chrono::steady_clock::now();
			DogData::Data cry_data = res.first + res.second;
			duration = end - start;
			this->en_time += duration.count();
			this->fcout << cry_data.getHexString() << std::format("|{:.12f}s", duration.count()) << std::endl;

			start = std::chrono::steady_clock::now();
			DogData::Data plain_data = this->cryptor->decrypt(res);
			end = std::chrono::steady_clock::now();
			duration = end - start;
			this->de_time += duration.count();
			std::string equal = (plain_data == ori_plain_data) ? "TRUE" : "FALSE";

			this->fpout << plain_data.getHexString() << std::format("|{}|{:.12f}s", equal, duration.count()) << std::endl;
		}
		this->fcout << std::format("total encrypt time:{:.12f}s", this->en_time);
		this->fpout << std::format("total decrypt time:{:.12f}s", this->de_time);
		
		printf("%s-%s finish\n", Working::now_time().c_str(), this->config_str.c_str());
	}
	catch (std::exception& e)
	{
		printf("%s-%s error\n", Working::now_time().c_str(), this->config_str.c_str());
		std::cout << e.what() << std::endl;
	}
}

Working::~Working()
{
	this->fcout.close();
	this->fpout.close();
	this->fp.close();
	this->fk.close();
	delete this->cryptor;
}

void Working::join_()
{
	this->join();
}
/*
int main()
{
	using namespace DogCryption::mode;

	using namespace DogCryption::padding;

	using namespace DogCryption::AES;
	using namespace DogCryption::SM4;

	DogCryption::Cryptor cryptor(AES128, PKCS7, OFB);

	DogData::Data plain = "C1";
	DogData::Data key = "0123456789ABCDEF0123456789ABCDEF";

	cryptor.set_key(key);

	std::pair<DogData::Data, DogData::Data> res1 = cryptor.encrypt(plain);
	DogData::Data res2 = cryptor.decrypt(res1);

	std::cout << res2.getUPHex16String() << std::endl;

	return 0;
}
*/
int main()
{
	using namespace DogCryption::mode;

	using namespace DogCryption::padding;

	using namespace DogCryption::AES;
	using namespace DogCryption::SM4;


	Working* w0 = nullptr, * w1 = nullptr, * w2 = nullptr, * w3 = nullptr, *w4 = nullptr, * w5 = nullptr, * w6 = nullptr, * w7 = nullptr;
	bool True = true, False = false;
	/*
	w0 = new Working("plain.txt", "key.txt", AES, 16, 16, PKCS7, ECB, True, True);
	w1 = new Working("plain.txt", "key.txt", AES, 16, 16, ZERO, ECB, True, True);
	w2 = new Working("plain.txt", "key.txt", AES, 16, 16, ANSI923, ECB, True, True);
	w3 = new Working("plain.txt", "key.txt", AES, 16, 16, ISO7816_4, ECB, True, True);
	w4 = new Working("plain.txt", "key.txt", AES, 16, 16, ISO10126, ECB, True, True);
	w5 = new Working("plain.txt", "key.txt", AES, 16, 16, PKCS7, ECB, False, True);
	w6 = new Working("plain.txt", "key.txt", AES, 16, 16, ZERO, ECB, False, True);
	w7 = new Working("plain.txt", "key.txt", AES, 16, 16, ANSI923, ECB, False, True);
	w0->join_(); w1->join_(); w2->join_(); w3->join_(); w4->join_(); w5->join_(); w6->join_(); w7->join_();
	delete w0; delete w1; delete w2; delete w3; delete w4; delete w5; delete w6; delete w7;
	w0 = new Working("plain.txt", "key.txt", AES, 16, 16, ISO7816_4, ECB, False, True);
	w1 = new Working("plain.txt", "key.txt", AES, 16, 16, ISO10126, ECB, False, True);
	w2 = new Working("plain.txt", "key.txt", AES, 16, 16, PKCS7, CBC, True, True);
	w3 = new Working("plain.txt", "key.txt", AES, 16, 16, ZERO, CBC, True, True);
	w4 = new Working("plain.txt", "key.txt", AES, 16, 16, ANSI923, CBC, True, True);
	w5 = new Working("plain.txt", "key.txt", AES, 16, 16, ISO7816_4, CBC, True, True);
	w6 = new Working("plain.txt", "key.txt", AES, 16, 16, ISO10126, CBC, True, True);
	w7 = new Working("plain.txt", "key.txt", AES, 16, 16, PKCS7, OFB, True, True);
	w0->join_(); w1->join_(); w2->join_(); w3->join_(); w4->join_(); w5->join_(); w6->join_(); w7->join_();
	delete w0; delete w1; delete w2; delete w3; delete w4; delete w5; delete w6; delete w7;
	w0 = new Working("plain.txt", "key.txt", AES, 16, 16, ZERO, OFB, True, True);
	w1 = new Working("plain.txt", "key.txt", AES, 16, 16, ANSI923, OFB, True, True);
	w2 = new Working("plain.txt", "key.txt", AES, 16, 16, ISO7816_4, OFB, True, True);
	w3 = new Working("plain.txt", "key.txt", AES, 16, 16, ISO10126, OFB, True, True);
	w4 = new Working("plain.txt", "key.txt", AES, 16, 16, NONE, OFB, True, False);
	w5 = new Working("plain.txt", "key.txt", AES, 16, 16, PKCS7, CTR, True, True);
	w6 = new Working("plain.txt", "key.txt", AES, 16, 16, ZERO, CTR, True, True);
	w7 = new Working("plain.txt", "key.txt", AES, 16, 16, ANSI923, CTR, True, True);
	w0->join_(); w1->join_(); w2->join_(); w3->join_(); w4->join_(); w5->join_(); w6->join_(); w7->join_();
	delete w0; delete w1; delete w2; delete w3; delete w4; delete w5; delete w6; delete w7;
	w0 = new Working("plain.txt", "key.txt", AES, 16, 16, ISO7816_4, CTR, True, True);
	w1 = new Working("plain.txt", "key.txt", AES, 16, 16, ISO10126, CTR, True, True);
	w2 = new Working("plain.txt", "key.txt", AES, 16, 16, NONE, CTR, True, False);
	w3 = new Working("plain.txt", "key.txt", AES, 16, 16, NONE, CFB1, True, False);
	w4 = new Working("plain.txt", "key.txt", AES, 16, 16, NONE, CFB8, True, False);
	w5 = new Working("plain.txt", "key.txt", AES, 16, 16, PKCS7, CFB128, True, True);
	w6 = new Working("plain.txt", "key.txt", AES, 16, 16, ZERO, CFB128, True, True);
	w7 = new Working("plain.txt", "key.txt", AES, 16, 16, ANSI923, CFB128, True, True);
	w0->join_(); w1->join_(); w2->join_(); w3->join_(); w4->join_(); w5->join_(); w6->join_(); w7->join_();
	delete w0; delete w1; delete w2; delete w3; delete w4; delete w5; delete w6; delete w7;
	w0 = new Working("plain.txt", "key.txt", AES, 16, 16, ISO7816_4, CFB128, True, True);
	w1 = new Working("plain.txt", "key.txt", AES, 16, 16, ISO10126, CFB128, True, True);
	w2 = new Working("plain.txt", "key.txt", AES, 16, 16, NONE, CFB128, True, False);
	w3 = new Working("plain.txt", "key.txt", AES, 16, 24, PKCS7, ECB, True, True);
	w4 = new Working("plain.txt", "key.txt", AES, 16, 24, ZERO, ECB, True, True);
	w5 = new Working("plain.txt", "key.txt", AES, 16, 24, ANSI923, ECB, True, True);
	w6 = new Working("plain.txt", "key.txt", AES, 16, 24, ISO7816_4, ECB, True, True);
	w7 = new Working("plain.txt", "key.txt", AES, 16, 24, ISO10126, ECB, True, True);
	w0->join_(); w1->join_(); w2->join_(); w3->join_(); w4->join_(); w5->join_(); w6->join_(); w7->join_();
	delete w0; delete w1; delete w2; delete w3; delete w4; delete w5; delete w6; delete w7;
	w0 = new Working("plain.txt", "key.txt", AES, 16, 24, PKCS7, ECB, False, True);
	w1 = new Working("plain.txt", "key.txt", AES, 16, 24, ZERO, ECB, False, True);
	w2 = new Working("plain.txt", "key.txt", AES, 16, 24, ANSI923, ECB, False, True);
	w3 = new Working("plain.txt", "key.txt", AES, 16, 24, ISO7816_4, ECB, False, True);
	w4 = new Working("plain.txt", "key.txt", AES, 16, 24, ISO10126, ECB, False, True);
	w5 = new Working("plain.txt", "key.txt", AES, 16, 24, PKCS7, CBC, True, True);
	w6 = new Working("plain.txt", "key.txt", AES, 16, 24, ZERO, CBC, True, True);
	w7 = new Working("plain.txt", "key.txt", AES, 16, 24, ANSI923, CBC, True, True);
	w0->join_(); w1->join_(); w2->join_(); w3->join_(); w4->join_(); w5->join_(); w6->join_(); w7->join_();
	delete w0; delete w1; delete w2; delete w3; delete w4; delete w5; delete w6; delete w7;
	w0 = new Working("plain.txt", "key.txt", AES, 16, 24, ISO7816_4, CBC, True, True);
	w1 = new Working("plain.txt", "key.txt", AES, 16, 24, ISO10126, CBC, True, True);
	w2 = new Working("plain.txt", "key.txt", AES, 16, 24, PKCS7, OFB, True, True);
	w3 = new Working("plain.txt", "key.txt", AES, 16, 24, ZERO, OFB, True, True);
	w4 = new Working("plain.txt", "key.txt", AES, 16, 24, ANSI923, OFB, True, True);
	w5 = new Working("plain.txt", "key.txt", AES, 16, 24, ISO7816_4, OFB, True, True);
	w6 = new Working("plain.txt", "key.txt", AES, 16, 24, ISO10126, OFB, True, True);
	w7 = new Working("plain.txt", "key.txt", AES, 16, 24, NONE, OFB, True, False);
	w0->join_(); w1->join_(); w2->join_(); w3->join_(); w4->join_(); w5->join_(); w6->join_(); w7->join_();
	delete w0; delete w1; delete w2; delete w3; delete w4; delete w5; delete w6; delete w7;
	w0 = new Working("plain.txt", "key.txt", AES, 16, 24, PKCS7, CTR, True, True);
	w1 = new Working("plain.txt", "key.txt", AES, 16, 24, ZERO, CTR, True, True);
	w2 = new Working("plain.txt", "key.txt", AES, 16, 24, ANSI923, CTR, True, True);
	w3 = new Working("plain.txt", "key.txt", AES, 16, 24, ISO7816_4, CTR, True, True);
	w4 = new Working("plain.txt", "key.txt", AES, 16, 24, ISO10126, CTR, True, True);
	w5 = new Working("plain.txt", "key.txt", AES, 16, 24, NONE, CTR, True, False);
	w6 = new Working("plain.txt", "key.txt", AES, 16, 24, NONE, CFB1, True, False);
	w7 = new Working("plain.txt", "key.txt", AES, 16, 24, NONE, CFB8, True, False);
	w0->join_(); w1->join_(); w2->join_(); w3->join_(); w4->join_(); w5->join_(); w6->join_(); w7->join_();
	delete w0; delete w1; delete w2; delete w3; delete w4; delete w5; delete w6; delete w7;
	w0 = new Working("plain.txt", "key.txt", AES, 16, 24, PKCS7, CFB128, True, True);
	w1 = new Working("plain.txt", "key.txt", AES, 16, 24, ZERO, CFB128, True, True);
	w2 = new Working("plain.txt", "key.txt", AES, 16, 24, ANSI923, CFB128, True, True);
	w3 = new Working("plain.txt", "key.txt", AES, 16, 24, ISO7816_4, CFB128, True, True);
	w4 = new Working("plain.txt", "key.txt", AES, 16, 24, ISO10126, CFB128, True, True);
	w5 = new Working("plain.txt", "key.txt", AES, 16, 24, NONE, CFB128, True, False);
	w6 = new Working("plain.txt", "key.txt", AES, 16, 32, PKCS7, ECB, True, True);
	w7 = new Working("plain.txt", "key.txt", AES, 16, 32, ZERO, ECB, True, True);
	w0->join_(); w1->join_(); w2->join_(); w3->join_(); w4->join_(); w5->join_(); w6->join_(); w7->join_();
	delete w0; delete w1; delete w2; delete w3; delete w4; delete w5; delete w6; delete w7;
	w0 = new Working("plain.txt", "key.txt", AES, 16, 32, ANSI923, ECB, True, True);
	w1 = new Working("plain.txt", "key.txt", AES, 16, 32, ISO7816_4, ECB, True, True);
	w2 = new Working("plain.txt", "key.txt", AES, 16, 32, ISO10126, ECB, True, True);
	w3 = new Working("plain.txt", "key.txt", AES, 16, 32, PKCS7, ECB, False, True);
	w4 = new Working("plain.txt", "key.txt", AES, 16, 32, ZERO, ECB, False, True);
	w5 = new Working("plain.txt", "key.txt", AES, 16, 32, ANSI923, ECB, False, True);
	w6 = new Working("plain.txt", "key.txt", AES, 16, 32, ISO7816_4, ECB, False, True);
	w7 = new Working("plain.txt", "key.txt", AES, 16, 32, ISO10126, ECB, False, True);
	w0->join_(); w1->join_(); w2->join_(); w3->join_(); w4->join_(); w5->join_(); w6->join_(); w7->join_();
	delete w0; delete w1; delete w2; delete w3; delete w4; delete w5; delete w6; delete w7;
	w0 = new Working("plain.txt", "key.txt", AES, 16, 32, PKCS7, CBC, True, True);
	w1 = new Working("plain.txt", "key.txt", AES, 16, 32, ZERO, CBC, True, True);
	w2 = new Working("plain.txt", "key.txt", AES, 16, 32, ANSI923, CBC, True, True);
	w3 = new Working("plain.txt", "key.txt", AES, 16, 32, ISO7816_4, CBC, True, True);
	w4 = new Working("plain.txt", "key.txt", AES, 16, 32, ISO10126, CBC, True, True);
	w5 = new Working("plain.txt", "key.txt", AES, 16, 32, PKCS7, OFB, True, True);
	w6 = new Working("plain.txt", "key.txt", AES, 16, 32, ZERO, OFB, True, True);
	w7 = new Working("plain.txt", "key.txt", AES, 16, 32, ANSI923, OFB, True, True);
	w0->join_(); w1->join_(); w2->join_(); w3->join_(); w4->join_(); w5->join_(); w6->join_(); w7->join_();
	delete w0; delete w1; delete w2; delete w3; delete w4; delete w5; delete w6; delete w7;
	w0 = new Working("plain.txt", "key.txt", AES, 16, 32, ISO7816_4, OFB, True, True);
	w1 = new Working("plain.txt", "key.txt", AES, 16, 32, ISO10126, OFB, True, True);
	w2 = new Working("plain.txt", "key.txt", AES, 16, 32, NONE, OFB, True, False);
	w3 = new Working("plain.txt", "key.txt", AES, 16, 32, PKCS7, CTR, True, True);
	w4 = new Working("plain.txt", "key.txt", AES, 16, 32, ZERO, CTR, True, True);
	w5 = new Working("plain.txt", "key.txt", AES, 16, 32, ANSI923, CTR, True, True);
	w6 = new Working("plain.txt", "key.txt", AES, 16, 32, ISO7816_4, CTR, True, True);
	w7 = new Working("plain.txt", "key.txt", AES, 16, 32, ISO10126, CTR, True, True);
	w0->join_(); w1->join_(); w2->join_(); w3->join_(); w4->join_(); w5->join_(); w6->join_(); w7->join_();
	delete w0; delete w1; delete w2; delete w3; delete w4; delete w5; delete w6; delete w7;
	w0 = new Working("plain.txt", "key.txt", AES, 16, 32, NONE, CTR, True, False);
	w1 = new Working("plain.txt", "key.txt", AES, 16, 32, NONE, CFB1, True, False);
	w2 = new Working("plain.txt", "key.txt", AES, 16, 32, NONE, CFB8, True, False);
	w3 = new Working("plain.txt", "key.txt", AES, 16, 32, PKCS7, CFB128, True, True);
	w4 = new Working("plain.txt", "key.txt", AES, 16, 32, ZERO, CFB128, True, True);
	w5 = new Working("plain.txt", "key.txt", AES, 16, 32, ANSI923, CFB128, True, True);
	w6 = new Working("plain.txt", "key.txt", AES, 16, 32, ISO7816_4, CFB128, True, True);
	w7 = new Working("plain.txt", "key.txt", AES, 16, 32, ISO10126, CFB128, True, True);
	w0->join_(); w1->join_(); w2->join_(); w3->join_(); w4->join_(); w5->join_(); w6->join_(); w7->join_();
	delete w0; delete w1; delete w2; delete w3; delete w4; delete w5; delete w6; delete w7;
	w0 = new Working("plain.txt", "key.txt", AES, 16, 32, NONE, CFB128, True, False);
	w1 = new Working("plain.txt", "key.txt", SM4, 16, 16, PKCS7, ECB, True, True);
	w2 = new Working("plain.txt", "key.txt", SM4, 16, 16, ZERO, ECB, True, True);
	w3 = new Working("plain.txt", "key.txt", SM4, 16, 16, ANSI923, ECB, True, True);
	w4 = new Working("plain.txt", "key.txt", SM4, 16, 16, ISO7816_4, ECB, True, True);
	w5 = new Working("plain.txt", "key.txt", SM4, 16, 16, ISO10126, ECB, True, True);
	w6 = new Working("plain.txt", "key.txt", SM4, 16, 16, PKCS7, ECB, False, True);
	w7 = new Working("plain.txt", "key.txt", SM4, 16, 16, ZERO, ECB, False, True);
	w0->join_(); w1->join_(); w2->join_(); w3->join_(); w4->join_(); w5->join_(); w6->join_(); w7->join_();
	delete w0; delete w1; delete w2; delete w3; delete w4; delete w5; delete w6; delete w7;
	w0 = new Working("plain.txt", "key.txt", SM4, 16, 16, ANSI923, ECB, False, True);
	w1 = new Working("plain.txt", "key.txt", SM4, 16, 16, ISO7816_4, ECB, False, True);
	w2 = new Working("plain.txt", "key.txt", SM4, 16, 16, ISO10126, ECB, False, True);
	w3 = new Working("plain.txt", "key.txt", SM4, 16, 16, PKCS7, CBC, True, True);
	w4 = new Working("plain.txt", "key.txt", SM4, 16, 16, ZERO, CBC, True, True);
	w5 = new Working("plain.txt", "key.txt", SM4, 16, 16, ANSI923, CBC, True, True);
	w6 = new Working("plain.txt", "key.txt", SM4, 16, 16, ISO7816_4, CBC, True, True);
	w7 = new Working("plain.txt", "key.txt", SM4, 16, 16, ISO10126, CBC, True, True);
	w0->join_(); w1->join_(); w2->join_(); w3->join_(); w4->join_(); w5->join_(); w6->join_(); w7->join_();
	delete w0; delete w1; delete w2; delete w3; delete w4; delete w5; delete w6; delete w7;
	w0 = new Working("plain.txt", "key.txt", SM4, 16, 16, PKCS7, OFB, True, True);
	w1 = new Working("plain.txt", "key.txt", SM4, 16, 16, ZERO, OFB, True, True);
	w2 = new Working("plain.txt", "key.txt", SM4, 16, 16, ANSI923, OFB, True, True);
	w3 = new Working("plain.txt", "key.txt", SM4, 16, 16, ISO7816_4, OFB, True, True);
	w4 = new Working("plain.txt", "key.txt", SM4, 16, 16, ISO10126, OFB, True, True);
	w5 = new Working("plain.txt", "key.txt", SM4, 16, 16, NONE, OFB, True, False);
	w6 = new Working("plain.txt", "key.txt", SM4, 16, 16, PKCS7, CTR, True, True);
	w7 = new Working("plain.txt", "key.txt", SM4, 16, 16, ZERO, CTR, True, True);
	w0->join_(); w1->join_(); w2->join_(); w3->join_(); w4->join_(); w5->join_(); w6->join_(); w7->join_();
	delete w0; delete w1; delete w2; delete w3; delete w4; delete w5; delete w6; delete w7;
	w0 = new Working("plain.txt", "key.txt", SM4, 16, 16, ANSI923, CTR, True, True);
	w1 = new Working("plain.txt", "key.txt", SM4, 16, 16, ISO7816_4, CTR, True, True);
	w2 = new Working("plain.txt", "key.txt", SM4, 16, 16, ISO10126, CTR, True, True);
	w3 = new Working("plain.txt", "key.txt", SM4, 16, 16, NONE, CTR, True, False);
	w4 = new Working("plain.txt", "key.txt", SM4, 16, 16, NONE, CFB1, True, False);
	w5 = new Working("plain.txt", "key.txt", SM4, 16, 16, NONE, CFB8, True, False);
	w6 = new Working("plain.txt", "key.txt", SM4, 16, 16, PKCS7, CFB128, True, True);
	w7 = new Working("plain.txt", "key.txt", SM4, 16, 16, ZERO, CFB128, True, True);
	w0->join_(); w1->join_(); w2->join_(); w3->join_(); w4->join_(); w5->join_(); w6->join_(); w7->join_();
	delete w0; delete w1; delete w2; delete w3; delete w4; delete w5; delete w6; delete w7;
	w0 = new Working("plain.txt", "key.txt", SM4, 16, 16, ANSI923, CFB128, True, True);
	w1 = new Working("plain.txt", "key.txt", SM4, 16, 16, ISO7816_4, CFB128, True, True);
	w2 = new Working("plain.txt", "key.txt", SM4, 16, 16, ISO10126, CFB128, True, True);
	w3 = new Working("plain.txt", "key.txt", SM4, 16, 16, NONE, CFB128, True, False);

	w0->join_(); w1->join_(); w2->join_(); w3->join_();
	delete w0; delete w1; delete w2; delete w3;
	*/

    w0 = new Working("plain.txt","key.txt",AES,16,16,PKCS7,ECB,True,True);
    w1 = new Working("plain.txt","key.txt",AES,16,16,ZERO,ECB,True,True);
    w2 = new Working("plain.txt","key.txt",AES,16,16,ANSI923,ECB,True,True);
    w3 = new Working("plain.txt","key.txt",AES,16,16,ISO7816_4,ECB,True,True);
    w4 = new Working("plain.txt","key.txt",AES,16,16,ISO10126,ECB,True,True);
    w5 = new Working("plain.txt","key.txt",AES,16,24,PKCS7,ECB,True,True);
    w6 = new Working("plain.txt","key.txt",AES,16,24,ZERO,ECB,True,True);
    w7 = new Working("plain.txt","key.txt",AES,16,24,ANSI923,ECB,True,True);
    w0->join_(); w1->join_(); w2->join_(); w3->join_();w4->join_();w5->join_();w6->join_();w7->join_();
    delete w0; delete w1; delete w2; delete w3; delete w4; delete w5; delete w6; delete w7;
    w0 = new Working("plain.txt","key.txt",AES,16,24,ISO7816_4,ECB,True,True);
    w1 = new Working("plain.txt","key.txt",AES,16,24,ISO10126,ECB,True,True);
    w2 = new Working("plain.txt","key.txt",AES,16,32,PKCS7,ECB,True,True);
    w3 = new Working("plain.txt","key.txt",AES,16,32,ZERO,ECB,True,True);
    w4 = new Working("plain.txt","key.txt",AES,16,32,ANSI923,ECB,True,True);
    w5 = new Working("plain.txt","key.txt",AES,16,32,ISO7816_4,ECB,True,True);
    w6 = new Working("plain.txt","key.txt",AES,16,32,ISO10126,ECB,True,True);
    w7 = new Working("plain.txt","key.txt",SM4,16,16,PKCS7,ECB,True,True);
    w0->join_(); w1->join_(); w2->join_(); w3->join_();w4->join_();w5->join_();w6->join_();w7->join_();
    delete w0; delete w1; delete w2; delete w3; delete w4; delete w5; delete w6; delete w7;
    w0 = new Working("plain.txt","key.txt",SM4,16,16,ZERO,ECB,True,True);
    w1 = new Working("plain.txt","key.txt",SM4,16,16,ANSI923,ECB,True,True);
    w2 = new Working("plain.txt","key.txt",SM4,16,16,ISO7816_4,ECB,True,True);
    w3 = new Working("plain.txt","key.txt",SM4,16,16,ISO10126,ECB,True,True);
    w4 = new Working("plain.txt","key.txt",AES,16,16,PKCS7,ECB,False,True);
    w5 = new Working("plain.txt","key.txt",AES,16,16,ZERO,ECB,False,True);
    w6 = new Working("plain.txt","key.txt",AES,16,16,ANSI923,ECB,False,True);
    w7 = new Working("plain.txt","key.txt",AES,16,16,ISO7816_4,ECB,False,True);
    w0->join_(); w1->join_(); w2->join_(); w3->join_();w4->join_();w5->join_();w6->join_();w7->join_();
    delete w0; delete w1; delete w2; delete w3; delete w4; delete w5; delete w6; delete w7;
    w0 = new Working("plain.txt","key.txt",AES,16,16,ISO10126,ECB,False,True);
    w1 = new Working("plain.txt","key.txt",AES,16,24,PKCS7,ECB,False,True);
    w2 = new Working("plain.txt","key.txt",AES,16,24,ZERO,ECB,False,True);
    w3 = new Working("plain.txt","key.txt",AES,16,24,ANSI923,ECB,False,True);
    w4 = new Working("plain.txt","key.txt",AES,16,24,ISO7816_4,ECB,False,True);
    w5 = new Working("plain.txt","key.txt",AES,16,24,ISO10126,ECB,False,True);
    w6 = new Working("plain.txt","key.txt",AES,16,32,PKCS7,ECB,False,True);
    w7 = new Working("plain.txt","key.txt",AES,16,32,ZERO,ECB,False,True);
    w0->join_(); w1->join_(); w2->join_(); w3->join_();w4->join_();w5->join_();w6->join_();w7->join_();
    delete w0; delete w1; delete w2; delete w3; delete w4; delete w5; delete w6; delete w7;
    w0 = new Working("plain.txt","key.txt",AES,16,32,ANSI923,ECB,False,True);
    w1 = new Working("plain.txt","key.txt",AES,16,32,ISO7816_4,ECB,False,True);
    w2 = new Working("plain.txt","key.txt",AES,16,32,ISO10126,ECB,False,True);
    w3 = new Working("plain.txt","key.txt",SM4,16,16,PKCS7,ECB,False,True);
    w4 = new Working("plain.txt","key.txt",SM4,16,16,ZERO,ECB,False,True);
    w5 = new Working("plain.txt","key.txt",SM4,16,16,ANSI923,ECB,False,True);
    w6 = new Working("plain.txt","key.txt",SM4,16,16,ISO7816_4,ECB,False,True);
    w7 = new Working("plain.txt","key.txt",SM4,16,16,ISO10126,ECB,False,True);
    w0->join_(); w1->join_(); w2->join_(); w3->join_();w4->join_();w5->join_();w6->join_();w7->join_();
    delete w0; delete w1; delete w2; delete w3; delete w4; delete w5; delete w6; delete w7;
    w0 = new Working("plain.txt","key.txt",AES,16,16,PKCS7,CBC,True,True);
    w1 = new Working("plain.txt","key.txt",AES,16,16,ZERO,CBC,True,True);
    w2 = new Working("plain.txt","key.txt",AES,16,16,ANSI923,CBC,True,True);
    w3 = new Working("plain.txt","key.txt",AES,16,16,ISO7816_4,CBC,True,True);
    w4 = new Working("plain.txt","key.txt",AES,16,16,ISO10126,CBC,True,True);
    w5 = new Working("plain.txt","key.txt",AES,16,24,PKCS7,CBC,True,True);
    w6 = new Working("plain.txt","key.txt",AES,16,24,ZERO,CBC,True,True);
    w7 = new Working("plain.txt","key.txt",AES,16,24,ANSI923,CBC,True,True);
    w0->join_(); w1->join_(); w2->join_(); w3->join_();w4->join_();w5->join_();w6->join_();w7->join_();
    delete w0; delete w1; delete w2; delete w3; delete w4; delete w5; delete w6; delete w7;
    w0 = new Working("plain.txt","key.txt",AES,16,24,ISO7816_4,CBC,True,True);
    w1 = new Working("plain.txt","key.txt",AES,16,24,ISO10126,CBC,True,True);
    w2 = new Working("plain.txt","key.txt",AES,16,32,PKCS7,CBC,True,True);
    w3 = new Working("plain.txt","key.txt",AES,16,32,ZERO,CBC,True,True);
    w4 = new Working("plain.txt","key.txt",AES,16,32,ANSI923,CBC,True,True);
    w5 = new Working("plain.txt","key.txt",AES,16,32,ISO7816_4,CBC,True,True);
    w6 = new Working("plain.txt","key.txt",AES,16,32,ISO10126,CBC,True,True);
    w7 = new Working("plain.txt","key.txt",SM4,16,16,PKCS7,CBC,True,True);
    w0->join_(); w1->join_(); w2->join_(); w3->join_();w4->join_();w5->join_();w6->join_();w7->join_();
    delete w0; delete w1; delete w2; delete w3; delete w4; delete w5; delete w6; delete w7;
    w0 = new Working("plain.txt","key.txt",SM4,16,16,ZERO,CBC,True,True);
    w1 = new Working("plain.txt","key.txt",SM4,16,16,ANSI923,CBC,True,True);
    w2 = new Working("plain.txt","key.txt",SM4,16,16,ISO7816_4,CBC,True,True);
    w3 = new Working("plain.txt","key.txt",SM4,16,16,ISO10126,CBC,True,True);
    w4 = new Working("plain.txt","key.txt",AES,16,16,PKCS7,OFB,True,True);
    w5 = new Working("plain.txt","key.txt",AES,16,16,ZERO,OFB,True,True);
    w6 = new Working("plain.txt","key.txt",AES,16,16,ANSI923,OFB,True,True);
    w7 = new Working("plain.txt","key.txt",AES,16,16,ISO7816_4,OFB,True,True);
    w0->join_(); w1->join_(); w2->join_(); w3->join_();w4->join_();w5->join_();w6->join_();w7->join_();
    delete w0; delete w1; delete w2; delete w3; delete w4; delete w5; delete w6; delete w7;
    w0 = new Working("plain.txt","key.txt",AES,16,16,ISO10126,OFB,True,True);
    w1 = new Working("plain.txt","key.txt",AES,16,24,PKCS7,OFB,True,True);
    w2 = new Working("plain.txt","key.txt",AES,16,24,ZERO,OFB,True,True);
    w3 = new Working("plain.txt","key.txt",AES,16,24,ANSI923,OFB,True,True);
    w4 = new Working("plain.txt","key.txt",AES,16,24,ISO7816_4,OFB,True,True);
    w5 = new Working("plain.txt","key.txt",AES,16,24,ISO10126,OFB,True,True);
    w6 = new Working("plain.txt","key.txt",AES,16,32,PKCS7,OFB,True,True);
    w7 = new Working("plain.txt","key.txt",AES,16,32,ZERO,OFB,True,True);
    w0->join_(); w1->join_(); w2->join_(); w3->join_();w4->join_();w5->join_();w6->join_();w7->join_();
    delete w0; delete w1; delete w2; delete w3; delete w4; delete w5; delete w6; delete w7;
    w0 = new Working("plain.txt","key.txt",AES,16,32,ANSI923,OFB,True,True);
    w1 = new Working("plain.txt","key.txt",AES,16,32,ISO7816_4,OFB,True,True);
    w2 = new Working("plain.txt","key.txt",AES,16,32,ISO10126,OFB,True,True);
    w3 = new Working("plain.txt","key.txt",SM4,16,16,PKCS7,OFB,True,True);
    w4 = new Working("plain.txt","key.txt",SM4,16,16,ZERO,OFB,True,True);
    w5 = new Working("plain.txt","key.txt",SM4,16,16,ANSI923,OFB,True,True);
    w6 = new Working("plain.txt","key.txt",SM4,16,16,ISO7816_4,OFB,True,True);
    w7 = new Working("plain.txt","key.txt",SM4,16,16,ISO10126,OFB,True,True);
    w0->join_(); w1->join_(); w2->join_(); w3->join_();w4->join_();w5->join_();w6->join_();w7->join_();
    delete w0; delete w1; delete w2; delete w3; delete w4; delete w5; delete w6; delete w7;
    w0 = new Working("plain.txt","key.txt",AES,16,16,NONE,OFB,True,False);
    w1 = new Working("plain.txt","key.txt",AES,16,24,NONE,OFB,True,False);
    w2 = new Working("plain.txt","key.txt",AES,16,32,NONE,OFB,True,False);
    w3 = new Working("plain.txt","key.txt",SM4,16,16,NONE,OFB,True,False);
    w4 = new Working("plain.txt","key.txt",AES,16,16,PKCS7,CTR,True,True);
    w5 = new Working("plain.txt","key.txt",AES,16,16,ZERO,CTR,True,True);
    w6 = new Working("plain.txt","key.txt",AES,16,16,ANSI923,CTR,True,True);
    w7 = new Working("plain.txt","key.txt",AES,16,16,ISO7816_4,CTR,True,True);
    w0->join_(); w1->join_(); w2->join_(); w3->join_();w4->join_();w5->join_();w6->join_();w7->join_();
    delete w0; delete w1; delete w2; delete w3; delete w4; delete w5; delete w6; delete w7;
    w0 = new Working("plain.txt","key.txt",AES,16,16,ISO10126,CTR,True,True);
    w1 = new Working("plain.txt","key.txt",AES,16,24,PKCS7,CTR,True,True);
    w2 = new Working("plain.txt","key.txt",AES,16,24,ZERO,CTR,True,True);
    w3 = new Working("plain.txt","key.txt",AES,16,24,ANSI923,CTR,True,True);
    w4 = new Working("plain.txt","key.txt",AES,16,24,ISO7816_4,CTR,True,True);
    w5 = new Working("plain.txt","key.txt",AES,16,24,ISO10126,CTR,True,True);
    w6 = new Working("plain.txt","key.txt",AES,16,32,PKCS7,CTR,True,True);
    w7 = new Working("plain.txt","key.txt",AES,16,32,ZERO,CTR,True,True);
    w0->join_(); w1->join_(); w2->join_(); w3->join_();w4->join_();w5->join_();w6->join_();w7->join_();
    delete w0; delete w1; delete w2; delete w3; delete w4; delete w5; delete w6; delete w7;
    w0 = new Working("plain.txt","key.txt",AES,16,32,ANSI923,CTR,True,True);
    w1 = new Working("plain.txt","key.txt",AES,16,32,ISO7816_4,CTR,True,True);
    w2 = new Working("plain.txt","key.txt",AES,16,32,ISO10126,CTR,True,True);
    w3 = new Working("plain.txt","key.txt",SM4,16,16,PKCS7,CTR,True,True);
    w4 = new Working("plain.txt","key.txt",SM4,16,16,ZERO,CTR,True,True);
    w5 = new Working("plain.txt","key.txt",SM4,16,16,ANSI923,CTR,True,True);
    w6 = new Working("plain.txt","key.txt",SM4,16,16,ISO7816_4,CTR,True,True);
    w7 = new Working("plain.txt","key.txt",SM4,16,16,ISO10126,CTR,True,True);
    w0->join_(); w1->join_(); w2->join_(); w3->join_();w4->join_();w5->join_();w6->join_();w7->join_();
    delete w0; delete w1; delete w2; delete w3; delete w4; delete w5; delete w6; delete w7;
    w0 = new Working("plain.txt","key.txt",AES,16,16,NONE,CTR,True,False);
    w1 = new Working("plain.txt","key.txt",AES,16,24,NONE,CTR,True,False);
    w2 = new Working("plain.txt","key.txt",AES,16,32,NONE,CTR,True,False);
    w3 = new Working("plain.txt","key.txt",SM4,16,16,NONE,CTR,True,False);
    w4 = new Working("plain.txt","key.txt",AES,16,16,PKCS7,CFB128,True,True);
    w5 = new Working("plain.txt","key.txt",AES,16,16,ZERO,CFB128,True,True);
    w6 = new Working("plain.txt","key.txt",AES,16,16,ANSI923,CFB128,True,True);
    w7 = new Working("plain.txt","key.txt",AES,16,16,ISO7816_4,CFB128,True,True);
    w0->join_(); w1->join_(); w2->join_(); w3->join_();w4->join_();w5->join_();w6->join_();w7->join_();
    delete w0; delete w1; delete w2; delete w3; delete w4; delete w5; delete w6; delete w7;
    w0 = new Working("plain.txt","key.txt",AES,16,16,ISO10126,CFB128,True,True);
    w1 = new Working("plain.txt","key.txt",AES,16,24,PKCS7,CFB128,True,True);
    w2 = new Working("plain.txt","key.txt",AES,16,24,ZERO,CFB128,True,True);
    w3 = new Working("plain.txt","key.txt",AES,16,24,ANSI923,CFB128,True,True);
    w4 = new Working("plain.txt","key.txt",AES,16,24,ISO7816_4,CFB128,True,True);
    w5 = new Working("plain.txt","key.txt",AES,16,24,ISO10126,CFB128,True,True);
    w6 = new Working("plain.txt","key.txt",AES,16,32,PKCS7,CFB128,True,True);
    w7 = new Working("plain.txt","key.txt",AES,16,32,ZERO,CFB128,True,True);
    w0->join_(); w1->join_(); w2->join_(); w3->join_();w4->join_();w5->join_();w6->join_();w7->join_();
    delete w0; delete w1; delete w2; delete w3; delete w4; delete w5; delete w6; delete w7;
    w0 = new Working("plain.txt","key.txt",AES,16,32,ANSI923,CFB128,True,True);
    w1 = new Working("plain.txt","key.txt",AES,16,32,ISO7816_4,CFB128,True,True);
    w2 = new Working("plain.txt","key.txt",AES,16,32,ISO10126,CFB128,True,True);
    w3 = new Working("plain.txt","key.txt",SM4,16,16,PKCS7,CFB128,True,True);
    w4 = new Working("plain.txt","key.txt",SM4,16,16,ZERO,CFB128,True,True);
    w5 = new Working("plain.txt","key.txt",SM4,16,16,ANSI923,CFB128,True,True);
    w6 = new Working("plain.txt","key.txt",SM4,16,16,ISO7816_4,CFB128,True,True);
    w7 = new Working("plain.txt","key.txt",SM4,16,16,ISO10126,CFB128,True,True);
    w0->join_(); w1->join_(); w2->join_(); w3->join_();w4->join_();w5->join_();w6->join_();w7->join_();
    delete w0; delete w1; delete w2; delete w3; delete w4; delete w5; delete w6; delete w7;
    w0 = new Working("plain.txt","key.txt",AES,16,16,NONE,CFB128,True,False);
    w1 = new Working("plain.txt","key.txt",AES,16,24,NONE,CFB128,True,False);
    w2 = new Working("plain.txt","key.txt",AES,16,32,NONE,CFB128,True,False);
    w3 = new Working("plain.txt","key.txt",SM4,16,16,NONE,CFB128,True,False);
    w4 = new Working("plain.txt","key.txt",AES,16,16,NONE,CFB8,True,False);
    w5 = new Working("plain.txt","key.txt",AES,16,24,NONE,CFB8,True,False);
    w6 = new Working("plain.txt","key.txt",AES,16,32,NONE,CFB8,True,False);
    w7 = new Working("plain.txt","key.txt",SM4,16,16,NONE,CFB8,True,False);
    w0->join_(); w1->join_(); w2->join_(); w3->join_();w4->join_();w5->join_();w6->join_();w7->join_();
    delete w0; delete w1; delete w2; delete w3; delete w4; delete w5; delete w6; delete w7;
    w0 = new Working("plain.txt","key.txt",AES,16,16,NONE,CFB1,True,False);
    w1 = new Working("plain.txt","key.txt",AES,16,24,NONE,CFB1,True,False);
    w2 = new Working("plain.txt","key.txt",AES,16,32,NONE,CFB1,True,False);
    w3 = new Working("plain.txt","key.txt",SM4,16,16,NONE,CFB1,True,False);
	w0->join_(); w1->join_(); w2->join_(); w3->join_();
	delete w0; delete w1; delete w2; delete w3;


	return 0;
}

