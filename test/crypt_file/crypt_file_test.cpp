#define _CRT_SECURE_NO_WARNINGS

#include "../../lib/dog_cryption.h"

#include <iostream>
#include <fstream>
#include <filesystem>

#include <iomanip>

#include <thread>

std::ofstream log_file("./log.txt");

std::string now_time()
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

class Working : std::jthread
{
	std::ifstream fk;
	DogCryption::cryptor* cryptor;
	std::string config_str;

	double en_time = 0;
	double de_time = 0;

	std::ofstream time_record;

public:
	Working(const std::string fk_name,
		const std::string cryption_name, const uint64_t block_size, const uint64_t key_size,
		const std::string padding,
		const std::string mult_function, const bool using_iv, const bool using_padding);
	void doing();
	~Working();
	void join_();
};

Working::Working(const std::string fk_name,
	const std::string cryption_name, const uint64_t block_size, const uint64_t key_size,
	const std::string padding,
	const std::string mult_function, const bool using_iv, const bool using_padding)
{
	this->cryptor = new DogCryption::cryptor(
		cryption_name, block_size, key_size,
		padding,
		mult_function, using_iv, using_padding, false);
	this->config_str = std::format("{}_{}_{}_{}_{}_{}_{}",
		cryption_name, block_size, key_size,
		padding, (using_padding ? "UsingPadding" : "NotUsingPadding"),
		mult_function, (using_iv ? "UsingIV" : "NotUsingIV"));
	this->fk.open(fk_name, std::ios::binary);
    std::filesystem::create_directory("./result/" + this->config_str);
	std::filesystem::create_directory("./result/" + this->config_str + "/crypt");
	std::filesystem::create_directory("./result/" + this->config_str + "/plain");
    time_record.open("./result/" + this->config_str + "/time_record.txt");
	time_record << "File_Name|Encrypt_Time(s)|Decrypt_Time(s)" << std::endl;
    jthread(&Working::doing, this).swap(*this);

	printf("%s %s start\n", now_time().c_str(), this->config_str.c_str());
    log_file << std::format("{} {} start\n", now_time().c_str(), this->config_str.c_str());
}

void Working::doing()
{
    std::string config = this->config_str;
	try
	{
		std::chrono::high_resolution_clock::time_point start, end;
		std::chrono::duration<double> duration_encrypt, duration_decrypt;

		std::filesystem::directory_iterator dit("./ori_plain_file");

        std::string key;

        DogData::Data key_data;

		for (auto& file : dit)
		{
            uint64_t file_size = std::filesystem::file_size(file);
			std::string ori_file_name = file.path().filename().string();

            std::getline(this->fk, key);
            key_data = DogData::Data(key);
            this->cryptor->set_key(key_data);

			std::ifstream plain0("./ori_plain_file/" + ori_file_name, std::ios::binary);
			std::ofstream crypt0("./result/" + this->config_str + "/crypt/" + ori_file_name + ".crypt", std::ios::binary);

			start = std::chrono::high_resolution_clock::now();
            this->cryptor->encrypt(plain0, crypt0, false);
			end = std::chrono::high_resolution_clock::now();
			duration_encrypt = end - start;
			plain0.close(); crypt0.close();

			std::ifstream crtpy1("./result/" + this->config_str + "/crypt/" + ori_file_name + ".crypt", std::ios::binary);
			std::ofstream plain1("./result/" + this->config_str + "/plain/" + ori_file_name + ".plain", std::ios::binary);

			start = std::chrono::high_resolution_clock::now();
            this->cryptor->decrypt(crtpy1, plain1, false);
			end = std::chrono::high_resolution_clock::now();
			duration_decrypt = end - start;
			plain1.close(); crtpy1.close();

			this->time_record << std::format("{}|{:.12f}s|{:.12f}s", file_size,duration_encrypt.count(),duration_decrypt.count()) << std::endl;
		}
		printf("%s %s finish\n", now_time().c_str(), this->config_str.c_str());
        log_file << std::format("{} {} finish\n", now_time().c_str(), this->config_str.c_str());
	}
	catch (std::exception& e)
	{
        printf("%s %s error\n %s", now_time().c_str(), config.c_str(), e.what());
		log_file << std::format("{} {} error\n {}", now_time().c_str(), config.c_str(), e.what());
	}
}

Working::~Working()
{
	this->fk.close();
	delete this->cryptor;
}

void Working::join_()
{
	this->join();
}

int main()
{
	using namespace DogCryption::mode;

	using namespace DogCryption::padding;

	using namespace DogCryption::AES;
	using namespace DogCryption::SM4;

	std::filesystem::create_directory("./result");

	Working* w0 = nullptr, * w1 = nullptr, * w2 = nullptr, * w3 = nullptr, * w4 = nullptr, * w5 = nullptr, * w6 = nullptr, * w7 = nullptr;
	bool True = true, False = false;
    
    w0 = new Working("./key.txt", AES, 16, 16, PKCS7, ECB, True, True);
    w1 = new Working("./key.txt", AES, 16, 16, ZERO, ECB, True, True);
    w2 = new Working("./key.txt", AES, 16, 16, ANSI923, ECB, True, True);
    w3 = new Working("./key.txt", AES, 16, 16, ISO7816_4, ECB, True, True);
    w4 = new Working("./key.txt", AES, 16, 16, ISO10126, ECB, True, True);
    w5 = new Working("./key.txt", AES, 16, 24, PKCS7, ECB, True, True);
    w6 = new Working("./key.txt", AES, 16, 24, ZERO, ECB, True, True);
    w7 = new Working("./key.txt", AES, 16, 24, ANSI923, ECB, True, True);
    w0->join_(); w1->join_(); w2->join_(); w3->join_(); w4->join_(); w5->join_(); w6->join_(); w7->join_();
    delete w0; delete w1; delete w2; delete w3; delete w4; delete w5; delete w6; delete w7;
    w0 = new Working("./key.txt", AES, 16, 24, ISO7816_4, ECB, True, True);
    w1 = new Working("./key.txt", AES, 16, 24, ISO10126, ECB, True, True);
    w2 = new Working("./key.txt", AES, 16, 32, PKCS7, ECB, True, True);
    w3 = new Working("./key.txt", AES, 16, 32, ZERO, ECB, True, True);
    w4 = new Working("./key.txt", AES, 16, 32, ANSI923, ECB, True, True);
    w5 = new Working("./key.txt", AES, 16, 32, ISO7816_4, ECB, True, True);
    w6 = new Working("./key.txt", AES, 16, 32, ISO10126, ECB, True, True);
    w7 = new Working("./key.txt", SM4, 16, 16, PKCS7, ECB, True, True);
    w0->join_(); w1->join_(); w2->join_(); w3->join_(); w4->join_(); w5->join_(); w6->join_(); w7->join_();
    delete w0; delete w1; delete w2; delete w3; delete w4; delete w5; delete w6; delete w7;
    w0 = new Working("./key.txt", SM4, 16, 16, ZERO, ECB, True, True);
    w1 = new Working("./key.txt", SM4, 16, 16, ANSI923, ECB, True, True);
    w2 = new Working("./key.txt", SM4, 16, 16, ISO7816_4, ECB, True, True);
    w3 = new Working("./key.txt", SM4, 16, 16, ISO10126, ECB, True, True);
    w4 = new Working("./key.txt", AES, 16, 16, PKCS7, ECB, False, True);
    w5 = new Working("./key.txt", AES, 16, 16, ZERO, ECB, False, True);
    w6 = new Working("./key.txt", AES, 16, 16, ANSI923, ECB, False, True);
    w7 = new Working("./key.txt", AES, 16, 16, ISO7816_4, ECB, False, True);
    w0->join_(); w1->join_(); w2->join_(); w3->join_(); w4->join_(); w5->join_(); w6->join_(); w7->join_();
    delete w0; delete w1; delete w2; delete w3; delete w4; delete w5; delete w6; delete w7;
    w0 = new Working("./key.txt", AES, 16, 16, ISO10126, ECB, False, True);
    w1 = new Working("./key.txt", AES, 16, 24, PKCS7, ECB, False, True);
    w2 = new Working("./key.txt", AES, 16, 24, ZERO, ECB, False, True);
    w3 = new Working("./key.txt", AES, 16, 24, ANSI923, ECB, False, True);
    w4 = new Working("./key.txt", AES, 16, 24, ISO7816_4, ECB, False, True);
    w5 = new Working("./key.txt", AES, 16, 24, ISO10126, ECB, False, True);
    w6 = new Working("./key.txt", AES, 16, 32, PKCS7, ECB, False, True);
    w7 = new Working("./key.txt", AES, 16, 32, ZERO, ECB, False, True);
    w0->join_(); w1->join_(); w2->join_(); w3->join_(); w4->join_(); w5->join_(); w6->join_(); w7->join_();
    delete w0; delete w1; delete w2; delete w3; delete w4; delete w5; delete w6; delete w7;
    w0 = new Working("./key.txt", AES, 16, 32, ANSI923, ECB, False, True);
    w1 = new Working("./key.txt", AES, 16, 32, ISO7816_4, ECB, False, True);
    w2 = new Working("./key.txt", AES, 16, 32, ISO10126, ECB, False, True);
    w3 = new Working("./key.txt", SM4, 16, 16, PKCS7, ECB, False, True);
    w4 = new Working("./key.txt", SM4, 16, 16, ZERO, ECB, False, True);
    w5 = new Working("./key.txt", SM4, 16, 16, ANSI923, ECB, False, True);
    w6 = new Working("./key.txt", SM4, 16, 16, ISO7816_4, ECB, False, True);
    w7 = new Working("./key.txt", SM4, 16, 16, ISO10126, ECB, False, True);
    w0->join_(); w1->join_(); w2->join_(); w3->join_(); w4->join_(); w5->join_(); w6->join_(); w7->join_();
    delete w0; delete w1; delete w2; delete w3; delete w4; delete w5; delete w6; delete w7;
    w0 = new Working("./key.txt", AES, 16, 16, PKCS7, CBC, True, True);
    w1 = new Working("./key.txt", AES, 16, 16, ZERO, CBC, True, True);
    w2 = new Working("./key.txt", AES, 16, 16, ANSI923, CBC, True, True);
    w3 = new Working("./key.txt", AES, 16, 16, ISO7816_4, CBC, True, True);
    w4 = new Working("./key.txt", AES, 16, 16, ISO10126, CBC, True, True);
    w5 = new Working("./key.txt", AES, 16, 24, PKCS7, CBC, True, True);
    w6 = new Working("./key.txt", AES, 16, 24, ZERO, CBC, True, True);
    w7 = new Working("./key.txt", AES, 16, 24, ANSI923, CBC, True, True);
    w0->join_(); w1->join_(); w2->join_(); w3->join_(); w4->join_(); w5->join_(); w6->join_(); w7->join_();
    delete w0; delete w1; delete w2; delete w3; delete w4; delete w5; delete w6; delete w7;
    w0 = new Working("./key.txt", AES, 16, 24, ISO7816_4, CBC, True, True);
    w1 = new Working("./key.txt", AES, 16, 24, ISO10126, CBC, True, True);
    w2 = new Working("./key.txt", AES, 16, 32, PKCS7, CBC, True, True);
    w3 = new Working("./key.txt", AES, 16, 32, ZERO, CBC, True, True);
    w4 = new Working("./key.txt", AES, 16, 32, ANSI923, CBC, True, True);
    w5 = new Working("./key.txt", AES, 16, 32, ISO7816_4, CBC, True, True);
    w6 = new Working("./key.txt", AES, 16, 32, ISO10126, CBC, True, True);
    w7 = new Working("./key.txt", SM4, 16, 16, PKCS7, CBC, True, True);
    w0->join_(); w1->join_(); w2->join_(); w3->join_(); w4->join_(); w5->join_(); w6->join_(); w7->join_();
    delete w0; delete w1; delete w2; delete w3; delete w4; delete w5; delete w6; delete w7;
    w0 = new Working("./key.txt", SM4, 16, 16, ZERO, CBC, True, True);
    w1 = new Working("./key.txt", SM4, 16, 16, ANSI923, CBC, True, True);
    w2 = new Working("./key.txt", SM4, 16, 16, ISO7816_4, CBC, True, True);
    w3 = new Working("./key.txt", SM4, 16, 16, ISO10126, CBC, True, True);
    w4 = new Working("./key.txt", AES, 16, 16, PKCS7, OFB, True, True);
    w5 = new Working("./key.txt", AES, 16, 16, ZERO, OFB, True, True);
    w6 = new Working("./key.txt", AES, 16, 16, ANSI923, OFB, True, True);
    w7 = new Working("./key.txt", AES, 16, 16, ISO7816_4, OFB, True, True);
    w0->join_(); w1->join_(); w2->join_(); w3->join_(); w4->join_(); w5->join_(); w6->join_(); w7->join_();
    delete w0; delete w1; delete w2; delete w3; delete w4; delete w5; delete w6; delete w7;
    w0 = new Working("./key.txt", AES, 16, 16, ISO10126, OFB, True, True);
    w1 = new Working("./key.txt", AES, 16, 24, PKCS7, OFB, True, True);
    w2 = new Working("./key.txt", AES, 16, 24, ZERO, OFB, True, True);
    w3 = new Working("./key.txt", AES, 16, 24, ANSI923, OFB, True, True);
    w4 = new Working("./key.txt", AES, 16, 24, ISO7816_4, OFB, True, True);
    w5 = new Working("./key.txt", AES, 16, 24, ISO10126, OFB, True, True);
    w6 = new Working("./key.txt", AES, 16, 32, PKCS7, OFB, True, True);
    w7 = new Working("./key.txt", AES, 16, 32, ZERO, OFB, True, True);
    w0->join_(); w1->join_(); w2->join_(); w3->join_(); w4->join_(); w5->join_(); w6->join_(); w7->join_();
    delete w0; delete w1; delete w2; delete w3; delete w4; delete w5; delete w6; delete w7;
    w0 = new Working("./key.txt", AES, 16, 32, ANSI923, OFB, True, True);
    w1 = new Working("./key.txt", AES, 16, 32, ISO7816_4, OFB, True, True);
    w2 = new Working("./key.txt", AES, 16, 32, ISO10126, OFB, True, True);
    w3 = new Working("./key.txt", SM4, 16, 16, PKCS7, OFB, True, True);
    w4 = new Working("./key.txt", SM4, 16, 16, ZERO, OFB, True, True);
    w5 = new Working("./key.txt", SM4, 16, 16, ANSI923, OFB, True, True);
    w6 = new Working("./key.txt", SM4, 16, 16, ISO7816_4, OFB, True, True);
    w7 = new Working("./key.txt", SM4, 16, 16, ISO10126, OFB, True, True);
    w0->join_(); w1->join_(); w2->join_(); w3->join_(); w4->join_(); w5->join_(); w6->join_(); w7->join_();
    delete w0; delete w1; delete w2; delete w3; delete w4; delete w5; delete w6; delete w7;
    w0 = new Working("./key.txt", AES, 16, 16, NONE, OFB, True, False);
    w1 = new Working("./key.txt", AES, 16, 24, NONE, OFB, True, False);
    w2 = new Working("./key.txt", AES, 16, 32, NONE, OFB, True, False);
    w3 = new Working("./key.txt", SM4, 16, 16, NONE, OFB, True, False);
    w4 = new Working("./key.txt", AES, 16, 16, PKCS7, CTR, True, True);
    w5 = new Working("./key.txt", AES, 16, 16, ZERO, CTR, True, True);
    w6 = new Working("./key.txt", AES, 16, 16, ANSI923, CTR, True, True);
    w7 = new Working("./key.txt", AES, 16, 16, ISO7816_4, CTR, True, True);
    w0->join_(); w1->join_(); w2->join_(); w3->join_(); w4->join_(); w5->join_(); w6->join_(); w7->join_();
    delete w0; delete w1; delete w2; delete w3; delete w4; delete w5; delete w6; delete w7;
    w0 = new Working("./key.txt", AES, 16, 16, ISO10126, CTR, True, True);
    w1 = new Working("./key.txt", AES, 16, 24, PKCS7, CTR, True, True);
    w2 = new Working("./key.txt", AES, 16, 24, ZERO, CTR, True, True);
    w3 = new Working("./key.txt", AES, 16, 24, ANSI923, CTR, True, True);
    w4 = new Working("./key.txt", AES, 16, 24, ISO7816_4, CTR, True, True);
    w5 = new Working("./key.txt", AES, 16, 24, ISO10126, CTR, True, True);
    w6 = new Working("./key.txt", AES, 16, 32, PKCS7, CTR, True, True);
    w7 = new Working("./key.txt", AES, 16, 32, ZERO, CTR, True, True);
    w0->join_(); w1->join_(); w2->join_(); w3->join_(); w4->join_(); w5->join_(); w6->join_(); w7->join_();
    delete w0; delete w1; delete w2; delete w3; delete w4; delete w5; delete w6; delete w7;
    w0 = new Working("./key.txt", AES, 16, 32, ANSI923, CTR, True, True);
    w1 = new Working("./key.txt", AES, 16, 32, ISO7816_4, CTR, True, True);
    w2 = new Working("./key.txt", AES, 16, 32, ISO10126, CTR, True, True);
    w3 = new Working("./key.txt", SM4, 16, 16, PKCS7, CTR, True, True);
    w4 = new Working("./key.txt", SM4, 16, 16, ZERO, CTR, True, True);
    w5 = new Working("./key.txt", SM4, 16, 16, ANSI923, CTR, True, True);
    w6 = new Working("./key.txt", SM4, 16, 16, ISO7816_4, CTR, True, True);
    w7 = new Working("./key.txt", SM4, 16, 16, ISO10126, CTR, True, True);
    w0->join_(); w1->join_(); w2->join_(); w3->join_(); w4->join_(); w5->join_(); w6->join_(); w7->join_();
    delete w0; delete w1; delete w2; delete w3; delete w4; delete w5; delete w6; delete w7;
    w0 = new Working("./key.txt", AES, 16, 16, NONE, CTR, True, False);
    w1 = new Working("./key.txt", AES, 16, 24, NONE, CTR, True, False);
    w2 = new Working("./key.txt", AES, 16, 32, NONE, CTR, True, False);
    w3 = new Working("./key.txt", SM4, 16, 16, NONE, CTR, True, False);
    w4 = new Working("./key.txt", AES, 16, 16, PKCS7, CFB128, True, True);
    w5 = new Working("./key.txt", AES, 16, 16, ZERO, CFB128, True, True);
    w6 = new Working("./key.txt", AES, 16, 16, ANSI923, CFB128, True, True);
    w7 = new Working("./key.txt", AES, 16, 16, ISO7816_4, CFB128, True, True);
    w0->join_(); w1->join_(); w2->join_(); w3->join_(); w4->join_(); w5->join_(); w6->join_(); w7->join_();
    delete w0; delete w1; delete w2; delete w3; delete w4; delete w5; delete w6; delete w7;
    w0 = new Working("./key.txt", AES, 16, 16, ISO10126, CFB128, True, True);
    w1 = new Working("./key.txt", AES, 16, 24, PKCS7, CFB128, True, True);
    w2 = new Working("./key.txt", AES, 16, 24, ZERO, CFB128, True, True);
    w3 = new Working("./key.txt", AES, 16, 24, ANSI923, CFB128, True, True);
    w4 = new Working("./key.txt", AES, 16, 24, ISO7816_4, CFB128, True, True);
    w5 = new Working("./key.txt", AES, 16, 24, ISO10126, CFB128, True, True);
    w6 = new Working("./key.txt", AES, 16, 32, PKCS7, CFB128, True, True);
    w7 = new Working("./key.txt", AES, 16, 32, ZERO, CFB128, True, True);
    w0->join_(); w1->join_(); w2->join_(); w3->join_(); w4->join_(); w5->join_(); w6->join_(); w7->join_();
    delete w0; delete w1; delete w2; delete w3; delete w4; delete w5; delete w6; delete w7;
    w0 = new Working("./key.txt", AES, 16, 32, ANSI923, CFB128, True, True);
    w1 = new Working("./key.txt", AES, 16, 32, ISO7816_4, CFB128, True, True);
    w2 = new Working("./key.txt", AES, 16, 32, ISO10126, CFB128, True, True);
    w3 = new Working("./key.txt", SM4, 16, 16, PKCS7, CFB128, True, True);
    w4 = new Working("./key.txt", SM4, 16, 16, ZERO, CFB128, True, True);
    w5 = new Working("./key.txt", SM4, 16, 16, ANSI923, CFB128, True, True);
    w6 = new Working("./key.txt", SM4, 16, 16, ISO7816_4, CFB128, True, True);
    w7 = new Working("./key.txt", SM4, 16, 16, ISO10126, CFB128, True, True);
    w0->join_(); w1->join_(); w2->join_(); w3->join_(); w4->join_(); w5->join_(); w6->join_(); w7->join_();
    delete w0; delete w1; delete w2; delete w3; delete w4; delete w5; delete w6; delete w7;
    w0 = new Working("./key.txt", AES, 16, 16, NONE, CFB128, True, False);
    w1 = new Working("./key.txt", AES, 16, 24, NONE, CFB128, True, False);
    w2 = new Working("./key.txt", AES, 16, 32, NONE, CFB128, True, False);
    w3 = new Working("./key.txt", SM4, 16, 16, NONE, CFB128, True, False);
    w4 = new Working("./key.txt", AES, 16, 16, NONE, CFB8, True, False);
    w5 = new Working("./key.txt", AES, 16, 24, NONE, CFB8, True, False);
    w6 = new Working("./key.txt", AES, 16, 32, NONE, CFB8, True, False);
    w7 = new Working("./key.txt", SM4, 16, 16, NONE, CFB8, True, False);
    w0->join_(); w1->join_(); w2->join_(); w3->join_(); w4->join_(); w5->join_(); w6->join_(); w7->join_();
    delete w0; delete w1; delete w2; delete w3; delete w4; delete w5; delete w6; delete w7;
    w0 = new Working("./key.txt", AES, 16, 16, NONE, CFB1, True, False);
    w1 = new Working("./key.txt", AES, 16, 24, NONE, CFB1, True, False);
    w2 = new Working("./key.txt", AES, 16, 32, NONE, CFB1, True, False);
    w3 = new Working("./key.txt", SM4, 16, 16, NONE, CFB1, True, False);
    w0->join_(); w1->join_(); w2->join_(); w3->join_();
    delete w0; delete w1; delete w2; delete w3;

	return 0;
}