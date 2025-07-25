#define _CRT_SECURE_NO_WARNINGS

#include "../../lib/dog_cryption.h"

#include <iostream>
#include <fstream>
#include <filesystem>
#include <iomanip>
#include <deque>
#include <atomic>
#include <mutex>

#include <random>

#include <thread>
#include <chrono>

std::ofstream CONFIG("./config.txt",std::ios::out);
const std::string PLAIN = "./plain.txt";
const std::string KEY = "./key.txt";
const std::string IV = "./iv.txt";
const std::string CRYPT_SET = "./crypt";
const std::string PLAIN_SET = "./plain";

/*生成随机数据并创建密文结果文件夹*/
void rand_data(uint64_t number)
{
	std::ofstream plain(PLAIN, std::ios::binary);
	std::ofstream key(KEY, std::ios::binary);
	std::ofstream iv(IV, std::ios::binary);
	std::random_device rd;
	for (uint64_t i = 0; i < number; ++i)
	{
		for (uint64_t j = 0; j < i + 1; ++j)
		{
			plain << (char)(rd() & 0xFF);
		}
		for (uint64_t j = 0; j < 32; ++j)
		{
			key << (char)(rd() & 0xFF);
		}
		for (uint64_t j = 0; j < 64; ++j)
		{
			iv << (char)(rd() & 0xFF);
		}
	}
	std::filesystem::path crypt(CRYPT_SET);
	if (!std::filesystem::exists(crypt))
	{
		std::filesystem::create_directory(crypt);
	}
}

std::vector<std::pair<std::thread*, std::atomic<bool>>> workers;

class Contain
{
public:
	bool with_config;
	bool with_check;
	bool with_iv;
	dog_cryption::CryptionConfig config;

	Contain(bool with_config, bool with_check, bool with_iv, dog_cryption::CryptionConfig config)
	{
		this->with_config = with_config;
		this->with_check = with_check;
		this->with_iv = with_iv;
		this->config = config;
	}
	Contain(){}

	std::string to_string()
	{
		return std::format("{}_{}_{}:{}",
			(this->with_config)?"withConfig":"withoutConfig",
			(this->with_check)?"withCheck":"withoutCheck",
			(this->with_iv)?"withIV":"withoutIV",
			this->config.to_string());
	}
};

class SafeDeque
{
private:
	std::deque<Contain> data;
	std::mutex mutex;
public:
	Contain pop_front()
	{
		std::lock_guard<std::mutex> lock(mutex);
		Contain result = this->data.front();
		data.pop_front();
		return result;
	}
	void push_back(Contain data)
	{
		std::lock_guard<std::mutex> lock(mutex);
		this->data.push_back(data);
	}
	uint64_t size()
	{
		std::lock_guard<std::mutex> lock(mutex);
		return this->data.size();
	}

	std::deque<Contain>::iterator begin()
	{
		std::lock_guard<std::mutex> lock(mutex);
		return this->data.begin();
	}
	std::deque<Contain>::iterator end()
	{
		std::lock_guard<std::mutex> lock(mutex);
		return this->data.end();
	}
};

SafeDeque deque;

bool start = true;

void control()
{
	while (start)
	{
		if (workers.size() < 8)
		{

		}
	}
}

void fill()
{
	dog_cryption::CryptionConfig config;
	Contain contain;

	uint64_t total = 0;

	for (uint8_t with_config = 0; with_config < 1; ++with_config)
	{
		for (uint8_t with_check = 0; with_check < 1; ++with_check)
		{
			for (uint8_t with_iv = 0; with_iv < 1; ++with_iv)
			{
				for (auto& algorithm : dog_cryption::Algorithm_list)
				{
					std::array<uint64_t, 3> block_size = dog_cryption::utils::get_region(algorithm.block_size_region_);
					std::array<uint64_t, 3> key_size = dog_cryption::utils::get_region(algorithm.key_size_region_);
					for (uint64_t block = block_size[0]; block <= block_size[1]; block += block_size[2])
					{
						for (uint64_t key = key_size[0]; key <= key_size[1]; key += key_size[2])
						{
							for (auto& mode : dog_cryption::mode::list)
							{
								if (mode.name_ == "CFBB")
								{
									for (uint64_t shift = 1; shift <=block; shift++)
									{
										if (!mode.force_padding_)
										{
											for (auto it = dog_cryption::padding::list.begin() + 1; it != dog_cryption::padding::list.end(); ++it)
											{
												config = dog_cryption::CryptionConfig(algorithm.name_, block, key, true, it->name_, mode.name_, true, shift);
												contain = Contain(with_config, with_check, with_iv, config);
												//deque.push_back(contain);
												//CONFIG << contain.to_string() << std::endl;
												total++;
											}
										}
										else
										{
											config = dog_cryption::CryptionConfig(algorithm.name_, block, key, false, "NONE", mode.name_, true, shift);
											contain = Contain(with_config, with_check, with_iv, config);
											//deque.push_back(contain);
											//CONFIG << contain.to_string() << std::endl;
											total++;
										}
									}
								}
								else if (mode.name_ == "CFBb")
								{
									for (uint64_t shift = 1; shift <= block * 8; shift++)
									{
										if (!mode.force_padding_)
										{
											for (auto it = dog_cryption::padding::list.begin() + 1; it != dog_cryption::padding::list.end(); ++it)
											{
												config = dog_cryption::CryptionConfig(algorithm.name_, block, key, true, it->name_, mode.name_, true, shift);
												contain = Contain(with_config, with_check, with_iv, config);
												//deque.push_back(contain);
												//CONFIG << contain.to_string() << std::endl;
												total++;
											}
										}
										else
										{
											config = dog_cryption::CryptionConfig(algorithm.name_, block, key, false, "NONE", mode.name_, true, shift);
											contain = Contain(with_config, with_check, with_iv, config);
											//deque.push_back(contain);
											//CONFIG << contain.to_string() << std::endl;
											total++;
										}
									}
								}
								else
								{
									if (!mode.force_padding_)
									{
										for (auto it = dog_cryption::padding::list.begin() + 1; it != dog_cryption::padding::list.end(); ++it)
										{
											if (!mode.force_iv_)
											{
												config = dog_cryption::CryptionConfig(algorithm.name_, block, key, true, it->name_, mode.name_, true, 0);
												contain = Contain(with_config, with_check, with_iv, config);												contain = Contain(with_config, with_check, with_iv, config);
												//deque.push_back(contain);
												//CONFIG << contain.to_string() << std::endl;
												total++;
											}
											else
											{
												for (uint64_t using_iv = 0; using_iv < 1; ++using_iv)
												{
													config = dog_cryption::CryptionConfig(algorithm.name_, block, key, true, it->name_, mode.name_, using_iv, 0);
													contain = Contain(with_config, with_check, with_iv, config);
													//deque.push_back(contain);
													//CONFIG << contain.to_string() << std::endl;
													total++;
												}
											}
										}
									}
									else
									{
										if (!mode.force_iv_)
										{
											config = dog_cryption::CryptionConfig(algorithm.name_, block, key, false, "NONE", mode.name_, true, 0);
											contain = Contain(with_config, with_check, with_iv, config);
											//deque.push_back(contain);
											//CONFIG << contain.to_string() << std::endl;
											total++;
										}
										else
										{
											for (uint64_t using_iv = 0; using_iv < 1; ++using_iv)
											{
												config = dog_cryption::CryptionConfig(algorithm.name_, block, key, false, "NONE", mode.name_, using_iv, 0);
												contain = Contain(with_config, with_check, with_iv, config);
												//deque.push_back(contain);
												//CONFIG << contain.to_string() << std::endl;
												total++;
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}
	std::cout << "Total: " << total << std::endl;
}

int main()
{
	rand_data(4096);

	fill();

	system("pause");

	return 0;
}

