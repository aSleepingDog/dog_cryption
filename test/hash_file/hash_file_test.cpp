#include "../../lib/dog_cryption.h"

#include <iostream>
#include <fstream>
#include <filesystem>

void hashWorker(std::string file_path, std::string hash_type)
{
	std::filesystem::directory_iterator files(file_path);

	std::ofstream result(hash_type + ".txt", std::ios::binary);

	dog_hash::hash_crypher hash_crypher(hash_type);

	for (auto& file : files)
	{
		std::string ori_file_name = file.path().filename().string();
		uint64_t file_size = std::filesystem::file_size(file);
		std::ifstream plain0(file_path + "/" + ori_file_name, std::ios::binary);
		std::chrono::duration<double> duration;
		if (!plain0.is_open())
		{
			break;
		}
		auto start = std::chrono::high_resolution_clock::now();
		dog_data::Data resData = dog_hash::hash_crypher::streamHash(hash_crypher, plain0);
		auto end = std::chrono::high_resolution_clock::now();
		duration = end - start;
		hash_crypher.init();
		result << std::format("{}|{}|{:.12f}s", file_size, resData.getHexString(true), duration.count()) << std::endl;
	}
}


int main()
{
	try
	{
		hashWorker("./ori_plain_file", "SHA2_224");
		hashWorker("./ori_plain_file", "SHA2_256");
		hashWorker("./ori_plain_file", "SHA2_384");
		hashWorker("./ori_plain_file", "SHA2_512");
		hashWorker("./ori_plain_file", "SM3");
	}
	catch (const std::exception& e)
	{
		std::cout << e.what() << std::endl;
	}

}