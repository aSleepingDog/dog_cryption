#include "../../libcryption/include/cryption/dog_cryption.h"

#include <iostream>
#include <print> 
#include <fstream>
#include <format>
#include <filesystem>

#define FATHER_PATH "./"
//#define FATHER_PATH "E:/project/crypher_cpp/src/gui/qtweb/"

std::string comcat_path(std::string path)
{
	return FATHER_PATH + path;
}

int main()
{
	std::cout << "开始生成文件散列值……" << std::endl;
	std::vector<std::pair<std::string, std::string>> file_and_hash;
	std::filesystem::path page_path(comcat_path("page"));//
	std::ofstream check_file(comcat_path("file_check_hash.h"));//
	if (!std::filesystem::exists(page_path))
	{
		std::cout << "目录不存在" << std::endl;
		return 1;
	}
	dog_hash::HashCrypher hash_crypher(dog_hash::SHA2::name, dog_hash::SHA2::b256::EFFECTIVE_SIZE);
	hash_crypher.init();
	for (auto fit : std::filesystem::directory_iterator(page_path))
	{
		if (fit.is_directory())
		{
			for (auto fit0 : std::filesystem::directory_iterator(fit))
			{
				std::string file_name = comcat_path("page/resource/") + fit0.path().filename().string();//
				std::ifstream input(file_name, std::ios::binary);
				if (!input.is_open())
				{
					std::cout << "文件不存在" << std::endl;
					return 1;
				}
				dog_data::Data hash = dog_hash::HashCrypher::streamHash(hash_crypher, input);
				file_and_hash.emplace_back(std::pair<std::string, std::string>('\"' + file_name + "\",", '\"' + hash.getHexString() + '\"'));
				hash_crypher.init();
			}
		}
		else
		{
			std::string file_name = comcat_path("page/") + fit.path().filename().string();//
			std::ifstream input(file_name, std::ios::binary);
			if (!input.is_open())
			{
				std::cout << "文件不存在" << std::endl;
				return 1;
			}
			dog_data::Data hash = dog_hash::HashCrypher::streamHash(hash_crypher, input);
			file_and_hash.emplace_back(std::pair<std::string, std::string>('\"' + file_name + "\",", '\"' + hash.getHexString() + '\"'));
			hash_crypher.init();
		}
	}
	
	uint64_t file_len_max = 0, hash_len_max = 0;
	for (auto& [file, hash] : file_and_hash)
	{
		if (file.size() > file_len_max)
		{
			file_len_max = file.size();
		}
		if (hash.size() > hash_len_max)
		{
			hash_len_max = file.size();
		}
	}
	std::string fmt_str = std::format("    {{{{ {{:<{}}}{{:<{}}} }}}},\\", file_len_max + 4, hash_len_max).c_str();
	check_file << "#define HASH_TABEL {\\\n";
	for (auto& [file, hash] : file_and_hash)
	{
		check_file << std::vformat(fmt_str,std::make_format_args(file, hash)) << std::endl;
	}
	check_file << "}\n//此文件由程序生成,请勿手动修改";
	std::cout << "文件散列值生成完成……" << std::endl;

	return 0;
}