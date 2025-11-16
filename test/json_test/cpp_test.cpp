#include "dog_torch.h"


#include <iostream>
#include <print> 
#include <fstream>
#include <format>
#include <filesystem>
#include <cmath>


int main()
{
	std::filesystem::path json_path = ".\\json_file";
	std::filesystem::path res_path = ".\\cpp_res";
	for (auto& entry : std::filesystem::directory_iterator(json_path))
	{
		std::ifstream json_file(entry.path());
		std::string json_string((std::istreambuf_iterator<char>(json_file)), std::istreambuf_iterator<char>());
		std::string::const_iterator it = json_string.begin();
		json_file.close();
		std::ofstream res_file(res_path / entry.path().filename().string());
		if (entry.path().filename().string().substr(0, 1)[0] < '5')
		{
			auto json = dog_torch::serialize::json::any::to_object(json_string, it);
			res_file << dog_torch::serialize::json::any::to_json_str(json, true);
		}
		else
		{
			auto json = dog_torch::serialize::json::any::to_array(json_string, it);
			res_file << dog_torch::serialize::json::any::to_json_str(json, true);
		}
	}
}