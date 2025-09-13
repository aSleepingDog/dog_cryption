#include "../libcryption/include/cryption/dog_cryption.h"

#include <iostream>
#include <print> 
#include <fstream>
#include <format>
#include <filesystem>

#include <cmath>

int main()
{
	std::filesystem::path path("..\\resource");
	if (!std::filesystem::exists(path))
	{
		std::cout << "目录不存在" << std::endl;
		return 1;
	}
	uint64_t i = 1;
	for (auto fit : std::filesystem::directory_iterator(path))
	{
		std::cout << i << " ";
		std::cout << fit.path().string() << "\n";
		i++;
	}
	std::cout.flush();
	return 0;
}