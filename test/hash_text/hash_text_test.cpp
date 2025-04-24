#include "../../lib/dog_cryption.h"

#include <iostream>
#include <fstream>

void hash_worker(const std::string& plain_path, const std::string res_path, const std::string& algorithm)
{
	std::ifstream plain(plain_path);
	if (!plain.is_open())
	{
		throw std::runtime_error("Failed to open file");
	}
	std::ofstream res(res_path);

	DogHash::hash_crypher h(algorithm);
	std::string line;

	uint64_t size = 0;

	std::chrono::steady_clock::time_point start, end;
	std::chrono::duration<double, std::milli> duration;

	while (std::getline(plain, line))
	{
		size += 2;
		while (line.size() > size)
		{
			line.pop_back();
		}
		DogData::Data plainData = line;

		start = std::chrono::steady_clock::now();
		DogData::Data resData = h.getDataHash(plainData);
		end = std::chrono::steady_clock::now();
		duration = end - start;
		res << std::format("{}|{:.12f}s", resData.getHexString(true), duration.count()) << std::endl;
	}


}

int main()
{
	hash_worker("./plain.txt", "SHA2_224.txt", "SHA2_224");
	hash_worker("./plain.txt", "SHA2_256.txt", "SHA2_256");
	hash_worker("./plain.txt", "SHA2_384.txt", "SHA2_384");
	hash_worker("./plain.txt", "SHA2_512.txt", "SHA2_512");
	hash_worker("./plain.txt", "SM3.txt", "SM3");
}