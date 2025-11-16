#include "crypto/symmetric/symmetric_base.h"

//utils
uint8_t dog_torch::crypto::symmetric::utils::rand_byte()
{
	std::random_device rd;
	return (uint8_t)rd() % 128;
}

bool dog_torch::crypto::symmetric::utils::is_integer(std::any a)
{
	const std::type_info& type = a.type();
	return type == typeid(uint8_t) || type == typeid(int8_t) ||
		type == typeid(uint16_t) || type == typeid(int16_t) ||
		type == typeid(uint32_t) || type == typeid(int32_t) ||
		type == typeid(uint64_t) || type == typeid(int64_t);
}
uint64_t dog_torch::crypto::symmetric::utils::get_integer(std::any a)
{
	const std::type_info& type = a.type();
	if (type == typeid(uint8_t))
	{
		return (uint64_t)std::any_cast<uint8_t>(a);
	}
	else if (type == typeid(int8_t))
	{
		return (uint64_t)std::any_cast<int8_t>(a);
	}
	else if (type == typeid(uint16_t))
	{
		return (uint64_t)std::any_cast<uint16_t>(a);
	}
	else if (type == typeid(int16_t))
	{
		return (uint64_t)std::any_cast<int16_t>(a);
	}
	else if (type == typeid(uint32_t))
	{
		return (uint64_t)std::any_cast<uint32_t>(a);
	}
	else if (type == typeid(int32_t))
	{
		return (uint64_t)std::any_cast<int32_t>(a);
	}
	else if (type == typeid(uint64_t))
	{
		return (uint64_t)std::any_cast<uint64_t>(a);
	}
	else if (type == typeid(int64_t))
	{
		return (uint64_t)std::any_cast<int64_t>(a);
	}
	else
	{
		throw CryptionException(DOG_EXCEPTION_MSG_OPINION("Error:Invalid integer type\n错误：无效的整数类型"));
	}
}
dog_torch::serialize::Data dog_torch::crypto::symmetric::utils::squareXOR(dog_torch::serialize::Data& a, dog_torch::serialize::Data& b, uint64_t size)
{
	dog_torch::serialize::Data res;
	res.reserve(size);
	uint64_t n = a.size() < b.size() ? a.size() : b.size();
	for (uint64_t i = 0; i < (n > size ? size : n); i++)
	{
		res.push_back(a.at(i) ^ b.at(i));
	}
	return res;
}
void dog_torch::crypto::symmetric::utils::squareXOR_self(dog_torch::serialize::Data& a, dog_torch::serialize::Data& b, uint64_t size)
{
	uint64_t n = a.size() < b.size() ? a.size() : b.size();
	for (uint64_t i = 0; i < (n > size ? size : n); i++)
	{
		a[i] ^= b[i];
	}
}
dog_torch::serialize::Data dog_torch::crypto::symmetric::utils::randiv(uint8_t block_size)
{
	dog_torch::serialize::Data iv(block_size);
	for (int i = 0; i < block_size; i++)
	{
		iv[i] = dog_torch::crypto::symmetric::utils::rand_byte();
	}
	return iv;
}
dog_torch::serialize::Data dog_torch::crypto::symmetric::utils::get_sequence(uint64_t lenght)
{
	dog_torch::serialize::Data res(lenght);
	uint8_t list[8] = { 0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF };
	for (uint64_t i = 0; i < lenght; i++)
	{
		res[i] = list[i % 8];
	}
	return res;
}

dog_torch::crypto::symmetric::AlgorithmConfig::AlgorithmConfig(std::string name, std::string block_sizeregion, std::string key_size_region)
{
	this->name = name;
	this->block_size_region = block_sizeregion;
	this->key_size_region = key_size_region;
}