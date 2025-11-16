#include "crypto/hash/hash_base.h"

dog_torch::crypto::hash::HashConfig::HashConfig(std::string name, std::string region)
{
	this->name = name;
	this->region = region;
}