#include "crypto/hash/algorithm/algorithm.h"

#define NSROOT dog_torch::crypto::hash::algorithm

const std::vector<NSROOT::Config> NSROOT::get_all_algorithms()
{
	return { SHA2::get_config(),SM3::get_Config() };
}

#undef NSROOT