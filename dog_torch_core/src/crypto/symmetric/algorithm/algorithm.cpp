#include "crypto/symmetric/algorithm/algorithm.h"

#define NSROOT dog_torch::crypto::symmetric::algorithm

const std::vector<NSROOT::Config> dog_torch::crypto::symmetric::algorithm::get_all_algorithms()
{
	return {
		AES::get_config(),
		SM4::get_config(),
		camellia::get_config(),
		Twofish::get_config()
	};
}

#undef NSROOT