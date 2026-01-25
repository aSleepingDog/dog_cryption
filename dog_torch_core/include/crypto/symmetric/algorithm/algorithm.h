#pragma once
#ifdef SHARED
#include "export.h"
#else
#define DOG_CRYPTION_API
#endif

#include "crypto/symmetric/symmetric.h"
#include "camellia.h"
#include "Rijndael.h"
#include "SM4.h"
#include "Twofish.h"

namespace dog_torch::crypto::symmetric::algorithm
{
	DOG_CRYPTION_API const std::vector<Config> get_all_algorithms();
}