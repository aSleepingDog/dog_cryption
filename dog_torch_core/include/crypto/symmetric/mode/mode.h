#pragma once
#ifdef SHARED
#include "export.h"
#else
#define DOG_CRYPTION_API
#endif

#include <vector>

#include "crypto/symmetric/symmetric.h"
#include "ECB.h"
#include "CBC.h"
#include "PCBC.h"
#include "CFB.h"
#include "OFB.h"
#include "CTR.h"

namespace dog_torch::crypto::symmetric::mode
{
	DOG_CRYPTION_API extern const std::vector<Config> ModeList;
}