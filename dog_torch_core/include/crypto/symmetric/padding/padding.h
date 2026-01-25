#pragma once
#ifdef SHARED
#include "export.h"
#else
#define DOG_CRYPTION_API
#endif

#include <vector>

#include "crypto/symmetric/symmetric.h"
#include "PKCS7.h"
#include "ZERO.h"
#include "ANSIX923.h"
#include "ISO7816_4.h"
#include "ISO10126.h"

namespace dog_torch::crypto::symmetric::padding
{
	DOG_CRYPTION_API extern const std::vector<std::shared_ptr<Padding>> PaddingList;
}