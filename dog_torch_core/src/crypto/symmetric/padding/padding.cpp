#include "crypto/symmetric/padding/padding.h"

#define NSROOT dog_torch::crypto::symmetric::padding

const std::vector<std::shared_ptr<NSROOT::Padding>> NSROOT::PaddingList =
{
	std::make_shared<NSROOT::PKCS7>(),
	std::make_shared<NSROOT::ZERO>(),
	std::make_shared<NSROOT::ANSIX923>(),
	std::make_shared<NSROOT::ISO7816_4>(),
	std::make_shared<NSROOT::ISO10126>()
};

#undef NSROOT