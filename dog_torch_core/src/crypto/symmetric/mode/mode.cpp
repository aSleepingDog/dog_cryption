#include "crypto/symmetric/mode/mode.h"

#define NSROOT dog_torch::crypto::symmetric::mode

const std::vector<NSROOT::Config> NSROOT::ModeList = {
	NSROOT::ECB::get_config(),
	NSROOT::CBC::get_config(),
	NSROOT::PCBC::get_config(),
	NSROOT::CFBB::get_config(),
	NSROOT::CFBb::get_config(),
	NSROOT::OFB::get_config(),
	NSROOT::CTR::get_config()
};

#undef NSROOT