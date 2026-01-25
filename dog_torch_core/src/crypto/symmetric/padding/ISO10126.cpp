#include "crypto/symmetric/padding/ISO10126.h"

#define NSROOT dog_torch::crypto::symmetric //NSROOT = namespace root

#define DOG_ERROR_LARGE_BLOCK "Error:Block size only support less than 256"

void dog_torch::crypto::symmetric::padding::ISO10126::padding(Data& data, uint64_t block_size)
{
	if (block_size > 0x100)
 	{
 		throw CryptionException(DOG_EXCEPTION_MSG_OPINION(DOG_ERROR_LARGE_BLOCK));
 	}
 	uint8_t end = block_size - data.size();
 	for (uint8_t i = 0; i < end - 1; i++)
 	{
 		data.push_back(NSROOT::utils::rand_byte());
 	}
 	data.push_back(end);
}

void dog_torch::crypto::symmetric::padding::ISO10126::unpadding(Data& data, uint64_t block_size)
{
    uint8_t end = *data.rbegin();
    for (uint32_t i = 0; i < end; i++)
    {
        data.pop_back();
    }
}

std::unique_ptr<NSROOT::padding::Padding> NSROOT::padding::ISO10126::clone() const
{
    return std::move(std::make_unique<ISO10126>(*this));
}

NSROOT::padding::padding_func NSROOT::padding::ISO10126::get_padding() const
{
	return padding;
}

NSROOT::padding::padding_func NSROOT::padding::ISO10126::get_unpadding() const
{
	return unpadding;
}

#undef NSROOT
#undef DOG_ERROR_LARGE_BLOCK