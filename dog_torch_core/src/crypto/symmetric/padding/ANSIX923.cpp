#include "crypto/symmetric/padding/ANSIX923.h"

#define NSROOT dog_torch::crypto::symmetric //NSROOT = namespace root

#define DOG_ERROR_LARGE_BLOCK "Error:Block size only support less than 256"

void NSROOT::padding::ANSIX923::padding(Data& data, uint64_t block_size)
{
	if (block_size > 0x100)
 	{
 		throw CryptionException(DOG_EXCEPTION_MSG_OPINION(DOG_ERROR_LARGE_BLOCK));
 	}
    if (data.size() > block_size)
    {
        return;
    }
 	uint8_t end = block_size - data.size();
 	for (uint8_t i = 0; i < end - 1; i++)
 	{
 		data.push_back(0x00);
 	}
 	data.push_back(end);
}

void NSROOT::padding::ANSIX923::unpadding(Data& data, uint64_t block_size)
{
    if (block_size > 0x100)
 	{
 		throw CryptionException(DOG_EXCEPTION_MSG_OPINION(DOG_ERROR_LARGE_BLOCK));
 	}
 	uint8_t value = *data.rbegin();
 	if ((uint32_t)value <= block_size)
 	{
 		for (uint32_t i = 0; i < value; i++)
 		{
 			data.pop_back();
 		}
 	}
}

std::unique_ptr<NSROOT::padding::Padding> NSROOT::padding::ANSIX923::clone() const
{
    return std::move(std::make_unique<ANSIX923>(*this));
}

NSROOT::padding::padding_func NSROOT::padding::ANSIX923::get_padding() const
{
	return padding;
}

NSROOT::padding::padding_func NSROOT::padding::ANSIX923::get_unpadding() const
{
	return unpadding;
}

#undef NSROOT
#undef DOG_ERROR_LARGE_BLOCK