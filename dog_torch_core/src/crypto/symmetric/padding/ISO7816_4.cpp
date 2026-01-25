#include "crypto/symmetric/padding/ISO7816_4.h"

#define NSROOT dog_torch::crypto::symmetric //NSROOT = namespace root

void NSROOT::padding::ISO7816_4::padding(Data& data, uint64_t block_size)
{
    if (data.size() > block_size)
    {
        return;
    }
 	data.push_back(0x80);
 	for (uint8_t i = data.size(); i < block_size; i++)
 	{
 		data.push_back(0x00);
 	}
}

void NSROOT::padding::ISO7816_4::unpadding(Data& data, uint64_t block_size)
{
    while (*data.rbegin() == 0x00)
 	{
 		data.pop_back();
 	}
 	data.pop_back();
}

std::unique_ptr<NSROOT::padding::Padding> NSROOT::padding::ISO7816_4::clone() const
{
    return std::move(std::make_unique<ISO7816_4>(*this));
}

NSROOT::padding::padding_func NSROOT::padding::ISO7816_4::get_padding() const
{
    return padding;
}

NSROOT::padding::padding_func NSROOT::padding::ISO7816_4::get_unpadding() const
{
    return unpadding;
}

#undef NSROOT