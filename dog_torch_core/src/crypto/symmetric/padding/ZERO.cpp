#include "crypto/symmetric/padding/ZERO.h"

#define NSROOT dog_torch::crypto::symmetric //NSROOT = namespace root

void NSROOT::padding::ZERO::padding(Data& data, uint64_t block_size)
{
    if (data.size() > block_size)
    {
        return;
    }
 	for (uint64_t i = data.size(); i < block_size; i++)
 	{
 		data.push_back(0x00);
 	}
}
void NSROOT::padding::ZERO::unpadding(Data& data, uint64_t block_size)
{
    while (*data.rbegin() == 0x00)
 	{
 		data.pop_back();
 		if (data.size() == 0) { return; }
 	}
}
std::unique_ptr<NSROOT::padding::Padding> NSROOT::padding::ZERO::clone() const
{
    return std::move(std::make_unique<ZERO>(*this));
}
NSROOT::padding::padding_func NSROOT::padding::ZERO::get_padding() const
{
	return padding;
}

NSROOT::padding::padding_func NSROOT::padding::ZERO::get_unpadding() const
{
	return unpadding;
}

#undef NSROOT