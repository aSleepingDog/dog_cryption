#include "crypto/symmetric/padding/ISO7816_4.h"

#define NSROOT dog_torch::crypto::symmetric //NSROOT = namespace root

void NSROOT::padding::ISO7816_4::padding(Data& data, uint64_t block_size)
{
 	if (data.size() > block_size)
 	{
 		throw CryptionException(DOG_EXCEPTION_MSG_OPINION("Error:Data size is bigger than block size\n错误：数据长度大于块大小"));
 	}
 	uint8_t end = block_size - data.size();
 	data.push_back(0x80);
 	for (uint8_t i = 0; i < end - 1; i++)
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

NSROOT::padding::padding_func NSROOT::padding::ISO7816_4::get_padding() const
{
    return padding_func();
}

NSROOT::padding::padding_func NSROOT::padding::ISO7816_4::get_unpadding() const
{
    return padding_func();
}

#undef NSROOT