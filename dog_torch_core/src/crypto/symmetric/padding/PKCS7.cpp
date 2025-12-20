#include "crypto/symmetric/padding/PKCS7.h"

#define NSROOT dog_torch::crypto::symmetric //NSROOT = namespace root

void NSROOT::padding::PKCS7::padding(Data& data, uint64_t block_size)
{
 	if (block_size > 0x100)
 	{
 		throw CryptionException(DOG_EXCEPTION_MSG_OPINION("Error:Block size is too big,PKCS7 only support less than 256\n错误：块大小过大，PKCS7仅支持小于256B的块"));
 	}
 	if (data.size() > block_size)
 	{
 		throw CryptionException(DOG_EXCEPTION_MSG_OPINION("Error:Data size is bigger than block size\n错误：数据长度大于块大小"));
 	}
 	uint8_t end = block_size - data.size();
 	for (uint8_t i = 0; i < end; i++)
 	{
 		data.push_back(end);
 	}
}
void NSROOT::padding::PKCS7::unpadding(Data& data, uint64_t block_size)
{
 	if (block_size > 0x100)
 	{
 		throw CryptionException(DOG_EXCEPTION_MSG_OPINION("Error:Block size is too big,PKCS7 only support less than 256\n错误：块大小过大，PKCS7仅支持小于256B的块"));
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
NSROOT::padding::padding_func NSROOT::padding::PKCS7::get_padding() const
{
    return padding;
}
NSROOT::padding::padding_func NSROOT::padding::PKCS7::get_unpadding() const
{
	return unpadding;
}

#undef NSROOT