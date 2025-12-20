#include "crypto/symmetric/padding/ISO10126.h"

#define NSROOT dog_torch::crypto::symmetric //NSROOT = namespace root

void dog_torch::crypto::symmetric::padding::ISO10126::padding(Data& data, uint64_t block_size)
{
	if (block_size > 0x100)
 	{
 		throw CryptionException(DOG_EXCEPTION_MSG_OPINION("Error:Block size is too big,PKCS7 only support less than 256\n错误：块大小过大，PKCS7仅支持小于256B的块"));
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

}

NSROOT::padding::padding_func NSROOT::padding::ISO10126::get_padding() const
{
	return padding;
}

NSROOT::padding::padding_func NSROOT::padding::ISO10126::get_unpadding() const
{
	return unpadding;
}
