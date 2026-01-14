#include "crypto/symmetric/mode/PCBC.h"

#define NSROOT dog_torch::crypto::symmetric //NSROOT = namespace root
#define DOG_DATA dog_torch::serialize::BinaryData

#define PCBC_ENCRYPT_INIT \
uint64_t block_size = algorithm.get_block_size(); \
uint64_t key_size = algorithm.get_key_size(); \
const Data& key = available_key; \
algorithm::block_self_cryption_func block_self_encryption = algorithm.get_encrypt_self();\
Data temp_block0 = iv;

#define PCBC_DECRYPT_INIT \
uint64_t block_size = algorithm.get_block_size(); \
uint64_t key_size = algorithm.get_key_size(); \
const Data& key = available_key; \
algorithm::block_self_cryption_func block_self_decryption = algorithm.get_decrypt_self();\
Data temp_block0 = iv;

DOG_DATA NSROOT::mode::PCBC::encrypt(const Data& plain, const Data& available_key, const algorithm::Algorithm& algorithm, const Data& iv, padding::padding_func padding)
{
	PCBC_ENCRYPT_INIT;

	Data temp_block1(block_size), temp_block2, crypt;
	crypt.reserve(((plain.size() / block_size) + 1) * block_size);
	uint64_t i = 0;
	for (; block_size <= plain.size() - i; i += block_size)
	{
		temp_block1 = plain.sub_by_len(i, block_size);
		temp_block2 = temp_block1;
		dog_torch::serialize::BinaryData::XOR_self(temp_block1, temp_block0, block_size);
		block_self_encryption(temp_block1, block_size, key, key_size);
		crypt += temp_block1;
		temp_block0 = temp_block1 ^ temp_block2;
	}
	temp_block1 = plain.sub_by_len(i, block_size);
	padding(temp_block1, block_size);
	dog_torch::serialize::BinaryData::XOR_self(temp_block1, temp_block0, block_size);
	block_self_encryption(temp_block1, block_size, key, key_size);
	crypt += temp_block1;
	return crypt;
}
DOG_DATA NSROOT::mode::PCBC::decrypt(const Data& crypt, const Data& available_key, const algorithm::Algorithm& algorithm, const Data& iv, padding::padding_func unpadding)
{
	PCBC_DECRYPT_INIT;

	Data temp_block1(block_size), temp_block2, plain;
	plain.reserve(((crypt.size() / block_size) + 1) * block_size);
	uint64_t i = 0;
	for (; block_size < crypt.size() - i; i += block_size)
	{
		temp_block1 = crypt.sub_by_len(i, block_size);
		temp_block2 = temp_block1;
		block_self_decryption(temp_block1, block_size, key, key_size);
		dog_torch::serialize::BinaryData::XOR_self(temp_block1, temp_block0, block_size);
		plain += temp_block1;
		temp_block0 = temp_block1 ^ temp_block2;
	}
	temp_block1 = crypt.sub_by_len(i, block_size);
	block_self_decryption(temp_block1, block_size, key, key_size);
	dog_torch::serialize::BinaryData::XOR_self(temp_block1, temp_block0, block_size);
	unpadding(temp_block1, block_size);
	plain += temp_block1;
	return plain;
}
void NSROOT::mode::PCBC::encrypt_stream(std::istream& plain, uint64_t max, std::ostream& crypt, const Data& available_key, const algorithm::Algorithm& algorithm, const Data& iv, padding::padding_func padding)
{
	PCBC_ENCRYPT_INIT;

	Data temp_block1(block_size), temp_block2;
	uint64_t total = 0;
	while (max - total >= block_size && read_byte_size(plain, temp_block1, block_size, total) == block_size)
	{
		temp_block2 = temp_block1;
		dog_torch::serialize::BinaryData::XOR_self(temp_block1, temp_block0, block_size);
		block_self_encryption(temp_block1, block_size, key, key_size);
		crypt.write((char*)temp_block1.data(), block_size);
		temp_block0 = temp_block1 ^ temp_block2;
	}
	read_byte_size(plain, temp_block1, block_size, total);
	padding(temp_block1, block_size);
	dog_torch::serialize::BinaryData::XOR_self(temp_block1, temp_block0, block_size);
	block_self_encryption(temp_block1, block_size, key, key_size);
	crypt.write((char*)temp_block1.data(), block_size);
	crypt.flush();
}
void NSROOT::mode::PCBC::decrypt_stream(std::istream& crypt, uint64_t max, std::ostream& plain, const Data& available_key, const algorithm::Algorithm& algorithm, const Data& iv, padding::padding_func unpadding)
{
	PCBC_DECRYPT_INIT;

	Data temp_block1(block_size), temp_block2;
	uint64_t total = 0;
	while (max - total > block_size && read_byte_size(crypt, temp_block1, block_size, total) == block_size)
	{
		temp_block2 = temp_block1;
		block_self_decryption(temp_block1, block_size, key, key_size);
		dog_torch::serialize::BinaryData::XOR_self(temp_block1, temp_block0, block_size);
		plain.write((char*)temp_block1.data(), block_size);
		temp_block0 = temp_block1 ^ temp_block2;
	}
	if (read_byte_size(crypt, temp_block1, block_size, total) < block_size) throw CryptionException(DOG_EXCEPTION_MSG_OPINION("The data is not encrypted by PCBC mode"));
	block_self_decryption(temp_block1, block_size, key, key_size);
	dog_torch::serialize::BinaryData::XOR_self(temp_block1, temp_block0, block_size);
	unpadding(temp_block1, block_size);
	plain.write((char*)temp_block1.data(), temp_block1.size());
	plain.flush();
}

NSROOT::mode::PCBC::PCBC(const padding::Padding& padding, const Data& iv) : Mode("PCBC")
{
	if (padding.get_name() == "None")
	{
		throw CryptionException(DOG_EXCEPTION_MSG_OPINION("ECB mode not support No padding"));
	}
	this->padding_ = padding.clone();
	this->iv_ = iv;
}
NSROOT::mode::PCBC::PCBC(const PCBC& other) : Mode("PCBC")
{
	this->padding_ = other.padding_->clone();
	this->iv_ = other.iv_;
}

std::unique_ptr<NSROOT::mode::Mode> NSROOT::mode::PCBC::clone() const
{
	return std::move(std::make_unique<PCBC>(*this));
}
bool NSROOT::mode::PCBC::check(const algorithm::Algorithm& algorithm) const
{
	return algorithm.get_block_size() == this->iv_.size();
}
const DOG_DATA& NSROOT::mode::PCBC::get_iv() const
{
	return this->iv_;
}
const NSROOT::padding::Padding& NSROOT::mode::PCBC::get_padding() const
{
	return *this->padding_;
}

bool dog_torch::crypto::symmetric::mode::PCBC::set_data_param(const std::string& param, const Data& value)
{
	if (param == "iv")
	{
		this->iv_ = value;
		return true;
	}
	return false;
}
bool dog_torch::crypto::symmetric::mode::PCBC::set_Padding(const padding::Padding& value)
{
	if (value.get_name() == "None")
	{
		throw CryptionException(DOG_EXCEPTION_MSG_OPINION("PCBC mode not support No padding"));
	}
	this->padding_ = value.clone();
	return true;
}

NSROOT::mode::crypt_func NSROOT::mode::PCBC::get_mult_encrypt() const
{
	return [this](const Data& plain, const Data& available_key, const algorithm::Algorithm& algorithm) -> Data
		{
			return encrypt(plain, available_key, algorithm, this->iv_, this->padding_->get_padding());
		};
}
NSROOT::mode::crypt_func NSROOT::mode::PCBC::get_mult_decrypt() const
{
	return [this](const Data& crypt, const Data& available_key, const algorithm::Algorithm& algorithm) -> Data
		{
			return decrypt(crypt, available_key, algorithm, this->iv_, this->padding_->get_unpadding());
		};
}
NSROOT::mode::stream_crypt_func NSROOT::mode::PCBC::get_stream_encrypt() const
{
	return [this](std::istream& plain, uint64_t max, std::ostream& crypt, const Data& available_key, const algorithm::Algorithm& algorithm) -> void
		{
			return encrypt_stream(plain, max, crypt, available_key, algorithm, this->iv_, this->padding_->get_padding());
		};
}
NSROOT::mode::stream_crypt_func NSROOT::mode::PCBC::get_stream_decrypt() const
{
	return [this](std::istream& crypt, uint64_t max, std::ostream& plain, const Data& available_key, const algorithm::Algorithm& algorithm) -> void
		{
			return decrypt_stream(crypt, max, plain, available_key, algorithm, this->iv_, this->padding_->get_unpadding());
		};
}


#undef NSROOT
#undef DOG_DATA