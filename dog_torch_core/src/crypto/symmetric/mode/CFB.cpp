#include "crypto/symmetric/mode/CFB.h"

#define NSROOT dog_torch::crypto::symmetric //NSROOT = namespace root
#define DOG_DATA dog_torch::serialize::BinaryData

#define DOG_ERROR_SHIFT_ZERO "Error:CFB shift should not be 0"

#define CFB_ENCRYPT_INIT \
uint64_t block_size = algorithm.get_block_size(); \
uint64_t key_size = algorithm.get_key_size(); \
const Data& key = available_key; \
algorithm::block_self_cryption_func block_self_encryption = algorithm.get_encrypt_self();\
Data temp_block0 = iv;\
using dog_torch::serialize::stream::utils::read_bytes_size;

#define CFB_DECRYPT_INIT \
uint64_t block_size = algorithm.get_block_size(); \
uint64_t key_size = algorithm.get_key_size(); \
const Data& key = available_key; \
algorithm::block_self_cryption_func block_self_encryption = algorithm.get_encrypt_self();\
Data temp_block0 = iv;\
using dog_torch::serialize::stream::utils::read_bytes_size;

NSROOT::mode::Config NSROOT::mode::CFBB::get_config()
{
	return {
	"CFBB",
	std::unordered_map<std::string, std::string>({
		{"padding","Padding"},
		{"shift","uint64_t"},
		{"iv","BinaryData"}
	})
	};
}

DOG_DATA NSROOT::mode::CFBB::encrypt(const Data & plain, const Data& available_key, const algorithm::Algorithm& algorithm, const Data& iv, uint64_t shift, padding::padding_func padding)
{
	CFB_ENCRYPT_INIT;

	Data crypt, temp_block1; crypt.reserve(((plain.size() / shift) + 1) * shift);
	uint64_t i = 0;
	for (; shift <= plain.size() - i; i += shift)
	{
		block_self_encryption(temp_block0, block_size, key, key_size);
		temp_block1 = plain.sub_bytes_by_len(i, shift);
		dog_torch::serialize::BinaryData::XOR_self(temp_block1, temp_block0, shift);
		crypt += temp_block1;
		temp_block0 = temp_block0.sub_bytes_by_len(shift, block_size - shift) + temp_block1;
	}
	block_self_encryption(temp_block0, block_size, key, key_size);
	temp_block1 = plain.sub_bytes_by_len(i, shift);
	padding(temp_block1, shift);
	dog_torch::serialize::BinaryData::XOR_self(temp_block1, temp_block0, temp_block1.size());
	crypt += temp_block1;
	return crypt;
}
DOG_DATA NSROOT::mode::CFBB::decrypt(const Data& crypt, const Data& available_key, const algorithm::Algorithm& algorithm, const Data& iv, uint64_t shift, padding::padding_func unpadding)
{
	CFB_DECRYPT_INIT;

	Data plain, temp_block1, temp_block2; plain.reserve(((crypt.size() / shift) + 1) * shift);
	uint64_t i = 0;
	for (; shift < crypt.size() - i; i += shift)
	{
		block_self_encryption(temp_block0, block_size, key, key_size);
		temp_block1 = crypt.sub_bytes_by_len(i, shift);
		temp_block2 = temp_block1;
		dog_torch::serialize::BinaryData::XOR_self(temp_block1, temp_block0, shift);
		plain += temp_block1;
		temp_block0 = temp_block0.sub_bytes_by_len(shift, block_size - shift) + temp_block2;
	}
	block_self_encryption(temp_block0, block_size, key, key_size);
	temp_block1 = crypt.sub_bytes_by_len(i, shift);
	dog_torch::serialize::BinaryData::XOR_self(temp_block1, temp_block0, temp_block1.size());
	unpadding(temp_block1, shift);
	plain += temp_block1;
	return plain;
}
void NSROOT::mode::CFBB::encrypt_stream(std::istream& plain, uint64_t max, std::ostream& crypt, const Data& available_key, const algorithm::Algorithm& algorithm, const Data& iv, uint64_t shift, padding::padding_func padding)
{
	CFB_ENCRYPT_INIT;

	Data temp_block1(shift),temp_block2;
	uint64_t total = 0;
	while (max - total >= shift && read_bytes_size(plain, temp_block1, shift, total) == shift)
	{
		block_self_encryption(temp_block0, block_size, key, key_size);
		dog_torch::serialize::BinaryData::XOR_self(temp_block1, temp_block0, shift);
		crypt.write((char*)temp_block1.data(), shift);
		temp_block0 = temp_block0.sub_bytes_by_len(shift, block_size - shift) + temp_block1;
	}
	read_bytes_size(plain, temp_block1, shift, total);
	padding(temp_block1, shift);
	block_self_encryption(temp_block0, block_size, key, key_size);
	dog_torch::serialize::BinaryData::XOR_self(temp_block1, temp_block0, temp_block1.size());
	crypt.write((char*)temp_block1.data(), temp_block1.size());
	crypt.flush();
}
void NSROOT::mode::CFBB::decrypt_stream(std::istream& crypt, uint64_t max, std::ostream& plain, const Data& available_key, const algorithm::Algorithm& algorithm, const Data& iv, uint64_t shift, padding::padding_func unpadding)
{
	CFB_DECRYPT_INIT;

	Data temp_block1(shift), temp_block2;
	uint64_t total = 0;
	while (max - total > shift && read_bytes_size(crypt, temp_block1, shift, total) == shift)
	{
		block_self_encryption(temp_block0, block_size, key, key_size);
		temp_block2 = temp_block1;
		dog_torch::serialize::BinaryData::XOR_self(temp_block1, temp_block0, shift);
		plain.write((char*)temp_block1.data(), shift);
		temp_block0 = temp_block0.sub_bytes_by_len(shift, block_size - shift) + temp_block2;
	}
	read_bytes_size(crypt, temp_block1, shift, total);
	block_self_encryption(temp_block0, block_size, key, key_size);
	dog_torch::serialize::BinaryData::XOR_self(temp_block1, temp_block0, temp_block1.size());
	unpadding(temp_block1, shift);
	plain.write((char*)temp_block1.data(), temp_block1.size());
	plain.flush();
}
void NSROOT::mode::CFBB::encryptp_stream(PauseableChannel& pchannel, std::istream& plain, uint64_t max, std::ostream& crypt, const Data& available_key, const algorithm::Algorithm& algorithm, const Data& iv, uint64_t shift, padding::padding_func padding)
{
	CFB_ENCRYPT_INIT;

	pchannel.start();

	Data temp_block1(shift), temp_block2;
	uint64_t total = 0;
	while (max - total >= shift && read_bytes_size(plain, temp_block1, shift, total) == shift)
	{
		block_self_encryption(temp_block0, block_size, key, key_size);
		dog_torch::serialize::BinaryData::XOR_self(temp_block1, temp_block0, shift);
		crypt.write((char*)temp_block1.data(), shift);
		temp_block0 = temp_block0.sub_bytes_by_len(shift, block_size - shift) + temp_block1;
		
		pchannel.add_progress(shift * 1.0 / max);
		if (pchannel.should_pause()) break;;
	}
	read_bytes_size(plain, temp_block1, shift, total);
	padding(temp_block1, shift);
	block_self_encryption(temp_block0, block_size, key, key_size);
	dog_torch::serialize::BinaryData::XOR_self(temp_block1, temp_block0, temp_block1.size());
	crypt.write((char*)temp_block1.data(), temp_block1.size());
	crypt.flush();

	pchannel.complete();
}
void NSROOT::mode::CFBB::decryptp_stream(PauseableChannel& pchannel, std::istream& crypt, uint64_t max, std::ostream& plain, const Data& available_key, const algorithm::Algorithm& algorithm, const Data& iv, uint64_t shift, padding::padding_func unpadding)
{
	CFB_DECRYPT_INIT;

	pchannel.start();

	Data temp_block1(shift), temp_block2;
	uint64_t total = 0;
	while (max - total > shift && read_bytes_size(crypt, temp_block1, shift, total) == shift)
	{
		block_self_encryption(temp_block0, block_size, key, key_size);
		temp_block2 = temp_block1;
		dog_torch::serialize::BinaryData::XOR_self(temp_block1, temp_block0, shift);
		plain.write((char*)temp_block1.data(), shift);
		temp_block0 = temp_block0.sub_bytes_by_len(shift, block_size - shift) + temp_block2;
		
		pchannel.add_progress(shift * 1.0 / max);
		if (pchannel.should_pause()) break;;
	}
	read_bytes_size(crypt, temp_block1, shift, total);
	block_self_encryption(temp_block0, block_size, key, key_size);
	dog_torch::serialize::BinaryData::XOR_self(temp_block1, temp_block0, temp_block1.size());
	unpadding(temp_block1, shift);
	plain.write((char*)temp_block1.data(), temp_block1.size());
	plain.flush();

	pchannel.complete();
}

DOG_DATA NSROOT::mode::CFBB::encrypt_CFB8(const Data& plain, const Data& available_key, const algorithm::Algorithm& algorithm, const Data& iv, padding::padding_func padding)
{
	CFB_ENCRYPT_INIT;

	Data crypt; crypt.reserve(plain.size());
	for (uint64_t i = 0; i < plain.size(); i++)
	{
		block_self_encryption(temp_block0, block_size, key, key_size);
		uint8_t b = plain[i] ^ temp_block0[0];
		crypt.push_back(b);
		temp_block0 = temp_block0.sub_bytes_by_len(1, block_size - 1) + b;
	}
	return crypt;
}
DOG_DATA NSROOT::mode::CFBB::decrypt_CFB8(const Data& crypt, const Data& available_key, const algorithm::Algorithm& algorithm, const Data& iv, padding::padding_func unpadding)
{
	CFB_DECRYPT_INIT;

	Data plain; plain.reserve(crypt.size());
	for (uint64_t i = 0; i < crypt.size(); i++)
	{
		block_self_encryption(temp_block0, block_size, key, key_size);
		uint8_t b = crypt[i] ^ temp_block0[0];
		plain.push_back(b);
		temp_block0 = temp_block0.sub_bytes_by_len(1, block_size - 1) + crypt[i];
	}
	return plain;
}
void NSROOT::mode::CFBB::encrypt_CFB8_stream(std::istream& plain, uint64_t max, std::ostream& crypt, const Data& available_key, const algorithm::Algorithm& algorithm, const Data& iv, padding::padding_func padding)
{
	CFB_ENCRYPT_INIT;

	uint64_t total = 0;
	uint8_t temp_block1;
	while (!plain.eof() && total < max)
	{
		temp_block1 = plain.get();
		total++;
		block_self_encryption(temp_block0, block_size, key, key_size);
		temp_block1 ^= temp_block0[0];
		crypt.put(temp_block1);
		temp_block0 = temp_block0.sub_bytes_by_len(1, block_size - 1) + temp_block1;
	}
	crypt.flush();
}
void NSROOT::mode::CFBB::decrypt_CFB8_stream(std::istream& crypt, uint64_t max, std::ostream& plain, const Data& available_key, const algorithm::Algorithm& algorithm, const Data& iv, padding::padding_func unpadding)
{
	CFB_DECRYPT_INIT;

	uint64_t total = 0;
	uint8_t temp_block1, temp_block2;
	while (!crypt.eof() && total < max)
	{
		temp_block1 = crypt.get();
		total++;
		temp_block2 = temp_block1;
		block_self_encryption(temp_block0, block_size, key, key_size);
		temp_block1 ^= temp_block0[0];
		plain.put(temp_block1);
		temp_block0 = temp_block0.sub_bytes_by_len(1, block_size - 1) + temp_block2;
	}
	plain.flush();
}
void NSROOT::mode::CFBB::encryptp_CFB8_stream(PauseableChannel& pchannel, std::istream& plain, uint64_t max, std::ostream& crypt, const Data& available_key, const algorithm::Algorithm& algorithm, const Data& iv, padding::padding_func padding)
{
	CFB_ENCRYPT_INIT;

	pchannel.start();

	uint64_t total = 0;
	uint8_t temp_block1;
	while (!plain.eof() && total < max)
	{
		temp_block1 = plain.get();
		total++;
		block_self_encryption(temp_block0, block_size, key, key_size);
		temp_block1 ^= temp_block0[0];
		crypt.put(temp_block1);
		temp_block0 = temp_block0.sub_bytes_by_len(1, block_size - 1) + temp_block1;

		pchannel.add_progress(1.0 / max);
		if (pchannel.should_pause()) break;;
	}
	crypt.flush();

	pchannel.complete();
}
void NSROOT::mode::CFBB::decryptp_CFB8_stream(PauseableChannel& pchannel, std::istream& crypt, uint64_t max, std::ostream& plain, const Data& available_key, const algorithm::Algorithm& algorithm, const Data& iv, padding::padding_func unpadding)
{
	CFB_DECRYPT_INIT;
	
	pchannel.start();

	uint64_t total = 0;
	uint8_t temp_block1, temp_block2;
	while (!crypt.eof() && total < max)
	{
		temp_block1 = crypt.get();
		total++;
		temp_block2 = temp_block1;
		block_self_encryption(temp_block0, block_size, key, key_size);
		temp_block1 ^= temp_block0[0];
		plain.put(temp_block1);
		temp_block0 = temp_block0.sub_bytes_by_len(1, block_size - 1) + temp_block2;

		pchannel.add_progress(1.0 / max);
		if (pchannel.should_pause()) break;;
	}
	plain.flush();

	pchannel.complete();
}

DOG_DATA NSROOT::mode::CFBB::encrypt_CFB128(const Data& plain, const Data& available_key, const algorithm::Algorithm& algorithm, const Data& iv, padding::padding_func padding)
{
	CFB_ENCRYPT_INIT;

	Data crypt; crypt.reserve(((plain.size() / block_size) + 1) * block_size);
	Data temp_block1;
	uint64_t i = 0;
	for (; 16 <= plain.size() - i; i += 16)
	{
		block_self_encryption(temp_block0, block_size, key, key_size);
		temp_block1 = plain.sub_bytes_by_len(i, 16);
		dog_torch::serialize::BinaryData::XOR_self(temp_block1, temp_block0, 16);
		crypt += temp_block1;
		temp_block0 = temp_block0.sub_bytes_by_len(16, block_size - 16) + temp_block1;
	}
	block_self_encryption(temp_block0, block_size, key, key_size);
	temp_block1 = plain.sub_bytes_by_len(i, 16);
	padding(temp_block1, 16);
	dog_torch::serialize::BinaryData::XOR_self(temp_block1, temp_block0, temp_block1.size());
	crypt += temp_block1;
	return crypt;
}
DOG_DATA NSROOT::mode::CFBB::decrypt_CFB128(const Data& crypt, const Data& available_key, const algorithm::Algorithm& algorithm, const Data& iv, padding::padding_func unpadding)
{
	CFB_DECRYPT_INIT;
	Data plain; plain.reserve(((crypt.size() / block_size) + 1) * block_size);
	Data temp_block1, temp_block2;
	uint64_t i = 0;
	for (; 16 < crypt.size() - i; i += 16)
	{
		block_self_encryption(temp_block0, block_size, key, key_size);
		temp_block1 = crypt.sub_bytes_by_len(i, 16);
		temp_block2 = temp_block1;
		dog_torch::serialize::BinaryData::XOR_self(temp_block1, temp_block0, 16);
		plain += temp_block1;
		temp_block0 = temp_block0.sub_bytes_by_len(16, block_size - 16) + temp_block2;
	}
	block_self_encryption(temp_block0, block_size, key, key_size);
	temp_block1 = crypt.sub_bytes_by_len(i, 16);
	dog_torch::serialize::BinaryData::XOR_self(temp_block1, temp_block0, 16);
	unpadding(temp_block1, 16);
	plain += temp_block1;
	return plain;
}
void NSROOT::mode::CFBB::encrypt_CFB128_stream(std::istream& plain, uint64_t max, std::ostream& crypt, const Data& available_key, const algorithm::Algorithm& algorithm, const Data& iv, padding::padding_func padding)
{
	CFB_ENCRYPT_INIT;

	Data temp_block1(16), temp_block2;
	uint64_t total = 0;
	while (max - total >= 16 && read_bytes_size(plain, temp_block1, 16, total) == 16)
	{
		block_self_encryption(temp_block0, block_size, key, key_size);
		dog_torch::serialize::BinaryData::XOR_self(temp_block1, temp_block0, 16);
		crypt.write((char*)temp_block1.data(), 16);
		temp_block0 = temp_block0.sub_bytes_by_len(16, block_size - 16) + temp_block1;
	}
	read_bytes_size(plain, temp_block1, 16, total);
	padding(temp_block1, 16);
	block_self_encryption(temp_block0, block_size, key, key_size);
	dog_torch::serialize::BinaryData::XOR_self(temp_block1, temp_block0, temp_block1.size());
	crypt.write((char*)temp_block1.data(), temp_block1.size());
	crypt.flush();

}
void NSROOT::mode::CFBB::decrypt_CFB128_stream(std::istream& crypt, uint64_t max, std::ostream& plain, const Data& available_key, const algorithm::Algorithm& algorithm, const Data& iv, padding::padding_func unpadding)
{
	CFB_DECRYPT_INIT;

	Data temp_block1(16), temp_block2;
	uint64_t total = 0;
	while (max - total > 16 && read_bytes_size(crypt, temp_block1, 16, total) == 16)
	{
		block_self_encryption(temp_block0, block_size, key, key_size);
		temp_block2 = temp_block1;
		dog_torch::serialize::BinaryData::XOR_self(temp_block1, temp_block0, 16);
		plain.write((char*)temp_block1.data(), 16);
		temp_block0 = temp_block0.sub_bytes_by_len(16, block_size - 16) + temp_block2;
	}
	read_bytes_size(crypt, temp_block1, 16, total);
	block_self_encryption(temp_block0, block_size, key, key_size);
	dog_torch::serialize::BinaryData::XOR_self(temp_block1, temp_block0, temp_block1.size());
	unpadding(temp_block1, 16);
	plain.write((char*)temp_block1.data(), temp_block1.size());
	plain.flush();
}
void NSROOT::mode::CFBB::encryptp_CFB128_stream(PauseableChannel& pchannel, std::istream& plain, uint64_t max, std::ostream& crypt, const Data& available_key, const algorithm::Algorithm& algorithm, const Data& iv, padding::padding_func padding)
{
	CFB_ENCRYPT_INIT;

	pchannel.start();

	Data temp_block1(16), temp_block2;
	uint64_t total = 0;
	while (max - total >= 16 && read_bytes_size(plain, temp_block1, 16, total) == 16)
	{
		block_self_encryption(temp_block0, block_size, key, key_size);
		dog_torch::serialize::BinaryData::XOR_self(temp_block1, temp_block0, 16);
		crypt.write((char*)temp_block1.data(), 16);
		temp_block0 = temp_block0.sub_bytes_by_len(16, block_size - 16) + temp_block1;

		pchannel.add_progress(16.0 / max);
		if (pchannel.should_pause()) break;;
	}
	read_bytes_size(plain, temp_block1, 16, total);
	padding(temp_block1, 16);
	block_self_encryption(temp_block0, block_size, key, key_size);
	dog_torch::serialize::BinaryData::XOR_self(temp_block1, temp_block0, temp_block1.size());
	crypt.write((char*)temp_block1.data(), temp_block1.size());
	crypt.flush();

	pchannel.complete();
}
void NSROOT::mode::CFBB::decryptp_CFB128_stream(PauseableChannel& pchannel, std::istream& crypt, uint64_t max, std::ostream& plain, const Data& available_key, const algorithm::Algorithm& algorithm, const Data& iv, padding::padding_func unpadding)
{
	CFB_DECRYPT_INIT;

	pchannel.start();

	Data temp_block1(16), temp_block2;
	uint64_t total = 0;
	while (max - total > 16 && read_bytes_size(crypt, temp_block1, 16, total) == 16)
	{
		block_self_encryption(temp_block0, block_size, key, key_size);
		temp_block2 = temp_block1;
		dog_torch::serialize::BinaryData::XOR_self(temp_block1, temp_block0, 16);
		plain.write((char*)temp_block1.data(), 16);
		temp_block0 = temp_block0.sub_bytes_by_len(16, block_size - 16) + temp_block2;

		pchannel.add_progress(16.0 / max);
		if (pchannel.should_pause()) break;;
	}
	read_bytes_size(crypt, temp_block1, 16, total);
	block_self_encryption(temp_block0, block_size, key, key_size);
	dog_torch::serialize::BinaryData::XOR_self(temp_block1, temp_block0, temp_block1.size());
	unpadding(temp_block1, 16);
	plain.write((char*)temp_block1.data(), temp_block1.size());
	plain.flush();

	pchannel.complete();
}

NSROOT::mode::CFBB::CFBB(const padding::Padding& padding, const Data& iv, uint64_t shift) : Mode("CFBB")
{
	if (shift == 0)
	{
		throw CryptionException(DOG_EXCEPTION_MSG_OPINION(DOG_ERROR_SHIFT_ZERO));
	}
	this->shift_ = shift;
	this->padding_ = padding.clone();
	this->iv_ = iv;
}
NSROOT::mode::CFBB::CFBB(const CFBB& other) : Mode("CFBB")
{
	this->padding_ = other.padding_->clone();
	this->shift_ = other.shift_;
	this->iv_ = other.iv_;
}
std::unique_ptr<NSROOT::mode::Mode> NSROOT::mode::CFBB::clone() const
{
	return std::move(std::make_unique<CFBB>(*this));
}
uint64_t NSROOT::mode::CFBB::get_shift() const
{
	return this->shift_;
}
const DOG_DATA& NSROOT::mode::CFBB::get_iv() const
{
	return this->iv_;
}
const NSROOT::padding::Padding& NSROOT::mode::CFBB::get_padding() const
{
	return *this->padding_;
}
bool NSROOT::mode::CFBB::check(const algorithm::Algorithm& algorithm) const
{
	return false;
}
bool NSROOT::mode::CFBB::set_uint64_param(const std::string& param, uint64_t value)
{
	if (param == "shift")
	{
		this->shift_ = value;
		return true;
	}
	return false;
}
bool NSROOT::mode::CFBB::set_data_param(const std::string& param, const Data& value)
{
	if (param == "iv")
	{
		this->iv_ = value;
		return true;
	}
	return false;
}
bool NSROOT::mode::CFBB::set_Padding(const padding::Padding& value)
{
	this->padding_ = value.clone();
	return true;
}
std::string NSROOT::mode::CFBB::fmt_config() const
{
	return "CFBByte" + std::to_string(this->shift_);
}
NSROOT::mode::crypt_func NSROOT::mode::CFBB::get_mult_encrypt() const
{
	if (this->shift_ == 1)
	{
		return [this](const Data& plain, const Data& available_key, const algorithm::Algorithm& algorithm)->Data
			{
				return encrypt_CFB8(plain, available_key, algorithm, this->iv_, this->padding_->get_padding());
			};
	}
	else if (this->shift_ == 16)
	{
		return [this](const Data& plain, const Data& available_key, const algorithm::Algorithm& algorithm)->Data
			{
				return encrypt_CFB128(plain, available_key, algorithm, this->iv_, this->padding_->get_padding());
			};
	}
	else
	{
		return [this](const Data& plain, const Data& available_key, const algorithm::Algorithm& algorithm)->Data
			{
				return encrypt(plain, available_key, algorithm, this->iv_, this->shift_, this->padding_->get_padding());
			};
	}
}
NSROOT::mode::crypt_func NSROOT::mode::CFBB::get_mult_decrypt() const
{
	if (this->shift_ == 1)
	{
		return [this](const Data& crypt, const Data& available_key, const algorithm::Algorithm& algorithm)->Data
			{
				return decrypt_CFB8(crypt, available_key, algorithm, this->iv_, this->padding_->get_unpadding());
			};
	}
	else if (this->shift_ == 16)
	{
		return [this](const Data& crypt, const Data& available_key, const algorithm::Algorithm& algorithm)->Data
			{
				return decrypt_CFB128(crypt, available_key, algorithm, this->iv_, this->padding_->get_unpadding());
			};
	}
	else
	{
		return [this](const Data& crypt, const Data& available_key, const algorithm::Algorithm& algorithm)->Data
			{
				return decrypt(crypt, available_key, algorithm, this->iv_, this->shift_, this->padding_->get_unpadding());
			};
	}
}
NSROOT::mode::stream_crypt_func NSROOT::mode::CFBB::get_stream_encrypt() const
{
	if (this->shift_ == 1)
	{
		return [this](std::istream& plain, uint64_t max, std::ostream& crypt, const Data& available_key, const algorithm::Algorithm& algorithm) -> void
			{
				return encrypt_CFB8_stream(plain, max, crypt, available_key, algorithm, this->iv_, this->padding_->get_padding());
			};
	}
	else if (this->shift_ == 16)
	{
		return [this](std::istream& plain, uint64_t max, std::ostream& crypt, const Data& available_key, const algorithm::Algorithm& algorithm) -> void
			{
				return encrypt_CFB128_stream(plain, max, crypt, available_key, algorithm, this->iv_, this->padding_->get_padding());
			};
	}
	else
	{
		return [this](std::istream& plain, uint64_t max, std::ostream& crypt, const Data& available_key, const algorithm::Algorithm& algorithm) -> void
			{
				return encrypt_stream(plain, max, crypt, available_key, algorithm, this->iv_, this->shift_, this->padding_->get_padding());
			};
	}
}
NSROOT::mode::stream_crypt_func NSROOT::mode::CFBB::get_stream_decrypt() const
{
	if (this->shift_ == 1)
	{
		return [this](std::istream& crypt, uint64_t max, std::ostream& plain, const Data& available_key, const algorithm::Algorithm& algorithm) -> void
			{
				return decrypt_CFB8_stream(crypt, max, plain, available_key, algorithm, this->iv_, this->padding_->get_unpadding());
			};
	}
	else if (this->shift_ == 16)
	{
		return [this](std::istream& crypt, uint64_t max, std::ostream& plain, const Data& available_key, const algorithm::Algorithm& algorithm) -> void
			{
				return decrypt_CFB128_stream(crypt, max, plain, available_key, algorithm, this->iv_, this->padding_->get_unpadding());
			};
	}
	else
	{
		return [this](std::istream& crypt, uint64_t max, std::ostream& plain, const Data& available_key, const algorithm::Algorithm& algorithm) -> void
			{
				return decrypt_stream(crypt, max, plain, available_key, algorithm, this->iv_, this->shift_, this->padding_->get_unpadding());
			};
	}
}
NSROOT::mode::streamp_crypt_func NSROOT::mode::CFBB::get_streamp_encrypt() const
{
	if (this->shift_ == 1)
	{
		return [this](PauseableChannel& pchannel, std::istream& plain, uint64_t max, std::ostream& crypt, const Data& available_key, const algorithm::Algorithm& algorithm) -> void
			{
				return encryptp_CFB8_stream(pchannel, plain, max, crypt, available_key, algorithm, this->iv_, this->padding_->get_padding());
			};
	}
	else if (this->shift_ == 16)
	{
		return [this](PauseableChannel& pchannel, std::istream& plain, uint64_t max, std::ostream& crypt, const Data& available_key, const algorithm::Algorithm& algorithm) -> void
			{
				return encryptp_CFB128_stream(pchannel, plain, max, crypt, available_key, algorithm, this->iv_, this->padding_->get_padding());
			};
	}
	else
	{
		return [this](PauseableChannel& pchannel, std::istream& plain, uint64_t max, std::ostream& crypt, const Data& available_key, const algorithm::Algorithm& algorithm) -> void
			{
				return encryptp_stream(pchannel, plain, max, crypt, available_key, algorithm, this->iv_, this->shift_, this->padding_->get_padding());
			};
	}
}
NSROOT::mode::streamp_crypt_func NSROOT::mode::CFBB::get_streamp_decrypt() const
{
	if (this->shift_ == 1)
	{
		return [this](PauseableChannel& pchannel, std::istream& crypt, uint64_t max, std::ostream& plain, const Data& available_key, const algorithm::Algorithm& algorithm) -> void
			{
				return decryptp_CFB8_stream(pchannel, crypt, max, plain, available_key, algorithm, this->iv_, this->padding_->get_unpadding());
			};
	}
	else if (this->shift_ == 16)
	{
		return [this](PauseableChannel& pchannel, std::istream& crypt, uint64_t max, std::ostream& plain, const Data& available_key, const algorithm::Algorithm& algorithm) -> void
			{
				return decryptp_CFB128_stream(pchannel, crypt, max, plain, available_key, algorithm, this->iv_, this->padding_->get_unpadding());
			};
	}
	else
	{
		return [this](PauseableChannel& pchannel, std::istream& crypt, uint64_t max, std::ostream& plain, const Data& available_key, const algorithm::Algorithm& algorithm) -> void
			{
				return decryptp_stream(pchannel, crypt, max, plain, available_key, algorithm, this->iv_, this->shift_, this->padding_->get_unpadding());
			};
	}
}

NSROOT::mode::Config NSROOT::mode::CFBb::get_config()
{
	return {
	"CFBb",
	std::unordered_map<std::string, std::string>({
		{"padding","Padding"},
		{"shift","uint64_t"},
		{"iv","BinaryData"}
	})
	};
}

DOG_DATA NSROOT::mode::CFBb::encrypt(const Data & plain, const Data& available_key, const algorithm::Algorithm& algorithm, const Data& iv, uint64_t shift, padding::padding_func padding)
{
	CFB_ENCRYPT_INIT;

	uint64_t read_byte_pos = 0;
	int8_t read_bit_pos = 0;
	dog_torch::serialize::BinaryData crypt;
	crypt.reserve(plain.size());
	Data temp_block1; temp_block1.reserve(((shift / 8) + 1) * 8);
	auto pick_shift = [&plain, &shift, &read_byte_pos, &read_bit_pos, &temp_block1]()->void
		{
			temp_block1.rm_pos();
			uint8_t fill_byte = 0x00;
			uint8_t temp_byte = 0x00;
			for (uint64_t i = 0; i < shift; i++)
			{
				temp_byte = plain[read_byte_pos];
				fill_byte |= ((temp_byte >> (7 - read_bit_pos)) & 0x01) << (7 - (i % 8));
				read_bit_pos++;
				if (i % 8 == 7)
				{
					temp_block1.push_back(fill_byte);
					fill_byte = 0x00;
				}
				if (read_bit_pos == 8)
				{
					read_bit_pos = 0;
					read_byte_pos++;
				}
				if (read_byte_pos == plain.size())
				{
					break;
				}
			}
			if (shift % 8 != 0)
			{
				temp_block1.push_back(fill_byte);
			}
		};
	int8_t waiting_byte = 0x00; int8_t write_bit_pos = 0;
	auto add_block = [&plain, &crypt, &shift, &waiting_byte, &write_bit_pos,&temp_block1]()->void
		{
			uint8_t temp_byte = 0x00;
			for (uint64_t i = 0; i < shift; i++)
			{
				if (i / 8 == temp_block1.size()) { break; }
				temp_byte = temp_block1[i / 8];
				waiting_byte |= ((temp_byte >> (7 - i % 8)) & 0x01) << (7 - (write_bit_pos % 8));
				write_bit_pos++;
				if (write_bit_pos == 8)
				{
					crypt.push_back(waiting_byte);
					if (plain.size() == crypt.size()) { break; }
					waiting_byte = 0x00;
					write_bit_pos = 0;
				}
			}
		};
	while(read_byte_pos < plain.size())
	{
		block_self_encryption(temp_block0, block_size, key, key_size);
		pick_shift();
		while (temp_block1.size() < block_size) { temp_block1.push_back(0x00); }
		dog_torch::serialize::BinaryData::XOR_self(temp_block1, temp_block0, block_size);
		add_block();
		temp_block0 = temp_block0.bit_left_move_norise(shift) | temp_block1.bit_right_move_norise(block_size * 8 - shift);
	}
	return crypt;
}
DOG_DATA NSROOT::mode::CFBb::decrypt(const Data& crypt, const Data& available_key, const algorithm::Algorithm& algorithm, const Data& iv, uint64_t shift, padding::padding_func unpadding)
{
	CFB_DECRYPT_INIT;

	dog_torch::serialize::BinaryData plain; plain.reserve(crypt.size());
	uint64_t read_byte_pos = 0;
	int8_t read_bit_pos = 0;
	dog_torch::serialize::BinaryData temp_block1, temp_block2; temp_block1.reserve((shift / 8) + 1); temp_block2.reserve((shift / 8) + 1);
	auto pick_shift = [&crypt, &shift, &read_byte_pos, &read_bit_pos, &temp_block1]()->void
		{
			temp_block1.rm_pos();
			uint8_t fill_byte = 0x00;
			uint8_t temp_byte = 0x00;
			for (uint64_t i = 0; i < shift; i++)
			{
				temp_byte = crypt[read_byte_pos];
				fill_byte |= ((temp_byte >> (7 - read_bit_pos)) & 0x01) << (7 - (i % 8));
				read_bit_pos++;
				if (i % 8 == 7)
				{
					temp_block1.push_back(fill_byte);
					fill_byte = 0x00;
				}
				if (read_bit_pos == 8)
				{
					read_bit_pos = 0;
					read_byte_pos++;
				}
				if (read_byte_pos == crypt.size())
				{
					break;
				}
			}
			if (shift % 8 != 0)
			{
				temp_block1.push_back(fill_byte);
			}
		};
	int8_t waiting_byte = 0x00; int8_t write_bit_pos = 0;
	auto add_block = [&crypt, &plain, &shift, &waiting_byte, &write_bit_pos,&temp_block2]()->void
		{
			uint8_t temp_byte = 0x00;
			for (uint64_t i = 0; i < shift; i++)
			{
				if (i / 8 == temp_block2.size()) { break; }
				temp_byte = temp_block2[i / 8];
				waiting_byte |= ((temp_byte >> (7 - i % 8)) & 0x01) << (7 - (write_bit_pos % 8));
				write_bit_pos++;
				if (write_bit_pos == 8)
				{
					plain.push_back(waiting_byte);
					if (plain.size() == crypt.size()) { break; }
					waiting_byte = 0x00;
					write_bit_pos = 0;
				}
			}
		};
	while (read_byte_pos < crypt.size())
	{
		block_self_encryption(temp_block0, block_size, key, key_size);
		pick_shift();
		while (temp_block1.size() < block_size) { temp_block1.push_back(0x00); }
		temp_block2 = dog_torch::serialize::BinaryData::XOR(temp_block1, temp_block0, block_size);
		add_block();
		temp_block0 = temp_block0.bit_left_move_norise(shift) | temp_block1.bit_right_move_norise(block_size * 8 - shift);
	}
	return plain;
}
void NSROOT::mode::CFBb::encrypt_stream(std::istream& plain, uint64_t max, std::ostream& crypt, const Data& available_key, const algorithm::Algorithm& algorithm, const Data& iv, uint64_t shift, padding::padding_func padding)
{
	CFB_ENCRYPT_INIT;

	int8_t read_bit_pos = 0;
	uint64_t read_total = 0, write_total = 0;
	Data temp_block1; temp_block1.reserve(((shift / 8) + 1) * 8);
	auto pick_shift = [&plain, &shift, &read_bit_pos, &temp_block1, &read_total, &max]()->void
		{
			temp_block1.rm_pos();//等效clear
			uint8_t fill_byte = 0, fill_bit_pos = 0;
			uint8_t temp_byte = 0x00;
			uint64_t i = 0;
			for (; i < shift; i++)
			{
				temp_byte = plain.peek();
				fill_byte |= ((temp_byte >> (7 - read_bit_pos)) & 0x01) << (7 - i % 8);
				read_bit_pos++;
				fill_bit_pos++;
				if (i % 8 == 7)
				{
					temp_block1.push_back(fill_byte);
					fill_byte = 0;
					fill_bit_pos = 0;
				}
				if (read_bit_pos == 8)
				{
					read_bit_pos = 0;
					plain.get();
					read_total++;
				}
				if (read_total == max)
				{
					break;
				}
			}
			if (fill_bit_pos != 0)
			{
				temp_block1.push_back(fill_byte);
			}
		};
	int8_t waiting_byte = 0x00; int8_t write_bit_pos = 0;
	auto add_block = [&crypt, &write_total, &max, &shift, &waiting_byte, &write_bit_pos, &temp_block1]()->void
		{
			uint8_t temp_byte = 0x00;
			for (uint64_t i = 0; i < shift; i++)
			{
				if (i / 8 == temp_block1.size()) { break; }
				temp_byte = temp_block1[i / 8];
				waiting_byte |= ((temp_byte >> (7 - i % 8)) & 0x01) << (7 - (write_bit_pos % 8));
				write_bit_pos++;
				if (write_bit_pos == 8)
				{
					crypt.put(waiting_byte);
					write_total++;
					if (write_total == max) { return; }
					waiting_byte = 0x00;
					write_bit_pos = 0;
				}
			}
		};
	while (read_total != max)
	{
		block_self_encryption(temp_block0, block_size, key, key_size);
		pick_shift();
		dog_torch::serialize::BinaryData::XOR_self(temp_block1, temp_block0, temp_block1.size());
		add_block();
		for (uint64_t i = temp_block1.size(); i < block_size; i++) { temp_block1.push_back(0x00); }
		temp_block0 = temp_block0.bit_left_move_norise(shift) | temp_block1.bit_right_move_norise(block_size * 8 - shift);
	}
	crypt.flush();
}
void NSROOT::mode::CFBb::decrypt_stream(std::istream& crypt, uint64_t max, std::ostream& plain, const Data& available_key, const algorithm::Algorithm& algorithm, const Data& iv, uint64_t shift, padding::padding_func unpadding)
{
	CFB_DECRYPT_INIT;

	int8_t read_bit_pos = 0;
	uint64_t read_total = 0, write_total = 0;
	Data temp_block1, temp_block2; temp_block1.reserve(((shift / 8) + 1) * 8);
	auto pick_shift = [&crypt, &shift, &read_bit_pos, &temp_block1, &read_total, &max]()->void
		{
			temp_block1.rm_pos();
			uint8_t fill_byte = 0, fill_bit_pos = 0;
			uint8_t temp_byte = 0x00;
			uint64_t i = 0;
			for (; i < shift; i++)
			{
				temp_byte = crypt.peek();
				fill_byte |= ((temp_byte >> (7 - read_bit_pos)) & 0x01) << (7 - i % 8);
				read_bit_pos++;
				fill_bit_pos++;
				if (i % 8 == 7)
				{
					temp_block1.push_back(fill_byte);
					fill_byte = 0;
					fill_bit_pos = 0;
				}
				if (read_bit_pos == 8)
				{
					read_bit_pos = 0;
					crypt.get();
					read_total++;
				}
				if (read_total == max)
				{
					break;
				}
			}
			if (fill_bit_pos != 0)
			{
				temp_block1.push_back(fill_byte);
			}
		};
	int8_t waiting_byte = 0x00; int8_t write_bit_pos = 0;
	auto add_block = [&plain, &write_total, &max, &shift, &waiting_byte, &write_bit_pos, &temp_block1]()->void
		{
			uint8_t temp_byte = 0x00;
			for (uint64_t i = 0; i < shift; i++)
			{
				if (i / 8 == temp_block1.size()) { break; }
				temp_byte = temp_block1[i / 8];
				waiting_byte |= ((temp_byte >> (7 - i % 8)) & 0x01) << (7 - (write_bit_pos % 8));
				write_bit_pos++;
				if (write_bit_pos == 8)
				{
					plain.put(waiting_byte);
					write_total++;
					if (write_total == max) { return; }
					waiting_byte = 0x00;
					write_bit_pos = 0;
				}
			}
		};
	while (read_total != max)
	{
		block_self_encryption(temp_block0, block_size, key, key_size);
		pick_shift();
		temp_block2 = temp_block1;
		dog_torch::serialize::BinaryData::XOR_self(temp_block1, temp_block0, temp_block1.size());
		add_block();
		for (uint64_t i = temp_block2.size(); i < block_size; i++) { temp_block2.push_back(0x00); }
		temp_block0 = temp_block0.bit_left_move_norise(shift) | temp_block2.bit_right_move_norise(block_size * 8 - shift);
	}
	plain.flush();
}
void NSROOT::mode::CFBb::encryptp_stream(PauseableChannel& pchannel, std::istream& plain, uint64_t max, std::ostream& crypt, const Data& available_key, const algorithm::Algorithm& algorithm, const Data& iv, uint64_t shift, padding::padding_func padding)
{
	CFB_ENCRYPT_INIT;

	pchannel.start();

	int8_t read_bit_pos = 0;
	uint64_t read_total = 0, write_total = 0;
	Data temp_block1; temp_block1.reserve(((shift / 8) + 1) * 8);
	auto pick_shift = [&plain, &shift, &read_bit_pos, &temp_block1, &read_total, &max]()->void
		{
			temp_block1.rm_pos();//等效clear
			uint8_t fill_byte = 0, fill_bit_pos = 0;
			uint8_t temp_byte = 0x00;
			uint64_t i = 0;
			for (; i < shift; i++)
			{
				temp_byte = plain.peek();
				fill_byte |= ((temp_byte >> (7 - read_bit_pos)) & 0x01) << (7 - i % 8);
				read_bit_pos++;
				fill_bit_pos++;
				if (i % 8 == 7)
				{
					temp_block1.push_back(fill_byte);
					fill_byte = 0;
					fill_bit_pos = 0;
				}
				if (read_bit_pos == 8)
				{
					read_bit_pos = 0;
					plain.get();
					read_total++;
				}
				if (read_total == max)
				{
					break;
				}
			}
			if (fill_bit_pos != 0)
			{
				temp_block1.push_back(fill_byte);
			}
		};
	int8_t waiting_byte = 0x00; int8_t write_bit_pos = 0;
	auto add_block = [&crypt, &write_total, &max, &shift, &waiting_byte, &write_bit_pos, &temp_block1]()->void
		{
			uint8_t temp_byte = 0x00;
			for (uint64_t i = 0; i < shift; i++)
			{
				if (i / 8 == temp_block1.size()) { break; }
				temp_byte = temp_block1[i / 8];
				waiting_byte |= ((temp_byte >> (7 - i % 8)) & 0x01) << (7 - (write_bit_pos % 8));
				write_bit_pos++;
				if (write_bit_pos == 8)
				{
					crypt.put(waiting_byte);
					write_total++;
					if (write_total == max) { return; }
					waiting_byte = 0x00;
					write_bit_pos = 0;
				}
			}
		};
	while (read_total != max)
	{
		block_self_encryption(temp_block0, block_size, key, key_size);
		pick_shift();
		dog_torch::serialize::BinaryData::XOR_self(temp_block1, temp_block0, temp_block1.size());
		add_block();
		for (uint64_t i = temp_block1.size(); i < block_size; i++) { temp_block1.push_back(0x00); }
		temp_block0 = temp_block0.bit_left_move_norise(shift) | temp_block1.bit_right_move_norise(block_size * 8 - shift);

		pchannel.add_progress((double)shift / 8 / max);
		if (pchannel.should_pause()) break;;
	}
	crypt.flush();

	pchannel.complete();
}
void NSROOT::mode::CFBb::decryptp_stream(PauseableChannel& pchannel, std::istream& crypt, uint64_t max, std::ostream& plain, const Data& available_key, const algorithm::Algorithm& algorithm, const Data& iv, uint64_t shift, padding::padding_func unpadding)
{
	CFB_DECRYPT_INIT;

	pchannel.start();

	int8_t read_bit_pos = 0;
	uint64_t read_total = 0, write_total = 0;
	Data temp_block1, temp_block2; temp_block1.reserve(((shift / 8) + 1) * 8);
	auto pick_shift = [&crypt, &shift, &read_bit_pos, &temp_block1, &read_total, &max]()->void
		{
			temp_block1.rm_pos();
			uint8_t fill_byte = 0, fill_bit_pos = 0;
			uint8_t temp_byte = 0x00;
			uint64_t i = 0;
			for (; i < shift; i++)
			{
				temp_byte = crypt.peek();
				fill_byte |= ((temp_byte >> (7 - read_bit_pos)) & 0x01) << (7 - i % 8);
				read_bit_pos++;
				fill_bit_pos++;
				if (i % 8 == 7)
				{
					temp_block1.push_back(fill_byte);
					fill_byte = 0;
					fill_bit_pos = 0;
				}
				if (read_bit_pos == 8)
				{
					read_bit_pos = 0;
					crypt.get();
					read_total++;
				}
				if (read_total == max)
				{
					break;
				}
			}
			if (fill_bit_pos != 0)
			{
				temp_block1.push_back(fill_byte);
			}
		};
	int8_t waiting_byte = 0x00; int8_t write_bit_pos = 0;
	auto add_block = [&plain, &write_total, &max, &shift, &waiting_byte, &write_bit_pos, &temp_block1]()->void
		{
			uint8_t temp_byte = 0x00;
			for (uint64_t i = 0; i < shift; i++)
			{
				if (i / 8 == temp_block1.size()) { break; }
				temp_byte = temp_block1[i / 8];
				waiting_byte |= ((temp_byte >> (7 - i % 8)) & 0x01) << (7 - (write_bit_pos % 8));
				write_bit_pos++;
				if (write_bit_pos == 8)
				{
					plain.put(waiting_byte);
					write_total++;
					if (write_total == max) { return; }
					waiting_byte = 0x00;
					write_bit_pos = 0;
				}
			}
		};
	while (read_total != max)
	{
		block_self_encryption(temp_block0, block_size, key, key_size);
		pick_shift();
		temp_block2 = temp_block1;
		dog_torch::serialize::BinaryData::XOR_self(temp_block1, temp_block0, temp_block1.size());
		add_block();
		for (uint64_t i = temp_block2.size(); i < block_size; i++) { temp_block2.push_back(0x00); }
		temp_block0 = temp_block0.bit_left_move_norise(shift) | temp_block2.bit_right_move_norise(block_size * 8 - shift);

		pchannel.add_progress((double)shift / 8 / max);
		if (pchannel.should_pause()) break;;
	}
	plain.flush();

	pchannel.complete();
}

DOG_DATA NSROOT::mode::CFBb::encrypt_CFB1(const Data & plain, const Data& available_key, const algorithm::Algorithm& algorithm, const Data& iv, padding::padding_func padding)
{
	CFB_ENCRYPT_INIT;

	uint8_t temp_block1 = 0;
	Data crypt; crypt.reserve(plain.size());
	for (uint64_t i = 0; i < plain.size(); i++)
	{
		uint8_t fill_byte = 0;
		for (uint64_t j = 0; j < 8; j++)
		{
			block_self_encryption(temp_block0, block_size, key, key_size);
			temp_block1 = (plain[i] << j) & 0x80;
			temp_block1 ^= (temp_block0[0] & 0x80);
			fill_byte |= (temp_block1 & 0x80) >> j;
			temp_block0.bit_left_move_norise_self(1);
			temp_block0[block_size - 1] |= (temp_block1 >> 7);
		}
		crypt.push_back(fill_byte);
	}
	return crypt;
}
DOG_DATA NSROOT::mode::CFBb::decrypt_CFB1(const Data& crypt, const Data& available_key, const algorithm::Algorithm& algorithm, const Data& iv, padding::padding_func unpadding)
{
	CFB_DECRYPT_INIT;

	uint8_t temp_block1 = 0, temp_block2 = 0;
	Data plain; plain.reserve(crypt.size());
	for (uint64_t i = 0; i < crypt.size(); i++)
	{
		uint8_t fill_byte = 0;
		for (uint64_t j = 0; j < 8; j++)
		{
			block_self_encryption(temp_block0, block_size, key, key_size);
			temp_block1 = (crypt[i] << j) & 0x80;
			temp_block2 = temp_block1;
			temp_block1 ^= (temp_block0[0] & 0x80);
			fill_byte |= (temp_block1 & 0x80) >> j;
			temp_block0.bit_left_move_norise_self(1);
			temp_block0[block_size - 1] |= (temp_block2 >> 7);
		}
		plain.push_back(fill_byte);
	}
	return plain;
}
void NSROOT::mode::CFBb::encrypt_CFB1_stream(std::istream& plain, uint64_t max, std::ostream& crypt, const Data& available_key, const algorithm::Algorithm& algorithm, const Data& iv, padding::padding_func padding)
{
	CFB_ENCRYPT_INIT;

	uint8_t temp_block1 = 0;
	uint64_t total = 0;
	while (!plain.eof() && total < max)
	{
		uint8_t fill_byte = 0;
		for (uint64_t j = 0; j < 8; j++)
		{
			block_self_encryption(temp_block0, block_size, key, key_size);
			temp_block1 = (plain.peek() << j) & 0x80;
			temp_block1 ^= (temp_block0[0] & 0x80);
			fill_byte |= (temp_block1 & 0x80) >> j;
			temp_block0.bit_left_move_norise_self(1);
			temp_block0[block_size - 1] |= (temp_block1 >> 7);
		}
		plain.get();
		crypt.put(fill_byte);
		total++;
	}
	crypt.flush();
}
void NSROOT::mode::CFBb::decrypt_CFB1_stream(std::istream& crypt, uint64_t max, std::ostream& plain, const Data& available_key, const algorithm::Algorithm& algorithm, const Data& iv, padding::padding_func unpadding)
{
	CFB_DECRYPT_INIT;

	uint8_t temp_block1 = 0, temp_block2 = 0;
	uint64_t total = 0;
	while (!crypt.eof() && total < max)
	{
		uint8_t fill_byte = 0;
		for (uint64_t j = 0; j < 8; j++)
		{
			block_self_encryption(temp_block0, block_size, key, key_size);
			temp_block1 = (crypt.peek() << j) & 0x80;
			temp_block2 = temp_block1;
			temp_block1 ^= (temp_block0[0] & 0x80);
			fill_byte |= (temp_block1 & 0x80) >> j;
			temp_block0.bit_left_move_norise_self(1);
			temp_block0[block_size - 1] |= (temp_block2 >> 7);
		}
		crypt.get();
		plain.put(fill_byte);
		total++;
	}
	plain.flush();
}
void NSROOT::mode::CFBb::encryptp_CFB1_stream(PauseableChannel& pchannel, std::istream& plain, uint64_t max, std::ostream& crypt, const Data& available_key, const algorithm::Algorithm& algorithm, const Data& iv, padding::padding_func padding)
{
	CFB_ENCRYPT_INIT;

	pchannel.start();

	uint8_t temp_block1 = 0;
	uint64_t total = 0;
	while (!plain.eof() && total < max)
	{
		uint8_t fill_byte = 0;
		for (uint64_t j = 0; j < 8; j++)
		{
			block_self_encryption(temp_block0, block_size, key, key_size);
			temp_block1 = (plain.peek() << j) & 0x80;
			temp_block1 ^= (temp_block0[0] & 0x80);
			fill_byte |= (temp_block1 & 0x80) >> j;
			temp_block0.bit_left_move_norise_self(1);
			temp_block0[block_size - 1] |= (temp_block1 >> 7);
		}
		plain.get();
		crypt.put(fill_byte);
		total++;

		pchannel.add_progress((double)1 / max);
		if (pchannel.should_pause()) break;;
	}
	crypt.flush();

	pchannel.complete();
}
void NSROOT::mode::CFBb::decryptp_CFB1_stream(PauseableChannel& pchannel, std::istream& crypt, uint64_t max, std::ostream& plain, const Data& available_key, const algorithm::Algorithm& algorithm, const Data& iv, padding::padding_func unpadding)
{
	CFB_DECRYPT_INIT;

	pchannel.start();

	uint8_t temp_block1 = 0, temp_block2 = 0;
	uint64_t total = 0;
	while (!crypt.eof() && total < max)
	{
		uint8_t fill_byte = 0;
		for (uint64_t j = 0; j < 8; j++)
		{
			block_self_encryption(temp_block0, block_size, key, key_size);
			temp_block1 = (crypt.peek() << j) & 0x80;
			temp_block2 = temp_block1;
			temp_block1 ^= (temp_block0[0] & 0x80);
			fill_byte |= (temp_block1 & 0x80) >> j;
			temp_block0.bit_left_move_norise_self(1);
			temp_block0[block_size - 1] |= (temp_block2 >> 7);
		}
		crypt.get();
		plain.put(fill_byte);
		total++;

		pchannel.add_progress((double)1 / max);
		if (pchannel.should_pause()) break;;
	}
	plain.flush();

	pchannel.complete();
}

NSROOT::mode::CFBb::CFBb(const padding::Padding& padding, const Data& iv, uint64_t shift) : Mode("CFBb")
{
	if (shift == 0)
	{
		throw CryptionException(DOG_EXCEPTION_MSG_OPINION(DOG_ERROR_SHIFT_ZERO));
	}
	this->shift_ = shift;
	this->padding_ = padding.clone();
	this->iv_ = iv;
}
NSROOT::mode::CFBb::CFBb(const CFBb& other) : Mode("CFBb")
{
	this->padding_ = other.padding_->clone();
	this->shift_ = other.shift_;
	this->iv_ = other.iv_;
}
uint64_t NSROOT::mode::CFBb::get_shift() const
{
	return shift_ % 8 == 0 ? shift_ / 8 : shift_;
}
const DOG_DATA& NSROOT::mode::CFBb::get_iv() const
{
	return this->iv_;
}
const NSROOT::padding::Padding& NSROOT::mode::CFBb::get_padding() const
{
	return *this->padding_;
}
bool NSROOT::mode::CFBb::check(const algorithm::Algorithm& algorithm) const
{
	return algorithm.get_block_size() == this->iv_.size();
}
std::string NSROOT::mode::CFBb::fmt_config() const
{
	return "CFBBit" + std::to_string(this->shift_);
}
std::unique_ptr<NSROOT::mode::Mode> NSROOT::mode::CFBb::clone() const
{
	return std::move(std::make_unique<CFBb>(*this));
}
bool NSROOT::mode::CFBb::set_uint64_param(const std::string& param, uint64_t value)
{
	if (param == "shift")
	{
		this->shift_ = value;
		return true;
	}
	return false;
}
bool NSROOT::mode::CFBb::set_data_param(const std::string& param, const Data& value)
{
	if (param == "iv")
	{
		this->iv_ = value;
		return true;
	}
	return false;
}
bool NSROOT::mode::CFBb::set_Padding(const padding::Padding& value)
{
	this->padding_ = value.clone();
	return true;
}
NSROOT::mode::crypt_func NSROOT::mode::CFBb::get_mult_encrypt() const
{
	if (this->shift_ % 8 == 0)
	{
		if (this->shift_ / 8 == 1)
		{
			return [this](const Data& plain, const Data& available_key, const algorithm::Algorithm& algorithm)->Data
				{
					return CFBB::encrypt_CFB8(plain, available_key, algorithm, this->iv_, this->padding_->get_padding());
				};
		}
		else if (this->shift_ / 8 == 16)
		{
			return [this](const Data& plain, const Data& available_key, const algorithm::Algorithm& algorithm)->Data
				{
					return CFBB::encrypt_CFB128(plain, available_key, algorithm, this->iv_, this->padding_->get_padding());
				};
		}
		else
		{
			return [this](const Data& plain, const Data& available_key, const algorithm::Algorithm& algorithm)->Data
				{
					return CFBB::encrypt(plain, available_key, algorithm, this->iv_, this->shift_ / 8, this->padding_->get_padding());
				};
		}
	}
	else if (this->shift_ == 1)
	{
		return [this](const Data& plain, const Data& available_key, const algorithm::Algorithm& algorithm)->Data
			{
				return encrypt_CFB1(plain, available_key, algorithm, this->iv_, this->padding_->get_padding());
			};
	}
	else
	{
		return [this](const Data& plain, const Data& available_key, const algorithm::Algorithm& algorithm)->Data
			{
				return encrypt(plain, available_key, algorithm, this->iv_, this->shift_, this->padding_->get_padding());
			};
	}
}
NSROOT::mode::crypt_func NSROOT::mode::CFBb::get_mult_decrypt() const
{
	if (this->shift_ % 8 == 0)
	{
		if (this->shift_ / 8 == 1)
		{
			return [this](const Data& crypt, const Data& available_key, const algorithm::Algorithm& algorithm)->Data
				{
					return CFBB::decrypt_CFB8(crypt, available_key, algorithm, this->iv_, this->padding_->get_unpadding());
				};
		}
		else if (this->shift_ / 8 == 16)
		{
			return [this](const Data& crypt, const Data& available_key, const algorithm::Algorithm& algorithm)->Data
				{
					return CFBB::decrypt_CFB128(crypt, available_key, algorithm, this->iv_, this->padding_->get_unpadding());
				};
		}
		else
		{
			return [this](const Data& crypt, const Data& available_key, const algorithm::Algorithm& algorithm)->Data
				{
					return CFBB::decrypt(crypt, available_key, algorithm, this->iv_, this->shift_ / 8, this->padding_->get_unpadding());
				};
		}
	}
	else if (this->shift_ == 1)
	{
		return [this](const Data& crypt, const Data& available_key, const algorithm::Algorithm& algorithm)->Data
			{
				return decrypt_CFB1(crypt, available_key, algorithm, this->iv_, this->padding_->get_unpadding());
			};
	}
	else
	{
		return [this](const Data& crypt, const Data& available_key, const algorithm::Algorithm& algorithm)->Data
			{
				return decrypt(crypt, available_key, algorithm, this->iv_, this->shift_, this->padding_->get_unpadding());
			};
	}
}
NSROOT::mode::stream_crypt_func NSROOT::mode::CFBb::get_stream_encrypt() const
{
	if (this->shift_ % 8 == 0)
	{
		if (this->shift_ / 8 == 1)
		{
			return [this](std::istream& plain, uint64_t max, std::ostream& crypt, const Data& available_key, const algorithm::Algorithm& algorithm)->void
				{
					return CFBB::encrypt_CFB8_stream(plain, max, crypt, available_key, algorithm, this->iv_, this->padding_->get_padding());
				};
		}
		else if (this->shift_ / 8 == 16)
		{
			return [this](std::istream& plain, uint64_t max, std::ostream& crypt, const Data& available_key, const algorithm::Algorithm& algorithm)->void
				{
					return CFBB::encrypt_CFB128_stream(plain, max, crypt, available_key, algorithm, this->iv_, this->padding_->get_padding());
				};
		}
		else
		{
			return [this](std::istream& plain, uint64_t max, std::ostream& crypt, const Data& available_key, const algorithm::Algorithm& algorithm)->void
				{
					return CFBB::encrypt_stream(plain, max, crypt, available_key, algorithm, this->iv_, this->shift_ / 8, this->padding_->get_padding());
				};
		}
	}
	else if (this->shift_ == 1)
	{
		return [this](std::istream& plain, uint64_t max, std::ostream& crypt, const Data& available_key, const algorithm::Algorithm& algorithm)->void
			{
				return encrypt_CFB1_stream(plain, max, crypt, available_key, algorithm, this->iv_, this->padding_->get_padding());
			};
	}
	else
	{
		return [this](std::istream& plain, uint64_t max, std::ostream& crypt, const Data& available_key, const algorithm::Algorithm& algorithm)->void
			{
				return encrypt_stream(plain, max, crypt, available_key, algorithm, this->iv_, this->shift_, this->padding_->get_padding());
			};
	}
}
NSROOT::mode::stream_crypt_func NSROOT::mode::CFBb::get_stream_decrypt() const
{
	if (this->shift_ % 8 == 0)
	{
		if (this->shift_ / 8 == 1)
		{
			return [this](std::istream& crypt, uint64_t max, std::ostream& plain, const Data& available_key, const algorithm::Algorithm& algorithm)->void
				{
					return CFBB::decrypt_CFB8_stream(crypt, max, plain, available_key, algorithm, this->iv_, this->padding_->get_unpadding());
				};
		}
		else if (this->shift_ / 8 == 16)
		{
			return [this](std::istream& crypt, uint64_t max, std::ostream& plain, const Data& available_key, const algorithm::Algorithm& algorithm)->void
				{
					return CFBB::decrypt_CFB128_stream(crypt, max, plain, available_key, algorithm, this->iv_, this->padding_->get_unpadding());
				};
		}
		else
		{
			return [this](std::istream& crypt, uint64_t max, std::ostream& plain, const Data& available_key, const algorithm::Algorithm& algorithm)->void
				{
					return CFBB::decrypt_stream(crypt, max, plain, available_key, algorithm, this->iv_,this->shift_ / 8, this->padding_->get_unpadding());
				};
		}
	}
	else if (this->shift_ == 1)
	{
		return [this](std::istream& crypt, uint64_t max, std::ostream& plain, const Data& available_key, const algorithm::Algorithm& algorithm)->void
			{
				return decrypt_CFB1_stream(crypt, max, plain, available_key, algorithm, this->iv_, this->padding_->get_unpadding());
			};
	}
	else
	{
		return [this](std::istream& crypt, uint64_t max, std::ostream& plain, const Data& available_key, const algorithm::Algorithm& algorithm)->void
			{
				return CFBb::decrypt_stream(crypt, max, plain, available_key, algorithm, this->iv_, this->shift_, this->padding_->get_unpadding());
			};
	}
}
NSROOT::mode::streamp_crypt_func NSROOT::mode::CFBb::get_streamp_encrypt() const
{
	if (this->shift_ % 8 == 0)
	{
		if (this->shift_ / 8 == 1)
		{
			return [this](PauseableChannel& pchannel, std::istream& plain, uint64_t max, std::ostream& crypt, const Data& available_key, const algorithm::Algorithm& algorithm)->void
				{
					return CFBB::encryptp_CFB8_stream(pchannel, plain, max, crypt, available_key, algorithm, this->iv_, this->padding_->get_padding());
				};
		}
		else if (this->shift_ / 8 == 16)
		{
			return [this](PauseableChannel& pchannel, std::istream& plain, uint64_t max, std::ostream& crypt, const Data& available_key, const algorithm::Algorithm& algorithm)->void
				{
					return CFBB::encryptp_CFB128_stream(pchannel, plain, max, crypt, available_key, algorithm, this->iv_, this->padding_->get_padding());
				};
		}
		else
		{
			return [this](PauseableChannel& pchannel, std::istream& plain, uint64_t max, std::ostream& crypt, const Data& available_key, const algorithm::Algorithm& algorithm)->void
				{
					return CFBB::encryptp_stream(pchannel, plain, max, crypt, available_key, algorithm, this->iv_, this->shift_ / 8, this->padding_->get_padding());
				};
		}
	}
	else if (this->shift_ == 1)
	{
		return [this](PauseableChannel& pchannel, std::istream& plain, uint64_t max, std::ostream& crypt, const Data& available_key, const algorithm::Algorithm& algorithm)->void
			{
				return encryptp_CFB1_stream(pchannel, plain, max, crypt, available_key, algorithm, this->iv_, this->padding_->get_padding());
			};
	}
	else
	{
		return [this](PauseableChannel& pchannel, std::istream& plain, uint64_t max, std::ostream& crypt, const Data& available_key, const algorithm::Algorithm& algorithm)->void
			{
				return encryptp_stream(pchannel, plain, max, crypt, available_key, algorithm, this->iv_, this->shift_, this->padding_->get_padding());
			};
	}
}
NSROOT::mode::streamp_crypt_func NSROOT::mode::CFBb::get_streamp_decrypt() const
{
	if (this->shift_ % 8 == 0)
	{
		if (this->shift_ / 8 == 1)
		{
			return [this](PauseableChannel& pchannel, std::istream& crypt, uint64_t max, std::ostream& plain, const Data& available_key, const algorithm::Algorithm& algorithm)->void
				{
					return CFBB::decryptp_CFB8_stream(pchannel, crypt, max, plain, available_key, algorithm, this->iv_, this->padding_->get_unpadding());
				};
		}
		else if (this->shift_ / 8 == 16)
		{
			return [this](PauseableChannel& pchannel, std::istream& crypt, uint64_t max, std::ostream& plain, const Data& available_key, const algorithm::Algorithm& algorithm)->void
				{
					return CFBB::decryptp_CFB128_stream(pchannel, crypt, max, plain, available_key, algorithm, this->iv_, this->padding_->get_unpadding());
				};
		}
		else
		{
			return [this](PauseableChannel& pchannel, std::istream& crypt, uint64_t max, std::ostream& plain, const Data& available_key, const algorithm::Algorithm& algorithm)->void
				{
					return CFBB::decryptp_stream(pchannel, crypt, max, plain, available_key, algorithm, this->iv_, this->shift_ / 8, this->padding_->get_unpadding());
				};
		}
	}
	else if (this->shift_ == 1)
	{
		return [this](PauseableChannel& pchannel, std::istream& crypt, uint64_t max, std::ostream& plain, const Data& available_key, const algorithm::Algorithm& algorithm)->void
			{
				return decryptp_CFB1_stream(pchannel, crypt, max, plain, available_key, algorithm, this->iv_, this->padding_->get_unpadding());
			};
	}
	else
	{
		return [this](PauseableChannel& pchannel, std::istream& crypt, uint64_t max, std::ostream& plain, const Data& available_key, const algorithm::Algorithm& algorithm)->void
			{
				return CFBb::decryptp_stream(pchannel, crypt, max, plain, available_key, algorithm, this->iv_, this->shift_, this->padding_->get_unpadding());
			};
	}
}

#undef NSROOT
#undef DOG_DATA
#undef CFB_ENCRYPT_PARAM_INIT
#undef CFB_DECRYPT_PARAM_INIT
#undef CFB_ENCRYPT_INIT
#undef CFB_DECRYPT_INIT
#undef DOG_ERROR_SHIFT_ZERO