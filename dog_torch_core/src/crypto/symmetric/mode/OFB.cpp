#include "crypto/symmetric/mode/OFB.h"

#define NSROOT dog_torch::crypto::symmetric //NSROOT = namespace root
#define DOG_DATA dog_torch::serialize::BinaryData

NSROOT::mode::Config NSROOT::mode::OFB::get_config()
{
	return {
	"OFB",
	std::unordered_map<std::string, std::string>({
		{"padding","Padding"},
		{"iv","BinaryData"}
	})
	};
}

#define OFB_ENCRYPT_INIT \
uint64_t block_size = algorithm.get_block_size(); \
uint64_t key_size = algorithm.get_key_size(); \
const Data& key = available_key; \
algorithm::block_self_cryption_func block_self_encryption = algorithm.get_encrypt_self();\
Data temp_block0 = iv;\
using dog_torch::serialize::stream::utils::read_bytes_size;

#define OFB_DECRYPT_INIT \
uint64_t block_size = algorithm.get_block_size(); \
uint64_t key_size = algorithm.get_key_size(); \
const Data& key = available_key; \
algorithm::block_self_cryption_func block_self_encryption = algorithm.get_encrypt_self();\
Data temp_block0 = iv;\
using dog_torch::serialize::stream::utils::read_bytes_size;

DOG_DATA NSROOT::mode::OFB::encrypt(const Data& plain, const Data& available_key, const algorithm::Algorithm& algorithm, const Data& iv, padding::padding_func padding)
{
	OFB_ENCRYPT_INIT;

	Data crypt; crypt.reserve(((plain.size() / block_size) + 1) * block_size);
	Data temp_block1;
	uint64_t i = 0;
	for (; block_size <= plain.size() - i; i += block_size)
	{
		block_self_encryption(temp_block0, block_size, key, key_size);
		temp_block1 = plain.sub_bytes_by_len(i, block_size);
		dog_torch::serialize::BinaryData::XOR_self(temp_block1, temp_block0, block_size);
		crypt += temp_block1;
	}
	block_self_encryption(temp_block0, block_size, key, key_size);
	temp_block1 = plain.sub_bytes_by_len(i, block_size);
	padding(temp_block1, block_size);
	dog_torch::serialize::BinaryData::XOR_self(temp_block1, temp_block0, temp_block1.size());
	crypt += temp_block1;
	return crypt;
}
DOG_DATA NSROOT::mode::OFB::decrypt(const Data& crypt, const Data& available_key, const algorithm::Algorithm& algorithm, const Data& iv, padding::padding_func unpadding)
{
	OFB_DECRYPT_INIT;

	Data plain; plain.reserve(((plain.size() / block_size) + 1) * block_size);
	Data temp_block1;
	uint64_t i = 0;
	for (; block_size < crypt.size() - i; i += block_size)
	{
		block_self_encryption(temp_block0, block_size, key, key_size);
		temp_block1 = crypt.sub_bytes_by_len(i, block_size);
		dog_torch::serialize::BinaryData::XOR_self(temp_block1, temp_block0, block_size);
		plain += temp_block1;
	}
	block_self_encryption(temp_block0, block_size, key, key_size);
	temp_block1 = crypt.sub_bytes_by_len(i, block_size);
	dog_torch::serialize::BinaryData::XOR_self(temp_block1, temp_block0, temp_block1.size());
	unpadding(temp_block1, block_size);
	plain += temp_block1;
	return plain;
}
void NSROOT::mode::OFB::encrypt_stream(std::istream& plain, uint64_t max, std::ostream& crypt, const Data& available_key, const algorithm::Algorithm& algorithm, const Data& iv, padding::padding_func padding)
{
	OFB_ENCRYPT_INIT;

	Data temp_block1(block_size);
	uint64_t total = 0;
	while (max - total >= block_size && read_bytes_size(plain, temp_block1, block_size, total) == block_size)
	{
		block_self_encryption(temp_block0, block_size, key, key_size);
		dog_torch::serialize::BinaryData::XOR_self(temp_block1, temp_block0, block_size);
		crypt.write((char*)temp_block1.data(), block_size);
	}
	read_bytes_size(plain, temp_block1, block_size, total);
	block_self_encryption(temp_block0, block_size, key, key_size);
	padding(temp_block1, block_size);
	dog_torch::serialize::BinaryData::XOR_self(temp_block1, temp_block0, temp_block1.size());
	crypt.write((char*)temp_block1.data(), temp_block1.size());
	crypt.flush();
}
void NSROOT::mode::OFB::decrypt_stream(std::istream& crypt, uint64_t max, std::ostream& plain, const Data& available_key, const algorithm::Algorithm& algorithm, const Data& iv, padding::padding_func unpadding)
{
	OFB_DECRYPT_INIT;
	Data temp_block1(block_size);
    uint64_t total = 0;
	while (max - total > block_size && read_bytes_size(crypt, temp_block1, block_size, total) == block_size)
	{
		block_self_encryption(temp_block0, block_size, key, key_size);
		dog_torch::serialize::BinaryData::XOR_self(temp_block1, temp_block0, block_size);
		plain.write((char*)temp_block1.data(), block_size);
	}
	read_bytes_size(crypt, temp_block1, block_size, total);
	block_self_encryption(temp_block0, block_size, key, key_size);
	dog_torch::serialize::BinaryData::XOR_self(temp_block1, temp_block0, temp_block1.size());
	unpadding(temp_block1, block_size);
	plain.write((char*)temp_block1.data(), temp_block1.size());
	plain.flush();
}

void NSROOT::mode::OFB::encryptp_stream(PauseableChannel& pchannel, std::istream& plain, uint64_t max, std::ostream& crypt, const Data& available_key, const algorithm::Algorithm& algorithm, const Data& iv, padding::padding_func padding)
{
	OFB_ENCRYPT_INIT;

	pchannel.start();

	Data temp_block1(block_size);
    uint64_t total = 0;
	while (max - total >= block_size && read_bytes_size(plain, temp_block1, block_size, total) == block_size)
	{
		block_self_encryption(temp_block0, block_size, key, key_size);
		dog_torch::serialize::BinaryData::XOR_self(temp_block1, temp_block0, block_size);
		crypt.write((char*)temp_block1.data(), block_size);

		pchannel.add_progress(block_size * 1.0 / max);
		if (pchannel.should_pause()) break;;
	}
	read_bytes_size(plain, temp_block1, block_size, total);
	block_self_encryption(temp_block0, block_size, key, key_size);
	padding(temp_block1, block_size);
	dog_torch::serialize::BinaryData::XOR_self(temp_block1, temp_block0, temp_block1.size());
	crypt.write((char*)temp_block1.data(), temp_block1.size());
	crypt.flush();

	pchannel.complete();
}

void NSROOT::mode::OFB::decryptp_stream(PauseableChannel& pchannel, std::istream& crypt, uint64_t max, std::ostream& plain, const Data& available_key, const algorithm::Algorithm& algorithm, const Data& iv, padding::padding_func unpadding)
{
	OFB_DECRYPT_INIT;

	pchannel.start();

	Data temp_block1(block_size);
    uint64_t total = 0;
	while (max - total > block_size && read_bytes_size(crypt, temp_block1, block_size, total) == block_size)
	{
		block_self_encryption(temp_block0, block_size, key, key_size);
		dog_torch::serialize::BinaryData::XOR_self(temp_block1, temp_block0, block_size);
		plain.write((char*)temp_block1.data(), block_size);

		pchannel.add_progress(block_size * 1.0 / max);
		if (pchannel.should_pause()) break;;
	}
	read_bytes_size(crypt, temp_block1, block_size, total);
	block_self_encryption(temp_block0, block_size, key, key_size);
	dog_torch::serialize::BinaryData::XOR_self(temp_block1, temp_block0, temp_block1.size());
	unpadding(temp_block1, block_size);
	plain.write((char*)temp_block1.data(), temp_block1.size());
	plain.flush();

	pchannel.complete();
}

NSROOT::mode::OFB::OFB(const padding::Padding& padding, const Data& iv) : Mode("OFB")
{
	this->padding_ = padding.clone();
	this->iv_ = iv;
}
NSROOT::mode::OFB::OFB(const OFB& other) : Mode("OFB")
{
	this->padding_ = other.padding_->clone();
	this->iv_ = other.iv_;
}

const DOG_DATA& dog_torch::crypto::symmetric::mode::OFB::get_iv() const
{
	return iv_;
}
const NSROOT::padding::Padding& dog_torch::crypto::symmetric::mode::OFB::get_padding() const
{
	return *padding_;
}

bool NSROOT::mode::OFB::check(const algorithm::Algorithm& algorithm) const
{
	return algorithm.get_block_size() == this->iv_.size();
}

std::unique_ptr<NSROOT::mode::Mode> NSROOT::mode::OFB::clone() const
{
	return std::move(std::make_unique<OFB>(*this));
}

bool NSROOT::mode::OFB::set_data_param(const std::string& param, const Data& value)
{
	if (param == "iv")
	{
		this->iv_ = value;
		return true;
	}
	return false;
}

bool NSROOT::mode::OFB::set_Padding(const padding::Padding& value)
{
	this->padding_ = value.clone();
	return true;
}

NSROOT::mode::crypt_func NSROOT::mode::OFB::get_mult_encrypt() const
{
	return [this](const Data& plain, const Data& available_key, const algorithm::Algorithm& algorithm) -> Data
		{
			return encrypt(plain, available_key, algorithm, this->iv_, this->padding_->get_padding());
		};
}
NSROOT::mode::crypt_func NSROOT::mode::OFB::get_mult_decrypt() const
{
	return [this](const Data& crypt, const Data& available_key, const algorithm::Algorithm& algorithm) -> Data
		{
			return decrypt(crypt, available_key, algorithm, this->iv_, this->padding_->get_unpadding());
		};
}
NSROOT::mode::stream_crypt_func NSROOT::mode::OFB::get_stream_encrypt() const
{
	return [this](std::istream& plain, uint64_t max, std::ostream& crypt, const Data& available_key, const algorithm::Algorithm& algorithm) -> void
		{
			return encrypt_stream(plain, max, crypt, available_key, algorithm, this->iv_, this->padding_->get_padding());
		};
}
NSROOT::mode::stream_crypt_func NSROOT::mode::OFB::get_stream_decrypt() const
{
	return [this](std::istream& crypt, uint64_t max, std::ostream& plain, const Data& available_key, const algorithm::Algorithm& algorithm) -> void
		{
			return decrypt_stream(crypt, max, plain, available_key, algorithm, this->iv_, this->padding_->get_unpadding());
		};
}

NSROOT::mode::streamp_crypt_func NSROOT::mode::OFB::get_streamp_encrypt() const
{
	return [this](PauseableChannel& pchannel, std::istream& plain, uint64_t max, std::ostream& crypt, const Data& available_key, const algorithm::Algorithm& algorithm) -> void
		{
			return encryptp_stream(pchannel, plain, max, crypt, available_key, algorithm, this->iv_, this->padding_->get_padding());
		};
}
NSROOT::mode::streamp_crypt_func NSROOT::mode::OFB::get_streamp_decrypt() const
{
	return [this](PauseableChannel& pchannel, std::istream& crypt, uint64_t max, std::ostream& plain, const Data& available_key, const algorithm::Algorithm& algorithm) -> void
		{
			return decryptp_stream(pchannel, crypt, max, plain, available_key, algorithm, this->iv_, this->padding_->get_unpadding());
		};
}

#undef NSROOT
#undef DOG_DATA
#undef OFB_ENCRYPT_INIT
#undef OFB_DECRYPT_INIT