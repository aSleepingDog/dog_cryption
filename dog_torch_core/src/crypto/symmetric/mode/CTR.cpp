#include "crypto/symmetric/mode/CTR.h"

#define NSROOT dog_torch::crypto::symmetric //NSROOT = namespace root
#define DOG_DATA dog_torch::serialize::BinaryData

NSROOT::mode::Config NSROOT::mode::CTR::get_config()
{
	return {
	"CTR",
	std::unordered_map<std::string, std::string>({
		{"padding","Padding"},
		{"iv","BinaryData"}
	})
	};
}

#define CTR_ENCRYPT_INIT \
uint64_t block_size = algorithm.get_block_size(); \
uint64_t key_size = algorithm.get_key_size(); \
const Data& key = available_key; \
algorithm::block_self_cryption_func block_self_encryption = algorithm.get_encrypt_self();\
Data temp_block0 = iv;\
auto update = [&temp_block0]() { update_counter(temp_block0, 1); }; \
using dog_torch::serialize::stream::utils::read_bytes_size;

#define CTR_DECRYPT_INIT \
uint64_t block_size = algorithm.get_block_size(); \
uint64_t key_size = algorithm.get_key_size(); \
const Data& key = available_key; \
algorithm::block_self_cryption_func block_self_encryption = algorithm.get_encrypt_self();\
Data temp_block0 = iv;\
auto update = [&temp_block0]() { update_counter(temp_block0, 1); }; \
using dog_torch::serialize::stream::utils::read_bytes_size;

void NSROOT::mode::CTR::update_counter(Data& counter, uint64_t value)
{
	uint64_t size = counter.size();
	if (size <= 2)
	{
		uint8_t counter_num = counter[size / 2];
		counter_num += value;
		counter[size / 2] = counter_num;
	}
	else if (size <= 4)
	{
		uint16_t counter_num = counter[size / 2];
		counter_num |= counter[size / 2 + 1];
		counter_num += value;
		counter[size / 2] = counter_num >> 8;
		counter[size / 2 + 1] = counter_num & 0xFF;
	}
	else if (size <= 8)
	{
		uint32_t counter_num = counter[size / 2];
		counter_num |= counter[size / 2 + 1];
		counter_num |= counter[size / 2 + 2];
		counter_num |= counter[size / 2 + 3];
		counter_num += value;
		counter[size / 2] = counter_num >> 24;
		counter[size / 2 + 1] = (counter_num >> 16) & 0xFF;
		counter[size / 2 + 2] = (counter_num >> 8) & 0xFF;
		counter[size / 2 + 3] = counter_num & 0xFF;
	}
	else
	{
		uint64_t counter_num = counter[size / 2];
		counter_num |= counter[size / 2 + 1];
		counter_num |= counter[size / 2 + 2];
		counter_num |= counter[size / 2 + 3];
		counter_num |= counter[size / 2 + 4];
		counter_num |= counter[size / 2 + 5];
		counter_num |= counter[size / 2 + 6];
		counter_num |= counter[size / 2 + 7];
		counter_num += value;
		counter[size / 2] = counter_num >> 56;
		counter[size / 2 + 1] = (counter_num >> 48) & 0xFF;
		counter[size / 2 + 2] = (counter_num >> 40) & 0xFF;
		counter[size / 2 + 3] = (counter_num >> 32) & 0xFF;
		counter[size / 2 + 4] = (counter_num >> 24) & 0xFF;
		counter[size / 2 + 5] = (counter_num >> 16) & 0xFF;
		counter[size / 2 + 6] = (counter_num >> 8) & 0xFF;
		counter[size / 2 + 7] = counter_num & 0xFF;
	}

	//using namespace dog_torch::math::number;
	//uint64_t size = counter.size();
	//BigInteger counter_num = BigInteger::from_vector(counter.sub_bytes_by_pos(size / 2, size).to_byte_vector());
	//counter = counter.sub_bytes_by_len(0, size / 2);
	//counter_num += value;
	//Data temp = counter_num.to_byte_vector();
	//if (temp.size() > size / 2)
	//{
	//	temp = temp.sub_bytes_by_len(1, size / 2);
	//}
	//counter += temp;
}

DOG_DATA NSROOT::mode::CTR::encrypt(const Data& plain, const Data& available_key, const algorithm::Algorithm& algorithm, const Data& iv, padding::padding_func padding)
{
	CTR_ENCRYPT_INIT;

	Data crypt; crypt.reserve(((plain.size() / block_size) + 1) * block_size);
	Data temp_block1;
	uint64_t i = 0;
	for (; block_size <= plain.size() - i; i += block_size)
	{
		block_self_encryption(temp_block0, block_size, key, key_size);
		temp_block1 = plain.sub_bytes_by_pos(i, i + block_size);
		dog_torch::serialize::BinaryData::XOR_self(temp_block1, temp_block0, block_size);
		crypt += temp_block1;
		update();
	}
	block_self_encryption(temp_block0, block_size, key, key_size);
	temp_block1 = plain.sub_bytes_by_pos(i, i + block_size);
	padding(temp_block1, block_size);
	dog_torch::serialize::BinaryData::XOR_self(temp_block1, temp_block0, temp_block1.size());
	crypt += temp_block1;
	return crypt;
}
DOG_DATA NSROOT::mode::CTR::decrypt(const Data& crypt, const Data& available_key, const algorithm::Algorithm& algorithm, const Data& iv, padding::padding_func unpadding)
{
	CTR_DECRYPT_INIT;

	Data temp_block1, plain; plain.reserve(((crypt.size() / block_size) + 1) * block_size);
	uint64_t i = 0;
	for (; block_size < crypt.size() - i; i += block_size)
	{
		block_self_encryption(temp_block0, block_size, key, key_size);
		temp_block1 = crypt.sub_bytes_by_pos(i, i + block_size);
		dog_torch::serialize::BinaryData::XOR_self(temp_block1, temp_block0, block_size);
		plain += temp_block1;
		update();
	}
	block_self_encryption(temp_block0, block_size, key, key_size);
	temp_block1 = crypt.sub_bytes_by_pos(i, i + block_size);
	dog_torch::serialize::BinaryData::XOR_self(temp_block1, temp_block0, temp_block1.size());
	unpadding(temp_block1, block_size);
	plain += temp_block1;
	return plain;
}
void NSROOT::mode::CTR::encrypt_stream(std::istream& plain, uint64_t max, std::ostream& crypt, const Data& available_key, const algorithm::Algorithm& algorithm, const Data& iv, padding::padding_func padding)
{
	CTR_ENCRYPT_INIT;

	Data temp_block1(block_size);
	uint64_t total = 0;
	while (max - total >= block_size && read_bytes_size(plain, temp_block1, block_size, total) == block_size)
	{
		block_self_encryption(temp_block0, block_size, key, key_size);
		dog_torch::serialize::BinaryData::XOR_self(temp_block1, temp_block0, block_size);
		crypt.write((char*)temp_block1.data(), block_size);
		update();
	}
	read_bytes_size(plain, temp_block1, block_size, total);
	padding(temp_block1, block_size);
	block_self_encryption(temp_block0, block_size, key, key_size);
	dog_torch::serialize::BinaryData::XOR_self(temp_block1, temp_block0, temp_block1.size());
	crypt.write((char*)temp_block1.data(), temp_block1.size());
	crypt.flush();
}
void NSROOT::mode::CTR::decrypt_stream(std::istream& crypt, uint64_t max, std::ostream& plain, const Data& available_key, const algorithm::Algorithm& algorithm, const Data& iv, padding::padding_func unpadding)
{
	CTR_DECRYPT_INIT;

	Data temp_block1(block_size);
	uint64_t total = 0;
	while (max - total > block_size && read_bytes_size(crypt, temp_block1, block_size, total) == block_size)
	{
		block_self_encryption(temp_block0, block_size, key, key_size);
		dog_torch::serialize::BinaryData::XOR_self(temp_block1, temp_block0, block_size);
		plain.write((char*)temp_block1.data(), block_size);
		update();
	}
	read_bytes_size(crypt, temp_block1, block_size, total);
	block_self_encryption(temp_block0, block_size, key, key_size);
	dog_torch::serialize::BinaryData::XOR_self(temp_block1, temp_block0, temp_block1.size());
	unpadding(temp_block1, block_size);
	plain.write((char*)temp_block1.data(), temp_block1.size());
	plain.flush();
}

void NSROOT::mode::CTR::encryptp_stream(PauseableChannel& pchannel, std::istream& plain, uint64_t max, std::ostream& crypt, const Data& available_key, const algorithm::Algorithm& algorithm, const Data& iv, padding::padding_func padding)
{
	CTR_ENCRYPT_INIT;

	pchannel.start();

	Data temp_block1(block_size);
	uint64_t total = 0;
	while (max - total >= block_size && read_bytes_size(plain, temp_block1, block_size, total) == block_size)
	{
		block_self_encryption(temp_block0, block_size, key, key_size);
		dog_torch::serialize::BinaryData::XOR_self(temp_block1, temp_block0, block_size);
		crypt.write((char*)temp_block1.data(), block_size);
		update();

		pchannel.add_progress(block_size * 1.0 / max);
		if (pchannel.should_pause()) break;;
	}
	read_bytes_size(plain, temp_block1, block_size, total);
	padding(temp_block1, block_size);
	block_self_encryption(temp_block0, block_size, key, key_size);
	dog_torch::serialize::BinaryData::XOR_self(temp_block1, temp_block0, temp_block1.size());
	crypt.write((char*)temp_block1.data(), temp_block1.size());
	crypt.flush();

	pchannel.complete();
}

void NSROOT::mode::CTR::decryptp_stream(PauseableChannel& pchannel, std::istream& crypt, uint64_t max, std::ostream& plain, const Data& available_key, const algorithm::Algorithm& algorithm, const Data& iv, padding::padding_func unpadding)
{
	CTR_DECRYPT_INIT;

	pchannel.start();

	Data temp_block1(block_size);
	uint64_t total = 0;
	while (max - total > block_size && read_bytes_size(crypt, temp_block1, block_size, total) == block_size)
	{
		block_self_encryption(temp_block0, block_size, key, key_size);
		dog_torch::serialize::BinaryData::XOR_self(temp_block1, temp_block0, block_size);
		plain.write((char*)temp_block1.data(), block_size);
		update();

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

NSROOT::mode::CTR::CTR(const padding::Padding& padding, const Data& iv) : Mode("CTR")
{
	this->padding_ = padding.clone();
	this->iv_ = iv;
}
NSROOT::mode::CTR::CTR(const CTR& other) : Mode("CTR")
{
	this->padding_ = other.padding_->clone();
	this->iv_ = other.iv_;
}

std::unique_ptr<NSROOT::mode::Mode> NSROOT::mode::CTR::clone() const
{
	return std::move(std::make_unique<CTR>(*this));
}

bool NSROOT::mode::CTR::check(const algorithm::Algorithm& algorithm) const
{
	return algorithm.get_block_size() == this->iv_.size();
}

const DOG_DATA& NSROOT::mode::CTR::get_iv() const
{
	return iv_;
}
const NSROOT::padding::Padding& NSROOT::mode::CTR::get_padding() const
{
	return *padding_;
}

bool NSROOT::mode::CTR::set_data_param(const std::string& param, const Data& value)
{
	if (param == "iv")
	{
		this->iv_ = value;
		return true;
	}
	return false;
}
bool NSROOT::mode::CTR::set_Padding(const padding::Padding& value)
{
	this->padding_ = value.clone();
	return true;
}

NSROOT::mode::crypt_func NSROOT::mode::CTR::get_mult_encrypt() const
{
	return [this](const Data& plain, const Data& available_key, const algorithm::Algorithm& algorithm) -> Data
		{
			return encrypt(plain, available_key, algorithm, this->iv_, this->padding_->get_padding());
		};
}
NSROOT::mode::crypt_func NSROOT::mode::CTR::get_mult_decrypt() const
{
	return [this](const Data& crypt, const Data& available_key, const algorithm::Algorithm& algorithm) -> Data
		{
			return decrypt(crypt, available_key, algorithm, this->iv_, this->padding_->get_unpadding());
		};
}
NSROOT::mode::stream_crypt_func NSROOT::mode::CTR::get_stream_encrypt() const
{
	return [this](std::istream& plain, uint64_t max, std::ostream& crypt, const Data& available_key, const algorithm::Algorithm& algorithm) -> void
		{
			return encrypt_stream(plain, max, crypt, available_key, algorithm, this->iv_, this->padding_->get_padding());
		};
}
NSROOT::mode::stream_crypt_func NSROOT::mode::CTR::get_stream_decrypt() const
{
	return [this](std::istream& crypt, uint64_t max, std::ostream& plain, const Data& available_key, const algorithm::Algorithm& algorithm) -> void
		{
			return decrypt_stream(crypt, max, plain, available_key, algorithm, this->iv_, this->padding_->get_unpadding());
		};
}

NSROOT::mode::streamp_crypt_func NSROOT::mode::CTR::get_streamp_encrypt() const
{
	return [this](PauseableChannel& pchannel, std::istream& plain, uint64_t max, std::ostream& crypt, const Data& available_key, const algorithm::Algorithm& algorithm) -> void
		{
			return encryptp_stream(pchannel, plain, max, crypt, available_key, algorithm, this->iv_, this->padding_->get_padding());
		};
}
NSROOT::mode::streamp_crypt_func NSROOT::mode::CTR::get_streamp_decrypt() const
{
	return [this](PauseableChannel& pchannel, std::istream& crypt, uint64_t max, std::ostream& plain, const Data& available_key, const algorithm::Algorithm& algorithm) -> void
		{
			return decryptp_stream(pchannel, crypt, max, plain, available_key, algorithm, this->iv_, this->padding_->get_unpadding());
		};
}

#undef NSROOT
#undef DOG_DATA
#undef CTR_ENCRYPT_INIT
#undef CTR_DECRYPT_INIT