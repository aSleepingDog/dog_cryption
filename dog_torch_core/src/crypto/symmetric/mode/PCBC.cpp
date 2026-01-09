#include "crypto/symmetric/mode/PCBC.h"

#define NSROOT dog_torch::crypto::symmetric //NSROOT = namespace root
#define DOG_DATA dog_torch::serialize::BinaryData

DOG_DATA NSROOT::mode::PCBC::encrypt(const Data& plain, const Cipher& cipher)
{
	const PCBC& pcbc = (const PCBC&)cipher.get_mode();
	padding::padding_func padding = pcbc.get_padding().get_padding();
	uint64_t block_size = cipher.get_block_size();
	const Data& key = cipher.get_available_key();
	uint64_t key_size = cipher.get_key_size();
	algorithm::block_self_cryption_func block_self_cryption = cipher.get_block_self_encryption();
	Data tempBlock1 = pcbc.get_iv();

	Data res; res.reserve(((plain.size() / block_size) + 1) * block_size);
	Data tempBlock0, tempBlock2;
	for (uint64_t i0 = 0; i0 <= plain.size(); i0 += block_size)
	{
		tempBlock0 = plain.sub_by_len(i0, block_size);
		padding(tempBlock0, block_size);
		tempBlock2 = dog_torch::serialize::BinaryData::XOR(tempBlock1, tempBlock0, tempBlock0.size());
		cipher.get_block_self_encryption()(tempBlock2, block_size, cipher.get_available_key(), cipher.get_key_size());
		res += tempBlock2;
		tempBlock1 = dog_torch::serialize::BinaryData::XOR(tempBlock2, tempBlock0, tempBlock0.size());
	}
	return res;
}
DOG_DATA NSROOT::mode::PCBC::decrypt(const Data& crypt, const Cipher& cipher)
{
	const PCBC& pcbc = (const PCBC&)cipher.get_mode();
	padding::padding_func unpadding = pcbc.get_padding().get_unpadding();
	uint64_t block_size = cipher.get_block_size();
	const Data& key = cipher.get_available_key();
	uint64_t key_size = cipher.get_key_size();
	algorithm::block_cryption_func block_cryption = cipher.get_block_decryption();
	Data tempBlock1 = pcbc.get_iv();

	Data res; res.reserve(((crypt.size() / block_size) + 1) * block_size);
	Data tempBlock0, tempBlock2;
	for (uint64_t i0 = 0; i0 < crypt.size(); i0 += block_size)
	{
		tempBlock0 = crypt.sub_by_len(i0, block_size);
		tempBlock2 = block_cryption(tempBlock0, block_size, key, key_size);
		dog_torch::serialize::BinaryData::XOR_self(tempBlock2, tempBlock1, tempBlock1.size());
		res += tempBlock2;
		tempBlock1 = dog_torch::serialize::BinaryData::XOR(tempBlock2, tempBlock0, tempBlock0.size());
	}
	unpadding(res, block_size);
	return res;
}
void NSROOT::mode::PCBC::encrypt_stream(std::istream& plain, std::ostream& crypt, const Cipher& cipher)
{
	plain.seekg(0, std::ios::end);
	uint64_t file_size = plain.tellg();
	plain.seekg(0, std::ios::beg);

	const PCBC& pcbc = (const PCBC&)cipher.get_mode();
	padding::padding_func padding = pcbc.get_padding().get_padding();
	uint64_t block_size = cipher.get_block_size();
	const Data& key = cipher.get_available_key();
	uint64_t key_size = cipher.get_key_size();
	algorithm::block_self_cryption_func block_self_cryption = cipher.get_block_self_encryption();
	Data tempBlock1 = pcbc.get_iv();

	dog_torch::serialize::BinaryData tempBlock0(block_size), tempBlock2(block_size);
	while (plain.tellg() <= file_size - block_size)
	{
		plain.read((char*)tempBlock0.data(), block_size);
		tempBlock2 = dog_torch::serialize::BinaryData::XOR(tempBlock1, tempBlock0, tempBlock0.size());
		block_self_cryption(tempBlock2, block_size, key, key_size);
		crypt.write((char*)tempBlock2.data(), block_size);
		tempBlock1 = dog_torch::serialize::BinaryData::XOR(tempBlock2, tempBlock0, tempBlock0.size());
	}
	plain.read((char*)tempBlock0.data(), block_size);
	if (plain.gcount() < block_size)
	{
		for (uint64_t i = 0; i < block_size - plain.gcount(); ++i) { tempBlock0.pop_back(); }
	}
	padding(tempBlock0, block_size);
	tempBlock2 = dog_torch::serialize::BinaryData::XOR(tempBlock1, tempBlock0, tempBlock0.size());
	cipher.get_block_self_encryption()(tempBlock2, block_size, cipher.get_available_key(), cipher.get_key_size());
	crypt.write((char*)tempBlock2.data(), block_size);
	tempBlock1 = dog_torch::serialize::BinaryData::XOR(tempBlock2, tempBlock0, tempBlock0.size());
}
void NSROOT::mode::PCBC::decrypt_stream(std::istream& crypt, std::ostream& plain, const Cipher& cipher)
{
	uint64_t now_pos = crypt.tellg();
	crypt.seekg(0, std::ios::end);
	uint64_t file_size = crypt.tellg();
	crypt.seekg(now_pos);

	const PCBC& pcbc = (const PCBC&)cipher.get_mode();
	padding::padding_func unpadding = pcbc.get_padding().get_unpadding();
	uint64_t block_size = cipher.get_block_size();
	const Data& key = cipher.get_available_key();
	uint64_t key_size = cipher.get_key_size();
	algorithm::block_cryption_func block_cryption = cipher.get_block_decryption();
	Data tempBlock1 = pcbc.get_iv();

	Data tempBlock0(block_size), tempBlock2;
	for (uint64_t i = 0; i < (file_size - now_pos - 1) / block_size; ++i)
	{
		crypt.read((char*)tempBlock0.data(), block_size);
		tempBlock2 = block_cryption(tempBlock0, block_size, key, key_size);
		dog_torch::serialize::BinaryData::XOR_self(tempBlock2, tempBlock1, tempBlock1.size());
		plain.write((char*)tempBlock2.data(), block_size);
		tempBlock1 = dog_torch::serialize::BinaryData::XOR(tempBlock2, tempBlock0, tempBlock0.size());
	}
	crypt.read((char*)tempBlock0.data(), block_size);
	tempBlock2 = block_cryption(tempBlock0, block_size, key, key_size);
	dog_torch::serialize::BinaryData::XOR_self(tempBlock2, tempBlock1, tempBlock1.size());
	unpadding(tempBlock2, block_size);
	plain.write((char*)tempBlock2.data(), tempBlock2.size());
	plain.flush();
}
void NSROOT::mode::PCBC::encrypt_streamp(std::istream& plain, std::ostream& crypt, const Cipher& cipher,
	std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress_, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_)

{
	plain.seekg(0, std::ios::end);
	uint64_t file_size = plain.tellg();
	plain.seekg(0, std::ios::beg);

	const PCBC& pcbc = (const PCBC&)cipher.get_mode();
	padding::padding_func padding = pcbc.get_padding().get_padding();
	uint64_t block_size = cipher.get_block_size();
	const Data& key = cipher.get_available_key();
	uint64_t key_size = cipher.get_key_size();
	algorithm::block_cryption_func block_cryption = cipher.get_block_encryption();
	Data tempBlock1 = pcbc.get_iv();

	Data tempBlock0(block_size), tempBlock2(block_size);
	while (plain.tellg() <= file_size - block_size)
	{
		plain.read((char*)tempBlock0.data(), block_size);
		tempBlock2 = dog_torch::serialize::BinaryData::XOR(tempBlock1, tempBlock0, tempBlock0.size());
		block_cryption(tempBlock2, block_size, key, key_size);
		crypt.write((char*)tempBlock2.data(), block_size);
		std::unique_lock<std::mutex> lock(*mutex_);
		while (*paused_ && !*stop_) { cond_->wait(lock); }
		if (*stop_) return;
		lock.unlock();
		progress_->store(NSROOT::mode::update_progress(progress_->load(), block_size, file_size));
		tempBlock1 = dog_torch::serialize::BinaryData::XOR(tempBlock2, tempBlock0, tempBlock0.size());
	}
	plain.read((char*)tempBlock0.data(), block_size);
	if (plain.gcount() < block_size)
	{
		for (uint64_t i = 0; i < block_size - plain.gcount(); ++i) { tempBlock0.pop_back(); }
	}
	padding(tempBlock0, block_size);
	tempBlock2 = dog_torch::serialize::BinaryData::XOR(tempBlock1, tempBlock0, tempBlock0.size());
	block_cryption(tempBlock2, block_size, key, key_size);
	crypt.write((char*)tempBlock2.data(), block_size);
	tempBlock1 = dog_torch::serialize::BinaryData::XOR(tempBlock2, tempBlock0, tempBlock0.size());
	progress_->store(1.0);
}
void NSROOT::mode::PCBC::decrypt_streamp(std::istream& crypt, std::ostream& plain, const Cipher& cipher,
	std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress_, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_)
{
	uint64_t now_pos = crypt.tellg();
	crypt.seekg(0, std::ios::end);
	uint64_t file_size = crypt.tellg();
	crypt.seekg(now_pos);

	const PCBC& pcbc = (const PCBC&)cipher.get_mode();
	padding::padding_func unpadding = pcbc.get_padding().get_unpadding();
	uint64_t block_size = cipher.get_block_size();
	const Data& key = cipher.get_available_key();
	uint64_t key_size = cipher.get_key_size();
	algorithm::block_cryption_func block_cryption = cipher.get_block_decryption();
	Data tempBlock1 = pcbc.get_iv();

	dog_torch::serialize::BinaryData tempBlock0(block_size), tempBlock2;
	for (uint64_t i = 0; i < (file_size - now_pos - 1) / block_size; ++i)
	{
		crypt.read((char*)tempBlock0.data(), block_size);
		tempBlock2 = block_cryption(tempBlock0, block_size, key, key_size);
		dog_torch::serialize::BinaryData::XOR_self(tempBlock2, tempBlock1, tempBlock1.size());
		plain.write((char*)tempBlock2.data(), block_size);
		std::unique_lock<std::mutex> lock(*mutex_);
		while (*paused_ && !*stop_) { cond_->wait(lock); }
		if (*stop_) return;
		lock.unlock();
		progress_->store(update_progress(progress_->load(), block_size, file_size));
		tempBlock1 = dog_torch::serialize::BinaryData::XOR(tempBlock2, tempBlock0, tempBlock0.size());
	}
	crypt.read((char*)tempBlock0.data(), block_size);
	tempBlock2 = block_cryption(tempBlock0, block_size, key, key_size);
	dog_torch::serialize::BinaryData::XOR_self(tempBlock2, tempBlock1, tempBlock1.size());
	unpadding(tempBlock2, block_size);
	plain.write((char*)tempBlock2.data(), tempBlock2.size());
	plain.flush();
	progress_->store(1.0);
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
	return encrypt;
}
NSROOT::mode::crypt_func NSROOT::mode::PCBC::get_mult_decrypt() const
{
	return decrypt;
}
NSROOT::mode::stream_crypt_func NSROOT::mode::PCBC::get_stream_encrypt() const
{
	return encrypt_stream;
}
NSROOT::mode::stream_crypt_func NSROOT::mode::PCBC::get_stream_decrypt() const
{
	return decrypt_stream;
}
NSROOT::mode::stream_cryptp_func NSROOT::mode::PCBC::get_stream_encryptp() const
{
	return encrypt_streamp;
}
NSROOT::mode::stream_cryptp_func NSROOT::mode::PCBC::get_stream_decryptp() const
{
	return decrypt_streamp;
}


#undef NSROOT
#undef DOG_DATA