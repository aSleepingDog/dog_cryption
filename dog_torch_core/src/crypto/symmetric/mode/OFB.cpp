#include "crypto/symmetric/mode/OFB.h"

#define NSROOT dog_torch::crypto::symmetric //NSROOT = namespace root
#define DOG_DATA dog_torch::serialize::Data

DOG_DATA NSROOT::mode::OFB::encrypt(const Data& plain, const Cipher& cipher)
{
	uint64_t block_size = cipher.get_block_size();
	uint64_t key_size = cipher.get_key_size();
	const Data& key = cipher.get_available_key();
	algorithm::block_self_cryption_func block_self_encryption = cipher.get_block_self_encryption();
	Data tempBlock0 = ((const OFB&)cipher.get_mode()).get_iv();
	padding::padding_func padding = ((const OFB&)cipher.get_mode()).get_padding().get_padding();

	Data res; res.reserve(((plain.size() / block_size) + 1) * block_size);
	Data tempBlock1;
	for (uint64_t i0 = 0; i0 <= plain.size(); i0 += block_size)
	{
		cipher.get_block_self_encryption()(tempBlock0, block_size, cipher.get_available_key(), cipher.get_key_size());
		tempBlock1 = plain.sub_by_pos(i0, i0 + block_size);
		if (tempBlock1.size() <= block_size) { padding(tempBlock1, block_size); }
		res = res + NSROOT::utils::squareXOR(tempBlock1, tempBlock0, tempBlock1.size());
	}
	return res;
}
DOG_DATA NSROOT::mode::OFB::decrypt(const Data& crypt, const Cipher& cipher)
{
	uint64_t block_size = cipher.get_block_size();
	uint64_t key_size = cipher.get_key_size();
	const Data& key = cipher.get_available_key();
	algorithm::block_self_cryption_func block_self_encryption = cipher.get_block_self_encryption();
	Data tempBlock0 = ((const OFB&)cipher.get_mode()).get_iv();
	padding::padding_func unpadding = ((const OFB&)cipher.get_mode()).get_padding().get_unpadding();

	Data res; res.reserve(crypt.size());
	Data tempBlock1; tempBlock1.reserve(block_size);
	for (uint64_t i0 = 0; i0 < crypt.size(); i0 += block_size)
	{
		block_self_encryption(tempBlock0, block_size, key, key_size);
		tempBlock1 = crypt.sub_by_len(i0, block_size);
		res = res + NSROOT::utils::squareXOR(tempBlock1, tempBlock0, tempBlock1.size());
		tempBlock1.rm_pos();
	}
	unpadding(res, block_size);
	return res;
}
void NSROOT::mode::OFB::encrypt_stream(std::istream& plain, std::ostream& crypt, const Cipher& cipher)
{
	plain.seekg(0, std::ios::end);
	uint64_t file_size = plain.tellg();
	plain.seekg(0, std::ios::beg);

	uint64_t block_size = cipher.get_block_size();
	uint64_t key_size = cipher.get_key_size();
	const Data& key = cipher.get_available_key();
	algorithm::block_self_cryption_func block_self_encryption = cipher.get_block_self_encryption();
	Data tempBlock0 = ((const OFB&)cipher.get_mode()).get_iv();
	padding::padding_func padding = ((const OFB&)cipher.get_mode()).get_padding().get_padding();

	Data tempBlock1(block_size);
	while (plain.tellg() <= file_size - block_size)
	{
		block_self_encryption(tempBlock0, block_size, key, key_size);
		plain.read((char*)tempBlock1.data(), block_size);
		crypt.write((char*)NSROOT::utils::squareXOR(tempBlock0, tempBlock1, block_size).data(), block_size);
	}
	block_self_encryption(tempBlock0, block_size, key, key_size);
	plain.read((char*)tempBlock1.data(), block_size);
	for (uint64_t i = 0; i < block_size - plain.gcount(); ++i) { tempBlock1.pop_back(); }
	if (plain.gcount() < block_size)
	{
		padding(tempBlock1, block_size);
	}
	crypt.write((char*)NSROOT::utils::squareXOR(tempBlock1, tempBlock0, tempBlock1.size()).data(), tempBlock1.size());
	crypt.flush();
}
void NSROOT::mode::OFB::decrypt_stream(std::istream& crypt, std::ostream& plain, const Cipher& cipher)
{
	uint64_t now_pos = crypt.tellg();
	crypt.seekg(now_pos, std::ios::end);
	uint64_t file_size = crypt.tellg();
	crypt.seekg(now_pos);

	uint64_t block_size = cipher.get_block_size();
	uint64_t key_size = cipher.get_key_size();
	const Data& key = cipher.get_available_key();
	algorithm::block_self_cryption_func block_self_encryption = cipher.get_block_self_encryption();
	Data tempBlock0 = ((const OFB&)cipher.get_mode()).get_iv();
	padding::padding_func unpadding = ((const OFB&)cipher.get_mode()).get_padding().get_unpadding();

	Data tempBlock1(block_size);
	for (uint64_t i = 0; i < (file_size - now_pos - 1) / block_size; ++i)
	{
		block_self_encryption(tempBlock0, block_size, key, key_size);
		crypt.read((char*)tempBlock1.data(), block_size);
		plain.write((char*)NSROOT::utils::squareXOR(tempBlock0, tempBlock1, block_size).data(), block_size);
	}
	block_self_encryption(tempBlock0, block_size, key, key_size);
	crypt.read((char*)tempBlock1.data(), block_size);
	uint64_t s = crypt.gcount();
	for (uint64_t i = 0; i < block_size - crypt.gcount(); ++i) { tempBlock1.pop_back(); }
	NSROOT::utils::squareXOR_self(tempBlock1, tempBlock0, tempBlock1.size());
	unpadding(tempBlock1, block_size);
	plain.write((char*)tempBlock1.data(), tempBlock1.size());
	plain.flush();
}
void NSROOT::mode::OFB::encrypt_streamp(std::istream& plain, std::ostream& crypt, const Cipher& cipher,
	std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress_, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_)
{
	plain.seekg(0, std::ios::end);
	uint64_t file_size = plain.tellg();
	plain.seekg(0, std::ios::beg);
	
	uint64_t block_size = cipher.get_block_size();
	uint64_t key_size = cipher.get_key_size();
	const Data& key = cipher.get_available_key();
	algorithm::block_self_cryption_func block_self_encryption = cipher.get_block_self_encryption();
	Data tempBlock0 = ((const OFB&)cipher.get_mode()).get_iv();
	padding::padding_func padding = ((const OFB&)cipher.get_mode()).get_padding().get_padding();
	
	Data tempBlock1(block_size);
	while (plain.tellg() <= file_size - block_size)
	{
		block_self_encryption(tempBlock0, block_size, key, key_size);
		plain.read((char*)tempBlock1.data(), block_size);
		crypt.write((char*)NSROOT::utils::squareXOR(tempBlock0, tempBlock1, block_size).data(), block_size);
		std::unique_lock<std::mutex> lock(*mutex_);
		while (*paused_ && !*stop_) { cond_->wait(lock); }
		if (*stop_) return;
		lock.unlock();
		progress_->store(NSROOT::mode::update_progress(progress_->load(), block_size, file_size));
	}
	block_self_encryption(tempBlock0, block_size, key, key_size);
	plain.read((char*)tempBlock1.data(), block_size);
	for (uint64_t i = 0; i < block_size - plain.gcount(); ++i) { tempBlock1.pop_back(); }
	if (plain.gcount() < block_size)
	{
		padding(tempBlock1, block_size);
	}
	crypt.write((char*)NSROOT::utils::squareXOR(tempBlock1, tempBlock0, tempBlock1.size()).data(), tempBlock1.size());
	crypt.flush();
	progress_->store(1.0);
}
void NSROOT::mode::OFB::decrypt_streamp(std::istream& crypt, std::ostream& plain, const Cipher& cipher,
	std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress_, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_)
{
	uint64_t now_pos = crypt.tellg();
	crypt.seekg(now_pos, std::ios::end);
	uint64_t file_size = crypt.tellg();
	crypt.seekg(now_pos);

	uint64_t block_size = cipher.get_block_size();
	uint64_t key_size = cipher.get_key_size();
	const Data& key = cipher.get_available_key();
	algorithm::block_self_cryption_func block_self_encryption = cipher.get_block_self_encryption();
	Data tempBlock0 = ((const OFB&)cipher.get_mode()).get_iv();
	padding::padding_func unpadding = ((const OFB&)cipher.get_mode()).get_padding().get_unpadding();

	Data tempBlock1(block_size);
	for (uint64_t i = 0; i < (file_size - now_pos - 1) / block_size; ++i)
	{
		block_self_encryption(tempBlock0, block_size, key, key_size);
		crypt.read((char*)tempBlock1.data(), block_size);
		plain.write((char*)NSROOT::utils::squareXOR(tempBlock0, tempBlock1, block_size).data(), block_size);
		std::unique_lock<std::mutex> lock(*mutex_);
		while (*paused_ && !*stop_) { cond_->wait(lock); }
		if (*stop_) return;
		lock.unlock();
		progress_->store(update_progress(progress_->load(), block_size, file_size));
	}
	block_self_encryption(tempBlock0, block_size, key, key_size);
	crypt.read((char*)tempBlock1.data(), block_size);
	uint64_t s = crypt.gcount();
	for (uint64_t i = 0; i < block_size - crypt.gcount(); ++i) { tempBlock1.pop_back(); }
	NSROOT::utils::squareXOR_self(tempBlock1, tempBlock0, tempBlock1.size());
	unpadding(tempBlock1, block_size);
	plain.write((char*)tempBlock1.data(), tempBlock1.size());
	progress_->store(update_progress(progress_->load(), block_size, file_size));
	plain.flush();
	progress_->store(1.0);
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

std::unique_ptr<NSROOT::mode::Mode> NSROOT::mode::OFB::clone() const
{
	return std::move(std::make_unique<OFB>(*this));
}

NSROOT::mode::crypt_func NSROOT::mode::OFB::get_mult_encrypt() const
{
	return encrypt;
}
NSROOT::mode::crypt_func NSROOT::mode::OFB::get_mult_decrypt() const
{
	return decrypt;
}
NSROOT::mode::stream_crypt_func NSROOT::mode::OFB::get_stream_encrypt() const
{
	return encrypt_stream;
}
NSROOT::mode::stream_crypt_func NSROOT::mode::OFB::get_stream_decrypt() const
{
	return decrypt_stream;
}
NSROOT::mode::stream_cryptp_func NSROOT::mode::OFB::get_stream_encryptp() const
{
	return encrypt_streamp;
}
NSROOT::mode::stream_cryptp_func NSROOT::mode::OFB::get_stream_decryptp() const
{
	return decrypt_streamp;
}


#undef NSROOT
#undef DOG_DATA