#include "crypto/symmetric/mode/PCBC.h"

#define NSROOT dog_torch::crypto::symmetric //NSROOT = namespace root
#define DOG_DATA dog_torch::serialize::Data

dog_torch::serialize::Data NSROOT::mode::PCBC::encrypt(const Data& plain, const Data& iv, Cryptor& cryptor)
{
	uint8_t block_size = cryptor.get_block_size();
	dog_torch::serialize::Data res; res.reserve(((plain.size() / block_size) + 1) * block_size);
	dog_torch::serialize::Data tempBlock0, tempBlock1 = iv, tempBlock2;
	for (uint64_t i0 = 0; i0 <= plain.size(); i0 += block_size)
	{
		tempBlock0 = plain.sub_by_len(i0, block_size);
		if (tempBlock0.size() < block_size) { cryptor.get_padding()(tempBlock0, block_size); }
		tempBlock2 = NSROOT::utils::squareXOR(tempBlock1, tempBlock0, tempBlock0.size());
		cryptor.get_block_self_encryption()(tempBlock2, block_size, cryptor.get_available_key(), cryptor.get_key_size());
		res += tempBlock2;
		tempBlock1 = NSROOT::utils::squareXOR(tempBlock2, tempBlock0, tempBlock0.size());
	}
	return res;
}
dog_torch::serialize::Data NSROOT::mode::PCBC::decrypt(const Data& crypt, const Data& iv, Cryptor& cryptor)
{
	uint8_t block_size = cryptor.get_block_size();
	dog_torch::serialize::Data res; res.reserve(((crypt.size() / block_size) + 1) * block_size);
	dog_torch::serialize::Data tempBlock0, tempBlock1 = iv, tempBlock2;
	for (uint64_t i0 = 0; i0 < crypt.size(); i0 += block_size)
	{
		tempBlock0 = crypt.sub_by_len(i0, block_size);
		tempBlock2 = cryptor.get_block_decryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
		NSROOT::utils::squareXOR_self(tempBlock2, tempBlock1, tempBlock1.size());
		res += tempBlock2;
		tempBlock1 = NSROOT::utils::squareXOR(tempBlock2, tempBlock0, tempBlock0.size());
	}
	cryptor.get_unpadding()(res, block_size);
	return res;
}
void NSROOT::mode::PCBC::encrypt_stream(std::istream& plain, const Data& iv, std::ostream& crypt, Cryptor& cryptor)
{
	uint8_t block_size = cryptor.get_block_size();
	plain.seekg(0, std::ios::end);
	uint64_t file_size = plain.tellg();
	plain.seekg(0, std::ios::beg);

	dog_torch::serialize::Data tempBlock0(block_size), tempBlock1 = iv, tempBlock2(block_size);
	while (plain.tellg() <= file_size - block_size)
	{
		plain.read((char*)tempBlock0.data(), block_size);
		tempBlock2 = NSROOT::utils::squareXOR(tempBlock1, tempBlock0, tempBlock0.size());
		cryptor.get_block_self_encryption()(tempBlock2, block_size, cryptor.get_available_key(), cryptor.get_key_size());
		crypt.write((char*)tempBlock2.data(), block_size);
		tempBlock1 = NSROOT::utils::squareXOR(tempBlock2, tempBlock0, tempBlock0.size());
	}
	plain.read((char*)tempBlock0.data(), block_size);
	if (plain.gcount() < block_size)
	{
		for (uint64_t i = 0; i < block_size - plain.gcount(); ++i) { tempBlock0.pop_back(); }
		cryptor.get_padding()(tempBlock0, block_size);
	}
	tempBlock2 = NSROOT::utils::squareXOR(tempBlock1, tempBlock0, tempBlock0.size());
	cryptor.get_block_self_encryption()(tempBlock2, block_size, cryptor.get_available_key(), cryptor.get_key_size());
	crypt.write((char*)tempBlock2.data(), block_size);
	tempBlock1 = NSROOT::utils::squareXOR(tempBlock2, tempBlock0, tempBlock0.size());
}
void NSROOT::mode::PCBC::decrypt_stream(std::istream& crypt, const Data& iv, std::ostream& plain, Cryptor& cryptor)
{
	uint8_t block_size = cryptor.get_block_size();
	uint64_t now_pos = crypt.tellg();
	crypt.seekg(0, std::ios::end);
	uint64_t file_size = crypt.tellg();
	crypt.seekg(now_pos);

	dog_torch::serialize::Data tempBlock0(block_size), tempBlock1 = iv, tempBlock2;
	for (uint64_t i = 0; i < (file_size - now_pos - 1) / block_size; ++i)
	{
		crypt.read((char*)tempBlock0.data(), block_size);
		tempBlock2 = cryptor.get_block_decryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
		NSROOT::utils::squareXOR_self(tempBlock2, tempBlock1, tempBlock1.size());
		plain.write((char*)tempBlock2.data(), block_size);
		tempBlock1 = NSROOT::utils::squareXOR(tempBlock2, tempBlock0, tempBlock0.size());
	}
	crypt.read((char*)tempBlock0.data(), block_size);
	tempBlock2 = cryptor.get_block_decryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
	NSROOT::utils::squareXOR_self(tempBlock2, tempBlock1, tempBlock1.size());
	cryptor.get_unpadding()(tempBlock2, block_size);
	plain.write((char*)tempBlock2.data(), tempBlock2.size());
	plain.flush();
}
void NSROOT::mode::PCBC::encrypt_streamp(std::istream& plain, const Data& iv, std::ostream& crypt, Cryptor& cryptor,
	std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress_, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_)

{
	uint8_t block_size = cryptor.get_block_size();
	plain.seekg(0, std::ios::end);
	uint64_t file_size = plain.tellg();
	plain.seekg(0, std::ios::beg);

	dog_torch::serialize::Data tempBlock0(block_size), tempBlock1 = iv, tempBlock2(block_size);
	while (plain.tellg() <= file_size - block_size)
	{
		plain.read((char*)tempBlock0.data(), block_size);
		tempBlock2 = NSROOT::utils::squareXOR(tempBlock1, tempBlock0, tempBlock0.size());
		cryptor.get_block_self_encryption()(tempBlock2, block_size, cryptor.get_available_key(), cryptor.get_key_size());
		crypt.write((char*)tempBlock2.data(), block_size);
		std::unique_lock<std::mutex> lock(*mutex_);
		while (*paused_ && !*stop_) { cond_->wait(lock); }
		if (*stop_) return;
		lock.unlock();
		progress_->store(NSROOT::mode::update_progress(progress_->load(), block_size, file_size));
		tempBlock1 = NSROOT::utils::squareXOR(tempBlock2, tempBlock0, tempBlock0.size());
	}
	plain.read((char*)tempBlock0.data(), block_size);
	if (plain.gcount() < block_size)
	{
		for (uint64_t i = 0; i < block_size - plain.gcount(); ++i) { tempBlock0.pop_back(); }
		cryptor.get_padding()(tempBlock0, block_size);
	}
	tempBlock2 = NSROOT::utils::squareXOR(tempBlock1, tempBlock0, tempBlock0.size());
	cryptor.get_block_self_encryption()(tempBlock2, block_size, cryptor.get_available_key(), cryptor.get_key_size());
	crypt.write((char*)tempBlock2.data(), block_size);
	tempBlock1 = NSROOT::utils::squareXOR(tempBlock2, tempBlock0, tempBlock0.size());
	progress_->store(1.0);
}
void NSROOT::mode::PCBC::decrypt_streamp(std::istream& crypt, const Data& iv, std::ostream& plain, Cryptor& cryptor,
	std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress_, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_)
{
	uint8_t block_size = cryptor.get_block_size();
	uint64_t now_pos = crypt.tellg();
	crypt.seekg(0, std::ios::end);
	uint64_t file_size = crypt.tellg();
	crypt.seekg(now_pos);

	dog_torch::serialize::Data tempBlock0(block_size), tempBlock1 = iv, tempBlock2;
	for (uint64_t i = 0; i < (file_size - now_pos - 1) / block_size; ++i)
	{
		crypt.read((char*)tempBlock0.data(), block_size);
		tempBlock2 = cryptor.get_block_decryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
		NSROOT::utils::squareXOR_self(tempBlock2, tempBlock1, tempBlock1.size());
		plain.write((char*)tempBlock2.data(), block_size);
		std::unique_lock<std::mutex> lock(*mutex_);
		while (*paused_ && !*stop_) { cond_->wait(lock); }
		if (*stop_) return;
		lock.unlock();
		progress_->store(NSROOT::mode::update_progress(progress_->load(), block_size, file_size));
		progress_->store(update_progress(progress_->load(), block_size, file_size));
		tempBlock1 = NSROOT::utils::squareXOR(tempBlock2, tempBlock0, tempBlock0.size());
	}
	crypt.read((char*)tempBlock0.data(), block_size);
	tempBlock2 = cryptor.get_block_decryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
	NSROOT::utils::squareXOR_self(tempBlock2, tempBlock1, tempBlock1.size());
	cryptor.get_unpadding()(tempBlock2, block_size);
	plain.write((char*)tempBlock2.data(), tempBlock2.size());
	plain.flush();
	progress_->store(1.0);
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