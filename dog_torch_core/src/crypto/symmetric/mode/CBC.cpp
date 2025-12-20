#include "crypto/symmetric/mode/CBC.h"

#define NSROOT dog_torch::crypto::symmetric //NSROOT = namespace root
#define DOG_DATA dog_torch::serialize::Data

DOG_DATA NSROOT::mode::CBC::encrypt(const Data& plain, const Data& iv, Cryptor& cryptor)
{
 	uint8_t block_size = cryptor.get_block_size();
 	dog_torch::serialize::Data res; res.reserve(((plain.size() / block_size) + 1) * block_size);
 	dog_torch::serialize::Data tempBlock; tempBlock.reserve(block_size);
 	dog_torch::serialize::Data tempKey = iv;
 	for (uint64_t i0 = 0; i0 <= plain.size(); i0 += block_size)
 	{
 		tempBlock = plain.sub_by_pos(i0, i0 + block_size);
 		if (tempBlock.size() < block_size) { cryptor.get_padding()(tempBlock, block_size); }
 		NSROOT::utils::squareXOR_self(tempBlock, tempKey, block_size);
 		cryptor.get_block_self_encryption()(tempBlock, block_size, cryptor.get_available_key(), cryptor.get_key_size());
 		res += tempBlock;
 		tempKey = tempBlock;
 	}
 	return res;
}
DOG_DATA NSROOT::mode::CBC::decrypt(const Data& crypt, const Data& iv, Cryptor& cryptor)
{
 	uint8_t block_size = cryptor.get_block_size();
 	dog_torch::serialize::Data res; res.reserve(((crypt.size() / block_size) + 1) * block_size);
 	dog_torch::serialize::Data tempBlock(block_size);
 	dog_torch::serialize::Data tempKey = iv;
 	for (uint64_t i0 = 0; i0 < crypt.size(); i0 += block_size)
 	{
 		tempBlock = crypt.sub_by_pos(i0, i0 + block_size);
 		cryptor.get_block_self_decryption()(tempBlock, block_size, cryptor.get_available_key(), cryptor.get_key_size());
 		NSROOT::utils::squareXOR_self(tempBlock, tempKey, block_size);
 		res += tempBlock;
 		tempKey = crypt.sub_by_pos(i0, i0 + block_size);
 	}
 	cryptor.get_unpadding()(res, block_size);
 	return res;
}
void NSROOT::mode::CBC::encrypt_stream(std::istream& plain, const Data& iv, std::ostream& crypt, Cryptor& cryptor)
{
 	uint8_t block_size = cryptor.get_block_size();
 	plain.seekg(0, std::ios::end);
 	uint64_t file_size = plain.tellg();
 	plain.seekg(0, std::ios::beg);

 	dog_torch::serialize::Data tempBlock(block_size);
 	dog_torch::serialize::Data tempKey = iv;
 	while (plain.tellg() <= file_size - block_size)
 	{
 		plain.read((char*)tempBlock.data(), block_size);
 		NSROOT::utils::squareXOR_self(tempBlock, tempKey, block_size);
 		cryptor.get_block_self_encryption()(tempBlock, block_size, cryptor.get_available_key(), cryptor.get_key_size());
 		crypt.write((char*)tempBlock.data(), block_size);
 		tempKey = tempBlock;
 	}
 	plain.read((char*)tempBlock.data(), block_size);
 	if (plain.gcount() < block_size)
 	{
 		for (uint64_t i = 0; i < block_size - plain.gcount(); ++i) { tempBlock.pop_back(); }
 		cryptor.get_padding()(tempBlock, block_size);
 	}
 	NSROOT::utils::squareXOR_self(tempBlock, tempKey, block_size);
 	cryptor.get_block_self_encryption()(tempBlock, block_size, cryptor.get_available_key(), cryptor.get_key_size());
 	crypt.write((char*)tempBlock.data(), block_size);
 	crypt.flush();
}
void NSROOT::mode::CBC::decrypt_stream(std::istream& crypt, const Data& iv, std::ostream& plain, Cryptor& cryptor)
{
 	uint8_t block_size = cryptor.get_block_size();
 	uint64_t now_pos = crypt.tellg();
 	crypt.seekg(0, std::ios::end);
 	uint64_t file_size = crypt.tellg();
 	crypt.seekg(now_pos);

 	dog_torch::serialize::Data tempBlock(block_size);
 	dog_torch::serialize::Data tempKey = iv;
 	for (uint64_t i = 0; i < (file_size - now_pos - 1) / block_size; ++i)
 	{
 		crypt.read((char*)tempBlock.data(), block_size);
 		cryptor.get_block_self_decryption()(tempBlock, block_size, cryptor.get_available_key(), cryptor.get_key_size());
 		NSROOT::utils::squareXOR_self(tempBlock, tempKey, block_size);
 		plain.write((char*)tempBlock.data(), block_size);
 		for (uint64_t i = 0; i < block_size; ++i) { crypt.unget(); }
 		crypt.read((char*)tempKey.data(), block_size);
 	}
 	crypt.read((char*)tempBlock.data(), block_size);
 	cryptor.get_block_self_decryption()(tempBlock, block_size, cryptor.get_available_key(), cryptor.get_key_size());
 	NSROOT::utils::squareXOR_self(tempBlock, tempKey, block_size);
 	cryptor.get_unpadding()(tempBlock, block_size);
 	plain.write((char*)tempBlock.data(), tempBlock.size());
 	plain.flush();
}
void NSROOT::mode::CBC::encrypt_streamp(std::istream& plain, const Data& iv, std::ostream& crypt, Cryptor& cryptor,
    std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress_, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_)
{
 	uint8_t block_size = cryptor.get_block_size();
 	plain.seekg(0, std::ios::end);
 	uint64_t file_size = plain.tellg();
 	plain.seekg(0, std::ios::beg);

 	dog_torch::serialize::Data tempBlock(block_size);
 	dog_torch::serialize::Data tempKey = iv;
 	while (plain.tellg() <= file_size - block_size)
 	{
 		plain.read((char*)tempBlock.data(), block_size);
 		NSROOT::utils::squareXOR_self(tempBlock, tempKey, block_size);
 		cryptor.get_block_self_encryption()(tempBlock, block_size, cryptor.get_available_key(), cryptor.get_key_size());
 		crypt.write((char*)tempBlock.data(), block_size);
 		std::unique_lock<std::mutex> lock(*mutex_);
 		while (*paused_ && !*stop_) { cond_->wait(lock); }
 		if (*stop_) return;
 		lock.unlock();
 		progress_->store(NSROOT::mode::update_progress(progress_->load(), block_size, file_size));
 		tempKey = tempBlock;
 	}
 	plain.read((char*)tempBlock.data(), block_size);
 	if (plain.gcount() < block_size)
 	{
 		for (uint64_t i = 0; i < block_size - plain.gcount(); ++i) { tempBlock.pop_back(); }
 		cryptor.get_padding()(tempBlock, block_size);
 	}
 	NSROOT::utils::squareXOR_self(tempBlock, tempKey, block_size);
 	cryptor.get_block_self_encryption()(tempBlock, block_size, cryptor.get_available_key(), cryptor.get_key_size());
 	crypt.write((char*)tempBlock.data(), block_size);
 	crypt.flush();
 	progress_->store(1.0);
}
void NSROOT::mode::CBC::decrypt_streamp(std::istream& crypt, const Data& iv, std::ostream& plain, Cryptor& cryptor,
    std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress_, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_)
{
 	uint8_t block_size = cryptor.get_block_size();
 	uint64_t now_pos = crypt.tellg();
 	crypt.seekg(0, std::ios::end);
 	uint64_t file_size = crypt.tellg();
 	crypt.seekg(now_pos);

 	dog_torch::serialize::Data tempBlock(block_size);
 	dog_torch::serialize::Data tempKey = iv;
 	for (uint64_t i = 0; i < (file_size - now_pos - 1) / block_size; ++i)
 	{
 		crypt.read((char*)tempBlock.data(), block_size);
 		cryptor.get_block_self_decryption()(tempBlock, block_size, cryptor.get_available_key(), cryptor.get_key_size());
 		NSROOT::utils::squareXOR_self(tempBlock, tempKey, block_size);
 		plain.write((char*)tempBlock.data(), block_size);
 		for (uint64_t i = 0; i < block_size; ++i) { crypt.unget(); }
 		crypt.read((char*)tempKey.data(), block_size);
 		std::unique_lock<std::mutex> lock(*mutex_);
 		while (*paused_ && !*stop_) { cond_->wait(lock); }
 		if (*stop_) return;
 		lock.unlock();
 		progress_->store(NSROOT::mode::update_progress(progress_->load(), block_size, file_size));
 	}
 	crypt.read((char*)tempBlock.data(), block_size);
 	cryptor.get_block_self_decryption()(tempBlock, block_size, cryptor.get_available_key(), cryptor.get_key_size());
 	NSROOT::utils::squareXOR_self(tempBlock, tempKey, block_size);
 	cryptor.get_unpadding()(tempBlock, block_size);
 	plain.write((char*)tempBlock.data(), tempBlock.size());
 	progress_->store(update_progress(progress_->load(), block_size, file_size));
 	plain.flush();
 	progress_->store(1.0);
}

NSROOT::mode::crypt_func NSROOT::mode::CBC::get_mult_encrypt() const
{
    return encrypt;
}
NSROOT::mode::crypt_func NSROOT::mode::CBC::get_mult_decrypt() const
{
    return decrypt;
}
NSROOT::mode::stream_crypt_func NSROOT::mode::CBC::get_stream_encrypt() const
{
    return encrypt_stream;
}
NSROOT::mode::stream_crypt_func NSROOT::mode::CBC::get_stream_decrypt() const
{
    return decrypt_stream;
}
NSROOT::mode::stream_cryptp_func NSROOT::mode::CBC::get_stream_encryptp() const
{
    return encrypt_streamp;
}
NSROOT::mode::stream_cryptp_func NSROOT::mode::CBC::get_stream_decryptp() const
{
    return decrypt_streamp;
}

#undef NSROOT
#undef DOG_DATA