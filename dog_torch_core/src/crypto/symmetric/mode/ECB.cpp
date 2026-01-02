#include "crypto/symmetric/mode/ECB.h"

#define NSROOT dog_torch::crypto::symmetric //NSROOT = namespace root
#define DOG_DATA dog_torch::serialize::Data

DOG_DATA NSROOT::mode::ECB::encrypt(const Data& plain, const Cipher& cipher)
{
    uint64_t block_size = cipher.get_block_size();
    uint64_t key_size = cipher.get_key_size();
    const Data& key = cipher.get_available_key();
    padding::padding_func padding = ((const ECB&)cipher.get_mode()).get_padding().get_padding();
    algorithm::block_self_cryption_func block_self_encryption = cipher.get_block_self_encryption();

    Data res;
  	res.reserve(((plain.size() / block_size) + 1) * block_size);
  	Data tempBlock;
  	for (uint64_t i0 = 0; i0 <= plain.size(); i0 += block_size)
  	{
  		tempBlock = plain.sub_by_pos(i0, i0 + block_size);
        padding(tempBlock, block_size);
  		block_self_encryption(tempBlock, block_size, key, key_size);
  		res += tempBlock;
  		tempBlock.rm_pos();
  	}
  	return res;
}
DOG_DATA NSROOT::mode::ECB::decrypt(const Data& crypt, const Cipher& cipher)
{
    uint64_t block_size = cipher.get_block_size();
    uint64_t key_size = cipher.get_key_size();
    const Data& key = cipher.get_available_key();
    padding::padding_func unpadding = ((const ECB&)cipher.get_mode()).get_padding().get_unpadding();
    algorithm::block_self_cryption_func block_self_decryption = cipher.get_block_self_decryption();

 	dog_torch::serialize::Data res; res.reserve(crypt.size());
 	dog_torch::serialize::Data tempBlock(block_size);
 	for (uint64_t i0 = 0; i0 < crypt.size(); i0 += block_size)
 	{
 		tempBlock = crypt.sub_by_pos(i0, i0 + block_size);
        block_self_decryption(tempBlock, block_size, key, key_size);
 		res += tempBlock;
 	}
 	unpadding(res, block_size);
 	return res;
}
void NSROOT::mode::ECB::encrypt_stream(std::istream& plain, std::ostream& crypt, const Cipher& cipher)
{
 	plain.seekg(0, std::ios::end);
 	uint64_t file_size = plain.tellg();
 	plain.seekg(0, std::ios::beg);

    uint64_t block_size = cipher.get_block_size();
    uint64_t key_size = cipher.get_key_size();
    const Data& key = cipher.get_available_key();
    padding::padding_func padding = ((const ECB&)cipher.get_mode()).get_padding().get_padding();
    algorithm::block_self_cryption_func block_self_encryption = cipher.get_block_self_encryption();

 	Data tempBlock(block_size);
 	while (plain.tellg() <= file_size - block_size)
 	{
 		plain.read((char*)tempBlock.data(), block_size);
 		block_self_encryption(tempBlock, block_size, key, key_size);
 		crypt.write((char*)tempBlock.data(), block_size);
 		//printf("%03ull%%\r", plain.tellg() * 100 / file_size);
 	}
 	plain.read((char*)tempBlock.data(), block_size);
 	if (plain.gcount() < block_size)
 	{
 		for (uint64_t i = 0; i < block_size - plain.gcount(); ++i) { tempBlock.pop_back(); }
 	}
    padding(tempBlock, block_size);
    block_self_encryption(tempBlock, block_size, key, key_size);
 	crypt.write((char*)tempBlock.data(), block_size);
 	crypt.flush();
 	//printf("100%%\r");
}
void NSROOT::mode::ECB::decrypt_stream(std::istream& crypt, std::ostream& plain, const Cipher& cipher)
{
 	uint64_t now_pos = crypt.tellg();
 	crypt.seekg(now_pos, std::ios::end);
 	uint64_t file_size = crypt.tellg();
 	crypt.seekg(now_pos);

    uint64_t block_size = cipher.get_block_size();
    uint64_t key_size = cipher.get_key_size();
    const Data& key = cipher.get_available_key();
    padding::padding_func unpadding = ((const ECB&)cipher.get_mode()).get_padding().get_padding();
    algorithm::block_self_cryption_func block_self_decryption = cipher.get_block_self_decryption();

 	Data tempBlock(block_size);

 	for (uint64_t i = 0; i < (file_size - now_pos - 1) / block_size; ++i)
 	{
 		crypt.read((char*)tempBlock.data(), block_size);
 		block_self_decryption(tempBlock, block_size, key, key_size);
 		plain.write((char*)tempBlock.data(), block_size);
 		//printf("%03ull%%\r", crypt.tellg() * 100 / file_size);
 	}
 	crypt.read((char*)tempBlock.data(), block_size);
    block_self_decryption(tempBlock, block_size, key, key_size);
 	unpadding(tempBlock, block_size);
 	plain.write((char*)tempBlock.data(), tempBlock.size());
 	plain.flush();
 	//printf("100%%\r");
}
void NSROOT::mode::ECB::encrypt_streamp(std::istream& plain, std::ostream& crypt, const Cipher& cipher,
    std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress_, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_)
{
 	plain.seekg(0, std::ios::end);
 	uint64_t file_size = plain.tellg();
 	plain.seekg(0, std::ios::beg);

    uint64_t block_size = cipher.get_block_size();
    uint64_t key_size = cipher.get_key_size();
    const Data& key = cipher.get_available_key();
    padding::padding_func padding = ((const ECB&)cipher.get_mode()).get_padding().get_padding();
    algorithm::block_self_cryption_func block_self_encryption = cipher.get_block_self_encryption();

 	Data tempBlock(block_size);
 	while (plain.tellg() <= file_size - block_size)
 	{
 		plain.read((char*)tempBlock.data(), block_size);
        block_self_encryption(tempBlock, block_size, key, key_size);
 		crypt.write((char*)tempBlock.data(), block_size);

 		std::unique_lock<std::mutex> lock(*mutex_);
 		while (*paused_ && !*stop_) { cond_->wait(lock); }
 		if (*stop_) return;
 		lock.unlock();

 		progress_->store(NSROOT::mode::update_progress(progress_->load(), block_size, file_size));
 	}
 	plain.read((char*)tempBlock.data(), block_size);
 	if (plain.gcount() < block_size)
 	{
 		for (uint64_t i = 0; i < block_size - plain.gcount(); ++i) { tempBlock.pop_back(); }
 	}
    padding(tempBlock, block_size);
    block_self_encryption(tempBlock, block_size, key, key_size);
    progress_->store(NSROOT::mode::update_progress(progress_->load(), block_size, file_size));
 	crypt.write((char*)tempBlock.data(), block_size);
 	crypt.flush();
 	progress_->store(1.0);
}
void NSROOT::mode::ECB::decrypt_streamp(std::istream& crypt, std::ostream& plain, const Cipher& cipher,
    std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress_, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_)
{
 	uint64_t now_pos = crypt.tellg();
 	crypt.seekg(now_pos, std::ios::end);
 	uint64_t file_size = crypt.tellg();
 	crypt.seekg(now_pos);

    uint64_t block_size = cipher.get_block_size();
    uint64_t key_size = cipher.get_key_size();
    const Data& key = cipher.get_available_key();
    padding::padding_func unpadding = ((const ECB&)cipher.get_mode()).get_padding().get_padding();
    algorithm::block_self_cryption_func block_self_decryption = cipher.get_block_self_decryption();


 	Data tempBlock(block_size);

 	for (uint64_t i = 0; i < (file_size - now_pos - 1) / block_size; ++i)
 	{
 		crypt.read((char*)tempBlock.data(), block_size);
        block_self_decryption(tempBlock, block_size, key, key_size);
 		plain.write((char*)tempBlock.data(), block_size);

 		std::unique_lock<std::mutex> lock(*mutex_);
 		while (*paused_ && !*stop_) { cond_->wait(lock); }
 		if (*stop_) return;
 		lock.unlock();
 		progress_->store(NSROOT::mode::update_progress(progress_->load(), block_size, file_size));
 	}
 	crypt.read((char*)tempBlock.data(), block_size);
    block_self_decryption(tempBlock, block_size, key, key_size);
    unpadding(tempBlock, block_size);
 	plain.write((char*)tempBlock.data(), tempBlock.size());
 	progress_->store(update_progress(progress_->load(), block_size, file_size));
 	plain.flush();
 	progress_->store(1.0);
}

NSROOT::mode::ECB::ECB(const padding::Padding& padding) : Mode("ECB")
{
    if (padding.get_name() == "None")
    {
        throw CryptionException(DOG_EXCEPTION_MSG_OPINION("ECB mode not support No padding"));
    }
    this->padding_ = padding.clone();
}

NSROOT::mode::ECB::ECB(const ECB& other) : Mode("ECB")
{
    this->padding_ = other.padding_->clone();
}

std::unique_ptr<NSROOT::mode::Mode> NSROOT::mode::ECB::clone() const
{
    return std::move(std::make_unique<ECB>(*this));
}
const NSROOT::padding::Padding& NSROOT::mode::ECB::get_padding() const
{
    return *padding_;
}

NSROOT::mode::crypt_func NSROOT::mode::ECB::get_mult_encrypt() const
{
    return encrypt;
}
NSROOT::mode::crypt_func NSROOT::mode::ECB::get_mult_decrypt() const
{
    return decrypt;
}
NSROOT::mode::stream_crypt_func NSROOT::mode::ECB::get_stream_encrypt() const
{
    return encrypt_stream;
}
NSROOT::mode::stream_crypt_func NSROOT::mode::ECB::get_stream_decrypt() const
{
    return decrypt_stream;
}
NSROOT::mode::stream_cryptp_func NSROOT::mode::ECB::get_stream_encryptp() const
{
    return encrypt_streamp;
}
NSROOT::mode::stream_cryptp_func NSROOT::mode::ECB::get_stream_decryptp() const
{
    return decrypt_streamp;
}

#undef NSROOT
#undef DOG_DATA