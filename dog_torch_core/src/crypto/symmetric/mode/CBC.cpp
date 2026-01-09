#include "crypto/symmetric/mode/CBC.h"

#define NSROOT dog_torch::crypto::symmetric //NSROOT = namespace root
#define DOG_DATA dog_torch::serialize::BinaryData

DOG_DATA NSROOT::mode::CBC::encrypt(const Data& plain, const Cipher& cipher)
{
    const CBC& cbc = (const CBC&)cipher.get_mode();
    padding::padding_func padding = cbc.get_padding().get_padding();
    const Data& key = cipher.get_available_key();
    uint64_t key_size = cipher.get_key_size();
    algorithm::block_self_cryption_func cipher_func = cipher.get_block_self_encryption();

 	uint8_t block_size = cipher.get_block_size();
 	dog_torch::serialize::BinaryData res; res.reserve(((plain.size() / block_size) + 1) * block_size);
 	dog_torch::serialize::BinaryData tempBlock; tempBlock.reserve(block_size);
    dog_torch::serialize::BinaryData tempKey = cbc.get_iv();
 	for (uint64_t i0 = 0; i0 <= plain.size(); i0 += block_size)
 	{
 		tempBlock = plain.sub_by_pos(i0, i0 + block_size);
 		if (tempBlock.size() < block_size) { padding(tempBlock, block_size); }
 		dog_torch::serialize::BinaryData::XOR_self(tempBlock, tempKey, block_size);
        cipher_func(tempBlock, block_size, key, key_size);
 		res += tempBlock;
 		tempKey = tempBlock;
 	}
 	return res;
}
DOG_DATA NSROOT::mode::CBC::decrypt(const Data& crypt, const Cipher& cipher)
{
    const CBC& cbc = (const CBC&)cipher.get_mode();
    padding::padding_func unpadding = cbc.get_padding().get_unpadding();
    const Data& key = cipher.get_available_key();
    uint64_t key_size = cipher.get_key_size();
    algorithm::block_self_cryption_func cipher_func = cipher.get_block_self_decryption();

 	uint8_t block_size = cipher.get_block_size();
 	dog_torch::serialize::BinaryData res; res.reserve(((crypt.size() / block_size) + 1) * block_size);
 	dog_torch::serialize::BinaryData tempBlock(block_size);
 	dog_torch::serialize::BinaryData tempKey = cbc.get_iv();
 	for (uint64_t i0 = 0; i0 < crypt.size(); i0 += block_size)
 	{
 		tempBlock = crypt.sub_by_pos(i0, i0 + block_size);
        cipher_func(tempBlock, block_size, key, key_size);
 		dog_torch::serialize::BinaryData::XOR_self(tempBlock, tempKey, block_size);
 		res += tempBlock;
 		tempKey = crypt.sub_by_pos(i0, i0 + block_size);
 	}
    unpadding(res, block_size);
 	return res;
}
void NSROOT::mode::CBC::encrypt_stream(std::istream& plain, std::ostream& crypt,const Cipher& cipher)
{
 	uint8_t block_size = cipher.get_block_size();
 	plain.seekg(0, std::ios::end);
 	uint64_t file_size = plain.tellg();
 	plain.seekg(0, std::ios::beg);

    const CBC& cbc = (const CBC&)cipher.get_mode();
    padding::padding_func padding = cbc.get_padding().get_padding();
    const Data& key = cipher.get_available_key();
    uint64_t key_size = cipher.get_key_size();
    algorithm::block_self_cryption_func cipher_func = cipher.get_block_self_encryption();

 	dog_torch::serialize::BinaryData tempBlock(block_size);
 	dog_torch::serialize::BinaryData tempKey = cbc.get_iv();
 	while (plain.tellg() <= file_size - block_size)
 	{
 		plain.read((char*)tempBlock.data(), block_size);
 		dog_torch::serialize::BinaryData::XOR_self(tempBlock, tempKey, block_size);
        cipher_func(tempBlock, block_size, key, key_size);
 		crypt.write((char*)tempBlock.data(), block_size);
 		tempKey = tempBlock;
 	}
 	plain.read((char*)tempBlock.data(), block_size);
 	if (plain.gcount() < block_size)
 	{
 		for (uint64_t i = 0; i < block_size - plain.gcount(); ++i) { tempBlock.pop_back(); }
        padding(tempBlock, block_size);
 	}
 	dog_torch::serialize::BinaryData::XOR_self(tempBlock, tempKey, block_size);
    cipher_func(tempBlock, block_size, key, key_size);
 	crypt.write((char*)tempBlock.data(), block_size);
 	crypt.flush();
}
void NSROOT::mode::CBC::decrypt_stream(std::istream& crypt, std::ostream& plain,const Cipher& cipher)
{
 	uint8_t block_size = cipher.get_block_size();
 	uint64_t now_pos = crypt.tellg();
 	crypt.seekg(0, std::ios::end);
 	uint64_t file_size = crypt.tellg();
 	crypt.seekg(now_pos);

    const CBC& cbc = (const CBC&)cipher.get_mode();
    padding::padding_func unpadding = cbc.get_padding().get_unpadding();
    const Data& key = cipher.get_available_key();
    uint64_t key_size = cipher.get_key_size();
    algorithm::block_self_cryption_func cipher_func = cipher.get_block_self_decryption();

 	dog_torch::serialize::BinaryData tempBlock(block_size);
 	dog_torch::serialize::BinaryData tempKey = cbc.get_iv();
 	for (uint64_t i = 0; i < (file_size - now_pos - 1) / block_size; ++i)
 	{
 		crypt.read((char*)tempBlock.data(), block_size);
        cipher_func(tempBlock, block_size, key, key_size);
 		dog_torch::serialize::BinaryData::XOR_self(tempBlock, tempKey, block_size);
 		plain.write((char*)tempBlock.data(), block_size);
 		for (uint64_t i = 0; i < block_size; ++i) { crypt.unget(); }
 		crypt.read((char*)tempKey.data(), block_size);
 	}
 	crypt.read((char*)tempBlock.data(), block_size);
    cipher_func(tempBlock, block_size, cipher.get_available_key(), key_size);
 	dog_torch::serialize::BinaryData::XOR_self(tempBlock, tempKey, block_size);
    unpadding(tempBlock, block_size);
 	plain.write((char*)tempBlock.data(), tempBlock.size());
 	plain.flush();
}
void NSROOT::mode::CBC::encrypt_streamp(std::istream& plain, std::ostream& crypt, const Cipher& cipher,
    std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress_, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_)
{
 	uint8_t block_size = cipher.get_block_size();
 	plain.seekg(0, std::ios::end);
 	uint64_t file_size = plain.tellg();
 	plain.seekg(0, std::ios::beg);

    const CBC& cbc = (const CBC&)cipher.get_mode();
    padding::padding_func padding = cbc.get_padding().get_padding();
    const Data& key = cipher.get_available_key();
    uint64_t key_size = cipher.get_key_size();
    algorithm::block_self_cryption_func cipher_func = cipher.get_block_self_encryption();

 	dog_torch::serialize::BinaryData tempBlock(block_size);
 	dog_torch::serialize::BinaryData tempKey = cbc.get_iv();
 	while (plain.tellg() <= file_size - block_size)
 	{
 		plain.read((char*)tempBlock.data(), block_size);
 		dog_torch::serialize::BinaryData::XOR_self(tempBlock, tempKey, block_size);
        cipher_func(tempBlock, block_size, key, key_size);
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
        padding(tempBlock, block_size);
 	}
 	dog_torch::serialize::BinaryData::XOR_self(tempBlock, tempKey, block_size);
    cipher_func(tempBlock, block_size, key, key_size);
 	crypt.write((char*)tempBlock.data(), block_size);
 	crypt.flush();
 	progress_->store(1.0);
}
void NSROOT::mode::CBC::decrypt_streamp(std::istream& crypt, std::ostream& plain, const Cipher& cipher,
    std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress_, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_)
{
 	uint8_t block_size = cipher.get_block_size();
    uint64_t now_pos = crypt.tellg();
    crypt.seekg(0, std::ios::end);
    uint64_t file_size = crypt.tellg();
    crypt.seekg(now_pos);

    const CBC& cbc = (const CBC&)cipher.get_mode();
    padding::padding_func unpadding = cbc.get_padding().get_unpadding();
    const Data& key = cipher.get_available_key();
    uint64_t key_size = cipher.get_key_size();
    algorithm::block_self_cryption_func cipher_func = cipher.get_block_self_decryption();

 	dog_torch::serialize::BinaryData tempBlock(block_size);
 	dog_torch::serialize::BinaryData tempKey = cbc.get_iv();
 	for (uint64_t i = 0; i < (file_size - now_pos - 1) / block_size; ++i)
 	{
 		crypt.read((char*)tempBlock.data(), block_size);
 		cipher_func(tempBlock, block_size, key, key_size);
 		dog_torch::serialize::BinaryData::XOR_self(tempBlock, tempKey, block_size);
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
    cipher_func(tempBlock, block_size, key, key_size);
 	dog_torch::serialize::BinaryData::XOR_self(tempBlock, tempKey, block_size);
    unpadding(tempBlock, block_size);
 	plain.write((char*)tempBlock.data(), tempBlock.size());
 	progress_->store(update_progress(progress_->load(), block_size, file_size));
 	plain.flush();
 	progress_->store(1.0);
}

NSROOT::mode::CBC::CBC(const padding::Padding& padding, const Data& iv) : Mode("CBC")
{
    if (padding.get_name() == "None")
    {
        throw CryptionException(DOG_EXCEPTION_MSG_OPINION("CBC mode not support No padding"));
    }
    this->padding_ = padding.clone();
    this->iv_ = iv;
}

NSROOT::mode::CBC::CBC(const CBC& other) : Mode("CBC")
{
    this->padding_ = other.padding_->clone();
    this->iv_ = other.iv_;
}

const DOG_DATA& dog_torch::crypto::symmetric::mode::CBC::get_iv() const
{
    return iv_;
}
const NSROOT::padding::Padding& dog_torch::crypto::symmetric::mode::CBC::get_padding() const
{
    return *(this->padding_);
}

bool dog_torch::crypto::symmetric::mode::CBC::set_data_param(const std::string& param, const Data& value)
{
    if (param == "iv")
    {
        this->iv_ = value;
        return true;
    }
    return false;
}

bool dog_torch::crypto::symmetric::mode::CBC::set_Padding(const padding::Padding& value)
{
    if (value.get_name() == "None")
    {
        throw CryptionException(DOG_EXCEPTION_MSG_OPINION("ECB mode not support No padding"));
    }
    this->padding_ = value.clone();
    return true;
}

std::unique_ptr<NSROOT::mode::Mode> NSROOT::mode::CBC::clone() const
{
    return std::move(std::make_unique<CBC>(*this));
}

DOG_DATA dog_torch::crypto::symmetric::mode::CBC::to_data() const
{
    using namespace dog_torch::serialize::tlv;
    Data res = integer_num((uint64_t)3);
    res += string(this->padding_->get_name());
    res += bytes(this->iv_.to_byte_vector());
    return res;
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