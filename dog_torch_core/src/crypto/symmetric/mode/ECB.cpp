#include "crypto/symmetric/mode/ECB.h"

#define NSROOT dog_torch::crypto::symmetric //NSROOT = namespace root
#define DOG_DATA dog_torch::serialize::BinaryData
#define DOG_ERROR_BAD_BLOCK "Error:The data is not encrypted by ECB mode"
#define DOG_ERROR_NONE_PADDING "Error:ECB mode not support No padding"

NSROOT::mode::Config NSROOT::mode::ECB::get_config()
{
    return {
    "ECB",
    std::unordered_map<std::string, std::string>({
        {"padding","Padding"}
    })
    };
}

#define ECB_ENCRYPT_INIT \
uint64_t block_size = algorithm.get_block_size(); \
uint64_t key_size = algorithm.get_key_size(); \
const Data& key = available_key; \
algorithm::block_self_cryption_func block_self_encryption = algorithm.get_encrypt_self();\
using dog_torch::serialize::stream::utils::read_bytes_size;

#define ECB_DECRYPT_INIT \
uint64_t block_size = algorithm.get_block_size(); \
uint64_t key_size = algorithm.get_key_size(); \
const Data& key = available_key; \
algorithm::block_self_cryption_func block_self_decryption = algorithm.get_decrypt_self();\
using dog_torch::serialize::stream::utils::read_bytes_size;

DOG_DATA NSROOT::mode::ECB::encrypt(const Data& plain, const Data& available_key, const algorithm::Algorithm& algorithm, padding::padding_func padding)
{
    ECB_ENCRYPT_INIT;

    Data temp_block(block_size), crypt; crypt.reserve(((plain.size() / block_size) + 1) * block_size);
    uint64_t i = 0;
    for (; block_size <= plain.size() - i; i += block_size)
    {
        temp_block = plain.sub_bytes_by_len(i, block_size);
        block_self_encryption(temp_block, block_size, key, key_size);
        crypt += temp_block;
    }
    temp_block = plain.sub_bytes_by_len(i, block_size);
    padding(temp_block, block_size);
    block_self_encryption(temp_block, block_size, key, key_size);
    crypt += temp_block;
    return crypt;
}
DOG_DATA NSROOT::mode::ECB::decrypt(const Data& crypt, const Data& available_key, const algorithm::Algorithm& algorithm, padding::padding_func unpadding)
{
    ECB_DECRYPT_INIT;

    Data temp_block(block_size), plain; plain.reserve(((crypt.size() / block_size) + 1) * block_size);
    uint64_t i = 0;
    for (; block_size < crypt.size() - i; i += block_size)
    {
        temp_block = crypt.sub_bytes_by_len(i, block_size);
        block_self_decryption(temp_block, block_size, key, key_size);
        plain += temp_block;
    }
    temp_block = crypt.sub_bytes_by_len(i, block_size);
    block_self_decryption(temp_block, block_size, key, key_size);
    unpadding(temp_block, block_size);
    plain += temp_block;
    return plain;
}
void NSROOT::mode::ECB::encrypt_stream(std::istream& plain, uint64_t max, std::ostream& crypt, const Data& available_key, const algorithm::Algorithm& algorithm, padding::padding_func padding)
{
    ECB_ENCRYPT_INIT;

    Data temp_block(block_size);
    uint64_t total = 0;
    while (max - total >= block_size && read_bytes_size(plain, temp_block, block_size, total) == block_size)
    {
        block_self_encryption(temp_block, block_size, key, key_size);
        crypt.write((char*)temp_block.data(), block_size);
    }
    read_bytes_size(plain, temp_block, block_size, total);
    padding(temp_block, block_size);
    block_self_encryption(temp_block, block_size, key, key_size);
    crypt.write((char*)temp_block.data(), block_size);
    crypt.flush();
}
void NSROOT::mode::ECB::decrypt_stream(std::istream& crypt, uint64_t max, std::ostream& plain, const Data& available_key, const algorithm::Algorithm& algorithm, padding::padding_func unpadding)
{
    ECB_DECRYPT_INIT;

    Data temp_block(block_size);
    uint64_t total = 0;
    while (max - total > block_size && read_bytes_size(crypt, temp_block, block_size, total) == block_size)
    {
        block_self_decryption(temp_block, block_size, key, key_size);
        plain.write((char*)temp_block.data(), block_size);
    }
    if (read_bytes_size(crypt, temp_block, block_size, total) < block_size) throw CryptionException(DOG_EXCEPTION_MSG_OPINION(DOG_ERROR_BAD_BLOCK));
    block_self_decryption(temp_block, block_size, key, key_size);
    unpadding(temp_block, block_size);
    plain.write((char*)temp_block.data(), temp_block.size());
    plain.flush();
}
void NSROOT::mode::ECB::encryptp_stream(PauseableChannel& pchannel, std::istream& plain, uint64_t max, std::ostream& crypt, const Data& available_key, const algorithm::Algorithm& algorithm, padding::padding_func padding)
{
    ECB_ENCRYPT_INIT;

    pchannel.start();

    Data temp_block(block_size);
    uint64_t total = 0;
    while (max - total >= block_size && read_bytes_size(plain, temp_block, block_size, total) == block_size)
    {
        block_self_encryption(temp_block, block_size, key, key_size);
        crypt.write((char*)temp_block.data(), block_size);

        pchannel.add_progress(block_size * 1.0 / max);
        if (pchannel.should_pause()) break;;
    }
    read_bytes_size(plain, temp_block, block_size, total);
    padding(temp_block, block_size);
    block_self_encryption(temp_block, block_size, key, key_size);
    crypt.write((char*)temp_block.data(), block_size);
    crypt.flush();

    pchannel.complete();
}
void NSROOT::mode::ECB::decryptp_stream(PauseableChannel& pchannel, std::istream& crypt, uint64_t max, std::ostream& plain, const Data& available_key, const algorithm::Algorithm& algorithm, padding::padding_func unpadding)
{
    ECB_DECRYPT_INIT;

    pchannel.start();

    Data temp_block(block_size);
    uint64_t total = 0;
    while (max - total > block_size && read_bytes_size(crypt, temp_block, block_size, total) == block_size)
    {
        block_self_decryption(temp_block, block_size, key, key_size);
        plain.write((char*)temp_block.data(), block_size);

        pchannel.add_progress(block_size * 1.0 / max);
        if (pchannel.should_pause()) break;;
    }
    if (read_bytes_size(crypt, temp_block, block_size, total) < block_size) throw CryptionException(DOG_EXCEPTION_MSG_OPINION(DOG_ERROR_BAD_BLOCK));
    block_self_decryption(temp_block, block_size, key, key_size);
    unpadding(temp_block, block_size);
    plain.write((char*)temp_block.data(), temp_block.size());
    plain.flush();

    pchannel.complete();
}

NSROOT::mode::ECB::ECB(const padding::Padding& padding) : Mode("ECB")
{
    if (padding.get_name() == "None")
    {
        throw CryptionException(DOG_EXCEPTION_MSG_OPINION(DOG_ERROR_NONE_PADDING));
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
bool NSROOT::mode::ECB::check(const algorithm::Algorithm& algorithm) const
{
    return true;
}

bool NSROOT::mode::ECB::set_Padding(const padding::Padding& value)
{
    if (value.get_name() == "None")
    {
        throw CryptionException(DOG_EXCEPTION_MSG_OPINION(DOG_ERROR_NONE_PADDING));
    }
    this->padding_ = value.clone();
    return true;
}

NSROOT::mode::crypt_func NSROOT::mode::ECB::get_mult_encrypt() const
{
    return [this](const Data& plain, const Data& available_key, const algorithm::Algorithm& algorithm) -> Data
        {
            return encrypt(plain, available_key, algorithm, this->padding_->get_padding());
        };
}
NSROOT::mode::crypt_func NSROOT::mode::ECB::get_mult_decrypt() const
{
    return [this](const Data& crypt, const Data& available_key, const algorithm::Algorithm& algorithm) -> Data
        {
            return decrypt(crypt, available_key, algorithm, this->padding_->get_unpadding());
        };
}
NSROOT::mode::stream_crypt_func NSROOT::mode::ECB::get_stream_encrypt() const
{
    return [this](std::istream& plain, uint64_t max, std::ostream& crypt, const Data& available_key, const algorithm::Algorithm& algorithm) -> void
        {
            return encrypt_stream(plain, max, crypt, available_key, algorithm, this->padding_->get_padding());
        };
}
NSROOT::mode::stream_crypt_func NSROOT::mode::ECB::get_stream_decrypt() const
{
    return [this](std::istream& crypt, uint64_t max, std::ostream& plain, const Data& available_key, const algorithm::Algorithm& algorithm) -> void
        {
            return decrypt_stream(crypt, max, plain, available_key, algorithm, this->padding_->get_unpadding());
        };
}
NSROOT::mode::streamp_crypt_func NSROOT::mode::ECB::get_streamp_encrypt() const
{
    return [this](PauseableChannel& pchannel, std::istream& plain, uint64_t max, std::ostream& crypt, const Data& available_key, const algorithm::Algorithm& algorithm) -> void
        {
            return encryptp_stream(pchannel, plain, max, crypt, available_key, algorithm, this->padding_->get_padding());
        };
}
NSROOT::mode::streamp_crypt_func NSROOT::mode::ECB::get_streamp_decrypt() const
{
    return [this](PauseableChannel& pchannel, std::istream& crypt, uint64_t max, std::ostream& plain, const Data& available_key, const algorithm::Algorithm& algorithm) -> void
        {
            return decryptp_stream(pchannel, crypt, max, plain, available_key, algorithm, this->padding_->get_unpadding());
        };
}

#undef NSROOT
#undef DOG_DATA
#undef ECB_ENCRYPT_INIT
#undef ECB_DECRYPT_INIT

#undef DOG_ERROR_BAD_BLOCK
#undef DOG_ERROR_NONE_PADDING