#include "crypto/mac/mac.h"

#define NSROOT dog_torch::crypto::mac

NSROOT::MacGenerator::MacGenerator(const BinaryData& key) : key_(key)
{
}
NSROOT::MacGenerator::~MacGenerator()
{
}

NSROOT::BinaryData NSROOT::MacGenerator::generate(const BinaryData& data)
{
    return "";
}
NSROOT::BinaryData NSROOT::MacGenerator::generate(std::istream& input, uint64_t size)
{
    return "";
}
NSROOT::BinaryData NSROOT::MacGenerator::generate(PauseableChannel& pc, std::istream& input, uint64_t size)
{
    pc.start();
    pc.complete();
    return "";
}
NSROOT::BinaryData NSROOT::MacGenerator::generate(std::filesystem::path path)
{
    return "";
}
NSROOT::BinaryData NSROOT::MacGenerator::generate(PauseableChannel& pc, std::filesystem::path path)
{
    pc.start();
    pc.complete();
    return "";
}

NSROOT::HMacGenerator::HMacGenerator(const BinaryData& key, const hash::algorithm::Hash& hasher)
    : MacGenerator(key), hasher_(hasher.clone())
{
    //std::cout << hasher.get_block_size() << std::endl;
}

NSROOT::BinaryData NSROOT::HMacGenerator::generate(const BinaryData& data)
{
    BinaryData effective_key = this->key_;
    uint64_t block_size = this->hasher_->get_block_size();
    HashGenerator hasher(*this->hasher_);
    if (key_.size() > block_size) effective_key = hasher.calculate(key_);
    while (effective_key.size() < block_size) effective_key.push_back(0x00);
    BinaryData ipad;ipad.reserve(block_size);
    BinaryData opad;opad.reserve(block_size);
    for (uint64_t i = 0; i < block_size; i++)
    {
        ipad.push_back(effective_key[i] ^ 0x36);
        opad.push_back(effective_key[i] ^ 0x5C);
    }
    auto update_func = this->hasher_->get_update();
    auto trims_func = this->hasher_->get_trims();
    hasher_->init();
    BinaryData value = this->hasher_->init_data();
    update_func(ipad, value);
    uint64_t pos = block_size;
    do
    {
        BinaryData block = this->hasher_->next_block(data, pos - block_size, pos, data.size() + block_size);
        update_func(block, value);
    } while (this->hasher_->have_next_block(pos, data.size() + block_size));
    opad += trims_func(value);
    return hasher.calculate(opad);
}
NSROOT::BinaryData NSROOT::HMacGenerator::generate(std::istream& input, uint64_t size)
{
    BinaryData effective_key = this->key_;
    uint64_t block_size = this->hasher_->get_block_size();
    HashGenerator hasher(*this->hasher_);
    if (key_.size() > block_size) effective_key = hasher.calculate(key_);
    while (effective_key.size() < block_size) effective_key.push_back(0x00);
    BinaryData ipad;ipad.reserve(block_size);
    BinaryData opad;opad.reserve(block_size);
    for (uint64_t i = 0; i < block_size; i++)
    {
        ipad.push_back(effective_key[i] ^ 0x36);
        opad.push_back(effective_key[i] ^ 0x5C);
    }
    auto update_func = this->hasher_->get_update();
    auto trims_func = this->hasher_->get_trims();
    hasher_->init();
    BinaryData value = this->hasher_->init_data();
    update_func(ipad, value);
    uint64_t pos = block_size;
    do
    {
        BinaryData block = this->hasher_->next_block(input, pos, size + block_size);
        update_func(block, value);
    } while (this->hasher_->have_next_block(pos, size + block_size));
    opad += trims_func(value);
    return hasher.calculate(opad);
}
NSROOT::BinaryData NSROOT::HMacGenerator::generate(PauseableChannel& pc, std::istream& input, uint64_t size)
{
    pc.start();
    BinaryData effective_key = this->key_;
    uint64_t block_size = this->hasher_->get_block_size();
    HashGenerator hasher(*this->hasher_);
    if (key_.size() > block_size) effective_key = hasher.calculate(key_);
    while (effective_key.size() < block_size) effective_key.push_back(0x00);
    BinaryData ipad;ipad.reserve(block_size);
    BinaryData opad;opad.reserve(block_size);
    for (uint64_t i = 0; i < block_size; i++)
    {
        ipad.push_back(effective_key[i] ^ 0x36);
        opad.push_back(effective_key[i] ^ 0x5C);
    }
    auto update_func = this->hasher_->get_update();
    auto trims_func = this->hasher_->get_trims();
    hasher_->init();
    BinaryData value = this->hasher_->init_data();
    update_func(ipad, value);
    uint64_t pos = block_size;
    do
    {
        BinaryData block = this->hasher_->next_block(input, pos, size + block_size);
        update_func(block, value);
        if (pc.should_pause()) break;
    } while (this->hasher_->have_next_block(pos, size + block_size));
    opad += trims_func(value);
    pc.complete();
    return hasher.calculate(opad);
}
NSROOT::BinaryData NSROOT::HMacGenerator::generate(std::filesystem::path path)
{
    std::ifstream input(path, std::ios::binary);
    uint64_t size = std::filesystem::file_size(path);
    return this->generate(input, size);
}
NSROOT::BinaryData NSROOT::HMacGenerator::generate(PauseableChannel& pc, std::filesystem::path path)
{
    std::ifstream input(path, std::ios::binary);
    uint64_t size = std::filesystem::file_size(path);
    return this->generate(pc, input, size);
}
#undef NSROOT