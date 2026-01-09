#include "crypto/hash/base.h"

#define NSROOT dog_torch::crypto::hash
#define DOG_DATA dog_torch::serialize::BinaryData

void NSROOT::algorithm::Hash::init()
{

}
DOG_DATA NSROOT::algorithm::Hash::init_data() const
{
	return "";
}
bool NSROOT::algorithm::Hash::have_next_block(const BigInt& pos, const BigInt& total) const
{
	return true;
}
DOG_DATA NSROOT::algorithm::Hash::next_block(const Data& data, BigInt& pos, const BigInt& total)
{
	return "";
}
DOG_DATA NSROOT::algorithm::Hash::next_block(std::istream& data, BigInt& pos, const BigInt& total)
{
	return "";
}
NSROOT::algorithm::update_func NSROOT::algorithm::Hash::get_update() const
{
	return nullptr;
}
NSROOT::algorithm::trims_func NSROOT::algorithm::Hash::get_trims() const
{
	return nullptr;
}
std::unique_ptr<NSROOT::algorithm::Hash> NSROOT::algorithm::Hash::clone() const
{
	return std::make_unique<Hash>(*this);
}

NSROOT::HashGenerator::HashGenerator(const algorithm::Hash& hash)
{
	this->hash_ = hash.clone();
	this->init();
}
void NSROOT::HashGenerator::init()
{
	this->hash_->init();
	this->value_ = this->hash_->init_data();
	this->pos_ = 0;
	this->total_ = 0;
}
DOG_DATA NSROOT::HashGenerator::calculate(const Data& data)
{
	this->total_ = data.size();
	auto update_func = this->hash_->get_update();
	auto trims_func = this->hash_->get_trims();
	do
	{
		Data block = this->hash_->next_block(data, this->pos_, this->total_);
		update_func(block,this->value_);
	} while (this->hash_->have_next_block(this->pos_, this->total_));
	return trims_func(this->value_);
}
DOG_DATA NSROOT::HashGenerator::calculate(std::istream& data)
{
	if (!data.good())
	{
		throw HashException(DOG_EXCEPTION_MSG_OPINION("stream is not good"));
	}
	uint64_t now_pos = data.tellg();
	this->pos_ = now_pos;
	data.seekg(0, std::ios::end);
	this->total_ = uint64_t(data.tellg());
	data.seekg(now_pos, std::ios::beg);
	auto update_func = this->hash_->get_update();
	auto trims_func = this->hash_->get_trims();
	do
	{
		Data block = this->hash_->next_block(data, this->pos_, this->total_);
		update_func(block, this->value_);
	} while (this->hash_->have_next_block(this->pos_, total_));
	return trims_func(this->value_);
}
DOG_DATA NSROOT::HashGenerator::calculate(const std::filesystem::path& path)
{
	if (!std::filesystem::exists(path))
	{
		throw HashException(DOG_EXCEPTION_MSG_OPINION("file not exist"));
	}
	this->total_ = std::filesystem::file_size(path);
	std::ifstream data(path, std::ios::binary);

	auto update_func = this->hash_->get_update();
	auto trims_func = this->hash_->get_trims();
	do
	{
		Data block = this->hash_->next_block(data, this->pos_, this->total_);
		update_func(block, this->value_);
	} while (this->hash_->have_next_block(this->pos_, this->total_));
	return trims_func(this->value_);
}

#undef NSROOT
#undef DOG_DATA