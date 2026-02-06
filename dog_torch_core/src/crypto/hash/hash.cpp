#include "crypto/hash/hash.h"

#define NSROOT dog_torch::crypto::hash
#define DOG_DATA dog_torch::serialize::BinaryData

#define DOG_ERROR_BAD_STREAM "Error:stream is not good"
#define DOG_ERROR_FILE_NO_EXICT "Error:file not exist"

NSROOT::algorithm::Hash::Hash(const Hash& other)
{
	this->name_ = other.name_;
	this->effective_ = other.effective_;
}
NSROOT::algorithm::Hash NSROOT::algorithm::Hash::operator=(const Hash& other)
{
	this->name_ = other.name_;
	this->effective_ = other.effective_;
	return *this;
}
NSROOT::algorithm::Hash::Hash(Hash&& other) noexcept
{
	this->name_ = std::move(other.name_);
	this->effective_ = std::move(other.effective_);
}
NSROOT::algorithm::Hash NSROOT::algorithm::Hash::operator=(Hash&& other) noexcept
{
	this->name_ = std::move(other.name_);
	this->effective_ = std::move(other.effective_);
	return *this;
}
void NSROOT::algorithm::Hash::init()
{

}
DOG_DATA NSROOT::algorithm::Hash::init_data() const
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
uint64_t NSROOT::algorithm::Hash::get_block_size() const
{
	return 0;
}
std::string NSROOT::algorithm::Hash::get_name() const
{
	return this->name_;
}
uint64_t NSROOT::algorithm::Hash::get_effective() const
{
	return this->effective_;
}
bool NSROOT::algorithm::Hash::have_next_block(uint64_t data_pos, uint64_t data_total)
{
	return false;
}
bool NSROOT::algorithm::Hash::have_next_block_big(const BigInt& data_pos, const BigInt& data_total)
{
	return false;
}

DOG_DATA NSROOT::algorithm::Hash::next_block(const Data& data, uint64_t start, uint64_t& data_pos, uint64_t data_total)
{
	return "";
}
DOG_DATA NSROOT::algorithm::Hash::next_block(std::istream& data, uint64_t& data_pos, uint64_t data_total)
{
	return "";
}
DOG_DATA NSROOT::algorithm::Hash::next_block_big(std::istream& data, BigInt& data_pos, const BigInt& data_total)
{
	return "";
}

NSROOT::HashGenerator::HashGenerator(const algorithm::Hash& hash)
{
	this->hash_ = hash.clone();
	this->init();
}
dog_torch::crypto::hash::HashGenerator::HashGenerator(const HashGenerator& other)
{
	this->hash_ = other.hash_->clone();
	this->value_ = other.value_;
	this->pos_ = other.pos_;
	this->total_ = other.total_;
}
dog_torch::crypto::hash::HashGenerator dog_torch::crypto::hash::HashGenerator::operator=(const HashGenerator& other)
{
	this->hash_ = other.hash_->clone();
	this->value_ = other.value_;
	this->pos_ = other.pos_;
	this->total_ = other.total_;
	return *this;
}
dog_torch::crypto::hash::HashGenerator::HashGenerator(HashGenerator&& other) noexcept
{
	this->hash_ = std::move(other.hash_);
	this->value_ = std::move(other.value_);
	this->pos_ = std::move(other.pos_);
	this->total_ = std::move(other.total_);
}
dog_torch::crypto::hash::HashGenerator dog_torch::crypto::hash::HashGenerator::operator=(HashGenerator&& other) noexcept
{
	this->hash_ = std::move(other.hash_);
	this->value_ = std::move(other.value_);
	this->pos_ = std::move(other.pos_);
	this->total_ = std::move(other.total_);
	return *this;
}
const dog_torch::crypto::hash::algorithm::Hash& dog_torch::crypto::hash::HashGenerator::get_hash() const
{
	return *this->hash_;
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
	uint64_t pos = this->pos_.to_abs_uint64();
	uint64_t total = this->total_.to_abs_uint64();
	do
	{
		Data block = this->hash_->next_block(data, pos, pos, total);		
		update_func(block,this->value_);
	} while (this->hash_->have_next_block(pos, total));
	Data res = trims_func(this->value_);
	this->init();
	return res;
}
DOG_DATA NSROOT::HashGenerator::calculate(std::istream& data, uint64_t max)
{
	if (!data.good())
	{
		throw HashException(DOG_EXCEPTION_MSG_OPINION(DOG_ERROR_BAD_STREAM));
	}

	this->pos_ = 0;
	this->total_ = max;

	uint64_t pos = this->pos_.to_abs_uint64();
	uint64_t total = this->total_.to_abs_uint64();

	auto update_func = this->hash_->get_update();
	auto trims_func = this->hash_->get_trims();
	do
	{
		Data block = this->hash_->next_block(data, pos, max);
		update_func(block, this->value_);
	} while (this->hash_->have_next_block(pos, total));
	Data res = trims_func(this->value_);
	this->init();
	return res;
}
DOG_DATA NSROOT::HashGenerator::calculate(PauseableChannel& pc, std::istream& data, uint64_t max)
{
	pc.start();
	if (!data.good())
	{
		pc.cancel();
		throw HashException(DOG_EXCEPTION_MSG_OPINION(DOG_ERROR_BAD_STREAM));
	}

	this->pos_ = 0;
	this->total_ = max;

	uint64_t pos = this->pos_.to_abs_uint64();
	uint64_t total = this->total_.to_abs_uint64();

	auto update_func = this->hash_->get_update();
	auto trims_func = this->hash_->get_trims();
	do
	{
		Data block = this->hash_->next_block(data, pos, max);
		update_func(block, this->value_);
		pc.add_progress(block.size() * 1.0 / max);
		if (pc.should_pause()) { break; }
	} while (this->hash_->have_next_block(pos, total));
	Data res = trims_func(this->value_);
	this->init();
	pc.complete();
	return res;
}
DOG_DATA NSROOT::HashGenerator::calculate(std::istream& data, const BigInt& max)
{
	if (!data.good())
	{
		throw HashException(DOG_EXCEPTION_MSG_OPINION(DOG_ERROR_BAD_STREAM));
	}

	this->pos_ = 0;
	this->total_ = max;

	auto update_func = this->hash_->get_update();
	auto trims_func = this->hash_->get_trims();
	do
	{
		Data block = this->hash_->next_block_big(data, this->pos_, max);
		update_func(block, this->value_);
	} while (this->hash_->have_next_block_big(this->pos_, this->total_));
	Data res = trims_func(this->value_);
	this->init();
	return res;
}
DOG_DATA NSROOT::HashGenerator::calculate(PauseableChannel& pc, std::istream& data, const BigInt& max)
{
	pc.start();
	if (!data.good())
	{
		pc.cancel();
		throw HashException(DOG_EXCEPTION_MSG_OPINION(DOG_ERROR_BAD_STREAM));
	}

	this->pos_ = 0;
	this->total_ = max;

	auto update_func = this->hash_->get_update();
	auto trims_func = this->hash_->get_trims();
	do
	{
		Data block = this->hash_->next_block_big(data, this->pos_, max);
		update_func(block, this->value_);
		if (pc.should_pause()) { break; }
		pc.add_progress(block.size() * 1.0 / max.to_abs_uint64());
	} while (this->hash_->have_next_block_big(this->pos_, total_));
	pc.complete();
	Data res = trims_func(this->value_);
	this->init();
	pc.complete();
	return res;
}
DOG_DATA NSROOT::HashGenerator::calculate(const std::filesystem::path& path)
{
	if (!std::filesystem::exists(path))
	{
		throw HashException(DOG_EXCEPTION_MSG_OPINION(DOG_ERROR_FILE_NO_EXICT));
	}
	this->total_ = std::filesystem::file_size(path);
	std::ifstream data(path, std::ios::binary);
	return this->calculate(data, this->total_.to_abs_uint64());
}
DOG_DATA NSROOT::HashGenerator::calculate(PauseableChannel& pc, const std::filesystem::path& path)
{
	if (!std::filesystem::exists(path))
	{
		throw HashException(DOG_EXCEPTION_MSG_OPINION(DOG_ERROR_FILE_NO_EXICT));
	}
	this->total_ = std::filesystem::file_size(path);
	std::ifstream data(path, std::ios::binary);
	return this->calculate(pc, data, this->total_.to_abs_uint64());
}

#undef NSROOT
#undef DOG_DATA

#undef DOG_ERROR_BAD_STREAM
#undef DOG_ERROR_FILE_NO_EXICT
