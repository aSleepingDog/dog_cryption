#include "crypto/hash/hash_crypter.h"

dog_torch::crypto::hash::HashCrypher::HashCrypher(std::string type, uint64_t effective)
{
	if (type == SHA2::name)
	{
		this->type_ = SHA2::name;
		this->effective_ = effective;
		this->config_fmt_ = SHA2::get_config;
		if (effective == 28)
		{
			using namespace SHA2::b224;
			this->type_ = SHA2::name;
			this->max_ = MAX;

			this->initial_value_ = IV;
			this->effective_size_ = EFFECTIVE_SIZE;

			this->block_size_ = BLOCK_SIZE;
			this->number_size_ = NUMBER_SIZE;
			this->hash_function_ = single_update;
		}
		else if (effective == 32)
		{
			using namespace SHA2::b256;
			this->type_ = SHA2::name;
			this->max_ = MAX;

			this->initial_value_ = IV;
			this->effective_size_ = EFFECTIVE_SIZE;

			this->block_size_ = BLOCK_SIZE;
			this->number_size_ = NUMBER_SIZE;
			this->hash_function_ = single_update;

		}
		else if (effective == 48)
		{
			using namespace SHA2::b384;
			this->type_ = SHA2::name;
			this->max_ = MAX;

			this->initial_value_ = IV;
			this->effective_size_ = EFFECTIVE_SIZE;

			this->block_size_ = BLOCK_SIZE;
			this->number_size_ = NUMBER_SIZE;
			this->hash_function_ = single_update;
		}
		else if (effective == 64)
		{
			using namespace SHA2::b512;
			this->type_ = SHA2::name;
			this->max_ = MAX;

			this->initial_value_ = IV;
			this->effective_size_ = EFFECTIVE_SIZE;

			this->block_size_ = BLOCK_SIZE;
			this->number_size_ = NUMBER_SIZE;
			this->hash_function_ = single_update;
		}
		else
		{
			throw dog_torch::crypto::hash::HashException(DOG_EXCEPTION_MSG_OPINION("Error:Unknown hash type\n错误：未知哈希类型"));
		}
	}
	else if (type == SM3::name)
	{
		this->effective_ = effective;
		this->config_fmt_ = SM3::get_config;
		if (effective == 32)
		{
			using namespace SM3::b256;
			this->type_ = SM3::name;
			this->max_ = MAX;

			this->initial_value_ = IV;
			this->effective_size_ = EFFECTIVE_SIZE;

			this->block_size_ = BLOCK_SIZE;
			this->number_size_ = NUMBER_SIZE;
			this->hash_function_ = single_update;
		}
		else
		{
            throw dog_torch::crypto::hash::HashException(DOG_EXCEPTION_MSG_OPINION("Error:Unknown hash type\n错误：未知哈希类型"));
		}
	}
	else
	{
		throw dog_torch::crypto::hash::HashException(DOG_EXCEPTION_MSG_OPINION("Error:Unknown hash type\n错误：未知哈希类型"));
	}
}
void dog_torch::crypto::hash::HashCrypher::update(dog_torch::serialize::Data data)
{
	//std::cout << initial_value.getHexString() << std::endl;
	uint64_t size = data.size();
	if (size == this->block_size_)
	{
		hash_function_(data, this->initial_value_);
		this->total_ += this->block_size_ << 3;
	}
	else if (size > (this->block_size_))
	{
		while (size > (this->block_size_))
		{
			data.pop_back();
		}
		hash_function_(data, this->initial_value_);
		this->total_ += this->block_size_ << 3;
	}
	else if (size < (this->block_size_))
	{
		this->total_ += size * 8;
		data.push_back(0x80);
		size++;
		//DogData::print::block(data);
		if (size <= (this->block_size_ - this->number_size_))
		{

			while (data.size() < (this->block_size_ - this->number_size_))
			{
				data.push_back(0x00);
			}

			std::vector<uint8_t> temp_number = this->total_.get_bytes();
			while (temp_number.size() < (this->number_size_))
			{
				temp_number.insert(temp_number.begin(), 0x00);
			}
			for (uint8_t& i : temp_number)
			{
				data.push_back(i);
			}

			hash_function_(data, this->initial_value_);

			this->is_effective_ = true;
		}
		else
		{
			//DogData::print::block(data);
			while (data.size() < this->block_size_)
			{
				data.push_back(0x00);
			}
			hash_function_(data, this->initial_value_);

			dog_torch::serialize::Data temp_block;
			temp_block.reserve(this->block_size_);
			for (int i = 0; i < (this->block_size_ - this->number_size_); i++)
			{
				temp_block.push_back(0x00);
			}
			std::vector<uint8_t> temp_number = this->total_.get_bytes();
			
			while (temp_number.size() < (this->number_size_))
			{
				temp_number.insert(temp_number.begin(), 0x00);
			}
			for (uint8_t& i : temp_number)
			{
				temp_block.push_back((uint8_t)i);
			}
			hash_function_(temp_block, this->initial_value_);
			//DogData::print::block(temp_block);

			this->is_effective_ = true;
		}

	}
	//DogData::print::block(data);
	
}
void dog_torch::crypto::hash::HashCrypher::init()
{
	if (type_ == SHA2::name)
	{
		if (effective_ == 28)
		{
			using namespace SHA2::b224;
			this->initial_value_ = IV;
		}
		else if (effective_ == 32)
		{
			using namespace SHA2::b256;
			this->initial_value_ = IV;
		}
		else if (effective_ == 48)
		{
			using namespace SHA2::b384;
			this->initial_value_ = IV;
		}
		else if (effective_ == 64)
		{
			using namespace SHA2::b512;
			this->initial_value_ = IV;
		}
		else
		{
			throw dog_torch::crypto::hash::HashException(DOG_EXCEPTION_MSG_OPINION("Error:Unknown hash type\n错误：未知哈希类型"));
		}
	}
	else if (type_ == SM3::name)
	{
		if (effective_ == 32)
		{
			using namespace SM3::b256;
			this->initial_value_ = IV;
		}
		else
		{
			throw dog_torch::crypto::hash::HashException(DOG_EXCEPTION_MSG_OPINION("Error:Unknown hash type\n错误：未知哈希类型"));
		}
	}
	else
	{
		throw dog_torch::crypto::hash::HashException(DOG_EXCEPTION_MSG_OPINION("Error:Unknown hash type\n错误：未知哈希类型"));
	}
	this->total_ = 0;
}
void dog_torch::crypto::hash::HashCrypher::finish()
{
	if (!this->is_effective_)
	{
		dog_torch::serialize::Data temp_block;
		temp_block.reserve(this->block_size_);
		temp_block.push_back(0x80);
		for (int i = 1; i < (this->block_size_ - this->number_size_); i++)
		{
			temp_block.push_back(0x00);
		}
		std::string number = this->total_.get_num(16, true);
		while (number.size() < (this->number_size_*2))
		{
			number = "0" + number;
		}
		dog_torch::serialize::Data temp_number = number.c_str();
		for (uint8_t& i : temp_number)
		{
			temp_block.push_back(i);
		}
		hash_function_(temp_block, this->initial_value_);
		//DogData::print::block(temp_block);
		this->is_effective_ = true;
	}
}
dog_torch::serialize::Data dog_torch::crypto::hash::HashCrypher::get_hash()
{
	return this->initial_value_.sub_by_pos(0, this->effective_size_);
}
std::string dog_torch::crypto::hash::HashCrypher::get_type() const
{
	return this->type_;
}
uint64_t dog_torch::crypto::hash::HashCrypher::get_effective() const
{
	return this->effective_;
}
std::string dog_torch::crypto::hash::HashCrypher::get_config() const
{
	return this->config_fmt_(this->type_, this->effective_);
}
std::function<void(dog_torch::serialize::Data, dog_torch::serialize::Data&)> dog_torch::crypto::hash::HashCrypher::get_update() const
{
	return this->hash_function_;
}
dog_torch::serialize::Data dog_torch::crypto::hash::HashCrypher::get_data_hash(dog_torch::serialize::Data data)
{
	uint64_t size = 0;
	while (size < data.size())
	{
		this->update(data.sub_by_pos(size, size + this->block_size_));
		size += this->block_size_;
	}
	this->finish();
	dog_torch::serialize::Data res = this->get_hash();
	this->init();
	return res;
}
dog_torch::serialize::Data dog_torch::crypto::hash::HashCrypher::get_string_hash(std::string data)
{
	return this->get_data_hash(dog_torch::serialize::Data(data.c_str(), 0));
}
dog_torch::serialize::Data dog_torch::crypto::hash::HashCrypher::streamHash(HashCrypher& crypher, std::istream& data)
{
	uint8_t block_size = crypher.block_size_;
	data.seekg(0, std::ios::end);
	uint64_t file_size = data.tellg();
	data.seekg(0, std::ios::beg);
	dog_torch::serialize::Data temp(block_size);
	for (uint64_t i = 0; i < (file_size / block_size); i++)
	{
		data.read((char*)temp.data(), block_size);
		crypher.update(temp);
		//printf("\rProgress: %.2f%%", crypher.progress * 100);
	}
	data.read((char*)temp.data(), block_size);
	for (uint64_t i = 0; i < block_size - data.gcount(); i++) { temp.pop_back(); }
	crypher.update(temp);
	crypher.finish();
	dog_torch::serialize::Data res = crypher.get_hash();
	data.seekg(0, std::ios::end);
	crypher.init();
	return res;
}
void dog_torch::crypto::hash::HashCrypher::streamHashp(HashCrypher& crypher, std::istream& data, dog_torch::serialize::Data* result,std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_)
{
	uint8_t block_size = crypher.block_size_;
	data.seekg(0, std::ios::end);
	uint64_t file_size = data.tellg();
	data.seekg(0, std::ios::beg);
	dog_torch::serialize::Data temp(block_size);
	for (uint64_t i = 0; i < (file_size / block_size); i++)
	{
		data.read((char*)temp.data(), block_size);
		crypher.update(temp);
		std::unique_lock<std::mutex> lock(*mutex_);
		while (*paused_ && !*stop_)
		{
			cond_->wait(lock);
		}
		if (*stop_)
		{
			return;
		}
		lock.unlock();
		progress->store(progress->load() + block_size * 1.0 / file_size);
	}
	data.read((char*)temp.data(), block_size);
	for (uint64_t i = 0; i < block_size - data.gcount(); i++) { temp.pop_back(); }
	crypher.update(temp);
	crypher.finish();
	progress->store(progress->load() + block_size * 1.0 / file_size);
	*result = crypher.get_hash();
	progress->store(1.0);
	data.seekg(0, std::ios::end);
	crypher.init();
}

const std::vector<dog_torch::crypto::hash::HashConfig> dog_torch::crypto::hash::list = { SHA2::config, SM3::config };
