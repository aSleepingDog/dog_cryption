#include "../include/cryption/hash.h"

dog_hash::HashException::HashException(const char* msg, const char* file, const char* function, uint64_t line)
{
	//std::format("{}:{}\n at {}({}:{})", typeid(*this).name(), msg, function, file, line);
	this->msg = std::format("{}:{}\n at {}({}:{})", typeid(*this).name(), msg, function, file, line);
}
const char* dog_hash::HashException::what() const throw()
{
	return this->msg.c_str();
}

dog_hash::HashCrypher::HashCrypher(std::string type, uint64_t effective)
{
	if (type == SHA2::name)
	{
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
			throw dog_hash::HashException("Unknown hash type", __FILE__, __FUNCTION__, __LINE__);
		}
	}
	else if (type == SM3::name)
	{
		this->effective_ = effective;
		this->config_fmt_ = SM3::get_config;
		if (effective == 32)
		{
			using namespace SM3::b256;
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
            throw dog_hash::HashException("Unknown hash type", __FILE__, __FUNCTION__, __LINE__);
		}
	}
	else
	{
		throw dog_hash::HashException("Unknown hash type", __FILE__, __FUNCTION__, __LINE__);
	}
}
void dog_hash::HashCrypher::update(dog_data::Data data)
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

			dog_data::Data temp_block;
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
void dog_hash::HashCrypher::init()
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
			throw dog_hash::HashException("Unknown hash type", __FILE__, __FUNCTION__, __LINE__);
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
			throw dog_hash::HashException("Unknown hash type", __FILE__, __FUNCTION__, __LINE__);
		}
	}
	else
	{
		throw dog_hash::HashException("Unknown hash type", __FILE__, __FUNCTION__, __LINE__);
	}
	this->total_ = 0;
}
void dog_hash::HashCrypher::finish()
{
	if (!this->is_effective_)
	{
		dog_data::Data temp_block;
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
		dog_data::Data temp_number = number.c_str();
		for (uint8_t& i : temp_number)
		{
			temp_block.push_back(i);
		}
		hash_function_(temp_block, this->initial_value_);
		//DogData::print::block(temp_block);
		this->is_effective_ = true;
	}
}
dog_data::Data dog_hash::HashCrypher::get_hash()
{
	return this->initial_value_.sub_by_pos(0, this->effective_size_);
}
std::string dog_hash::HashCrypher::get_type() const
{
	return this->type_;
}
uint64_t dog_hash::HashCrypher::get_effective() const
{
	return this->effective_;
}
std::string dog_hash::HashCrypher::get_config() const
{
	return this->config_fmt_(this->type_, this->effective_);
}
std::function<void(dog_data::Data, dog_data::Data&)> dog_hash::HashCrypher::get_update() const
{
	return this->hash_function_;
}
dog_data::Data dog_hash::HashCrypher::getDataHash(dog_data::Data data)
{
	uint64_t size = 0;
	while (size < data.size())
	{
		this->update(data.sub_by_pos(size, size + this->block_size_));
		size += this->block_size_;
	}
	this->finish();
	dog_data::Data res = this->get_hash();
	this->init();
	return res;
}
dog_data::Data dog_hash::HashCrypher::getStringHash(std::string data)
{
	return this->getDataHash(dog_data::Data(data.c_str(), 0));
}
dog_data::Data dog_hash::HashCrypher::streamHash(HashCrypher& crypher, std::istream& data)
{
	uint8_t block_size = crypher.block_size_;
	data.seekg(0, std::ios::end);
	uint64_t file_size = data.tellg();
	data.seekg(0, std::ios::beg);
	dog_data::Data temp(block_size);
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
	dog_data::Data res = crypher.get_hash();
	data.seekg(0, std::ios::end);
	crypher.init();
	return res;
}
void dog_hash::HashCrypher::streamHashp(HashCrypher& crypher, std::istream& data, dog_data::Data* result,
	std::mutex* mutex_, std::condition_variable* cond_, std::atomic<double>* progress, std::atomic<bool>* running_, std::atomic<bool>* paused_, std::atomic<bool>* stop_)
{
	uint8_t block_size = crypher.block_size_;
	data.seekg(0, std::ios::end);
	uint64_t file_size = data.tellg();
	data.seekg(0, std::ios::beg);
	dog_data::Data temp(block_size);
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

std::string dog_hash::SHA2::get_config(std::string name, uint64_t effective)
{
	return name + "-" + std::to_string(effective * 8);
}

//SHA2
uint32_t dog_hash::SHA2::tick4B(dog_data::Data& data, uint64_t size, uint64_t index)
{
	return (uint32_t)(data[size - index * 4] << 24) + (data[size - index * 4 + 1] << 16) + (data[size - index * 4 + 2] << 8) + (data[size - index * 4 + 3]);
}
uint32_t dog_hash::SHA2::CRMB(uint32_t i, uint64_t n)
{
	//circleRightMoveBit
	int temp = n % 32;
	return (i >> temp) | (i << 32 - temp);
}
uint32_t dog_hash::SHA2::function1_64(uint32_t e, uint32_t f, uint32_t g, uint32_t h, dog_data::Data& block, int size, int n)
{
	uint32_t S1 = CRMB(e, 6) ^ CRMB(e, 11) ^ CRMB(e, 25);
	//printf("%0x\n", S1);
	uint32_t ch = (e & f) ^ ((~e) & g);
	uint32_t k = k_256[n];
	uint32_t w = tick4B(block, size, (64 - n));
	//printf("%0x\n", w);
	return h + S1 + ch + k + w;
}
uint32_t dog_hash::SHA2::function2_64(uint32_t a, uint32_t b, uint32_t c)
{
	uint32_t S0 = CRMB(a, 2) ^ CRMB(a, 13) ^ CRMB(a, 22);
	uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
	return S0 + maj;
}
uint64_t dog_hash::SHA2::tick8B(dog_data::Data& data, uint64_t size, uint64_t index)
{
	uint64_t res = 0;
	res += ((uint64_t)data[size - index * 8 + 0] << (56 - 8 * 0));
	res += ((uint64_t)data[size - index * 8 + 1] << (56 - 8 * 1));
	res += ((uint64_t)data[size - index * 8 + 2] << (56 - 8 * 2));
	res += ((uint64_t)data[size - index * 8 + 3] << (56 - 8 * 3));
	res += ((uint64_t)data[size - index * 8 + 4] << (56 - 8 * 4));
	res += ((uint64_t)data[size - index * 8 + 5] << (56 - 8 * 5));
	res += ((uint64_t)data[size - index * 8 + 6] << (56 - 8 * 6));
	res += ((uint64_t)data[size - index * 8 + 7] << (56 - 8 * 7));
	return res;
}
uint64_t dog_hash::SHA2::CRMB(uint64_t i, uint64_t n)
{
	int temp = n % 64;
	return (i >> temp) | (i << 64 - temp);
}
uint64_t dog_hash::SHA2::function1_128(uint64_t e, uint64_t f, uint64_t g, uint64_t h, dog_data::Data& block, int size, int n)
{
	uint64_t S1 = CRMB(e, 14) ^ CRMB(e, 18) ^ CRMB(e, 41);
	uint64_t ch = (e & f) ^ ((~e) & g);
	uint64_t temp = h + S1 + ch + k_512[n] + tick8B(block, size, (80 - n));
	return temp;
}
uint64_t dog_hash::SHA2::function2_128(uint64_t a, uint64_t b, uint64_t c)
{
	uint64_t S0 = CRMB(a, 28) ^ CRMB(a, 34) ^ CRMB(a, 39);
	uint64_t maj = (a & b) ^ (a & c) ^ (b & c);
	return S0 + maj;
}

void dog_hash::SHA2::b256::single_update(dog_data::Data plain, dog_data::Data& change_value)
{
	if (plain.size() != 64)
	{
		throw HashException("plain size is not 64", __FILE__, __FUNCTION__, __LINE__);
	}
	dog_data::Data tempBlock = std::move(plain);
	uint32_t tempN[9], tempH[8];
	for (int i = 0; i < 8; i++)
	{
		uint32_t tempInt = 0;
		tempInt |= (uint32_t)change_value[i * 4] << 24;
        tempInt |= (uint32_t)change_value[i * 4 + 1] << 16;
		tempInt |= (uint32_t)change_value[i * 4 + 2] << 8;
		tempInt |= (uint32_t)change_value[i * 4 + 3];
        tempN[i] = tempInt;
		tempH[i] = tempInt;
	}
	tempN[8] = 0;
	
	uint64_t size = tempBlock.size();
	while (size < 256)
	{
		uint32_t s0 = tick4B(tempBlock, size, 15);
		uint32_t s1 = tick4B(tempBlock, size, 2);
		uint32_t s2 = tick4B(tempBlock, size, 16);
		uint32_t s3 = tick4B(tempBlock, size, 7);
		s0 = CRMB(s0, 7) ^ CRMB(s0, 18) ^ (s0 >> 3);
		s1 = CRMB(s1, 17) ^ CRMB(s1, 19) ^ (s1 >> 10);
		uint32_t append = s0 + s1 + s2 + s3;
		for (int i0 = 0; i0 < 4; i0++)
		{
			tempBlock.push_back((uint8_t)(append << i0 * 8 >> 24));
		}
        size += 4;
	}
	for (int i0 = 0; i0 < 64; i0++)
	{
		uint32_t T1 = function1_64(tempN[4], tempN[5], tempN[6], tempN[7], tempBlock, size, i0);
		uint32_t T2 = function2_64(tempN[0], tempN[1], tempN[2]);
		tempN[3] += T1;
		tempN[7] = T1 + T2;
		for (int j = 8; j > 0; j--)
		{
			tempN[j] = tempN[j - 1];
		}
		tempN[0] = tempN[8];
	}
	for (int i1 = 0; i1 < 8; i1++)
	{
		tempH[i1] += tempN[i1];
		tempN[i1] = tempH[i1];
	}

	for (int i = 0; i < 8; i++)
	{
		for (int i0 = 0; i0 < 4; i0++)
		{
			change_value[i * 4 + i0] = (uint8_t)((tempH[i] >> (24 - i0 * 8)) & 0xFF);
		}
	}
}
void dog_hash::SHA2::b224::single_update(dog_data::Data plain, dog_data::Data& change_value)
{
	if (plain.size() != 64)
	{
		throw HashException("plain size is not 64", __FILE__, __FUNCTION__, __LINE__);
	}
	dog_data::Data tempBlock = std::move(plain);
	uint32_t tempN[9], tempH[8];
	for (int i = 0; i < 8; i++)
	{
		uint32_t tempInt = 0;
		tempInt |= (uint32_t)change_value[i * 4] << 24;
		tempInt |= (uint32_t)change_value[i * 4 + 1] << 16;
		tempInt |= (uint32_t)change_value[i * 4 + 2] << 8;
		tempInt |= (uint32_t)change_value[i * 4 + 3];
		tempN[i] = tempInt;
		tempH[i] = tempInt;
	}
	tempN[8] = 0;

	uint64_t size = tempBlock.size();
	while (size < 256)
	{
		uint32_t s0 = tick4B(tempBlock, size, 15);
		uint32_t s1 = tick4B(tempBlock, size, 2);
		uint32_t s2 = tick4B(tempBlock, size, 16);
		uint32_t s3 = tick4B(tempBlock, size, 7);
		s0 = CRMB(s0, 7) ^ CRMB(s0, 18) ^ (s0 >> 3);
		s1 = CRMB(s1, 17) ^ CRMB(s1, 19) ^ (s1 >> 10);
		uint32_t append = s0 + s1 + s2 + s3;
		for (int i0 = 0; i0 < 4; i0++)
		{
			tempBlock.push_back((uint8_t)(append << i0 * 8 >> 24));
		}
		size += 4;
	}
	for (int i0 = 0; i0 < 64; i0++)
	{
		uint32_t T1 = function1_64(tempN[4], tempN[5], tempN[6], tempN[7], tempBlock, tempBlock.size(), i0);
		uint32_t T2 = function2_64(tempN[0], tempN[1], tempN[2]);
		tempN[3] += T1;
		tempN[7] = T1 + T2;
		for (int j = 8; j > 0; j--)
		{
			tempN[j] = tempN[j - 1];
		}
		tempN[0] = tempN[8];
	}
	for (int i1 = 0; i1 < 8; i1++)
	{
		tempH[i1] += tempN[i1];
		tempN[i1] = tempH[i1];
	}

	for (int i = 0; i < 8; i++)
	{
		for (int i0 = 0; i0 < 4; i0++)
		{
			change_value[i * 4 + i0] = (uint8_t)((tempH[i] >> (24 - i0 * 8)) & 0xFF);
		}
	}
}

void dog_hash::SHA2::b512::single_update(dog_data::Data plain, dog_data::Data& change_value)
{
	if (plain.size() != 128)
	{
		throw HashException("plain size is not 64", __FILE__, __FUNCTION__, __LINE__);
	}
	dog_data::Data tempBlock = std::move(plain);
	uint64_t tempN[9], tempH[8];
	for (int i = 0; i < 8; i++)
	{
		uint64_t tempInt = 0;
		tempInt |= (uint64_t)change_value[i * 8] << 56;
		tempInt |= (uint64_t)change_value[i * 8 + 1] << 48;
		tempInt |= (uint64_t)change_value[i * 8 + 2] << 40;
		tempInt |= (uint64_t)change_value[i * 8 + 3] << 32;
		tempInt |= (uint64_t)change_value[i * 8 + 4] << 24;
		tempInt |= (uint64_t)change_value[i * 8 + 5] << 16;
		tempInt |= (uint64_t)change_value[i * 8 + 6] << 8;
		tempInt |= (uint64_t)change_value[i * 8 + 7];
		tempN[i] = tempInt;
		tempH[i] = tempInt;
	}
	tempN[8] = 0;
	uint64_t size = tempBlock.size();
	while (size < 640)
	{
		uint64_t s0 = tick8B(tempBlock, size, 15);
		uint64_t s1 = tick8B(tempBlock, size, 2);
		uint64_t s2 = tick8B(tempBlock, size, 16);
		uint64_t s3 = tick8B(tempBlock, size, 7);
		s0 = CRMB(s0, 1) ^ CRMB(s0, 8) ^ (s0 >> 7);
		s1 = CRMB(s1, 19) ^ CRMB(s1, 61) ^ (s1 >> 6);
		uint64_t append = s0 + s1 + s2 + s3;
		for (int i0 = 0; i0 < 8; i0++)
		{
			tempBlock.push_back((uint8_t)(append << i0 * 8 >> 56));
		}
		size += 8;
	}
	for (int i0 = 0; i0 < 80; i0++)
	{
		uint64_t T1 = function1_128(tempN[4], tempN[5], tempN[6], tempN[7], tempBlock, size, i0);
		uint64_t T2 = function2_128(tempN[0], tempN[1], tempN[2]);
		tempN[3] += T1;
		tempN[7] = T1 + T2;
		for (int j = 8; j > 0; j--)
		{
			tempN[j] = tempN[j - 1];
		}
		tempN[0] = tempN[8];
	}
	for (int i1 = 0; i1 < 8; i1++)
	{
		tempH[i1] += tempN[i1];
		tempN[i1] = tempH[i1];
	}
	for (int i = 0; i < 8; i++)
	{
		for (int i0 = 0; i0 < 8; i0++)
		{
			change_value[i * 8 + i0] = (uint8_t)((tempH[i] >> (56 - i0 * 8)) & 0xFF);
		}
	}
}
void dog_hash::SHA2::b384::single_update(dog_data::Data plain, dog_data::Data& change_value)
{
	if (plain.size() != 128)
	{
		throw HashException("plain size is not 64", __FILE__, __FUNCTION__, __LINE__);
	}
	dog_data::Data tempBlock = std::move(plain);
	uint64_t tempN[9], tempH[8];
	for (int i = 0; i < 8; i++)
	{
		uint64_t tempInt = 0;
		tempInt |= (uint64_t)change_value[i * 8] << 56;
		tempInt |= (uint64_t)change_value[i * 8 + 1] << 48;
		tempInt |= (uint64_t)change_value[i * 8 + 2] << 40;
		tempInt |= (uint64_t)change_value[i * 8 + 3] << 32;
		tempInt |= (uint64_t)change_value[i * 8 + 4] << 24;
		tempInt |= (uint64_t)change_value[i * 8 + 5] << 16;
		tempInt |= (uint64_t)change_value[i * 8 + 6] << 8;
		tempInt |= (uint64_t)change_value[i * 8 + 7];
		tempN[i] = tempInt;
		tempH[i] = tempInt;
	}
	tempN[8] = 0;
	uint64_t size = tempBlock.size();
	while (size < 640)
	{
		uint64_t s0 = tick8B(tempBlock, size, 15);
		uint64_t s1 = tick8B(tempBlock, size, 2);
		uint64_t s2 = tick8B(tempBlock, size, 16);
		uint64_t s3 = tick8B(tempBlock, size, 7);
		s0 = CRMB(s0, 1) ^ CRMB(s0, 8) ^ (s0 >> 7);
		s1 = CRMB(s1, 19) ^ CRMB(s1, 61) ^ (s1 >> 6);
		uint64_t append = s0 + s1 + s2 + s3;
		for (int i0 = 0; i0 < 8; i0++)
		{
			tempBlock.push_back((uint8_t)(append << i0 * 8 >> 56));
		}
		size += 8;
	}
	for (int i0 = 0; i0 < 80; i0++)
	{
		uint64_t T1 = function1_128(tempN[4], tempN[5], tempN[6], tempN[7], tempBlock, size, i0);
		uint64_t T2 = function2_128(tempN[0], tempN[1], tempN[2]);
		tempN[3] += T1;
		tempN[7] = T1 + T2;
		for (int j = 8; j > 0; j--)
		{
			tempN[j] = tempN[j - 1];
		}
		tempN[0] = tempN[8];
	}
	for (int i1 = 0; i1 < 8; i1++)
	{
		tempH[i1] += tempN[i1];
		tempN[i1] = tempH[i1];
	}
	for (int i = 0; i < 8; i++)
	{
		for (int i0 = 0; i0 < 8; i0++)
		{
			change_value[i * 8 + i0] = (uint8_t)((tempH[i] >> (56 - i0 * 8)) & 0xFF);
		}
	}
}

std::string dog_hash::SM3::get_config(std::string name, uint64_t effective)
{
	return name + "-" + std::to_string(effective);
}

//SM3
uint32_t dog_hash::SM3::CLMB(uint32_t i, uint64_t n)
{
	int temp = n % 32;
	return (i << temp) | i >> (32 - temp);
}
uint32_t dog_hash::SM3::SM3tick4B(dog_data::Data& data, uint64_t index)
{
	return (uint32_t)(data[4 * index] << 24) + (uint32_t)(data[4 * index + 1] << 16) + (uint32_t)(data[4 * index + 2] << 8) + (uint32_t)(data[4 * index + 3]);
}
uint32_t dog_hash::SM3::functionP1_SM3(dog_data::Data& data, uint64_t index)
{
	uint32_t w1 = SM3tick4B(data, index - 16);
	uint32_t w2 = SM3tick4B(data, index - 9);
	uint32_t w3 = SM3tick4B(data, index - 3);
	uint32_t w4 = SM3tick4B(data, index - 13);
	uint32_t w5 = SM3tick4B(data, index - 6);
	uint32_t W0 = (w1 ^ w2 ^ (CLMB(w3, 15)));
	uint32_t _P = W0 ^ CLMB(W0, 15) ^ CLMB(W0, 23);
	return _P ^ CLMB(w4, 7) ^ w5;
}
uint32_t dog_hash::SM3::functionFF1_SM3(uint32_t a, uint32_t b, uint32_t c, int i)
{
	if (i < 16)
	{
		return a ^ b ^ c;
	}
	else
	{
		return (a & b) | (a & c) | (b & c);
	}
}
uint32_t dog_hash::SM3::functionGG1_SM3(uint32_t a, uint32_t b, uint32_t c, int i)
{
	if (i < 16)
	{
		return a ^ b ^ c;
	}
	else
	{
		return (a & b) | (~a & c);
	}
}

void dog_hash::SM3::b256::single_update(dog_data::Data plain, dog_data::Data& change_value)
{
	if (plain.size() != 64)
	{
		throw HashException("plain size is not 64", __FILE__, __FUNCTION__, __LINE__);
	}
	dog_data::Data tempBlock = std::move(plain);
	uint32_t tempN[8], tempH[8];
	for (int i = 0; i < 8; i++)
	{
		uint32_t tempInt = 0;
		tempInt |= (uint32_t)change_value[i * 4] << 24;
		tempInt |= (uint32_t)change_value[i * 4 + 1] << 16;
		tempInt |= (uint32_t)change_value[i * 4 + 2] << 8;
		tempInt |= (uint32_t)change_value[i * 4 + 3];
		tempN[i] = tempInt;
		tempH[i] = tempInt;
	}
	for (int i0 = 16; i0 < 68; i0++)
	{
		uint32_t W = functionP1_SM3(tempBlock, i0);
		for (int i1 = 0; i1 < 4; i1++)
		{
			tempBlock.push_back((uint8_t)(W << i1 * 8 >> 24));
		}
	}
	for (int i0 = 0; i0 < 64; i0++)
	{
		uint32_t W = SM3tick4B(tempBlock, i0) ^ SM3tick4B(tempBlock, i0 + 4);
		for (int i1 = 0; i1 < 4; i1++)
		{
			tempBlock.push_back((uint8_t)(W << i1 * 8 >> 24));
		}
	}
	for (int i0 = 0; i0 < 64; i0++)
	{
		uint32_t T = (i0 < 16) ? (0x79cc4519) : (0x7a879d8a);
		uint32_t SS1 = CLMB((CLMB(tempN[0], 12) + tempN[4] + CLMB(T, i0)), 7);
		uint32_t SS2 = SS1 ^ CLMB(tempN[0], 12);
		uint32_t TT1 = functionFF1_SM3(tempN[0], tempN[1], tempN[2], i0) + tempN[3] + SS2 + SM3tick4B(tempBlock, i0 + 68);
		uint32_t TT2 = functionGG1_SM3(tempN[4], tempN[5], tempN[6], i0) + tempN[7] + SS1 + SM3tick4B(tempBlock, i0);
		tempN[3] = tempN[2];
		tempN[2] = CLMB(tempN[1], 9);
		tempN[1] = tempN[0];
		tempN[0] = TT1;
		tempN[7] = tempN[6];
		tempN[6] = CLMB(tempN[5], 19);
		tempN[5] = tempN[4];
		tempN[4] = TT2 ^ CLMB(TT2, 9) ^ CLMB(TT2, 17);
	}
	for (int i0 = 0; i0 < 8; i0++)
	{
		tempH[i0] = tempH[i0] ^ tempN[i0];
		tempN[i0] = tempH[i0];
	}
	for (int i = 0; i < 8; i++)
	{
		for (int i0 = 0; i0 < 4; i0++)
		{
			change_value[i * 4 + i0] = (uint8_t)((tempH[i] >> (24 - i0 * 8)) & 0xFF);
		}
	}
}

dog_hash::HashConfig::HashConfig(std::string name, std::string region)
{
	this->name = name;
	this->region = region;
}

//常量区
namespace dog_hash
{
	namespace SHA2
	{
		const std::string name = "SHA2";
		const std::string effective_region = "32,28|64,48";
		const HashConfig config = HashConfig(name, effective_region);
		const uint32_t k_256[64] = {
				0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
				0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
				0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
				0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
				0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
				0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
				0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
				0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2 };
		namespace b256
		{
			const dog_data::Data IV = "6A09E667BB67AE853C6EF372A54FF53A510E527F9B05688C1F83D9AB5BE0CD19";
			const dog_number::BigInteger MAX = "18446744073709551615";
			const uint64_t EFFECTIVE_SIZE = 32;
			const uint64_t BLOCK_SIZE = 64;
			const uint64_t NUMBER_SIZE = 8;
		}
		namespace b224
		{
			const dog_data::Data IV = "C1059ED8367CD5073070DD17F70E5939FFC00B316858151164F98FA7BEFA4FA4";
			const dog_number::BigInteger MAX = "18446744073709551615";
			const uint64_t EFFECTIVE_SIZE = 28;
			const uint64_t BLOCK_SIZE = 64;
			const uint64_t NUMBER_SIZE = 8;
		}
		const uint64_t k_512[80] = {
			0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
			0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
			0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
			0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
			0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
			0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
			0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
			0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
			0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
			0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
			0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
			0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
			0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
			0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
			0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
			0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
			0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
			0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
			0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
			0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817 };
		namespace b384
		{
			const dog_data::Data IV = "CBBB9D5DC1059ED8629A292A367CD5079159015A3070DD17152FECD8F70E593967332667FFC00B318EB44A8768581511DB0C2E0D64F98FA747B5481DBEFA4FA4";
			const dog_number::BigInteger MAX = "340282366920938463463374607431768211455";
			const uint64_t EFFECTIVE_SIZE = 48;
			const uint64_t BLOCK_SIZE = 128;
			const uint64_t NUMBER_SIZE = 16;
		}
		namespace b512
		{
			const dog_data::Data IV = "6A09E667F3BCC908BB67AE8584CAA73B3C6EF372FE94F82BA54FF53A5F1D36F1510E527FADE682D19B05688C2B3E6C1F1F83D9ABFB41BD6B5BE0CD19137E2179";
			const dog_number::BigInteger MAX = "340282366920938463463374607431768211455";
			const uint64_t EFFECTIVE_SIZE = 64;
			const uint64_t BLOCK_SIZE = 128;
			const uint64_t NUMBER_SIZE = 16;
		}
	}

	namespace SM3
	{
		const std::string name = "SM3";
		const std::string effective_region = "32";
		const HashConfig config = HashConfig(name, effective_region);
		namespace b256
		{
			const dog_data::Data IV = "7380166F4914B2B9172442D7DA8A0600A96F30BC163138AAE38DEE4DB0FB0E4E";
			const dog_number::BigInteger MAX = "18446744073709551615";
			const uint64_t EFFECTIVE_SIZE = 32;
			const uint64_t BLOCK_SIZE = 64;
			const uint64_t NUMBER_SIZE = 8;
		}
	}

	const std::vector<HashConfig> list = { SHA2::config, SM3::config };
}