#include "hash_method.h"

dog_hash::HashException::HashException(const char* msg, const char* file, const char* function, uint64_t line)
{
	this->msg = std::format("{}:{}\n at {}({}:{})", typeid(*this).name(), msg, function, file, line);
}
const char* dog_hash::HashException::what() const throw()
{
	return this->msg.c_str();
}


dog_hash::hash_crypher::hash_crypher(std::string sign)
{
	if (sign == SHA2::SHA256)
	{
		this->type = SHA2::SHA256;
		this->max = SHA2::SHA256_MAX;

		this->initial_value = SHA2::SHA256_IV;
		this->effective_size = SHA2::SHA256_EFFECTIVE_SIZE;

		this->block_size = SHA2::SHA256_BLOCK_SIZE;
		this->number_size = SHA2::SHA256_NUMBER_SIZE;
		this->hash_function = SHA2::SHA256_update;
	}
	else if (sign == SHA2::SHA224)
	{
		this->type = SHA2::SHA224;
		this->max = SHA2::SHA224_MAX;

		this->initial_value = SHA2::SHA224_IV;
		this->effective_size = SHA2::SHA224_EFFECTIVE_SIZE;

		this->block_size = SHA2::SHA224_BLOCK_SIZE;
		this->number_size = SHA2::SHA224_NUMBER_SIZE;
		this->hash_function = SHA2::SHA224_update;
	}
	else if (sign == SHA2::SHA384)
	{
		this->type = SHA2::SHA384;
		this->max = SHA2::SHA384_MAX;

		this->initial_value = SHA2::SHA384_IV;
		this->effective_size = SHA2::SHA384_EFFECTIVE_SIZE;

		this->block_size = SHA2::SHA384_BLOCK_SIZE;
		this->number_size = SHA2::SHA384_NUMBER_SIZE;
		this->hash_function = SHA2::SHA384_update;
	}
	else if (sign == SHA2::SHA512)
	{
		this->type = SHA2::SHA512;
		this->max = SHA2::SHA512_MAX;

		this->initial_value = SHA2::SHA512_IV;
		this->effective_size = SHA2::SHA512_EFFECTIVE_SIZE;

		this->block_size = SHA2::SHA512_BLOCK_SIZE;
		this->number_size = SHA2::SHA512_NUMBER_SIZE;
		this->hash_function = SHA2::SHA512_update;
	}
	else if (sign == SM3::SM3)
	{
		this->type = SM3::SM3;
		this->max = SM3::SM3_MAX;

		this->initial_value = SM3::SM3_IV;
		this->effective_size = SM3::SM3_EFFECTIVE_SIZE;

		this->block_size = SM3::SM3_BLOCK_SIZE;
		this->number_size = SM3::SM3_NUMBER_SIZE;
		this->hash_function = SM3::SM3_update;

	}
	else
	{
		throw dog_hash::HashException("Unknown hash type", __FILE__, __FUNCTION__, __LINE__);
	}
}
void dog_hash::hash_crypher::update(dog_data::Data data)
{
	//std::cout << initial_value.getHexString() << std::endl;
	uint64_t size = data.size();
	if (size == this->block_size)
	{
		hash_function(data, this->initial_value);
		this->total += this->block_size << 3;
	}
	else if (size > (this->block_size))
	{
		while (size > (this->block_size))
		{
			data.pop_back();
		}
		hash_function(data, this->initial_value);
		this->total += this->block_size << 3;
	}
	else if (size < (this->block_size))
	{
		this->total += size * 8;
		data.push_back(0x80);
		size++;
		//DogData::print::block(data);
		if (size <= (this->block_size - this->number_size))
		{

			while (data.size() < (this->block_size - this->number_size))
			{
				data.push_back(0x00);
			}

			std::vector<uint8_t> temp_number = this->total.get_bytes();
			while (temp_number.size() < (this->number_size))
			{
				temp_number.insert(temp_number.begin(), 0x00);
			}
			for (uint8_t& i : temp_number)
			{
				data.push_back(i);
			}

			hash_function(data, this->initial_value);

			this->is_effective = true;
		}
		else
		{
			//DogData::print::block(data);
			while (data.size() < this->block_size)
			{
				data.push_back(0x00);
			}
			hash_function(data, this->initial_value);

			dog_data::Data temp_block;
			temp_block.reserve(this->block_size);
			for (int i = 0; i < (this->block_size - this->number_size); i++)
			{
				temp_block.push_back(0x00);
			}
			std::vector<uint8_t> temp_number = this->total.get_bytes();
			
			while (temp_number.size() < (this->number_size))
			{
				temp_number.insert(temp_number.begin(), 0x00);
			}
			for (uint8_t& i : temp_number)
			{
				temp_block.push_back((uint8_t)i);
			}
			hash_function(temp_block, this->initial_value);
			//DogData::print::block(temp_block);

			this->is_effective = true;
		}

	}
	//DogData::print::block(data);
	
}
void dog_hash::hash_crypher::init()
{
	this->total = 0;
	if (type == SHA2::SHA256)
	{
		this->initial_value = SHA2::SHA256_IV;
	}
	else if (type == SHA2::SHA224)
	{
		this->initial_value = SHA2::SHA224_IV;
	}
	else if (type == SHA2::SHA384)
	{
		this->initial_value = SHA2::SHA384_IV;
	}
	else if (type == SHA2::SHA512)
	{
		this->initial_value = SHA2::SHA512_IV;
	}
	else if (type == SM3::SM3)
	{
		this->initial_value = SM3::SM3_IV;
	}
	else
	{
		throw dog_hash::HashException("Unknown hash type", __FILE__, __FUNCTION__, __LINE__);
	}
	this->is_effective = false;
}
void dog_hash::hash_crypher::finish()
{
	if (!this->is_effective)
	{
		dog_data::Data temp_block;
		temp_block.reserve(this->block_size);
		temp_block.push_back(0x80);
		for (int i = 1; i < (this->block_size - this->number_size); i++)
		{
			temp_block.push_back(0x00);
		}
		std::string number = this->total.get_num(16, true);
		while (number.size() < (this->number_size*2))
		{
			number = "0" + number;
		}
		dog_data::Data temp_number = number.c_str();
		for (uint8_t& i : temp_number)
		{
			temp_block.push_back(i);
		}
		hash_function(temp_block, this->initial_value);
		//DogData::print::block(temp_block);
		this->is_effective = true;
	}
}
dog_data::Data dog_hash::hash_crypher::get_hash()
{
	return this->initial_value.sub_by_pos(0, this->effective_size);
}
std::string dog_hash::hash_crypher::get_type() const
{
	return this->type;
}
dog_data::Data dog_hash::hash_crypher::getDataHash(dog_data::Data data)
{
	uint64_t size = 0;
	while (size < data.size())
	{
		this->update(data.sub_by_pos(size, size + this->block_size));
		size += this->block_size;
	}
	this->finish();
	dog_data::Data res = this->get_hash();
	this->init();
	return res;
}
dog_data::Data dog_hash::hash_crypher::getStringHash(std::string data)
{
	return this->getDataHash(dog_data::Data(data.c_str(), 0));
}
dog_data::Data dog_hash::hash_crypher::streamHash(hash_crypher& crypher, std::istream& data)
{
	uint8_t block_size = crypher.block_size;
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
void dog_hash::hash_crypher::streamHashp(hash_crypher& crypher, std::istream& data,std::atomic<double>* progress, dog_data::Data* result)
{
	uint8_t block_size = crypher.block_size;
	data.seekg(0, std::ios::end);
	uint64_t file_size = data.tellg();
	data.seekg(0, std::ios::beg);
	dog_data::Data temp(block_size);
	for (uint64_t i = 0; i < (file_size / block_size); i++)
	{
		data.read((char*)temp.data(), block_size);
		crypher.update(temp);
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

void dog_hash::SHA2::SHA256_update(dog_data::Data plain, dog_data::Data& change_value)
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
void dog_hash::SHA2::SHA224_update(dog_data::Data plain, dog_data::Data& change_value)
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

void dog_hash::SHA2::SHA512_update(dog_data::Data plain, dog_data::Data& change_value)
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
void dog_hash::SHA2::SHA384_update(dog_data::Data plain, dog_data::Data& change_value)
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

void dog_hash::SM3::SM3_update(dog_data::Data plain, dog_data::Data& change_value)
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
