#include "hash_method.h"

DogHash::hash_exception::hash_exception(const char* msg, const char* file, const char* function, uint64_t line)
{
	this->msg = std::format("{}:{}\n at {}({}:{})", typeid(*this).name(), msg, function, file, line);
}
const char* DogHash::hash_exception::what() const throw()
{
	return this->msg.c_str();
}


DogHash::hash_crypher::hash_crypher(std::string sign)
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
		throw DogHash::hash_exception("Unknown hash type", __FILE__, __FUNCTION__, __LINE__);
	}
}
void DogHash::hash_crypher::update(DogData::Data data)
{
	//std::cout << initial_value.getHexString() << std::endl;
	Ullong size = data.size();
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

			std::vector<byte> temp_number = this->total.getBytes();
			while (temp_number.size() < (this->number_size))
			{
				temp_number.insert(temp_number.begin(), 0x00);
			}
			for (byte& i : temp_number)
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

			DogData::Data temp_block;
			temp_block.reserve(this->block_size);
			for (int i = 0; i < (this->block_size - this->number_size); i++)
			{
				temp_block.push_back(0x00);
			}
			std::vector<byte> temp_number = this->total.getBytes();
			
			while (temp_number.size() < (this->number_size))
			{
				temp_number.insert(temp_number.begin(), 0x00);
			}
			for (byte& i : temp_number)
			{
				temp_block.push_back((byte)i);
			}
			hash_function(temp_block, this->initial_value);
			//DogData::print::block(temp_block);

			this->is_effective = true;
		}

	}
	//DogData::print::block(data);
	
}
void DogHash::hash_crypher::init()
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
		throw DogHash::hash_exception("Unknown hash type", __FILE__, __FUNCTION__, __LINE__);
	}
	this->is_effective = false;
}
void DogHash::hash_crypher::finish()
{
	if (!this->is_effective)
	{
		DogData::Data temp_block;
		temp_block.reserve(this->block_size);
		temp_block.push_back(0x80);
		for (int i = 1; i < (this->block_size - this->number_size); i++)
		{
			temp_block.push_back(0x00);
		}
		std::string number = this->total.getUpHEX();
		while (number.size() < (this->number_size*2))
		{
			number = "0" + number;
		}
		DogData::Data temp_number = number.c_str();
		for (byte& i : temp_number)
		{
			temp_block.push_back(i);
		}
		hash_function(temp_block, this->initial_value);
		//DogData::print::block(temp_block);
		this->is_effective = true;
	}
}
DogData::Data DogHash::hash_crypher::get_hash()
{
	return this->initial_value.sub_by_pos(0, this->effective_size);
}
std::string DogHash::hash_crypher::get_type() const
{
	return this->type;
}
DogData::Data DogHash::hash_crypher::getDataHash(DogData::Data data)
{
	Ullong size = 0;
	while (size < data.size())
	{
		this->update(data.sub_by_pos(size, size + this->block_size));
		size += this->block_size;
	}
	this->finish();
	DogData::Data res = this->get_hash();
	this->init();
	return res;
}
DogData::Data DogHash::hash_crypher::getStringHash(std::string data)
{
	return this->getDataHash(DogData::Data(data.c_str(), 0));
}
DogData::Data DogHash::hash_crypher::streamHash(hash_crypher& crypher, std::istream& data)
{
	byte block_size = crypher.block_size;
	data.seekg(0, std::ios::end);
	Ullong file_size = data.tellg();
	data.seekg(0, std::ios::beg);
	DogData::Data temp(block_size);
	for (Ullong i = 0; i < (file_size / block_size); i++)
	{
		data.read((char*)temp.data(), block_size);
		crypher.update(temp);
		//printf("\rProgress: %.2f%%", crypher.progress * 100);
	}
	data.read((char*)temp.data(), block_size);
	for (Ullong i = 0; i < block_size - data.gcount(); i++) { temp.pop_back(); }
	crypher.update(temp);
	crypher.finish();
	DogData::Data res = crypher.get_hash();
	data.seekg(0, std::ios::end);
	crypher.init();
	return res;
}
void DogHash::hash_crypher::streamHashp(hash_crypher& crypher, std::istream& data,std::atomic<double>* progress, DogData::Data* result)
{
	byte block_size = crypher.block_size;
	data.seekg(0, std::ios::end);
	Ullong file_size = data.tellg();
	data.seekg(0, std::ios::beg);
	DogData::Data temp(block_size);
	for (Ullong i = 0; i < (file_size / block_size); i++)
	{
		data.read((char*)temp.data(), block_size);
		crypher.update(temp);
		progress->store(progress->load() + block_size * 1.0 / file_size);
	}
	data.read((char*)temp.data(), block_size);
	for (Ullong i = 0; i < block_size - data.gcount(); i++) { temp.pop_back(); }
	crypher.update(temp);
	crypher.finish();
	progress->store(progress->load() + block_size * 1.0 / file_size);
	*result = crypher.get_hash();
	progress->store(1.0);
	data.seekg(0, std::ios::end);
	crypher.init();
}

//SHA2
DogHash::Uint DogHash::SHA2::tick4B(DogData::Data& data, Ullong size, Ullong index)
{
	return (Uint)(data[size - index * 4] << 24) + (data[size - index * 4 + 1] << 16) + (data[size - index * 4 + 2] << 8) + (data[size - index * 4 + 3]);
}
DogHash::Uint DogHash::SHA2::CRMB(Uint i, Ullong n)
{
	//circleRightMoveBit
	int temp = n % 32;
	return (i >> temp) | (i << 32 - temp);
}
DogHash::Uint DogHash::SHA2::function1_64(Uint e, Uint f, Uint g, Uint h, DogData::Data& block, int size, int n)
{
	Uint S1 = CRMB(e, 6) ^ CRMB(e, 11) ^ CRMB(e, 25);
	//printf("%0x\n", S1);
	Uint ch = (e & f) ^ ((~e) & g);
	Uint k = k_256[n];
	Uint w = tick4B(block, size, (64 - n));
	//printf("%0x\n", w);
	return h + S1 + ch + k + w;
}
DogHash::Uint DogHash::SHA2::function2_64(Uint a, Uint b, Uint c)
{
	Uint S0 = CRMB(a, 2) ^ CRMB(a, 13) ^ CRMB(a, 22);
	Uint maj = (a & b) ^ (a & c) ^ (b & c);
	return S0 + maj;
}
DogHash::Ullong DogHash::SHA2::tick8B(DogData::Data& data, Ullong size, Ullong index)
{
	Ullong res = 0;
	res += ((Ullong)data[size - index * 8 + 0] << (56 - 8 * 0));
	res += ((Ullong)data[size - index * 8 + 1] << (56 - 8 * 1));
	res += ((Ullong)data[size - index * 8 + 2] << (56 - 8 * 2));
	res += ((Ullong)data[size - index * 8 + 3] << (56 - 8 * 3));
	res += ((Ullong)data[size - index * 8 + 4] << (56 - 8 * 4));
	res += ((Ullong)data[size - index * 8 + 5] << (56 - 8 * 5));
	res += ((Ullong)data[size - index * 8 + 6] << (56 - 8 * 6));
	res += ((Ullong)data[size - index * 8 + 7] << (56 - 8 * 7));
	return res;
}
DogHash::Ullong DogHash::SHA2::CRMB(Ullong i, Ullong n)
{
	int temp = n % 64;
	return (i >> temp) | (i << 64 - temp);
}
DogHash::Ullong DogHash::SHA2::function1_128(Ullong e, Ullong f, Ullong g, Ullong h, DogData::Data& block, int size, int n)
{
	Ullong S1 = CRMB(e, 14) ^ CRMB(e, 18) ^ CRMB(e, 41);
	Ullong ch = (e & f) ^ ((~e) & g);
	Ullong temp = h + S1 + ch + k_512[n] + tick8B(block, size, (80 - n));
	return temp;
}
DogHash::Ullong DogHash::SHA2::function2_128(Ullong a, Ullong b, Ullong c)
{
	Ullong S0 = CRMB(a, 28) ^ CRMB(a, 34) ^ CRMB(a, 39);
	Ullong maj = (a & b) ^ (a & c) ^ (b & c);
	return S0 + maj;
}

void DogHash::SHA2::SHA256_update(DogData::Data plain, DogData::Data& change_value)
{
	if (plain.size() != 64)
	{
		throw hash_exception("plain size is not 64", __FILE__, __FUNCTION__, __LINE__);
	}
	DogData::Data tempBlock = std::move(plain);
	Uint tempN[9], tempH[8];
	for (int i = 0; i < 8; i++)
	{
		Uint tempInt = 0;
		tempInt |= (Uint)change_value[i * 4] << 24;
        tempInt |= (Uint)change_value[i * 4 + 1] << 16;
		tempInt |= (Uint)change_value[i * 4 + 2] << 8;
		tempInt |= (Uint)change_value[i * 4 + 3];
        tempN[i] = tempInt;
		tempH[i] = tempInt;
	}
	tempN[8] = 0;
	
	Ullong size = tempBlock.size();
	while (size < 256)
	{
		Uint s0 = tick4B(tempBlock, size, 15);
		Uint s1 = tick4B(tempBlock, size, 2);
		Uint s2 = tick4B(tempBlock, size, 16);
		Uint s3 = tick4B(tempBlock, size, 7);
		s0 = CRMB(s0, 7) ^ CRMB(s0, 18) ^ (s0 >> 3);
		s1 = CRMB(s1, 17) ^ CRMB(s1, 19) ^ (s1 >> 10);
		Uint append = s0 + s1 + s2 + s3;
		for (int i0 = 0; i0 < 4; i0++)
		{
			tempBlock.push_back((byte)(append << i0 * 8 >> 24));
		}
        size += 4;
	}
	for (int i0 = 0; i0 < 64; i0++)
	{
		Uint T1 = function1_64(tempN[4], tempN[5], tempN[6], tempN[7], tempBlock, size, i0);
		Uint T2 = function2_64(tempN[0], tempN[1], tempN[2]);
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
			change_value[i * 4 + i0] = (byte)((tempH[i] >> (24 - i0 * 8)) & 0xFF);
		}
	}
}
void DogHash::SHA2::SHA224_update(DogData::Data plain, DogData::Data& change_value)
{
	if (plain.size() != 64)
	{
		throw hash_exception("plain size is not 64", __FILE__, __FUNCTION__, __LINE__);
	}
	DogData::Data tempBlock = std::move(plain);
	Uint tempN[9], tempH[8];
	for (int i = 0; i < 8; i++)
	{
		Uint tempInt = 0;
		tempInt |= (Uint)change_value[i * 4] << 24;
		tempInt |= (Uint)change_value[i * 4 + 1] << 16;
		tempInt |= (Uint)change_value[i * 4 + 2] << 8;
		tempInt |= (Uint)change_value[i * 4 + 3];
		tempN[i] = tempInt;
		tempH[i] = tempInt;
	}
	tempN[8] = 0;

	Ullong size = tempBlock.size();
	while (size < 256)
	{
		Uint s0 = tick4B(tempBlock, size, 15);
		Uint s1 = tick4B(tempBlock, size, 2);
		Uint s2 = tick4B(tempBlock, size, 16);
		Uint s3 = tick4B(tempBlock, size, 7);
		s0 = CRMB(s0, 7) ^ CRMB(s0, 18) ^ (s0 >> 3);
		s1 = CRMB(s1, 17) ^ CRMB(s1, 19) ^ (s1 >> 10);
		Uint append = s0 + s1 + s2 + s3;
		for (int i0 = 0; i0 < 4; i0++)
		{
			tempBlock.push_back((byte)(append << i0 * 8 >> 24));
		}
		size += 4;
	}
	for (int i0 = 0; i0 < 64; i0++)
	{
		Uint T1 = function1_64(tempN[4], tempN[5], tempN[6], tempN[7], tempBlock, tempBlock.size(), i0);
		Uint T2 = function2_64(tempN[0], tempN[1], tempN[2]);
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
			change_value[i * 4 + i0] = (byte)((tempH[i] >> (24 - i0 * 8)) & 0xFF);
		}
	}
}

void DogHash::SHA2::SHA512_update(DogData::Data plain, DogData::Data& change_value)
{
	if (plain.size() != 128)
	{
		throw hash_exception("plain size is not 64", __FILE__, __FUNCTION__, __LINE__);
	}
	DogData::Data tempBlock = std::move(plain);
	Ullong tempN[9], tempH[8];
	for (int i = 0; i < 8; i++)
	{
		Ullong tempInt = 0;
		tempInt |= (Ullong)change_value[i * 8] << 56;
		tempInt |= (Ullong)change_value[i * 8 + 1] << 48;
		tempInt |= (Ullong)change_value[i * 8 + 2] << 40;
		tempInt |= (Ullong)change_value[i * 8 + 3] << 32;
		tempInt |= (Ullong)change_value[i * 8 + 4] << 24;
		tempInt |= (Ullong)change_value[i * 8 + 5] << 16;
		tempInt |= (Ullong)change_value[i * 8 + 6] << 8;
		tempInt |= (Ullong)change_value[i * 8 + 7];
		tempN[i] = tempInt;
		tempH[i] = tempInt;
	}
	tempN[8] = 0;
	Ullong size = tempBlock.size();
	while (size < 640)
	{
		Ullong s0 = tick8B(tempBlock, size, 15);
		Ullong s1 = tick8B(tempBlock, size, 2);
		Ullong s2 = tick8B(tempBlock, size, 16);
		Ullong s3 = tick8B(tempBlock, size, 7);
		s0 = CRMB(s0, 1) ^ CRMB(s0, 8) ^ (s0 >> 7);
		s1 = CRMB(s1, 19) ^ CRMB(s1, 61) ^ (s1 >> 6);
		Ullong append = s0 + s1 + s2 + s3;
		for (int i0 = 0; i0 < 8; i0++)
		{
			tempBlock.push_back((byte)(append << i0 * 8 >> 56));
		}
		size += 8;
	}
	for (int i0 = 0; i0 < 80; i0++)
	{
		Ullong T1 = function1_128(tempN[4], tempN[5], tempN[6], tempN[7], tempBlock, size, i0);
		Ullong T2 = function2_128(tempN[0], tempN[1], tempN[2]);
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
			change_value[i * 8 + i0] = (byte)((tempH[i] >> (56 - i0 * 8)) & 0xFF);
		}
	}
}
void DogHash::SHA2::SHA384_update(DogData::Data plain, DogData::Data& change_value)
{
	if (plain.size() != 128)
	{
		throw hash_exception("plain size is not 64", __FILE__, __FUNCTION__, __LINE__);
	}
	DogData::Data tempBlock = std::move(plain);
	Ullong tempN[9], tempH[8];
	for (int i = 0; i < 8; i++)
	{
		Ullong tempInt = 0;
		tempInt |= (Ullong)change_value[i * 8] << 56;
		tempInt |= (Ullong)change_value[i * 8 + 1] << 48;
		tempInt |= (Ullong)change_value[i * 8 + 2] << 40;
		tempInt |= (Ullong)change_value[i * 8 + 3] << 32;
		tempInt |= (Ullong)change_value[i * 8 + 4] << 24;
		tempInt |= (Ullong)change_value[i * 8 + 5] << 16;
		tempInt |= (Ullong)change_value[i * 8 + 6] << 8;
		tempInt |= (Ullong)change_value[i * 8 + 7];
		tempN[i] = tempInt;
		tempH[i] = tempInt;
	}
	tempN[8] = 0;
	Ullong size = tempBlock.size();
	while (size < 640)
	{
		Ullong s0 = tick8B(tempBlock, size, 15);
		Ullong s1 = tick8B(tempBlock, size, 2);
		Ullong s2 = tick8B(tempBlock, size, 16);
		Ullong s3 = tick8B(tempBlock, size, 7);
		s0 = CRMB(s0, 1) ^ CRMB(s0, 8) ^ (s0 >> 7);
		s1 = CRMB(s1, 19) ^ CRMB(s1, 61) ^ (s1 >> 6);
		Ullong append = s0 + s1 + s2 + s3;
		for (int i0 = 0; i0 < 8; i0++)
		{
			tempBlock.push_back((byte)(append << i0 * 8 >> 56));
		}
		size += 8;
	}
	for (int i0 = 0; i0 < 80; i0++)
	{
		Ullong T1 = function1_128(tempN[4], tempN[5], tempN[6], tempN[7], tempBlock, size, i0);
		Ullong T2 = function2_128(tempN[0], tempN[1], tempN[2]);
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
			change_value[i * 8 + i0] = (byte)((tempH[i] >> (56 - i0 * 8)) & 0xFF);
		}
	}
}

//SM3
DogHash::Uint DogHash::SM3::CLMB(Uint i, Ullong n)
{
	int temp = n % 32;
	return (i << temp) | i >> (32 - temp);
}
DogHash::Uint DogHash::SM3::SM3tick4B(DogData::Data& data, Ullong index)
{
	return (Uint)(data[4 * index] << 24) + (Uint)(data[4 * index + 1] << 16) + (Uint)(data[4 * index + 2] << 8) + (Uint)(data[4 * index + 3]);
}
DogHash::Uint DogHash::SM3::functionP1_SM3(DogData::Data& data, Ullong index)
{
	Uint w1 = SM3tick4B(data, index - 16);
	Uint w2 = SM3tick4B(data, index - 9);
	Uint w3 = SM3tick4B(data, index - 3);
	Uint w4 = SM3tick4B(data, index - 13);
	Uint w5 = SM3tick4B(data, index - 6);
	Uint W0 = (w1 ^ w2 ^ (CLMB(w3, 15)));
	Uint _P = W0 ^ CLMB(W0, 15) ^ CLMB(W0, 23);
	return _P ^ CLMB(w4, 7) ^ w5;
}
DogHash::Uint DogHash::SM3::functionFF1_SM3(Uint a, Uint b, Uint c, int i)
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
DogHash::Uint DogHash::SM3::functionGG1_SM3(Uint a, Uint b, Uint c, int i)
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

void DogHash::SM3::SM3_update(DogData::Data plain, DogData::Data& change_value)
{
	if (plain.size() != 64)
	{
		throw hash_exception("plain size is not 64", __FILE__, __FUNCTION__, __LINE__);
	}
	DogData::Data tempBlock = std::move(plain);
	Uint tempN[8], tempH[8];
	for (int i = 0; i < 8; i++)
	{
		Uint tempInt = 0;
		tempInt |= (Uint)change_value[i * 4] << 24;
		tempInt |= (Uint)change_value[i * 4 + 1] << 16;
		tempInt |= (Uint)change_value[i * 4 + 2] << 8;
		tempInt |= (Uint)change_value[i * 4 + 3];
		tempN[i] = tempInt;
		tempH[i] = tempInt;
	}
	for (int i0 = 16; i0 < 68; i0++)
	{
		Uint W = functionP1_SM3(tempBlock, i0);
		for (int i1 = 0; i1 < 4; i1++)
		{
			tempBlock.push_back((byte)(W << i1 * 8 >> 24));
		}
	}
	for (int i0 = 0; i0 < 64; i0++)
	{
		Uint W = SM3tick4B(tempBlock, i0) ^ SM3tick4B(tempBlock, i0 + 4);
		for (int i1 = 0; i1 < 4; i1++)
		{
			tempBlock.push_back((byte)(W << i1 * 8 >> 24));
		}
	}
	for (int i0 = 0; i0 < 64; i0++)
	{
		Uint T = (i0 < 16) ? (0x79cc4519) : (0x7a879d8a);
		Uint SS1 = CLMB((CLMB(tempN[0], 12) + tempN[4] + CLMB(T, i0)), 7);
		Uint SS2 = SS1 ^ CLMB(tempN[0], 12);
		Uint TT1 = functionFF1_SM3(tempN[0], tempN[1], tempN[2], i0) + tempN[3] + SS2 + SM3tick4B(tempBlock, i0 + 68);
		Uint TT2 = functionGG1_SM3(tempN[4], tempN[5], tempN[6], i0) + tempN[7] + SS1 + SM3tick4B(tempBlock, i0);
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
			change_value[i * 4 + i0] = (byte)((tempH[i] >> (24 - i0 * 8)) & 0xFF);
		}
	}
}
