#include "symmetric_encryption.h"

DogCryption::cryption_config::cryption_config(const std::string& cryption_algorithm, const Ullong block_size, const Ullong key_size, const std::string& padding_function, const std::string& mult_function, bool using_iv, bool using_padding, bool using_parallelism)
{
	this->cryption_algorithm = cryption_algorithm;
	this->block_size = block_size;
	this->key_size = key_size;
	this->using_padding = using_padding;
	this->padding_function = padding_function;
	this->mult_function = mult_function;
	this->using_iv = using_iv;
	this->using_parallelism = using_parallelism;
	this->is_valid = true;
}
DogData::Data DogCryption::cryption_config::to_data() const
{
	DogData::Data res; res.reserve(this->cryption_algorithm.size() +
		int(log2(block_size)) / 8 + int(log2(key_size)) / 8 + 5);
	res.push_back((byte)this->cryption_algorithm.size());
	for (byte c : this->cryption_algorithm)
	{
		res.push_back(c);
	}
	res.push_back((byte)((log2(block_size) / 8) + 1));
	for (int i = 0; i < 64; i += 8)
	{
		if (block_size >> (56 - i))
		{
			res.push_back(block_size >> (56 - i));
		}
	}
	res.push_back((byte)((log2(key_size) / 8) + 1));
	for (int i = 0; i < 64; i += 8)
	{
		if (key_size >> (56 - i))
		{
			res.push_back(key_size >> (56 - i));
		}
	}

	{
		using namespace DogCryption::padding;
		if (padding_function == PKCS7)
		{
			res.push_back(0x00);
		}
		else if (padding_function == ZERO)
		{
			res.push_back(0x01);
		}
		else if (padding_function == ANSI923)
		{
			res.push_back(0x02);
		}
		else if (padding_function == ISO7816_4)
		{
			res.push_back(0x03);
		}
		else if (padding_function == ISO10126)
		{
			res.push_back(0x04);
		}
		else
		{
			throw cryption_exception("invalid padding function", __FILE__, __FUNCTION__, __LINE__);
		}
	}

	{
		using namespace DogCryption::mode;
		if (mult_function == ECB)
		{
			res.push_back(0x00);
		}
		else if (mult_function == CBC)
		{
			res.push_back(0x01);
		}
		else if (mult_function == OFB)
		{
			res.push_back(0x02);
		}
		else if (mult_function == CTR)
		{
			res.push_back(0x03);
		}
		else if (mult_function == CFB1)
		{
			res.push_back(0x04);
		}
		else if (mult_function == CFB8)
		{
			res.push_back(0x05);
		}
		else if (mult_function == CFB128)
		{
			res.push_back(0x06);
		}
		else
		{
			throw cryption_exception("invalid encryption mode", __FILE__, __FUNCTION__, __LINE__);
		}

	}

	if (using_iv)
	{
		res.push_back(0x01);
	}
	else
	{
		res.push_back(0x00);
	}
	if (using_padding)
	{
		res.push_back(0x01);
	}
	else
	{
		res.push_back(0x00);
	}
	if (using_parallelism)
	{
		res.push_back(0x01);
	}
	else
	{
		res.push_back(0x00);
	}
	return res;
}
std::string DogCryption::cryption_config::to_string() const
{
	std::string result = std::format("{}_{}_{}_{}_{}_{}_{}",
		this->cryption_algorithm, this->block_size, this->key_size,
		this->padding_function, (this->using_padding ? "UsingPadding" : "NotUsingPadding"),
		this->mult_function, (using_iv ? "UsingIV" : "NotUsingIV"));
	return result;
}
DogCryption::cryption_config DogCryption::cryption_config::get_cryption_config(std::istream& config_stream, bool return_start)
{
	char cryption_algorithm_size = config_stream.get();
	if (cryption_algorithm_size == 0)
	{
		throw cryption_exception("invalid cryption config in algorithm", __FILE__, __FUNCTION__, __LINE__);
	}
	char* cryption_algorithm_chars = new char[cryption_algorithm_size + 1];
	for (int i = 0; i < cryption_algorithm_size; i++)
	{
		cryption_algorithm_chars[i] = config_stream.get();;
	}
	cryption_algorithm_chars[cryption_algorithm_size] = '\0';
	std::string cryption_algorithm(cryption_algorithm_chars);
	delete[] cryption_algorithm_chars;
	char block_size_size = config_stream.get();
	if (block_size_size == 0)
	{
		throw cryption_exception("invalid cryption config in block size", __FILE__, __FUNCTION__, __LINE__);
	}
	Ullong block_size = 0;
	for (int i = 0; i < block_size_size; ++i)
	{
		Ullong temp_number = config_stream.get();
		block_size |= (temp_number << i * 8);
	}
	if (block_size == 0)
	{
		throw cryption_exception("invalid cryption config in block size", __FILE__, __FUNCTION__, __LINE__);
	}
	char key_size_size = config_stream.get();
	if (key_size_size == 0)
	{
		throw cryption_exception("invalid cryption config in key size", __FILE__, __FUNCTION__, __LINE__);
	}
	Ullong key_size = 0;
	for (int i = 0; i < key_size_size; ++i)
	{
		Ullong temp_number = config_stream.get();
		key_size |= (temp_number << i * 8);
	}
	if (key_size == 0)
	{
		throw cryption_exception("invalid cryption config in key size", __FILE__, __FUNCTION__, __LINE__);
	}
	std::string padding_function_name;
	{
		using namespace DogCryption::padding;
		switch (config_stream.get())
		{
		case 0:
		{
			padding_function_name = PKCS7;
			break;
		}
		case 1:
		{
			padding_function_name = ZERO;
			break;
		}
		case 2:
		{
			padding_function_name = ANSI923;
			break;
		}
		case 3:
		{
			padding_function_name = ISO7816_4;
			break;
		}
		case 4:
		{
			padding_function_name = ISO10126;
			break;
		}
		default:
		{
			throw cryption_exception("invalid padding function", __FILE__, __FUNCTION__, __LINE__);
		}
		}

	}
	std::string mode_function_name;
	{
		using namespace DogCryption::mode;
		switch (config_stream.get())
		{
		case 0:
		{
			mode_function_name = ECB;
			break;
		}
		case 1:
		{
			mode_function_name = CBC;
			break;
		}
		case 2:
		{
			mode_function_name = OFB;
			break;
		}
		case 3:
		{
			mode_function_name = CTR;
			break;
		}
		case 4:
		{
			mode_function_name = CFB1;
			break;
		}
		case 5:
		{
			mode_function_name = CFB8;
			break;
		}
		case 6:
		{
			mode_function_name = CFB128;
			break;
		}
		default:
		{
			throw cryption_exception("invalid encryption mode", __FILE__, __FUNCTION__, __LINE__);
		}
		}

	}
	bool using_iv = config_stream.get();
	bool using_padding = config_stream.get();
	bool using_parallelism = config_stream.get();
	//std::cout << config_stream.tellg() << std::endl;
	if (return_start) { config_stream.seekg(0, std::ios::beg); }
	return DogCryption::cryption_config(
		cryption_algorithm, block_size, key_size,
		padding_function_name,
		mode_function_name, using_iv, using_padding, using_parallelism
	);
}
DogCryption::cryption_config DogCryption::cryption_config::get_cryption_config(const DogData::Data& config_data)
{
	Ullong pos = 0;
	char cryption_algorithm_size = config_data[pos++];
	char* cryption_algorithm_chars = new char[cryption_algorithm_size + 1];
	for (int i = 0; i < cryption_algorithm_size; i++)
	{
		cryption_algorithm_chars[i] = config_data[pos++];;
	}
	cryption_algorithm_chars[cryption_algorithm_size] = '\0';
	std::string cryption_algorithm(cryption_algorithm_chars);
	delete[] cryption_algorithm_chars;
	char block_size_size = config_data[pos++];
	Ullong block_size = 0;
	for (int i = 0; i < block_size_size; ++i)
	{
		Ullong temp_number = config_data[pos++];
		block_size |= (temp_number << i * 8);
	}

	char key_size_size = config_data[pos++];
	Ullong key_size = 0;
	for (int i = 0; i < key_size_size; ++i)
	{
		Ullong temp_number = config_data[pos++];
		key_size |= (temp_number << i * 8);
	}

	std::string padding_function_name;
	{
		using namespace DogCryption::padding;
		switch (config_data[pos++])
		{
		case 0:
		{
			padding_function_name = PKCS7;
			break;
		}
		case 1:
		{
			padding_function_name = ZERO;
			break;
		}
		case 2:
		{
			padding_function_name = ANSI923;
			break;
		}
		case 3:
		{
			padding_function_name = ISO7816_4;
			break;
		}
		case 4:
		{
			padding_function_name = ISO10126;
			break;
		}
		default:
		{
			throw cryption_exception("invalid padding function", __FILE__, __FUNCTION__, __LINE__);
		}
		}

	}
	std::string mode_function_name;
	{
		using namespace DogCryption::mode;
		switch (config_data[pos++])
		{
		case 0:
		{
			mode_function_name = ECB;
			break;
		}
		case 1:
		{
			mode_function_name = CBC;
			break;
		}
		case 2:
		{
			mode_function_name = OFB;
			break;
		}
		case 3:
		{
			mode_function_name = CTR;
			break;
		}
		case 4:
		{
			mode_function_name = CFB1;
			break;
		}
		case 5:
		{
			mode_function_name = CFB8;
			break;
		}
		case 6:
		{
			mode_function_name = CFB128;
			break;
		}
		default:
		{
			throw cryption_exception("invalid encryption mode", __FILE__, __FUNCTION__, __LINE__);
		}
		}

	}
	bool using_iv = config_data[pos++];
	bool using_padding = config_data[pos++];
	bool using_parallelism = config_data[pos++];
	//std::cout << pos << std::endl;
	return DogCryption::cryption_config(
		cryption_algorithm, block_size, key_size,
		padding_function_name,
		mode_function_name, using_iv, using_padding, using_parallelism
	);
}

DogCryption::cryption_exception::cryption_exception(const char* msg, const char* file, const char* function, uint64_t line)
{
	this->msg = std::format("{}:{}\n at {}({}:{})", typeid(*this).name(), msg, function, file, line);
}
const char* DogCryption::cryption_exception::what() const throw()
{
	return this->msg.c_str();
}

//cryptor
DogCryption::cryptor::cryptor(
	const std::string& cryption_algorithm, const Ullong block_size, const Ullong key_size, 
	const std::string& padding_function, 
	const std::string& mult_function, bool using_iv, bool using_padding, bool using_parallelism)
{
	this->cryption_algorithm = cryption_algorithm;
	if (cryption_algorithm == DogCryption::AES::AES)
	{
		using namespace DogCryption::AES;
		this->block_size = AES_BLOCK_SIZE;
		this->extend_key = AES_extend_key;
		if ((key_size != AES128_KEY_SIZE) && (key_size != AES192_KEY_SIZE) && (key_size != AES256_KEY_SIZE))
		{
			throw cryption_exception("invalid key size for AES,AES only support 16B 24B 32B", __FILE__, __FUNCTION__, __LINE__);
		}
		this->key_size = key_size;

		this->block_encryption = AESEncodingMachineSelf;
		this->block_decryption = AESDecodingMachineSelf;
	}
	else if (cryption_algorithm == DogCryption::SM4::SM4)
	{
		using namespace DogCryption::SM4;
		this->block_size = SM4_BLOCK_SIZE;
		this->extend_key = SM4_extend_key;
		if (key_size != SM4_KEY_SIZE)
		{
			throw cryption_exception("invalid key size for SM4,SM4 only support 16B", __FILE__, __FUNCTION__, __LINE__);
		}
		this->key_size = key_size;

		this->block_encryption = SM4EncodingMachineSelf;
		this->block_decryption = SM4DecodingMachineSelf;
	}
	else
	{
		throw cryption_exception("invalid cryption algorithm", __FILE__, __FUNCTION__, __LINE__);
	}

	{
		using namespace DogCryption::padding;
		this->padding_function = padding_function;
		if (padding_function == PKCS7)
		{
			this->padding = PKCS7_padding;
			this->unpadding = PKCS7_unpadding;
		}
		else if (padding_function == ZERO)
		{
			this->padding = ZERO_padding;
			this->unpadding = ZERO_unpadding;
		}
		else if (padding_function == ANSI923)
		{
			this->padding = ANSI923_padding;
			this->unpadding = ANSI923_unpadding;
		}
		else if (padding_function == ISO7816_4)
		{
			this->padding = ISO7816_4_padding;
			this->unpadding = ISO7816_4_unpadding;
		}
		else if (padding_function == ISO10126)
		{
			this->padding = ISO10126_padding;
			this->unpadding = ISO10126_unpadding;
		}
		else if (padding_function == NONE)
		{
			this->padding = NONE_padding;
			this->unpadding = NONE_unpadding;
		}
		else
		{
            throw cryption_exception("invalid padding function", __FILE__, __FUNCTION__, __LINE__);
		}
	}

	{
		using namespace DogCryption::mode;
		this->mult_function = mult_function;
		if (mult_function == ECB)
		{
			this->using_iv = using_iv;
			this->using_padding = true;
			this->using_parallelism = using_parallelism;

			this->mult_encrypt = encrypt_ECB;
			this->mult_decrypt = decrypt_ECB;

			this->stream_encrypt = encrypt_ECB_stream;
			this->stream_decrypt = decrypt_ECB_stream;

			this->stream_encryptp = encrypt_ECB_streamp;
			this->stream_decryptp = decrypt_ECB_streamp;
		}
		else if (mult_function == CBC)
		{
			this->using_iv = true;
			this->using_padding = true;
			this->using_parallelism = false;

			this->mult_encrypt = encrypt_CBC;
			this->mult_decrypt = decrypt_CBC;

			this->stream_encrypt = encrypt_CBC_stream;
			this->stream_decrypt = decrypt_CBC_stream;

			this->stream_encryptp = encrypt_CBC_streamp;
			this->stream_decryptp = decrypt_CBC_streamp;
		}
		else if (mult_function == OFB)
		{
			this->using_iv = true;
			this->using_padding = using_padding;
			this->using_parallelism = false;

			this->mult_encrypt = encrypt_OFB;
			this->mult_decrypt = decrypt_OFB;

			this->stream_encrypt = encrypt_OFB_stream;
			this->stream_decrypt = decrypt_OFB_stream;

			this->stream_encryptp = encrypt_OFB_streamp;
			this->stream_decryptp = decrypt_OFB_streamp;
		}
		else if (mult_function == CTR)
		{
			this->using_iv = true;
			this->using_padding = using_padding;
			this->using_parallelism = using_parallelism;

			this->mult_encrypt = encrypt_CTR;
			this->mult_decrypt = decrypt_CTR;

			this->stream_encrypt = encrypt_CTR_stream;
			this->stream_decrypt = decrypt_CTR_stream;

			this->stream_encryptp = encrypt_CTR_streamp;
			this->stream_decryptp = decrypt_CTR_streamp;
		}
		else if (mult_function == CFB1)
		{
			this->using_iv = true;
			this->using_padding = using_padding;
			this->using_parallelism = false;

			this->mult_encrypt = encrypt_CFB1;
			this->mult_decrypt = decrypt_CFB1;

			this->stream_encrypt = encrypt_CFB1_stream;
			this->stream_decrypt = decrypt_CFB1_stream;

			this->stream_encryptp = encrypt_CFB1_streamp;
			this->stream_decryptp = decrypt_CFB1_streamp;
		}
		else if (mult_function == CFB8)
		{
			this->using_iv = true;
			this->using_padding = using_padding;
			this->using_parallelism = false;

			this->mult_encrypt = encrypt_CFB8;
			this->mult_decrypt = decrypt_CFB8;

			this->stream_encrypt = encrypt_CFB8_stream;
			this->stream_decrypt = decrypt_CFB8_stream;

			this->stream_encryptp = encrypt_CFB8_streamp;
			this->stream_decryptp = decrypt_CFB8_streamp;
		}
		else if (mult_function == CFB128)
		{
			this->using_iv = true;
			this->using_padding = using_padding;
			this->using_parallelism = false;

			this->mult_encrypt = encrypt_CFB128;
			this->mult_decrypt = decrypt_CFB128;

			this->stream_encrypt = encrypt_CFB128_stream;
			this->stream_decrypt = decrypt_CFB128_stream;

			this->stream_encryptp = encrypt_CFB128_streamp;
			this->stream_decryptp = decrypt_CFB128_streamp;
		}
		else
		{
			throw cryption_exception("invalid encryption mode", __FILE__, __FUNCTION__, __LINE__);
		}

	}

	this->is_valid = true;
}
void DogCryption::cryptor::set_key(DogData::Data key)
{
	this->original_key = key;
	this->key = this->extend_key(key, this->key_size);
	this->is_setting_key = true;
}
void DogCryption::cryptor::swap(cryptor& other)
{
	std::swap(this->is_valid, other.is_valid);
	std::swap(this->cryption_algorithm, other.cryption_algorithm);
	std::swap(this->block_size, other.block_size);
	std::swap(this->key_size, other.key_size);
	std::swap(this->padding_function, other.padding_function);
	std::swap(this->mult_function, other.mult_function);
	std::swap(this->using_iv, other.using_iv);
	std::swap(this->using_padding, other.using_padding);
	std::swap(this->using_parallelism, other.using_parallelism);
	std::swap(this->reback_size, other.reback_size);
	std::swap(this->key, other.key);
	std::swap(this->original_key, other.original_key);
	std::swap(this->padding, other.padding);
	std::swap(this->unpadding, other.unpadding);
	std::swap(this->block_encryption, other.block_encryption);
	std::swap(this->block_decryption, other.block_decryption);
	std::swap(this->mult_encrypt, other.mult_encrypt);
	std::swap(this->mult_decrypt, other.mult_decrypt);
	std::swap(this->stream_encrypt, other.stream_encrypt);
	std::swap(this->stream_decrypt, other.stream_decrypt);
}
void DogCryption::cryptor::swap_config(cryptor& other)
{
	std::swap(this->is_valid, other.is_valid);
	std::swap(this->cryption_algorithm, other.cryption_algorithm);
	std::swap(this->block_size, other.block_size);
	std::swap(this->key_size, other.key_size);
	std::swap(this->padding_function, other.padding_function);
	std::swap(this->mult_function, other.mult_function);
	std::swap(this->using_iv, other.using_iv);
	std::swap(this->using_padding, other.using_padding);
	std::swap(this->using_parallelism, other.using_parallelism);
	std::swap(this->reback_size, other.reback_size);

	std::swap(this->padding, other.padding);
	std::swap(this->unpadding, other.unpadding);
	std::swap(this->block_encryption, other.block_encryption);
	std::swap(this->block_decryption, other.block_decryption);
	std::swap(this->mult_encrypt, other.mult_encrypt);
	std::swap(this->mult_decrypt, other.mult_decrypt);
	std::swap(this->stream_encrypt, other.stream_encrypt);
	std::swap(this->stream_decrypt, other.stream_decrypt);
}
DogCryption::Ullong DogCryption::cryptor::get_block_size() const
{
	return this->block_size;
}
DogCryption::Ullong DogCryption::cryptor::get_key_size() const
{
	return this->key_size;
}
bool DogCryption::cryptor::get_using_iv() const
{
	return this->using_iv;
}
bool DogCryption::cryptor::get_using_padding() const
{
	return this->using_padding;
}
bool DogCryption::cryptor::get_using_parallelism() const
{
	return this->using_parallelism;
}
DogCryption::Ullong DogCryption::cryptor::get_reback_size() const
{
	return this->reback_size;
}
DogData::Data DogCryption::cryptor::get_original_key() const
{
	return this->original_key;
}
DogData::Data DogCryption::cryptor::get_available_key() const
{
	return this->key;
}
std::function<void(DogData::Data&, DogCryption::byte)> DogCryption::cryptor::get_padding() const
{
	return this->padding;
}
std::function<void(DogData::Data&, DogCryption::byte)> DogCryption::cryptor::get_unpadding() const
{
	return this->unpadding;
}
std::function<void(DogData::Data&, DogCryption::byte, const DogData::Data&, DogCryption::byte)> DogCryption::cryptor::get_block_encryption() const
{
	return this->block_encryption;
}
std::function<void(DogData::Data&, DogCryption::byte, const DogData::Data&, DogCryption::byte)> DogCryption::cryptor::get_block_decryption() const
{
	return this->block_decryption;
}
DogCryption::cryption_config DogCryption::cryptor::get_config()
{
	std::string cryption_algorithm = this->cryption_algorithm;
	std::string padding = this->padding_function;
	std::string mult_function = this->mult_function;
	DogCryption::cryption_config res(
		cryption_algorithm,this->block_size,this->key_size,
		padding,
		mult_function,this->using_iv,this->using_padding,this->using_parallelism
	);
	return res;
}

std::pair<DogData::Data, DogData::Data> DogCryption::cryptor::encrypt(DogData::Data iv, DogData::Data data)
{
	if(!this->is_valid)
	{
		throw cryption_exception("Cryptor is not valid because key is not set or key is invalid", __FILE__, __FUNCTION__, __LINE__);
	}
	if (this->using_iv)
	{
		return std::make_pair(iv, this->mult_encrypt(data, iv, *this));
	}
	else
	{
		return std::make_pair("", this->mult_encrypt(data, iv, *this));
	}
}
std::pair<DogData::Data, DogData::Data> DogCryption::cryptor::encrypt(DogData::Data data)
{
	if (!this->is_valid)
	{
		throw cryption_exception("Cryptor is not valid because key is not set or key is invalid", __FILE__, __FUNCTION__, __LINE__);
	}
	if (!this->is_setting_key)
	{
		throw cryption_exception("Cryptor is not valid because key is not set or key is invalid", __FILE__, __FUNCTION__, __LINE__);
	}
	if (this->using_iv)
	{
		DogData::Data iv = DogCryption::utils::randiv(this->block_size);
		return std::make_pair(iv, this->mult_encrypt(data, iv, *this));
	}
	else
	{
		return std::make_pair("", this->mult_encrypt(data, "", *this));
	}
}

DogData::Data DogCryption::cryptor::decrypt(std::pair<DogData::Data, DogData::Data> datas)
{
	if (!this->is_valid)
	{
		throw cryption_exception("Cryptor is not valid because key is not set or key is invalid", __FILE__, __FUNCTION__, __LINE__);
	}
	if (!this->is_setting_key)
	{
		throw cryption_exception("Cryptor is not valid because key is not set or key is invalid", __FILE__, __FUNCTION__, __LINE__);
	}
	return this->mult_decrypt(datas.second, datas.first, *this);
}
DogData::Data DogCryption::cryptor::decrypt(DogData::Data iv, DogData::Data data)
{
	if (!this->is_valid)
	{
		throw cryption_exception("Cryptor is not valid because key is not set or key is invalid", __FILE__, __FUNCTION__, __LINE__);
	}
	if (!this->is_setting_key)
	{
		throw cryption_exception("Cryptor is not valid because key is not set or key is invalid", __FILE__, __FUNCTION__, __LINE__);
	}
	return this->decrypt(std::make_pair(iv, data));
}

void DogCryption::cryptor::encrypt(std::istream& plain, std::ostream& crypt, DogData::Data iv, bool with_config)
{
	if (!this->is_valid)
	{
		throw cryption_exception("Cryptor is not valid because config is vaild", __FILE__, __FUNCTION__, __LINE__);
	}
	if (!this->is_setting_key)
	{
		throw cryption_exception("Cryptor is not valid because key is not set or key is invalid", __FILE__, __FUNCTION__, __LINE__);
	}
	if (with_config)
	{
		DogCryption::cryption_config config = this->get_config();
		DogData::Data config_data = config.to_data();
        crypt.write((char*)config_data.data(), config_data.size());
	}
	if (this->using_iv)
	{
		if (iv.size() < this->block_size) 
		{
			throw cryption_exception(std::format("IV size is not enough need {} now {}", this->block_size, iv.size()).c_str(), __FILE__, __FUNCTION__, __LINE__);
		}
		else
		{
			DogData::Data iv_ = iv.sub_by_len(0, this->block_size);
			crypt.write((char*)iv_.data(), this->block_size);
			this->stream_encrypt(plain, iv_, crypt, *this);
		}
	}
	else
	{
		this->stream_encrypt(plain, "", crypt, *this);
	}
}
void DogCryption::cryptor::encrypt(std::istream& plain, std::ostream& crypt, DogData::Data iv)
{
	if (!this->is_valid)
	{
		throw cryption_exception("Cryptor is not valid because key is not set or key is invalid", __FILE__, __FUNCTION__, __LINE__);
	}
	if (!this->is_setting_key)
	{
		throw cryption_exception("Cryptor is not valid because key is not set or key is invalid", __FILE__, __FUNCTION__, __LINE__);
	}
	if (this->using_iv)
	{
		if (iv.size() < this->block_size)
		{
			throw cryption_exception(std::format("IV size is not enough need {} now {}", this->block_size, iv.size()).c_str(), __FILE__, __FUNCTION__, __LINE__);
		}
		else
		{
			DogData::Data iv_ = iv.sub_by_len(0, this->block_size);
			crypt.write((char*)iv_.data(), this->block_size);
			this->stream_encrypt(plain, iv_, crypt, *this);
		}
	}
	else
	{
		this->stream_encrypt(plain, "", crypt, *this);
	}
}
DogData::Data DogCryption::cryptor::encrypt(std::istream& plain, std::ostream& crypt, bool with_config)
{
	if (!this->is_valid)
	{
		throw cryption_exception("Cryptor is not valid because key is not set or key is invalid", __FILE__, __FUNCTION__, __LINE__);
	}
	if (!this->is_setting_key)
	{
		throw cryption_exception("Cryptor is not valid because key is not set or key is invalid", __FILE__, __FUNCTION__, __LINE__);
	}
	if (with_config)
	{
		DogCryption::cryption_config config = this->get_config();
		DogData::Data config_data = config.to_data();
		crypt.write((char*)config_data.data(), config_data.size());
	}
	if (this->using_iv)
	{
		DogData::Data iv_ = DogCryption::utils::randiv(this->block_size);
		crypt.write((char*)iv_.data(), this->block_size);
		this->stream_encrypt(plain, iv_, crypt, *this);
		return iv_;
	}
	else
	{
		this->stream_encrypt(plain, "", crypt, *this);
		return DogData::EMPTY_DATA;
	}
}
DogData::Data DogCryption::cryptor::encryptp(std::istream& plain, std::ostream& crypt, bool with_config, std::atomic<double>* progress)
{
	if (!this->is_valid)
	{
		throw cryption_exception("Cryptor is not valid because key is not set or key is invalid", __FILE__, __FUNCTION__, __LINE__);
	}
	if (!this->is_setting_key)
	{
		throw cryption_exception("Cryptor is not valid because key is not set or key is invalid", __FILE__, __FUNCTION__, __LINE__);
	}
	if (with_config)
	{
		DogCryption::cryption_config config = this->get_config();
		DogData::Data config_data = config.to_data();
		crypt.write((char*)config_data.data(), config_data.size());
		crypt.flush();
	}
	if (this->using_iv)
	{
		DogData::Data iv_ = DogCryption::utils::randiv(this->block_size);
		crypt.write((char*)iv_.data(), this->block_size);
		this->stream_encryptp(plain, iv_, crypt, *this, progress);
		return iv_;
	}
	else
	{
		this->stream_encryptp(plain, "", crypt, *this, progress);
		return DogData::EMPTY_DATA;
	}
}
DogData::Data DogCryption::cryptor::encrypt(std::istream& plain, std::ostream& crypt)
{
	if (!this->is_valid)
	{
		throw cryption_exception("Cryptor is not valid because key is not set or key is invalid", __FILE__, __FUNCTION__, __LINE__);
	}
	if (!this->is_setting_key)
	{
		throw cryption_exception("Cryptor is not valid because key is not set or key is invalid", __FILE__, __FUNCTION__, __LINE__);
	}
	if (this->using_iv)
	{
		DogData::Data iv_ = DogCryption::utils::randiv(this->block_size);
		crypt.write((char*)iv_.data(), this->block_size);
		this->stream_encrypt(plain, iv_, crypt, *this);
		return iv_;
	}
	else
	{
		this->stream_encrypt(plain, "", crypt, *this);
		return DogData::EMPTY_DATA;
	}
}
DogData::Data DogCryption::cryptor::encryptp(std::istream& plain, std::ostream& crypt, std::atomic<double>* progress)
{
	if (!this->is_valid)
	{
		throw cryption_exception("Cryptor is not valid because key is not set or key is invalid", __FILE__, __FUNCTION__, __LINE__);
	}
	if (!this->is_setting_key)
	{
		throw cryption_exception("Cryptor is not valid because key is not set or key is invalid", __FILE__, __FUNCTION__, __LINE__);
	}
	if (this->using_iv)
	{
		DogData::Data iv_ = DogCryption::utils::randiv(this->block_size);
		crypt.write((char*)iv_.data(), this->block_size);
		this->stream_encryptp(plain, iv_, crypt, *this, progress);
		return iv_;
	}
	else
	{
		this->stream_encryptp(plain, "", crypt, *this, progress);
		return DogData::EMPTY_DATA;
	}
}

void DogCryption::cryptor::decrypt(std::istream& crypt, std::ostream& plain,bool with_config)
{
	std::unique_ptr<DogCryption::cryption_config> ori_config = nullptr;
	if (with_config)
	{
		ori_config = std::make_unique<DogCryption::cryption_config>(this->get_config());
		DogCryption::cryption_config config = DogCryption::cryption_config::get_cryption_config(crypt, false);
		DogCryption::cryptor(config).swap_config(*this);
	}
	if (!this->is_valid)
	{
		throw cryption_exception("Cryptor is not valid because key is not set or key is invalid", __FILE__, __FUNCTION__, __LINE__);
	}
	if (!this->is_setting_key)
	{
		throw cryption_exception("Cryptor is not valid because key is not set or key is invalid", __FILE__, __FUNCTION__, __LINE__);
	}
	DogData::Data iv_(this->block_size);
	if (this->using_iv)
	{
		crypt.read((char*)iv_.data(), this->block_size);
	}
	this->stream_decrypt(crypt, iv_, plain, *this);
	if (ori_config != nullptr) { DogCryption::cryptor(*ori_config).swap_config(*this); }
}
void DogCryption::cryptor::decryptp(std::istream& crypt, std::ostream& plain, bool with_config, std::atomic<double>* progress)
{
	std::unique_ptr<DogCryption::cryption_config> ori_config = nullptr;
	if (with_config)
	{
		ori_config = std::make_unique<DogCryption::cryption_config>(this->get_config());
		DogCryption::cryption_config config = DogCryption::cryption_config::get_cryption_config(crypt, false);
		DogCryption::cryptor(config).swap_config(*this);
	}
	if (!this->is_valid)
	{
		throw cryption_exception("Cryptor is not valid because key is not set or key is invalid", __FILE__, __FUNCTION__, __LINE__);
	}
	if (!this->is_setting_key)
	{
		throw cryption_exception("Cryptor is not valid because key is not set or key is invalid", __FILE__, __FUNCTION__, __LINE__);
	}
	DogData::Data iv_(this->block_size);
	if (this->using_iv)
	{
		crypt.read((char*)iv_.data(), this->block_size);
	}
	this->stream_decryptp(crypt, iv_, plain, *this, progress);
	if (ori_config != nullptr) { DogCryption::cryptor(*ori_config).swap_config(*this); }
}
void DogCryption::cryptor::decrypt(std::istream& crypt, std::ostream& plain)
{
	if (!this->is_valid)
	{
		throw cryption_exception("Cryptor is not valid because key is not set or key is invalid", __FILE__, __FUNCTION__, __LINE__);
	}
	if (!this->is_setting_key)
	{
		throw cryption_exception("Cryptor is not valid because key is not set or key is invalid", __FILE__, __FUNCTION__, __LINE__);
	}
	DogData::Data iv_(this->block_size);
	if (this->using_iv)
	{
		crypt.read((char*)iv_.data(), this->block_size);
	}
	this->stream_decrypt(crypt, iv_, plain, *this);
}
void DogCryption::cryptor::decryptp(std::istream& crypt, std::ostream& plain, std::atomic<double>* progress)
{
	if (!this->is_valid)
	{
		throw cryption_exception("Cryptor is not valid because key is not set or key is invalid", __FILE__, __FUNCTION__, __LINE__);
	}
	if (!this->is_setting_key)
	{
		throw cryption_exception("Cryptor is not valid because key is not set or key is invalid", __FILE__, __FUNCTION__, __LINE__);
	}
	DogData::Data iv_(this->block_size);
	if (this->using_iv)
	{
		crypt.read((char*)iv_.data(), this->block_size);
	}
	this->stream_decryptp(crypt, iv_, plain, *this, progress);
}

//padding&unpadding
void DogCryption::padding::NONE_padding(DogData::Data& data, byte block_size)
{
}
void DogCryption::padding::NONE_unpadding(DogData::Data& data, byte block_size)
{
}

void DogCryption::padding::PKCS7_padding(DogData::Data& data, byte block_size)
{
	if (data.size() > block_size)
	{
		throw cryption_exception("Data size is bigger than block size", __FILE__, __FUNCTION__, __LINE__);
	}
	byte end = block_size - data.size();
	for (byte i = 0; i < end; i++)
	{
		data.push_back(end);
	}
}
void DogCryption::padding::PKCS7_unpadding(DogData::Data& data, byte block_size)
{
	byte value = *data.rbegin();
	if ((Uint)value <= block_size)
	{
		for (Uint i = 0; i < value; i++)
		{
			data.pop_back();
		}
	}
}

void DogCryption::padding::ZERO_padding(DogData::Data& data, byte block_size)
{
	if (data.size() > block_size)
	{
		throw cryption_exception("Data size is bigger than block size", __FILE__, __FUNCTION__, __LINE__);
	}
	Ullong up_size = block_size - data.size();
	for (Ullong i = 0; i < up_size; i++)
	{
        data.push_back(0x00);
	}
}
void DogCryption::padding::ZERO_unpadding(DogData::Data& data, byte block_size)
{
	while (*data.rbegin() == 0x00)
	{
		data.pop_back();
		if (data.size() == 0) { return; }
	}
}

void DogCryption::padding::ANSI923_padding(DogData::Data& data, byte block_size)
{
	byte end = block_size - data.size();
	for (byte i = 0; i < end - 1; i++)
	{
		data.push_back(0x00);
	}
	data.push_back(end);
}
void DogCryption::padding::ANSI923_unpadding(DogData::Data& data, byte block_size)
{
	byte value = *data.rbegin();
	if ((Uint)value <= block_size)
	{
		for (Uint i = 0; i < value; i++)
		{
			data.pop_back();
		}
	}
}

void DogCryption::padding::ISO7816_4_padding(DogData::Data& data, byte block_size)
{
	if (data.size() > block_size)
	{
		throw cryption_exception("Data size is bigger than block size", __FILE__, __FUNCTION__, __LINE__);
	}
	byte end = block_size - data.size();
	data.push_back(0x80);
	for (byte i = 0; i < end - 1; i++)
	{
		data.push_back(0x00);
	}
}
void DogCryption::padding::ISO7816_4_unpadding(DogData::Data& data, byte block_size)
{
	while (*data.rbegin() == 0x00)
	{
		data.pop_back();
	}
	data.pop_back();
}

void DogCryption::padding::ISO10126_padding(DogData::Data& data, byte block_size)
{
	byte end = block_size - data.size();
	for (byte i = 0; i < end - 1; i++)
	{
        data.push_back(DogCryption::utils::rand_byte());
	}
    data.push_back(end);
}
void DogCryption::padding::ISO10126_unpadding(DogData::Data& data, byte block_size)
{
	byte value = *data.rbegin();
	if ((Uint)value <= block_size)
	{
		for (Uint i = 0; i < value; i++)
		{
			data.pop_back();
		}
	}
}

//utils
DogCryption::byte DogCryption::utils::rand_byte()
{
	std::random_device rd;
	return (byte)rd() % 128;
}
DogData::Data DogCryption::utils::squareXOR(DogData::Data& a, DogData::Data& b, Ullong size)
{
	DogData::Data res;
	res.reserve(size);
	Ullong n = a.size() < b.size() ? a.size() : b.size();
	for (Ullong i = 0; i < (n > size ? size : n); i++)
	{
		res.push_back(a.at(i) ^ b.at(i));
	}
	return res;
}
void DogCryption::utils::squareXOR_self(DogData::Data& a, DogData::Data& b, Ullong size)
{
	Ullong n = a.size() < b.size() ? a.size() : b.size();
	for (Ullong i = 0; i < (n > size ? size : n); i++)
	{
		a[i] ^= b[i];
	}
}
DogData::Data DogCryption::utils::randiv(byte block_size)
{
	DogData::Data iv(block_size);
	for (int i = 0; i < block_size; i++)
	{
		iv[i] = DogCryption::utils::rand_byte();
	}
	return iv;
}

double DogCryption::mode::update_progress(double progress, double progress_step, double progress_max)
{
	return progress + progress_step*1.0 / progress_max;
}

//multi_mode
DogData::Data DogCryption::mode::encrypt_ECB(DogData::Data plain, DogData::Data iv, DogCryption::cryptor& cryptor)
{
	DogData::Data res; byte block_size = cryptor.get_block_size();
	res.reserve(((plain.size() / block_size) + 1) * block_size);
	DogData::Data tempBlock;
	for (Ullong i0 = 0; i0 <= plain.size(); i0 += block_size)
	{
		tempBlock = plain.sub_by_pos(i0, i0 + block_size);
		if (tempBlock.size() < block_size) { cryptor.get_padding()(tempBlock, block_size); }
		cryptor.get_block_encryption()(tempBlock, block_size, cryptor.get_available_key(), cryptor.get_key_size());
		res += tempBlock;
		tempBlock.clear_leave_pos();
	}
	return res;
}
DogData::Data DogCryption::mode::decrypt_ECB(DogData::Data crypt, DogData::Data iv, DogCryption::cryptor& cryptor)
{
	byte block_size = cryptor.get_block_size();
	DogData::Data res; res.reserve(crypt.size());
	DogData::Data tempBlock(block_size);
	for (Ullong i0 = 0; i0 < crypt.size(); i0 += block_size)
	{
		tempBlock = crypt.sub_by_pos(i0, i0 + block_size);
		cryptor.get_block_decryption()(tempBlock, block_size, cryptor.get_available_key(), cryptor.get_key_size());
		res += tempBlock;
	}
	cryptor.get_unpadding()(res, block_size);
	return res;
}
void DogCryption::mode::encrypt_ECB_stream(std::istream& plain, DogData::Data iv, std::ostream& crypt, DogCryption::cryptor& cryptor)
{
	byte block_size = cryptor.get_block_size();
	plain.seekg(0, std::ios::end);
	Ullong file_size = plain.tellg();
	plain.seekg(0, std::ios::beg);
	
	DogData::Data tempBlock(block_size);
	while (plain.tellg() <= file_size - block_size)
	{
		plain.read((char*)tempBlock.data(), block_size);
		cryptor.get_block_encryption()(tempBlock, block_size, cryptor.get_available_key(), cryptor.get_key_size());
		crypt.write((char*)tempBlock.data(), block_size);
		//printf("%03ull%%\r", plain.tellg() * 100 / file_size);
	}
	plain.read((char*)tempBlock.data(), block_size);
	if (plain.gcount() < block_size)
	{
		for (Ullong i = 0; i < block_size - plain.gcount(); ++i) { tempBlock.pop_back(); }
		cryptor.get_padding()(tempBlock, block_size);
		
	}
	cryptor.get_block_encryption()(tempBlock, block_size, cryptor.get_available_key(), cryptor.get_key_size());
	crypt.write((char*)tempBlock.data(), block_size);
	crypt.flush();
	//printf("100%%\r");
}
void DogCryption::mode::decrypt_ECB_stream(std::istream& crypt, DogData::Data iv, std::ostream& plain, DogCryption::cryptor& cryptor)
{
	byte block_size = cryptor.get_block_size();
	Ullong now_pos = crypt.tellg();
	crypt.seekg(0, std::ios::end);
	Ullong file_size = crypt.tellg();
	crypt.seekg(now_pos);

	DogData::Data tempBlock(block_size);
	
	for (Ullong i = 0; i < (file_size - now_pos - 1) / block_size; ++i)
	{
		crypt.read((char*)tempBlock.data(), block_size);
		cryptor.get_block_decryption()(tempBlock, block_size, cryptor.get_available_key(), cryptor.get_key_size());
		plain.write((char*)tempBlock.data(), block_size);
		//printf("%03ull%%\r", crypt.tellg() * 100 / file_size);
	}
	crypt.read((char*)tempBlock.data(), block_size);
	cryptor.get_block_decryption()(tempBlock, block_size, cryptor.get_available_key(), cryptor.get_key_size());
	cryptor.get_unpadding()(tempBlock, block_size);
	plain.write((char*)tempBlock.data(), tempBlock.size());
	plain.flush();
	//printf("100%%\r");
}
void DogCryption::mode::encrypt_ECB_streamp(std::istream& plain, DogData::Data iv, std::ostream& crypt, DogCryption::cryptor& cryptor, std::atomic<double>* progress)
{
	byte block_size = cryptor.get_block_size();
	plain.seekg(0, std::ios::end);
	Ullong file_size = plain.tellg();
	plain.seekg(0, std::ios::beg);

	DogData::Data tempBlock(block_size);
	while (plain.tellg() <= file_size - block_size)
	{
		plain.read((char*)tempBlock.data(), block_size);
		cryptor.get_block_encryption()(tempBlock, block_size, cryptor.get_available_key(), cryptor.get_key_size());
		crypt.write((char*)tempBlock.data(), block_size);
		if (progress->load() < 0.0)
		{
			return;
		}
		progress->store(update_progress(progress->load(), block_size, file_size));
	}
	plain.read((char*)tempBlock.data(), block_size);
	if (plain.gcount() < block_size)
	{
		for (Ullong i = 0; i < block_size - plain.gcount(); ++i) { tempBlock.pop_back(); }
		cryptor.get_padding()(tempBlock, block_size);

	}
	cryptor.get_block_encryption()(tempBlock, block_size, cryptor.get_available_key(), cryptor.get_key_size());
	if (progress->load() < 0.0) { return; }
	progress->store(update_progress(progress->load(), block_size, file_size));
	crypt.write((char*)tempBlock.data(), block_size);
	crypt.flush();
	progress->store(1.0);
}
void DogCryption::mode::decrypt_ECB_streamp(std::istream& crypt, DogData::Data iv, std::ostream& plain, DogCryption::cryptor& cryptor, std::atomic<double>* progress)
{
	byte block_size = cryptor.get_block_size();
	Ullong now_pos = crypt.tellg();
	crypt.seekg(0, std::ios::end);
	Ullong file_size = crypt.tellg();
	crypt.seekg(now_pos);

	DogData::Data tempBlock(block_size);

	for (Ullong i = 0; i < (file_size - now_pos - 1) / block_size; ++i)
	{
		crypt.read((char*)tempBlock.data(), block_size);
		cryptor.get_block_decryption()(tempBlock, block_size, cryptor.get_available_key(), cryptor.get_key_size());
		plain.write((char*)tempBlock.data(), block_size);
		if (progress->load() < 0.0)
		{
			return;
		}
		progress->store(update_progress(progress->load(), block_size, file_size));
	}
	crypt.read((char*)tempBlock.data(), block_size);
	cryptor.get_block_decryption()(tempBlock, block_size, cryptor.get_available_key(), cryptor.get_key_size());
	cryptor.get_unpadding()(tempBlock, block_size);
	plain.write((char*)tempBlock.data(), tempBlock.size());
	if(progress->load()<0){return;}progress->store(update_progress(progress->load(), block_size, file_size));
	plain.flush();
	progress->store(1.0);
}

DogData::Data DogCryption::mode::encrypt_CBC(DogData::Data plain, DogData::Data iv, DogCryption::cryptor& cryptor)
{
	byte block_size = cryptor.get_block_size();
	DogData::Data res; res.reserve(((plain.size() / block_size) + 1) * block_size);
	DogData::Data tempBlock; tempBlock.reserve(block_size);
	DogData::Data tempKey = iv;
	for (Ullong i0 = 0; i0 <= plain.size(); i0 += block_size)
	{
		tempBlock = plain.sub_by_pos(i0, i0 + block_size);
		if (tempBlock.size() < block_size) { cryptor.get_padding()(tempBlock, block_size); }
		DogCryption::utils::squareXOR_self(tempBlock, tempKey, block_size);
		cryptor.get_block_encryption()(tempBlock, block_size, cryptor.get_available_key(), cryptor.get_key_size());
		res += tempBlock;
		tempKey = tempBlock;
	}
	return res;
}
DogData::Data DogCryption::mode::decrypt_CBC(DogData::Data crypt, DogData::Data iv, DogCryption::cryptor& cryptor)
{
	byte block_size = cryptor.get_block_size();
	DogData::Data res; res.reserve(((crypt.size() / block_size) + 1) * block_size);
	DogData::Data tempBlock(block_size);
	DogData::Data tempKey = iv;
	for (Ullong i0 = 0; i0 < crypt.size(); i0 += block_size)
	{
		tempBlock = crypt.sub_by_pos(i0, i0 + block_size);
		cryptor.get_block_decryption()(tempBlock, block_size, cryptor.get_available_key(), cryptor.get_key_size());
        DogCryption::utils::squareXOR_self(tempBlock, tempKey, block_size);
		res += tempBlock;
		tempKey = crypt.sub_by_pos(i0, i0 + block_size);
	}
	cryptor.get_unpadding()(res, block_size);
	return res;
}
void DogCryption::mode::encrypt_CBC_stream(std::istream& plain, DogData::Data iv, std::ostream& crypt, DogCryption::cryptor& cryptor)
{
	byte block_size = cryptor.get_block_size();
	plain.seekg(0, std::ios::end);
	Ullong file_size = plain.tellg();
	plain.seekg(0, std::ios::beg);

	DogData::Data tempBlock(block_size);
	DogData::Data tempKey = iv;
	while (plain.tellg() <= file_size - block_size)
	{
		plain.read((char*)tempBlock.data(), block_size);
		DogCryption::utils::squareXOR_self(tempBlock, tempKey, block_size);
		cryptor.get_block_encryption()(tempBlock, block_size, cryptor.get_available_key(), cryptor.get_key_size());
		crypt.write((char*)tempBlock.data(), block_size);
		tempKey = tempBlock;
	}
	plain.read((char*)tempBlock.data(), block_size);
	if (plain.gcount() < block_size)
	{
		for (Ullong i = 0; i < block_size - plain.gcount(); ++i) { tempBlock.pop_back(); }
		cryptor.get_padding()(tempBlock, block_size);
	}
	DogCryption::utils::squareXOR_self(tempBlock, tempKey, block_size);
	cryptor.get_block_encryption()(tempBlock, block_size, cryptor.get_available_key(), cryptor.get_key_size());
	crypt.write((char*)tempBlock.data(), block_size);
	crypt.flush();
}
void DogCryption::mode::decrypt_CBC_stream(std::istream& crypt, DogData::Data iv, std::ostream& plain, DogCryption::cryptor& cryptor)
{
	byte block_size = cryptor.get_block_size();
	Ullong now_pos = crypt.tellg();
	crypt.seekg(0, std::ios::end);
	Ullong file_size = crypt.tellg();
	crypt.seekg(now_pos);

	DogData::Data tempBlock(block_size);
	DogData::Data tempKey = iv;
	for (Ullong i = 0; i < (file_size - now_pos - 1) / block_size; ++i)
	{
		crypt.read((char*)tempBlock.data(), block_size);
		cryptor.get_block_decryption()(tempBlock, block_size, cryptor.get_available_key(), cryptor.get_key_size());
		DogCryption::utils::squareXOR_self(tempBlock, tempKey, block_size);
		plain.write((char*)tempBlock.data(), block_size);
		for (Ullong i = 0; i < block_size; ++i) { crypt.unget(); }
		crypt.read((char*)tempKey.data(), block_size);
	}
	crypt.read((char*)tempBlock.data(), block_size);
	cryptor.get_block_decryption()(tempBlock, block_size, cryptor.get_available_key(), cryptor.get_key_size());
	DogCryption::utils::squareXOR_self(tempBlock, tempKey, block_size);
	cryptor.get_unpadding()(tempBlock, block_size);
	plain.write((char*)tempBlock.data(), tempBlock.size());
	plain.flush();
}
void DogCryption::mode::encrypt_CBC_streamp(std::istream& plain, DogData::Data iv, std::ostream& crypt, DogCryption::cryptor& cryptor, std::atomic<double>* progress)
{
	byte block_size = cryptor.get_block_size();
	plain.seekg(0, std::ios::end);
	Ullong file_size = plain.tellg();
	plain.seekg(0, std::ios::beg);

	DogData::Data tempBlock(block_size);
	DogData::Data tempKey = iv;
	while (plain.tellg() <= file_size - block_size)
	{
		plain.read((char*)tempBlock.data(), block_size);
		DogCryption::utils::squareXOR_self(tempBlock, tempKey, block_size);
		cryptor.get_block_encryption()(tempBlock, block_size, cryptor.get_available_key(), cryptor.get_key_size());
		crypt.write((char*)tempBlock.data(), block_size);
		if (progress->load() < 0.0)
		{
			return;
		}
		progress->store(update_progress(progress->load(), block_size, file_size));
		tempKey = tempBlock;
	}
	plain.read((char*)tempBlock.data(), block_size);
	if (plain.gcount() < block_size)
	{
		for (Ullong i = 0; i < block_size - plain.gcount(); ++i) { tempBlock.pop_back(); }
		cryptor.get_padding()(tempBlock, block_size);
	}
	DogCryption::utils::squareXOR_self(tempBlock, tempKey, block_size);
	cryptor.get_block_encryption()(tempBlock, block_size, cryptor.get_available_key(), cryptor.get_key_size());
	crypt.write((char*)tempBlock.data(), block_size);
	if(progress->load()<0){return;}progress->store(update_progress(progress->load(), block_size, file_size));
	crypt.flush();
	progress->store(1.0);
}
void DogCryption::mode::decrypt_CBC_streamp(std::istream& crypt, DogData::Data iv, std::ostream& plain, DogCryption::cryptor& cryptor, std::atomic<double>* progress)
{
	byte block_size = cryptor.get_block_size();
	Ullong now_pos = crypt.tellg();
	crypt.seekg(0, std::ios::end);
	Ullong file_size = crypt.tellg();
	crypt.seekg(now_pos);

	DogData::Data tempBlock(block_size);
	DogData::Data tempKey = iv;
	for (Ullong i = 0; i < (file_size - now_pos - 1) / block_size; ++i)
	{
		crypt.read((char*)tempBlock.data(), block_size);
		cryptor.get_block_decryption()(tempBlock, block_size, cryptor.get_available_key(), cryptor.get_key_size());
		DogCryption::utils::squareXOR_self(tempBlock, tempKey, block_size);
		plain.write((char*)tempBlock.data(), block_size);
		for (Ullong i = 0; i < block_size; ++i) { crypt.unget(); }
		crypt.read((char*)tempKey.data(), block_size);
		if(progress->load()<0){return;}progress->store(update_progress(progress->load(), block_size, file_size));
	}
	crypt.read((char*)tempBlock.data(), block_size);
	cryptor.get_block_decryption()(tempBlock, block_size, cryptor.get_available_key(), cryptor.get_key_size());
	DogCryption::utils::squareXOR_self(tempBlock, tempKey, block_size);
	cryptor.get_unpadding()(tempBlock, block_size);
	plain.write((char*)tempBlock.data(), tempBlock.size());
	if (progress->load() < 0.0)
	{
		return;
	}
	progress->store(update_progress(progress->load(), block_size, file_size));
	plain.flush();
	progress->store(1.0);
}

DogData::Data DogCryption::mode::encrypt_OFB(DogData::Data plain, DogData::Data iv, DogCryption::cryptor& cryptor)
{
	byte block_size = cryptor.get_block_size();
	DogData::Data res; res.reserve(((plain.size() / block_size) + 1) * block_size);
	DogData::Data tempBlock0 = iv;
	DogData::Data tempBlock1;
	for (Ullong i0 = 0; i0 <= plain.size(); i0 += block_size)
	{
		cryptor.get_block_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
		tempBlock1 = plain.sub_by_pos(i0, i0 + block_size);
		if (tempBlock1.size() <= block_size && cryptor.get_using_padding()) { cryptor.get_padding()(tempBlock1, block_size); }
		res = res + DogCryption::utils::squareXOR(tempBlock1, tempBlock0, tempBlock1.size());
	}
	return res;
}
DogData::Data DogCryption::mode::decrypt_OFB(DogData::Data crypt, DogData::Data iv, DogCryption::cryptor& cryptor)
{
	byte block_size = cryptor.get_block_size();
	DogData::Data res; res.reserve(crypt.size());
	DogData::Data tempBlock0 = iv;
	DogData::Data tempBlock1; tempBlock1.reserve(block_size);
	for (Ullong i0 = 0; i0 < crypt.size(); i0 += block_size)
	{
		cryptor.get_block_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
		tempBlock1 = crypt.sub_by_len(i0, block_size);
		res = res + DogCryption::utils::squareXOR(tempBlock1, tempBlock0, tempBlock1.size());
		tempBlock1.clear_leave_pos();
	}
	if (cryptor.get_using_padding())
	{
		cryptor.get_unpadding()(res, block_size);
	}
	return res;
}
void DogCryption::mode::encrypt_OFB_stream(std::istream& plain, DogData::Data iv, std::ostream& crypt, DogCryption::cryptor& cryptor)
{
	byte block_size = cryptor.get_block_size();
	plain.seekg(0, std::ios::end);
	Ullong file_size = plain.tellg();
	plain.seekg(0, std::ios::beg);
	DogData::Data tempBlock0 = iv;
	DogData::Data tempBlock1(block_size);
	while (plain.tellg() <= file_size - block_size)
	{
		cryptor.get_block_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
        plain.read((char*)tempBlock1.data(), block_size);
		crypt.write((char*)DogCryption::utils::squareXOR(tempBlock0, tempBlock1, block_size).data(), block_size);
	}
	cryptor.get_block_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
	plain.read((char*)tempBlock1.data(), block_size);
	for (Ullong i = 0; i < block_size - plain.gcount(); ++i) { tempBlock1.pop_back(); }
	if (cryptor.get_using_padding() && plain.gcount() < block_size)
	{
		cryptor.get_padding()(tempBlock1, block_size);
	}
	crypt.write((char*)DogCryption::utils::squareXOR(tempBlock1, tempBlock0, tempBlock1.size()).data(), tempBlock1.size());
	crypt.flush();
}
void DogCryption::mode::decrypt_OFB_stream(std::istream& crypt, DogData::Data iv, std::ostream& plain, DogCryption::cryptor& cryptor)
{
	byte block_size = cryptor.get_block_size();
	Ullong now_pos = crypt.tellg();
	crypt.seekg(0, std::ios::end);
	Ullong file_size = crypt.tellg();
	crypt.seekg(now_pos);

	DogData::Data tempBlock0 = iv;
	DogData::Data tempBlock1(block_size);
	for (Ullong i = 0; i < (file_size - now_pos - 1) / block_size; ++i)
	{
		cryptor.get_block_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
		crypt.read((char*)tempBlock1.data(), block_size);
		plain.write((char*)DogCryption::utils::squareXOR(tempBlock0, tempBlock1, block_size).data(), block_size);
	}
	cryptor.get_block_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
	crypt.read((char*)tempBlock1.data(), block_size);
	Ullong s = crypt.gcount();
	for (Ullong i = 0; i < block_size - crypt.gcount(); ++i) { tempBlock1.pop_back(); }
	DogCryption::utils::squareXOR_self(tempBlock1, tempBlock0, tempBlock1.size());
	if (cryptor.get_using_padding())
	{
		cryptor.get_unpadding()(tempBlock1, block_size);
	}
	plain.write((char*)tempBlock1.data(), tempBlock1.size());
	plain.flush();
}
void DogCryption::mode::encrypt_OFB_streamp(std::istream& plain, DogData::Data iv, std::ostream& crypt, DogCryption::cryptor& cryptor, std::atomic<double>* progress)
{
	byte block_size = cryptor.get_block_size();
	plain.seekg(0, std::ios::end);
	Ullong file_size = plain.tellg();
	plain.seekg(0, std::ios::beg);
	DogData::Data tempBlock0 = iv;
	DogData::Data tempBlock1(block_size);
	while (plain.tellg() <= file_size - block_size)
	{
		cryptor.get_block_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
		plain.read((char*)tempBlock1.data(), block_size);
		crypt.write((char*)DogCryption::utils::squareXOR(tempBlock0, tempBlock1, block_size).data(), block_size);
		if (progress->load() < 0.0)
		{
			return;
		}
		progress->store(update_progress(progress->load(), block_size, file_size));
	}
	cryptor.get_block_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
	plain.read((char*)tempBlock1.data(), block_size);
	for (Ullong i = 0; i < block_size - plain.gcount(); ++i) { tempBlock1.pop_back(); }
	if (cryptor.get_using_padding() && plain.gcount() < block_size)
	{
		cryptor.get_padding()(tempBlock1, block_size);
	}
	crypt.write((char*)DogCryption::utils::squareXOR(tempBlock1, tempBlock0, tempBlock1.size()).data(), tempBlock1.size());
	if(progress->load()<0){return;}progress->store(update_progress(progress->load(), block_size, file_size));
	crypt.flush();
	progress->store(1.0);
}
void DogCryption::mode::decrypt_OFB_streamp(std::istream& crypt, DogData::Data iv, std::ostream& plain, DogCryption::cryptor& cryptor, std::atomic<double>* progress)
{
	byte block_size = cryptor.get_block_size();
	Ullong now_pos = crypt.tellg();
	crypt.seekg(0, std::ios::end);
	Ullong file_size = crypt.tellg();
	crypt.seekg(now_pos);

	DogData::Data tempBlock0 = iv;
	DogData::Data tempBlock1(block_size);
	for (Ullong i = 0; i < (file_size - now_pos - 1) / block_size; ++i)
	{
		cryptor.get_block_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
		crypt.read((char*)tempBlock1.data(), block_size);
		plain.write((char*)DogCryption::utils::squareXOR(tempBlock0, tempBlock1, block_size).data(), block_size);
		if (progress->load() < 0.0)
		{
			return;
		}
		progress->store(update_progress(progress->load(), block_size, file_size));
	}
	cryptor.get_block_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
	crypt.read((char*)tempBlock1.data(), block_size);
	Ullong s = crypt.gcount();
	for (Ullong i = 0; i < block_size - crypt.gcount(); ++i) { tempBlock1.pop_back(); }
	DogCryption::utils::squareXOR_self(tempBlock1, tempBlock0, tempBlock1.size());
	if (cryptor.get_using_padding())
	{
		cryptor.get_unpadding()(tempBlock1, block_size);
	}
	plain.write((char*)tempBlock1.data(), tempBlock1.size());
	if(progress->load()<0){return;}progress->store(update_progress(progress->load(), block_size, file_size));
	plain.flush();
	progress->store(1.0);
}

DogData::Data DogCryption::mode::encrypt_CTR(DogData::Data plain, DogData::Data iv, DogCryption::cryptor& cryptor)
{
	byte block_size = cryptor.get_block_size();
	DogData::Data res; res.reserve(((plain.size() / block_size) + 1) * block_size);
	DogData::Data tempBlock0 = iv;
	Ullong endNum = 0;
	for (Ullong i0 = 0; i0 < 8; i0++)
	{
		endNum += (Ullong)tempBlock0[i0 + 8] << (8 * (7 - i0));
	}
	DogData::Data tempBlock1;
	DogData::Data tempBlock2;
	for (Ullong i0 = 0; i0 <= plain.size(); i0 += block_size)
	{
		tempBlock2 = tempBlock0;
		cryptor.get_block_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
		tempBlock1 = plain.sub_by_len(i0, block_size);
		if (tempBlock1.size() < block_size && cryptor.get_using_padding()) { cryptor.get_padding()(tempBlock1, block_size); }
		res = res + DogCryption::utils::squareXOR(tempBlock1, tempBlock0, tempBlock1.size());
		tempBlock1.clear_leave_pos();
		endNum++;
		for (int i1 = 0; i1 < 8; i1++)
		{
			tempBlock2[i1 + 8] = (byte)(endNum >> (8 * (7 - i1)));
		}
		tempBlock0 = tempBlock2;
	}
	return res;
}
DogData::Data DogCryption::mode::decrypt_CTR(DogData::Data crypt, DogData::Data iv, DogCryption::cryptor& cryptor)
{
	byte block_size = cryptor.get_block_size();
	DogData::Data res; res.reserve(((crypt.size() / block_size) + 1) * block_size);
	DogData::Data tempBlock0 = iv;
	Ullong endNum = 0;
	for (Ullong i0 = 0; i0 < 8; i0++)
	{
		endNum += (Ullong)tempBlock0[i0 + 8] << (8 * (7 - i0));
	}
	DogData::Data tempBlock1;
	DogData::Data tempBlock2;
	for (Ullong i0 = 0; i0 < crypt.size(); i0 += block_size)
	{
		tempBlock2 = tempBlock0;
		cryptor.get_block_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
		tempBlock1 = crypt.sub_by_pos(i0, i0 + block_size);
		res = res + DogCryption::utils::squareXOR(tempBlock1, tempBlock0, tempBlock1.size());
		endNum++;
		for (int i1 = 0; i1 < 8; i1++)
		{
			tempBlock2[i1 + 8] = (byte)(endNum >> (8 * (7 - i1)));
		}
		tempBlock0 = tempBlock2;
	}
	if (cryptor.get_using_padding()) { cryptor.get_unpadding()(res, block_size); }
	return res;
}
void DogCryption::mode::encrypt_CTR_stream(std::istream& plain, DogData::Data iv, std::ostream& crypt, DogCryption::cryptor& cryptor)
{
	byte block_size = cryptor.get_block_size();
	plain.seekg(0, std::ios::end);
	Ullong file_size = plain.tellg();
	plain.seekg(0, std::ios::beg);

	DogData::Data tempBlock0 = iv;
	Ullong endNum = 0;
	for (Ullong i0 = 0; i0 < 8; i0++)
	{
		endNum += (Ullong)tempBlock0[i0 + 8] << (8 * (7 - i0));
	}
	DogData::Data tempBlock1(block_size);
	DogData::Data tempBlock2(block_size);
	while (plain.tellg() <= file_size - block_size)
	{
		tempBlock2 = tempBlock0;
		cryptor.get_block_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
		plain.read((char*)tempBlock1.data(), block_size);
		crypt.write((char*)DogCryption::utils::squareXOR(tempBlock0, tempBlock1, block_size).data(), block_size);
		endNum++;
		for (int i1 = 0; i1 < 8; i1++)
		{
			tempBlock2[i1 + 8] = (byte)(endNum >> (8 * (7 - i1)));
		}
		tempBlock0 = tempBlock2;
	}
	tempBlock2 = tempBlock0;
	cryptor.get_block_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
	plain.read((char*)tempBlock1.data(), block_size);
	for (Ullong i = 0; i < block_size - plain.gcount(); ++i) { tempBlock1.pop_back(); }
	if (cryptor.get_using_padding() && plain.gcount() < block_size)
	{
		cryptor.get_padding()(tempBlock1, block_size);
	}
	crypt.write((char*)DogCryption::utils::squareXOR(tempBlock1, tempBlock0, tempBlock1.size()).data(), tempBlock1.size());
	crypt.flush();
}
void DogCryption::mode::decrypt_CTR_stream(std::istream& crypt, DogData::Data iv, std::ostream& plain, DogCryption::cryptor& cryptor)
{
	byte block_size = cryptor.get_block_size();
	Ullong now_pos = crypt.tellg();
	crypt.seekg(0, std::ios::end);
	Ullong file_size = crypt.tellg();
	crypt.seekg(now_pos);

	DogData::Data tempBlock0 = iv;
	Ullong endNum = 0;
	for (Ullong i0 = 0; i0 < 8; i0++)
	{
		endNum += (Ullong)tempBlock0[i0 + 8] << (8 * (7 - i0));
	}
	DogData::Data tempBlock1(block_size);
	DogData::Data tempBlock2(block_size);
	for (Ullong i = 0; i < (file_size - now_pos - 1) / block_size; ++i)
	{
		tempBlock2 = tempBlock0;
		cryptor.get_block_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
		crypt.read((char*)tempBlock1.data(), block_size);
		plain.write((char*)DogCryption::utils::squareXOR(tempBlock1, tempBlock0, block_size).data(), block_size);
		endNum++;
		for (int i1 = 0; i1 < 8; i1++)
		{
			tempBlock2[i1 + 8] = (byte)(endNum >> (8 * (7 - i1)));
		}
		tempBlock0 = tempBlock2;
	}
	tempBlock2 = tempBlock0;
	cryptor.get_block_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
	crypt.read((char*)tempBlock1.data(), block_size);
	for (Ullong i = 0; i < block_size - crypt.gcount(); ++i) { tempBlock1.pop_back(); }
	DogCryption::utils::squareXOR_self(tempBlock1, tempBlock0, tempBlock1.size());
	if (cryptor.get_using_padding())
	{
		cryptor.get_unpadding()(tempBlock1, block_size);
	}
	plain.write((char*)tempBlock1.data(), tempBlock1.size());
	plain.flush();
}
void DogCryption::mode::encrypt_CTR_streamp(std::istream& plain, DogData::Data iv, std::ostream& crypt, DogCryption::cryptor& cryptor, std::atomic<double>* progress)
{
	byte block_size = cryptor.get_block_size();
	plain.seekg(0, std::ios::end);
	Ullong file_size = plain.tellg();
	plain.seekg(0, std::ios::beg);

	DogData::Data tempBlock0 = iv;
	Ullong endNum = 0;
	for (Ullong i0 = 0; i0 < 8; i0++)
	{
		endNum += (Ullong)tempBlock0[i0 + 8] << (8 * (7 - i0));
	}
	DogData::Data tempBlock1(block_size);
	DogData::Data tempBlock2(block_size);
	while (plain.tellg() <= file_size - block_size)
	{
		tempBlock2 = tempBlock0;
		cryptor.get_block_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
		plain.read((char*)tempBlock1.data(), block_size);
		crypt.write((char*)DogCryption::utils::squareXOR(tempBlock0, tempBlock1, block_size).data(), block_size);
		if (progress->load() < 0.0)
		{
			return;
		}
		progress->store(update_progress(progress->load(), block_size, file_size));
		endNum++;
		for (int i1 = 0; i1 < 8; i1++)
		{
			tempBlock2[i1 + 8] = (byte)(endNum >> (8 * (7 - i1)));
		}
		tempBlock0 = tempBlock2;
	}
	tempBlock2 = tempBlock0;
	cryptor.get_block_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
	plain.read((char*)tempBlock1.data(), block_size);
	for (Ullong i = 0; i < block_size - plain.gcount(); ++i) { tempBlock1.pop_back(); }
	if (cryptor.get_using_padding() && plain.gcount() < block_size)
	{
		cryptor.get_padding()(tempBlock1, block_size);
	}
	crypt.write((char*)DogCryption::utils::squareXOR(tempBlock1, tempBlock0, tempBlock1.size()).data(), tempBlock1.size());
	if(progress->load()<0){return;}progress->store(update_progress(progress->load(), block_size, file_size));
	crypt.flush();
	progress->store(1.0);
}
void DogCryption::mode::decrypt_CTR_streamp(std::istream& crypt, DogData::Data iv, std::ostream& plain, DogCryption::cryptor& cryptor, std::atomic<double>* progress)
{
	byte block_size = cryptor.get_block_size();
	Ullong now_pos = crypt.tellg();
	crypt.seekg(0, std::ios::end);
	Ullong file_size = crypt.tellg();
	crypt.seekg(now_pos);

	DogData::Data tempBlock0 = iv;
	Ullong endNum = 0;
	for (Ullong i0 = 0; i0 < 8; i0++)
	{
		endNum += (Ullong)tempBlock0[i0 + 8] << (8 * (7 - i0));
	}
	DogData::Data tempBlock1(block_size);
	DogData::Data tempBlock2(block_size);
	for (Ullong i = 0; i < (file_size - now_pos - 1) / block_size; ++i)
	{
		tempBlock2 = tempBlock0;
		cryptor.get_block_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
		crypt.read((char*)tempBlock1.data(), block_size);
		plain.write((char*)DogCryption::utils::squareXOR(tempBlock1, tempBlock0, block_size).data(), block_size);
		if (progress->load() < 0.0)
		{
			return;
		}
		progress->store(update_progress(progress->load(), block_size, file_size));
		endNum++;
		for (int i1 = 0; i1 < 8; i1++)
		{
			tempBlock2[i1 + 8] = (byte)(endNum >> (8 * (7 - i1)));
		}
		tempBlock0 = tempBlock2;
	}
	tempBlock2 = tempBlock0;
	cryptor.get_block_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
	crypt.read((char*)tempBlock1.data(), block_size);
	for (Ullong i = 0; i < block_size - crypt.gcount(); ++i) { tempBlock1.pop_back(); }
	DogCryption::utils::squareXOR_self(tempBlock1, tempBlock0, tempBlock1.size());
	if (cryptor.get_using_padding())
	{
		cryptor.get_unpadding()(tempBlock1, block_size);
	}
	plain.write((char*)tempBlock1.data(), tempBlock1.size());
	if(progress->load()<0){return;}progress->store(update_progress(progress->load(), block_size, file_size));
	plain.flush();
	progress->store(1.0);
}

DogData::Data DogCryption::mode::encrypt_CFBbyte(DogData::Data plain, DogData::Data iv, DogCryption::cryptor& cryptor)
{
	byte block_size = cryptor.get_block_size();
	//反馈字节数
	byte nbyte = cryptor.get_reback_size();
	
	DogData::Data res; res.reserve(((plain.size() / nbyte) + 1) * nbyte);
	DogData::Data tempBlock0 = iv;
	DogData::Data tempBlock1(nbyte);
	DogData::Data tempBlock2(nbyte);
	Ullong i = 0;
	for (i = 0; i <= plain.size() - nbyte; i += nbyte);
	{
		cryptor.get_block_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
		tempBlock1 = plain.sub_by_len(i, nbyte);
		tempBlock2 = tempBlock0.sub_by_len(0, nbyte);
		DogCryption::utils::squareXOR_self(tempBlock1, tempBlock2, tempBlock1.size());
        res += tempBlock1;
		tempBlock0 = tempBlock0.sub_by_len(nbyte, block_size - nbyte) + tempBlock1;
	}
	cryptor.get_block_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
	tempBlock1 = plain.sub_by_len(i, nbyte);
	if (cryptor.get_using_padding()) { cryptor.get_padding()(tempBlock1, nbyte); }
	tempBlock2 = tempBlock0.sub_by_len(0, nbyte);
	DogCryption::utils::squareXOR_self(tempBlock1, tempBlock2, tempBlock1.size());
	res += tempBlock1;
	return res;
}
DogData::Data DogCryption::mode::decrypt_CFBbyte(DogData::Data crypt, DogData::Data iv, DogCryption::cryptor& cryptor)
{
	byte block_size = cryptor.get_block_size();
	//反馈字节数
	byte nbyte = cryptor.get_reback_size();

	DogData::Data res; res.reserve(((crypt.size() / nbyte) + 1) * nbyte);
	DogData::Data tempBlock0 = iv;
	DogData::Data tempBlock1(nbyte);
	DogData::Data tempBlock2(nbyte);
	Ullong i = 0;
	for (i = 0; i < crypt.size() - nbyte; i += nbyte);
	{
		cryptor.get_block_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
		tempBlock1 = crypt.sub_by_len(i, nbyte);
		tempBlock2 = tempBlock0.sub_by_len(0, nbyte);
		DogCryption::utils::squareXOR_self(tempBlock1, tempBlock2, tempBlock1.size());
		res += tempBlock1;
		tempBlock0 = tempBlock0.sub_by_len(nbyte, block_size - nbyte) + tempBlock1;
	}
	cryptor.get_block_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
	tempBlock1 = crypt.sub_by_len(i, nbyte);
	if (cryptor.get_using_padding() && tempBlock1.size() == nbyte) { cryptor.get_unpadding()(tempBlock1, nbyte); }
    tempBlock2 = tempBlock0.sub_by_len(0, nbyte);
	DogCryption::utils::squareXOR_self(tempBlock1, tempBlock2, tempBlock1.size());
	res += tempBlock1;
	return res;
}
void DogCryption::mode::encrypt_CFBbyte_stream(std::istream& plain, DogData::Data iv, std::ostream& crypt, DogCryption::cryptor& cryptor)
{
	byte block_size = cryptor.get_block_size();
	plain.seekg(0, std::ios::end);
	Ullong file_size = plain.tellg();
	plain.seekg(0, std::ios::beg);
	//反馈字节数
	byte nbyte = 1;

	DogData::Data tempBlock0 = iv;
	DogData::Data tempBlock1(nbyte);
	DogData::Data tempBlock2(nbyte);
	while (plain.tellg() <= file_size - nbyte)
	{
		cryptor.get_block_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
		plain.read((char*)tempBlock1.data(), nbyte);
		tempBlock2 = tempBlock0.sub_by_len(0, nbyte);
		DogCryption::utils::squareXOR_self(tempBlock1, tempBlock2, nbyte);
		crypt.write((char*)tempBlock1.data(), nbyte);
		tempBlock0 = tempBlock0.sub_by_len(nbyte, block_size - nbyte) + tempBlock1;
	}
	cryptor.get_block_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
	plain.read((char*)tempBlock1.data(), nbyte);
	tempBlock2 = tempBlock0.sub_by_len(0, nbyte);
	for (int i = 0; i < nbyte - plain.gcount(); ++i) { tempBlock1.pop_back(); }
	if (cryptor.get_using_padding() && plain.gcount() < nbyte) { cryptor.get_padding()(tempBlock1, nbyte); }
	DogCryption::utils::squareXOR_self(tempBlock1, tempBlock2, tempBlock1.size());
	crypt.write((char*)tempBlock1.data(), nbyte);
	crypt.flush();
}
void DogCryption::mode::decrypt_CFBbyte_stream(std::istream& crypt, DogData::Data iv, std::ostream& plain, DogCryption::cryptor& cryptor)
{
	byte block_size = cryptor.get_block_size();
	Ullong now_pos = crypt.tellg();
	crypt.seekg(0, std::ios::end);
	Ullong file_size = crypt.tellg();
	crypt.seekg(now_pos);
	
	//反馈字节数
	byte nbyte = 1;

	DogData::Data tempBlock0 = iv;
	DogData::Data tempBlock1(nbyte);
	DogData::Data tempBlock2(nbyte);
	while (crypt.tellg() < file_size - nbyte)
	{
		cryptor.get_block_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
		crypt.read((char*)tempBlock1.data(), nbyte);
		tempBlock2 = tempBlock0.sub_by_len(0, nbyte);
		DogCryption::utils::squareXOR_self(tempBlock1, tempBlock2, nbyte);
		plain.write((char*)tempBlock1.data(), nbyte);
		tempBlock0 = tempBlock0.sub_by_len(nbyte, block_size - nbyte) + tempBlock1;
	}
	cryptor.get_block_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
	crypt.read((char*)tempBlock1.data(), nbyte);
	tempBlock2 = tempBlock0.sub_by_len(0, nbyte);
	DogCryption::utils::squareXOR_self(tempBlock1, tempBlock2, tempBlock1.size());
	if (cryptor.get_using_padding()) { cryptor.get_unpadding()(tempBlock1, nbyte); }
	plain.write((char*)tempBlock1.data(), nbyte);
	plain.flush();
}
void DogCryption::mode::encrypt_CFBbyte_streamp(std::istream& plain, DogData::Data iv, std::ostream& crypt, DogCryption::cryptor& cryptor, std::atomic<double>* progress)
{
	byte block_size = cryptor.get_block_size();
	plain.seekg(0, std::ios::end);
	Ullong file_size = plain.tellg();
	plain.seekg(0, std::ios::beg);
	//反馈字节数
	byte nbyte = 1;

	DogData::Data tempBlock0 = iv;
	DogData::Data tempBlock1(nbyte);
	DogData::Data tempBlock2(nbyte);
	while (plain.tellg() <= file_size - nbyte)
	{
		cryptor.get_block_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
		plain.read((char*)tempBlock1.data(), nbyte);
		tempBlock2 = tempBlock0.sub_by_len(0, nbyte);
		DogCryption::utils::squareXOR_self(tempBlock1, tempBlock2, nbyte);
		crypt.write((char*)tempBlock1.data(), nbyte);
		if (progress->load() < 0.0)
		{
			return;
		}
		progress->store(update_progress(progress->load(), nbyte, file_size));
		tempBlock0 = tempBlock0.sub_by_len(nbyte, block_size - nbyte) + tempBlock1;
	}
	cryptor.get_block_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
	plain.read((char*)tempBlock1.data(), nbyte);
	tempBlock2 = tempBlock0.sub_by_len(0, nbyte);
	for (int i = 0; i < nbyte - plain.gcount(); ++i) { tempBlock1.pop_back(); }
	if (cryptor.get_using_padding() && plain.gcount() < nbyte) { cryptor.get_padding()(tempBlock1, nbyte); }
	DogCryption::utils::squareXOR_self(tempBlock1, tempBlock2, tempBlock1.size());
	crypt.write((char*)tempBlock1.data(), nbyte);
	if(progress->load()<0){return;}progress->store(update_progress(progress->load(), nbyte, file_size));
	crypt.flush();
	progress->store(1.0);
}
void DogCryption::mode::decrypt_CFBbyte_streamp(std::istream& crypt, DogData::Data iv, std::ostream& plain, DogCryption::cryptor& cryptor, std::atomic<double>* progress)
{
	byte block_size = cryptor.get_block_size();
	Ullong now_pos = crypt.tellg();
	crypt.seekg(0, std::ios::end);
	Ullong file_size = crypt.tellg();
	crypt.seekg(now_pos);

	//反馈字节数
	byte nbyte = 1;

	DogData::Data tempBlock0 = iv;
	DogData::Data tempBlock1(nbyte);
	DogData::Data tempBlock2(nbyte);
	while (crypt.tellg() < file_size - nbyte)
	{
		cryptor.get_block_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
		crypt.read((char*)tempBlock1.data(), nbyte);
		tempBlock2 = tempBlock0.sub_by_len(0, nbyte);
		DogCryption::utils::squareXOR_self(tempBlock1, tempBlock2, nbyte);
		plain.write((char*)tempBlock1.data(), nbyte);
		if (progress->load() < 0.0)
		{
			return;
		}
		progress->store(update_progress(progress->load(), nbyte, file_size));
		tempBlock0 = tempBlock0.sub_by_len(nbyte, block_size - nbyte) + tempBlock1;
	}
	cryptor.get_block_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
	crypt.read((char*)tempBlock1.data(), nbyte);
	tempBlock2 = tempBlock0.sub_by_len(0, nbyte);
	DogCryption::utils::squareXOR_self(tempBlock1, tempBlock2, tempBlock1.size());
	if (cryptor.get_using_padding()) { cryptor.get_unpadding()(tempBlock1, nbyte); }
	plain.write((char*)tempBlock1.data(), nbyte);
	if(progress->load()<0){return;}progress->store(update_progress(progress->load(), nbyte, file_size));
	plain.flush();
	progress->store(1.0);
}

DogData::Data DogCryption::mode::encrypt_CFB8(DogData::Data plain, DogData::Data iv, DogCryption::cryptor& cryptor)
{
	byte block_size = cryptor.get_block_size();
	DogData::Data res; res.reserve(((plain.size() / block_size) + 1) * block_size);
	DogData::Data tempBlock0 = iv;
	DogData::Data tempBlock1; tempBlock1.reserve(block_size);
	for (Ullong i0 = 0; i0 < plain.size(); i0++)
	{
		tempBlock1 = tempBlock0;
		cryptor.get_block_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
		byte b = plain[i0] ^ tempBlock0[0];
		res.push_back(b);
		tempBlock1.push_back(b);
	}
	return res;
}
DogData::Data DogCryption::mode::decrypt_CFB8(DogData::Data crypt, DogData::Data iv, DogCryption::cryptor& cryptor)
{
	byte block_size = cryptor.get_block_size();
	DogData::Data res; res.reserve(((crypt.size() / block_size) + 1) * block_size);
	DogData::Data tempBlock0 = iv;
	DogData::Data tempBlock1; tempBlock1.reserve(block_size);
	for (Ullong i0 = 0; i0 < crypt.size(); i0++)
	{
		tempBlock1 = tempBlock0;
		cryptor.get_block_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
		byte b = crypt[i0] ^ tempBlock0[0];
		res.push_back(b);
		tempBlock0.push_back(crypt[i0]);
	}
	return res;
}
void DogCryption::mode::encrypt_CFB8_stream(std::istream& plain, DogData::Data iv, std::ostream& crypt, DogCryption::cryptor& cryptor)
{
	byte block_size = cryptor.get_block_size();
	plain.seekg(0, std::ios::end);
	Ullong file_size = plain.tellg();
	plain.seekg(0, std::ios::beg);

	DogData::Data tempBlock0 = iv;
	DogData::Data tempBlock1(block_size);
	DogData::Data middleResult;middleResult.reserve(block_size);
	while (plain.tellg() < file_size)
	{
		tempBlock1 = tempBlock0;
		cryptor.get_block_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
		byte b = plain.get() ^ tempBlock0[0];
        middleResult.push_back(b);
		if (middleResult.size() == block_size) 
		{ 
			crypt.write((char*)middleResult.data(), block_size); 
			middleResult.clear_leave_pos(); 
		}
		tempBlock1.push_back(b);
	}
	crypt.write((char*)middleResult.data(), middleResult.size());
	crypt.flush();
}
void DogCryption::mode::decrypt_CFB8_stream(std::istream& crypt, DogData::Data iv, std::ostream& plain, DogCryption::cryptor& cryptor)
{
	byte block_size = cryptor.get_block_size();
	Ullong now_pos = crypt.tellg();
	crypt.seekg(0, std::ios::end);
	Ullong file_size = crypt.tellg();
	crypt.seekg(now_pos);

	DogData::Data tempBlock0 = iv;
	DogData::Data tempBlock1; tempBlock1.reserve(block_size);
	DogData::Data middleResult; middleResult.reserve(block_size);
	while (crypt.tellg() < file_size)
	{
		tempBlock1 = tempBlock0;
		cryptor.get_block_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
		byte b = crypt.peek() ^ tempBlock0[0];
		middleResult.push_back(b);
		if (middleResult.size() == block_size) 
		{ 
			plain.write((char*)middleResult.data(), block_size); 
			//DogData::print::block(middleResult);
			middleResult.clear_leave_pos(); 
		}
		tempBlock0.push_back(crypt.get());
	}
	plain.write((char*)middleResult.data(), middleResult.size());
	//DogData::print::block(middleResult);
	plain.flush();
}
void DogCryption::mode::encrypt_CFB8_streamp(std::istream& plain, DogData::Data iv, std::ostream& crypt, DogCryption::cryptor& cryptor, std::atomic<double>* progress)
{
	byte block_size = cryptor.get_block_size();
	plain.seekg(0, std::ios::end);
	Ullong file_size = plain.tellg();
	plain.seekg(0, std::ios::beg);

	DogData::Data tempBlock0 = iv;
	DogData::Data tempBlock1(block_size);
	DogData::Data middleResult; middleResult.reserve(block_size);
	while (plain.tellg() < file_size)
	{
		tempBlock1 = tempBlock0;
		cryptor.get_block_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
		byte b = plain.get() ^ tempBlock0[0];
		middleResult.push_back(b);
		if (middleResult.size() == block_size)
		{
			crypt.write((char*)middleResult.data(), block_size);
			if (progress->load() < 0.0)
			{
				return;
			}
			progress->store(update_progress(progress->load(), block_size, file_size));
			middleResult.clear_leave_pos();
		}
		tempBlock1.push_back(b);
	}
	crypt.write((char*)middleResult.data(), middleResult.size());
	if(progress->load()<0){return;}progress->store(update_progress(progress->load(), middleResult.size(), file_size));
	crypt.flush();
	progress->store(1.0);
}
void DogCryption::mode::decrypt_CFB8_streamp(std::istream& crypt, DogData::Data iv, std::ostream& plain, DogCryption::cryptor& cryptor, std::atomic<double>* progress)
{
	byte block_size = cryptor.get_block_size();
	Ullong now_pos = crypt.tellg();
	crypt.seekg(0, std::ios::end);
	Ullong file_size = crypt.tellg();
	crypt.seekg(now_pos);

	DogData::Data tempBlock0 = iv;
	DogData::Data tempBlock1; tempBlock1.reserve(block_size);
	DogData::Data middleResult; middleResult.reserve(block_size);
	while (crypt.tellg() < file_size)
	{
		tempBlock1 = tempBlock0;
		cryptor.get_block_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
		byte b = crypt.peek() ^ tempBlock0[0];
		middleResult.push_back(b);
		if (middleResult.size() == block_size)
		{
			plain.write((char*)middleResult.data(), block_size);
			if (progress->load() < 0.0)
			{
				return;
			}
			progress->store(update_progress(progress->load(), block_size, file_size));
			middleResult.clear_leave_pos();
		}
		tempBlock0.push_back(crypt.get());
	}
	plain.write((char*)middleResult.data(), middleResult.size());
	if(progress->load()<0){return;}progress->store(update_progress(progress->load(), middleResult.size(), file_size));
	plain.flush();
	progress->store(1.0);
}

DogData::Data DogCryption::mode::encrypt_CFB1(DogData::Data plain, DogData::Data iv, DogCryption::cryptor& cryptor)
{
	byte block_size = cryptor.get_block_size();
	DogData::Data res; res.reserve(((plain.size() / block_size) + 1) * block_size);
	DogData::Data tempBlock0 = iv;
	DogData::Data tempBlock1; tempBlock1.reserve(block_size);
	for (Ullong i0 = 0; i0 < plain.size(); i0++)
	{
		byte B = 0x00;
		for (int j = 0; j < 8; j++)
		{
			tempBlock1 = tempBlock0;
			cryptor.get_block_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
			byte b = (plain[i0] >> (7 - j) & 0x01) ^ (tempBlock0[0] >> (7 - j) & 0x01);
			B += b << (7 - j);
			byte c = b, d = 0x00;
			for (int i1 = 0; i1 < 16; i1++)
			{
				d = tempBlock1[15 - i1] >> 7;
				tempBlock1[15 - i1] = (tempBlock1[15 - i1] << 1) + c;
				c = d;
			}
		}
		res.push_back(B);
	}
	return res;
}
DogData::Data DogCryption::mode::decrypt_CFB1(DogData::Data crypt, DogData::Data iv, DogCryption::cryptor& cryptor)
{
	byte block_size = cryptor.get_block_size();
	DogData::Data res; res.reserve(((crypt.size() / block_size) + 1) * block_size);
	DogData::Data tempBlock0 = iv;
	DogData::Data tempBlock1; tempBlock1.reserve(block_size);
	for (Ullong i0 = 0; i0 < crypt.size(); i0++)
	{
		byte B = 0x00;
		for (int j = 0; j < 8; j++)
		{
			tempBlock1 = tempBlock0;
			cryptor.get_block_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
			byte b = (crypt[i0] >> (7 - j) & 0x01) ^ (tempBlock0[0] >> (7 - j) & 0x01);
			B += b << (7 - j);
			byte c = crypt[i0] >> (7 - j) & 0x01, d = 0x00;
			for (int i1 = 0; i1 < 16; i1++)
			{
				d = tempBlock1[15 - i1] >> 7;
				tempBlock1[15 - i1] = (tempBlock1[15 - i1] << 1) + c;
				c = d;
			}
		}
		res.push_back(B);
	}
	return res;

}
void DogCryption::mode::encrypt_CFB1_stream(std::istream& plain, DogData::Data iv, std::ostream& crypt, DogCryption::cryptor& cryptor)
{
	byte block_size = cryptor.get_block_size();
	plain.seekg(0, std::ios::end);
	Ullong file_size = plain.tellg();
	plain.seekg(0, std::ios::beg);

	DogData::Data tempBlock0 = iv;
	DogData::Data tempBlock1(block_size);
	while (plain.tellg() < file_size) 
	{
		//Ullong s = plain.tellg();
		//printf("%llu\r", s);
		byte B = 0x00;
		for (int j = 0; j < 8; j++)
		{
			tempBlock1 = tempBlock0;
			cryptor.get_block_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
			byte b = (plain.peek() >> (7 - j) & 0x01) ^ (tempBlock0[0] >> (7 - j) & 0x01);
			B += b << (7 - j);
			byte c = b, d = 0x00;
			for (int i1 = 0; i1 < 16; i1++)
			{
				d = tempBlock1[15 - i1] >> 7;
				tempBlock1[15 - i1] = (tempBlock1[15 - i1] << 1) + c;
				c = d;
			}
		}
		plain.get();
		crypt.put(B);
	}
	crypt.flush();
}
void DogCryption::mode::decrypt_CFB1_stream(std::istream& crypt, DogData::Data iv, std::ostream& plain, DogCryption::cryptor& cryptor)
{
	byte block_size = cryptor.get_block_size();
	Ullong now_pos = crypt.tellg();
	crypt.seekg(0, std::ios::end);
	Ullong file_size = crypt.tellg();
	crypt.seekg(now_pos);

	DogData::Data tempBlock0 = iv;
	DogData::Data tempBlock1; tempBlock1.reserve(block_size);
	while (crypt.tellg() < file_size)
	{
		//Ullong s = crypt.tellg();
		//printf("%llu\r", s);

		byte B = 0x00;
		for (int j = 0; j < 8; j++)
		{
			tempBlock1 = tempBlock0;
			cryptor.get_block_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
			byte b = (crypt.peek() >> (7 - j) & 0x01) ^ (tempBlock0[0] >> (7 - j) & 0x01);
			B += b << (7 - j);
			byte c = crypt.peek() >> (7 - j) & 0x01, d = 0x00;
			for (int i1 = 0; i1 < 16; i1++)
			{
				d = tempBlock1[15 - i1] >> 7;
				tempBlock1[15 - i1] = (tempBlock1[15 - i1] << 1) + c;
				c = d;
			}
		}
		crypt.get();
		plain.put(B);
	}
	plain.flush();
}
void DogCryption::mode::encrypt_CFB1_streamp(std::istream& plain, DogData::Data iv, std::ostream& crypt, DogCryption::cryptor& cryptor, std::atomic<double>* progress)
{
	byte block_size = cryptor.get_block_size();
	plain.seekg(0, std::ios::end);
	Ullong file_size = plain.tellg();
	plain.seekg(0, std::ios::beg);

	DogData::Data tempBlock0 = iv;
	DogData::Data tempBlock1(block_size);
	while (plain.tellg() < file_size)
	{
		//Ullong s = plain.tellg();
		//printf("%llu\r", s);
		byte B = 0x00;
		for (int j = 0; j < 8; j++)
		{
			tempBlock1 = tempBlock0;
			cryptor.get_block_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
			byte b = (plain.peek() >> (7 - j) & 0x01) ^ (tempBlock0[0] >> (7 - j) & 0x01);
			B += b << (7 - j);
			byte c = b, d = 0x00;
			for (int i1 = 0; i1 < 16; i1++)
			{
				d = tempBlock1[15 - i1] >> 7;
				tempBlock1[15 - i1] = (tempBlock1[15 - i1] << 1) + c;
				c = d;
			}
		}
		plain.get();
		crypt.put(B);
		if (progress->load() < 0.0)
		{
			return;
		}
		progress->store(update_progress(progress->load(), 1, file_size));
	}
	crypt.flush();
	progress->store(1.0);
}
void DogCryption::mode::decrypt_CFB1_streamp(std::istream& crypt, DogData::Data iv, std::ostream& plain, DogCryption::cryptor& cryptor, std::atomic<double>* progress)
{
	byte block_size = cryptor.get_block_size();
	Ullong now_pos = crypt.tellg();
	crypt.seekg(0, std::ios::end);
	Ullong file_size = crypt.tellg();
	crypt.seekg(now_pos);

	DogData::Data tempBlock0 = iv;
	DogData::Data tempBlock1; tempBlock1.reserve(block_size);
	while (crypt.tellg() < file_size)
	{
		//Ullong s = crypt.tellg();
		//printf("%llu\r", s);

		byte B = 0x00;
		for (int j = 0; j < 8; j++)
		{
			tempBlock1 = tempBlock0;
			cryptor.get_block_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
			byte b = (crypt.peek() >> (7 - j) & 0x01) ^ (tempBlock0[0] >> (7 - j) & 0x01);
			B += b << (7 - j);
			byte c = crypt.peek() >> (7 - j) & 0x01, d = 0x00;
			for (int i1 = 0; i1 < 16; i1++)
			{
				d = tempBlock1[15 - i1] >> 7;
				tempBlock1[15 - i1] = (tempBlock1[15 - i1] << 1) + c;
				c = d;
			}
		}
		crypt.get();
		plain.put(B);
		if (progress->load() < 0.0)
		{
			return;
		}
		progress->store(update_progress(progress->load(), 1, file_size));
	}
	plain.flush();
	progress->store(1.0);
}

DogData::Data DogCryption::mode::encrypt_CFB128(DogData::Data plain, DogData::Data iv, DogCryption::cryptor& cryptor)
{
	byte block_size = cryptor.get_block_size();
	DogData::Data res; res.reserve(((plain.size() / block_size) + 1) * block_size);
	DogData::Data tempBlock0 = iv;
	DogData::Data tempBlock1(block_size);
	Ullong i0 = 0;
	for (i0 = 0; i0 <= plain.size() - 16 && plain.size() >= 16; i0 += 16)
	{
		cryptor.get_block_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
		tempBlock1 = plain.sub_by_len(i0, block_size);
		DogCryption::utils::squareXOR_self(tempBlock1, tempBlock0, 16);
		res = res + tempBlock1;
		tempBlock0 = tempBlock1;
	}
	cryptor.get_block_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
	tempBlock1 = plain.sub_by_len(i0, block_size);
	if (tempBlock1.size() < 16 && cryptor.get_using_padding()) { cryptor.get_padding()(tempBlock1, 16); }
	DogCryption::utils::squareXOR_self(tempBlock1, tempBlock0, 16);
	res += tempBlock1;
	return res;
}
DogData::Data DogCryption::mode::decrypt_CFB128(DogData::Data crypt, DogData::Data iv, DogCryption::cryptor& cryptor)
{
	byte block_size = cryptor.get_block_size();
	DogData::Data res; res.reserve(((crypt.size() / block_size) + 1) * block_size);
	DogData::Data tempBlock0 = iv;
	DogData::Data tempBlock1(block_size);
	Ullong i0 = 0;
	for (i0 = 0; i0 < crypt.size() - 16 && crypt.size() > 16; i0 += 16)
	{
		cryptor.get_block_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
		tempBlock1 = crypt.sub_by_pos(i0, i0 + 16);
		res = res + DogCryption::utils::squareXOR(tempBlock0, tempBlock1, block_size);
		tempBlock0 = tempBlock1;
	}
	cryptor.get_block_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
	tempBlock1 = crypt.sub_by_pos(i0, i0 + 16);
	DogCryption::utils::squareXOR_self(tempBlock1, tempBlock0, tempBlock0.size());
	if (cryptor.get_using_padding())
	{
		cryptor.get_unpadding()(tempBlock1, 16);
	}
	res += tempBlock1;
	return res;
}
void DogCryption::mode::encrypt_CFB128_stream(std::istream& plain, DogData::Data iv, std::ostream& crypt, DogCryption::cryptor& cryptor)
{
	byte block_size = cryptor.get_block_size();
	plain.seekg(0, std::ios::end);
	Ullong file_size = plain.tellg();
	plain.seekg(0, std::ios::beg);

	DogData::Data tempBlock0 = iv;
	DogData::Data tempBlock1(block_size);
	while (plain.tellg() <= file_size - block_size)
	{
		cryptor.get_block_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
		plain.read((char*)tempBlock1.data(), 16);
		DogCryption::utils::squareXOR_self(tempBlock0, tempBlock1, block_size);
		crypt.write((char*)tempBlock0.data(),16);
	}
	cryptor.get_block_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
	plain.read((char*)tempBlock1.data(), 16);
	for (int i = 0; i < 16 - plain.gcount(); i++) { tempBlock1.pop_back(); }
	if (cryptor.get_using_padding() && plain.gcount() < 16) { cryptor.get_padding()(tempBlock1, 16); }
	DogCryption::utils::squareXOR_self(tempBlock1, tempBlock0, tempBlock1.size());
	crypt.write((char*)tempBlock1.data(), tempBlock1.size());
	crypt.flush();
}
void DogCryption::mode::decrypt_CFB128_stream(std::istream& crypt, DogData::Data iv, std::ostream& plain, DogCryption::cryptor& cryptor)
{
	byte block_size = cryptor.get_block_size();
	Ullong now_pos = crypt.tellg();
	crypt.seekg(0, std::ios::end);
	Ullong file_size = crypt.tellg();
	crypt.seekg(now_pos);

	DogData::Data tempBlock0 = iv;
	DogData::Data tempBlock1(block_size);
	for (Ullong i = 0; i < (file_size - now_pos - 1) / block_size; ++i)
	{
		cryptor.get_block_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
		crypt.read((char*)tempBlock1.data(), block_size);
		plain.write((char*)DogCryption::utils::squareXOR(tempBlock0, tempBlock1, block_size).data(), block_size);
		tempBlock0 = tempBlock1;
	}
	cryptor.get_block_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
	crypt.read((char*)tempBlock1.data(), block_size);
    for (int i = 0; i < 16 - crypt.gcount(); i++) { tempBlock1.pop_back(); }
	DogCryption::utils::squareXOR_self(tempBlock1, tempBlock0, block_size);
	cryptor.get_unpadding()(tempBlock1, block_size);
	plain.write((char*)tempBlock1.data(), tempBlock1.size());
	plain.flush();
}
void DogCryption::mode::encrypt_CFB128_streamp(std::istream& plain, DogData::Data iv, std::ostream& crypt, DogCryption::cryptor& cryptor, std::atomic<double>* progress)
{
	byte block_size = cryptor.get_block_size();
	plain.seekg(0, std::ios::end);
	Ullong file_size = plain.tellg();
	plain.seekg(0, std::ios::beg);

	DogData::Data tempBlock0 = iv;
	DogData::Data tempBlock1(block_size);
	while (plain.tellg() <= file_size - block_size)
	{
		cryptor.get_block_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
		plain.read((char*)tempBlock1.data(), 16);
		DogCryption::utils::squareXOR_self(tempBlock0, tempBlock1, block_size);
		crypt.write((char*)tempBlock0.data(), 16);
		if (progress->load() < 0.0)
		{
			return;
		}
		progress->store(update_progress(progress->load(), 16, file_size));
	}
	cryptor.get_block_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
	plain.read((char*)tempBlock1.data(), 16);
	for (int i = 0; i < 16 - plain.gcount(); i++) { tempBlock1.pop_back(); }
	if (cryptor.get_using_padding() && plain.gcount() < 16) { cryptor.get_padding()(tempBlock1, 16); }
	DogCryption::utils::squareXOR_self(tempBlock1, tempBlock0, tempBlock1.size());
	crypt.write((char*)tempBlock1.data(), tempBlock1.size());
	if(progress->load()<0){return;}progress->store(update_progress(progress->load(), 16, file_size));
	crypt.flush();
	progress->store(1.0);

}
void DogCryption::mode::decrypt_CFB128_streamp(std::istream& crypt, DogData::Data iv, std::ostream& plain, DogCryption::cryptor& cryptor, std::atomic<double>* progress)
{
	byte block_size = cryptor.get_block_size();
	Ullong now_pos = crypt.tellg();
	crypt.seekg(0, std::ios::end);
	Ullong file_size = crypt.tellg();
	crypt.seekg(now_pos);

	DogData::Data tempBlock0 = iv;
	DogData::Data tempBlock1(block_size);
	for (Ullong i = 0; i < (file_size - now_pos - 1) / block_size; ++i)
	{
		cryptor.get_block_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
		crypt.read((char*)tempBlock1.data(), block_size);
		plain.write((char*)DogCryption::utils::squareXOR(tempBlock0, tempBlock1, block_size).data(), block_size);
		if (progress->load() < 0.0)
		{
			return;
		}
		progress->store(update_progress(progress->load(), 16, file_size));
		tempBlock0 = tempBlock1;
	}
	cryptor.get_block_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
	crypt.read((char*)tempBlock1.data(), block_size);
	for (int i = 0; i < 16 - crypt.gcount(); i++) { tempBlock1.pop_back(); }
	DogCryption::utils::squareXOR_self(tempBlock1, tempBlock0, block_size);
	cryptor.get_unpadding()(tempBlock1, block_size);
	plain.write((char*)tempBlock1.data(), tempBlock1.size());
	if(progress->load()<0){return;}progress->store(update_progress(progress->load(), 16, file_size));
	plain.flush();
	progress->store(1.0);
}

//AES
DogData::Data DogCryption::AES::extendKey128(DogData::Data& key)
{
	DogData::Data res;
	res.reserve(176);
	
	if (key.size() < 16)
	{
		throw cryption_exception(std::format("Error:Invalid Key Size {}  < 16\n错误:密钥长度过短 {} < 16", key.size(), key.size()).c_str(),
			__FILE__, __FUNCTION__, __LINE__);
	}
	for (int i = 0; i < 16; i++)
	{
		res.push_back(key.at(i));
	}	
	for (int i = 16; i < 176; i += 4)
	{
		if (i % 16 == 0)
		{
			//取当前列-1
			byte temp1[4] = { res.at(i - 4), res.at(i - 3), res.at(i - 2), res.at(i - 1) };
			//列位移
			byte typeB = temp1[0];
			for (int i = 0; i < 3; i++)
			{
				temp1[i] = temp1[i + 1];
			}
			temp1[3] = typeB;
			//字节代还
			for (int i = 0; i < 4; i++)
			{
				temp1[i] = SBox[temp1[i] >> 4][temp1[i] & 0x0f];
			}
			//轮常量异或
			temp1[0] = temp1[0] ^ round[(i / 16) - 1];
			//取当前列-4并异或
			byte temp2[4] = { res.at(i - 16), res.at(i - 15), res.at(i - 14), res.at(i - 13) };
			for (int i = 0; i < 4; i++)
			{
				res.push_back(temp1[i] ^ temp2[i]);
			}
		}
		else
		{
			//取当前列-1
			byte temp1[4] = { res.at(i - 4), res.at(i - 3), res.at(i - 2), res.at(i - 1) };
			//取当前列-4并异或
			byte temp2[4] = { res.at(i - 16), res.at(i - 15), res.at(i - 14), res.at(i - 13) };
			for (int i = 0; i < 4; i++)
			{
				res.push_back(temp1[i] ^ temp2[i]);
			}
		}
	}
	return res;
}
DogData::Data DogCryption::AES::extendKey192(DogData::Data& key)
{
	DogData::Data res;
	res.reserve(208);
	if (key.size() < 24)
	{
		throw cryption_exception(std::format("Error:Invalid Key Size {}  < 24\n错误:密钥长度过短 {} < 24", key.size(), key.size()).c_str(),
			__FILE__, __FUNCTION__, __LINE__);
	}
	for (int i = 0; i < 24; i++)
	{
		res.push_back(key.at(i));
	}
	for (int i = 24; i < 208; i += 4)
	{
		if (i % 24 == 0)
		{
			//取当前列-1
			byte temp1[4] = { res.at(i - 4), res.at(i - 3), res.at(i - 2), res.at(i - 1) };
			//列位移
			byte typeB = temp1[0];
			for (int i = 0; i < 3; i++)
			{
				temp1[i] = temp1[i + 1];
			}
			temp1[3] = typeB;
			//字节代还
			for (int i = 0; i < 4; i++)
			{
				temp1[i] = SBox[temp1[i] >> 4][temp1[i] & 0x0f];
			}
			//轮常量异或
			temp1[0] = temp1[0] ^ round[(i / 24) - 1];
			//取当前列-6并异或
			byte temp2[4] = { res.at(i - 24), res.at(i - 23), res.at(i - 22), res.at(i - 21) };
			for (int i = 0; i < 4; i++)
			{
				res.push_back(temp1[i] ^ temp2[i]);
			}
		}
		else
		{
			//取当前列-1
			byte temp1[4] = { res.at(i - 4), res.at(i - 3), res.at(i - 2), res.at(i - 1) };
			//取当前列-6并异或
			byte temp2[4] = { res.at(i - 24), res.at(i - 23), res.at(i - 22), res.at(i - 21) };
			for (int i = 0; i < 4; i++)
			{
				res.push_back(temp1[i] ^ temp2[i]);
			}
		}
	}
	return res;
}
DogData::Data DogCryption::AES::extendKey256(DogData::Data& key)
{
	DogData::Data res;
	res.reserve(240);
	if (key.size() < 32)
	{
		throw cryption_exception(std::format("Error:Invalid Key Size {}  < 32\n错误:密钥长度过短 {} < 32", key.size(), key.size()).c_str(),
			__FILE__, __FUNCTION__, __LINE__);
	}
	for (int i = 0; i < 32; i++)
	{
		res.push_back(key.at(i));
	}
	for (int i = 32; i < 240; i += 4)
	{
		if (i % 32 == 0)
		{
			//取当前列-1
			byte temp1[4] = { res.at(i - 4), res.at(i - 3), res.at(i - 2), res.at(i - 1) };
			//列位移
			byte typeB = temp1[0];
			for (int i0 = 0; i0 < 3; i0++)
			{
				temp1[i0] = temp1[i0 + 1];
			}
			temp1[3] = typeB;
			//字节代还
			for (int i0 = 0; i0 < 4; i0++)
			{
				temp1[i0] = SBox[temp1[i0] >> 4][temp1[i0] & 0x0f];
			}
			//轮常量异或
			temp1[0] = temp1[0] ^ round[(i / 32) - 1];
			//取当前列-8并异或
			byte temp2[4] = { res.at(i - 32), res.at(i - 31), res.at(i - 30), res.at(i - 29) };
			for (int i0 = 0; i0 < 4; i0++)
			{
				res.push_back(temp1[i0] ^ temp2[i0]);
			}
		}
		else if (i % 16 == 0)
		{
			//取当前列-1
			byte temp1[4] = { res.at(i - 4), res.at(i - 3), res.at(i - 2), res.at(i - 1) };
			for (int i0 = 0; i0 < 4; i0++)
			{
				temp1[i0] = SBox[temp1[i0] >> 4][temp1[i0] & 0x0f];
			}
			//取当前列-8并异或
			byte temp2[4] = { res.at(i - 32), res.at(i - 31), res.at(i - 30), res.at(i - 29) };
			for (int i0 = 0; i0 < 4; i0++)
			{
				res.push_back(temp1[i0] ^ temp2[i0]);
			}
		}
		else
		{
			//取当前列-1
			byte temp1[4] = { res.at(i - 4), res.at(i - 3), res.at(i - 2), res.at(i - 1) };
			//取当前列-8并异或
			byte temp2[4] = { res.at(i - 32), res.at(i - 31), res.at(i - 30), res.at(i - 29) };
			for (int i0 = 0; i0 < 4; i0++)
			{
				res.push_back(temp1[i0] ^ temp2[i0]);
			}
		}
	}
	return res;
}
DogData::Data DogCryption::AES::AES_extend_key(DogData::Data& key, Ullong mode)
{
	if (mode == 16)
	{
		return extendKey128(key);
	}
	else if (mode == 24)
	{
		return extendKey192(key);
	}
	else if (mode == 32)
	{
		return extendKey256(key);
	}
	else
	{
		throw cryption_exception("wrong key length", __FILE__, __FUNCTION__, __LINE__);
	}
}

DogCryption::byte DogCryption::AES::Xtime(DogCryption::byte a, DogCryption::byte b)
{
	//1 2 4 8
	if (a == 0x01)
	{
		return b;
	}
	else if (a == 0x02)
	{
		if (b >> 7 == 0)
		{
			return b << 1;
		}
		else//  <==> else if (b >> 7 == 1)
		{
			return (b << 1) ^ 0x1b;
		}
	}
	else if (a == 0x04)
	{
		return Xtime(0x02, Xtime(0x02, b));
	}
	else if (a == 0x08)
	{
		return Xtime(0x02, Xtime(0x02, Xtime(0x02, b)));
	}
	else if (a == 0x03) //02+01
	{
		return Xtime(0x02, b) ^ b;
	}
	else if (a == 0x09) //08+01=09
	{
		return Xtime(0x08, b) ^ b;
	}
	else if (a == 0x0b) //08+02+01=13=0b
	{
		return Xtime(0x08, b) ^ Xtime(0x02, b) ^ b;
	}
	else if (a == 0x0d) //08+04+01
	{
		return Xtime(0x08, b) ^ Xtime(0x04, b) ^ b;
	}
	else if (a == 0x0e) //08+04+02=0e=14
	{
		return Xtime(0x08, b) ^ Xtime(0x04, b) ^ Xtime(0x02, b);
	}
	else
	{
		throw cryption_exception("wrong value of a", __FILE__, __FUNCTION__, __LINE__);
	}
}
DogData::Data DogCryption::AES::AESMiddleEncryptionMethod(DogData::Data datablock, int flag, int mode)
{

	DogData::Data res;
	res.reserve(16);
	//字节代换(00 04 08 12)
	for (int i = 0; i < 16; i++)
	{
		datablock[i] = AES::SBox[datablock.at(i) >> 4][datablock.at(i) & 0x0f];
	}

	/*printf("字节代换后数据\n");
	ShowBlock(datablock);*/

	//行位移
	//01 05 09 13 左移1位
	byte b1, b2;
	b1 = datablock[1];
	datablock[1] = datablock[5];
	datablock[5] = datablock[9];
	datablock[9] = datablock[13];
	datablock[13] = b1;
	//02 06 10 14 左移2位
	b1 = datablock[2];
	b2 = datablock[6];
	datablock[2] = datablock[10];
	datablock[6] = datablock[14];
	datablock[10] = b1;
	datablock[14] = b2;
	//03 07 11 15 右移1位代替左移3位
	b1 = datablock[15];
	datablock[15] = datablock[11];
	datablock[11] = datablock[7];
	datablock[7] = datablock[3];
	datablock[3] = b1;

	/*printf("行移位后数据\n");
	ShowBlock(datablock);*/

	//列混合
	if ((mode == 128 && flag != 9) || (mode == 192 && flag != 11) || (mode == 256 && flag != 13))
	{
		for (int i0 = 0; i0 < 16; i0 += 4)
		{
			for (int i1 = 0; i1 < 16; i1 += 4)
			{
				byte tempB = 0;
				for (int i2 = 0; i2 < 4; i2++)
				{
					tempB ^= DogCryption::AES::Xtime(MixTable[i1 + i2], datablock[i0 + i2]);
				}
				res.push_back(tempB);
			}
		}
	}
	else
	{
		for (int i0 = 0; i0 < 16; i0++)
		{
			res.push_back(datablock[i0]);
		}
	}

	return res;
}
DogData::Data DogCryption::AES::AESMiddleDecryptionMethod(DogData::Data datablock, int flag, int mode)
{
	DogData::Data res;
	res.reserve(16);
	//列混合
	if (flag != 0)
	{
		for (int i0 = 0; i0 < 16; i0 += 4)
		{
			for (int i1 = 0; i1 < 16; i1 += 4)
			{
				byte tempB = 0;
				for (int i2 = 0; i2 < 4; i2++)
				{
					tempB ^= DogCryption::AES::Xtime(UMixTable[i1 + i2], datablock[i0 + i2]);
				}
				res.push_back(tempB);
			}
		}
	}
	else
	{
		for (int i0 = 0; i0 < 16; i0++)
		{
			res.push_back(datablock[i0]);
		}
	}

	/*printf("列混合后数据\n");
	ShowBlock(res);*/

	//行位移
	byte b1, b2;
	//01 05 09 13 右移1位
	b1 = res[13];
	res[13] = res[9];
	res[9] = res[5];
	res[5] = res[1];
	res[1] = b1;
	//02 06 10 14 右移2位
	b1 = res[14];
	b2 = res[10];
	res[14] = res[6];
	res[10] = res[2];
	res[2] = b2;
	res[6] = b1;
	//03 07 11 15 左移1位代替右移3位
	b1 = res[3];
	res[3] = res[7];
	res[7] = res[11];
	res[11] = res[15];
	res[15] = b1;

	/*printf("行移位后数据\n");
	ShowBlock(res);*/

	//字节代换
	for (int i = 0; i < 16; i++)
	{
		res[i] = AES::InvSBox[res[i] >> 4][res[i] & 0x0f];
	}

	/*printf("字节代换后数据\n");
	ShowBlock(res);*/


	return res;
}
void DogCryption::AES::AESEncodingMachineSelf(DogData::Data& plain, byte block_size, const DogData::Data& key, byte key_size)
{
	DogData::Data tempKey = key.sub_by_pos(0, 16);
	plain = DogCryption::utils::squareXOR(plain, tempKey, 16);
	for (int i = 0; i < ((key_size / 4) + 6); i++)
	{
		plain = AES::AESMiddleEncryptionMethod(plain, i, key_size << 3);
		tempKey = key.sub_by_pos(16 * (i + 1), 16 * (i + 2));
		plain = DogCryption::utils::squareXOR(plain, tempKey, 16);
	}
}
void DogCryption::AES::AESDecodingMachineSelf(DogData::Data& cipher, byte block_size, const DogData::Data& key, byte key_size)
{
	DogData::Data tempKey = key.sub_by_pos((key_size * 4) + 96, (key_size * 4) + 112);
	cipher = DogCryption::utils::squareXOR(cipher, tempKey, 16);
	for (int i = 0; i < ((key_size / 4) + 6); i++)
	{
		cipher = AESMiddleDecryptionMethod(cipher, i, key_size << 3);
		tempKey = key.sub_by_pos(16 * ((key_size / 4) + 5 - i), 16 * ((key_size / 4) + 6 - i));//取当前轮密钥
		cipher = DogCryption::utils::squareXOR(cipher, tempKey, 16);//轮密钥加
	}
}

//SM4
DogCryption::Uint DogCryption::SM4::CLMB(Uint i, int n)
{
	int temp = n % 32;
	return  (i >> (32 - temp)) | (i << temp);
}
DogCryption::Uint DogCryption::SM4::TMixChange1(Uint n)
{
	Uint res = 0;
	for (int i = 0; i < 4; i++)
	{
		byte bs = (n >> (24 - i * 8)) & 0xff;
		bs = SBox[bs >> 4][(bs & 0x0f)];
		res += (Uint)bs << (24 - i * 8);
	}
	return res ^ CLMB(res, 13) ^ CLMB(res, 23);
}
DogCryption::Uint DogCryption::SM4::TMixChange2(Uint n)
{
	Uint res = 0;
	for (int i0 = 0; i0 < 4; ++i0)
	{
		byte bs = (n >> (24 - i0 * 8)) & 0xff;
		bs = SBox[bs >> 4][(bs & 0x0f)];
		res += (Uint)bs << (24 - i0 * 8);
	}
	Uint e = res ^ CLMB(res, 2) ^ CLMB(res, 10) ^ CLMB(res, 18) ^ CLMB(res, 24);
	return e;
}
DogData::Data DogCryption::SM4::SM4_extend_key(DogData::Data key, Ullong mode)
{
	DogData::Data res; res.reserve(128);
	Uint K[36];
	for (Ullong i = 0; i < 16; i += 4)
	{
		K[i / 4] = (Uint)key[i] << 24 | (Uint)key[i + 1] << 16 | (Uint)key[i + 2] << 8 | (Uint)key[i + 3];
		K[i / 4] ^= FK[i / 4];
	}
	for (Ullong i = 4; i < 36; i++)
	{
		K[i] = K[i - 4] ^ TMixChange1(K[i - 3] ^ K[i - 2] ^ K[i - 1] ^ CK[i - 4]);
		for (int i0 = 0; i0 < 4; i0++)
		{
			res.push_back((byte)(K[i] >> (24 - i0 * 8) & 0xff));
		}
	}
	return res;
}
void DogCryption::SM4::SM4EncodingMachineSelf(DogData::Data& plain, byte block_size, const DogData::Data& key, byte key_size)
{
	Uint temp[4] = { 0,0,0,0 };
	for (int i = 0; i < 16; i += 4)
	{
		for (int i0 = 0; i0 < 4; i0++)
		{
			temp[i / 4] += (Uint)plain[i + i0] << (24 - i0 * 8);
		}
	}
	for (int i = 0; i < 128; i += 4)
	{
		Uint tempRK = 0;
		//printf("%d\n", i);
		for (int j = 0; j < 4; j++)
		{
			tempRK += (Uint)key[i + j] << (24 - j * 8);
		}
		int n0 = (i / 4) % 4;// 2025/03/07-23:40 int n0 = (i / 4) % 4改成int n0=(i>>2)&0xff 出现i从108跃至-439497484 原因不明
		int n1 = (n0 + 1) % 4;
		int n2 = (n0 + 2) % 4;
		int n3 = (n0 + 3) % 4;
		temp[n0] = temp[n0] ^ TMixChange2(temp[n1] ^ temp[n2] ^ temp[n3] ^ tempRK);// 2025/03/07-23:40 发生上句修改后 此句执行后 出现i从108跃至-439497484 原因不明
	}
	for (int i = 0; i < 4; i++)
	{
		for (int j = 0; j < 4; j++)
		{
			plain[i * 4 + j] = (byte)(temp[3 - i] >> (24 - j * 8) & 0xff);
		}
	}
}
void DogCryption::SM4::SM4DecodingMachineSelf(DogData::Data& crypt, byte block_size, const DogData::Data& key, byte key_size)
{
	Uint temp[4] = { 0,0,0,0 };
	for (int i = 0; i < 16; i += 4)
	{
		for (int i0 = 0; i0 < 4; i0++)
		{
			temp[i / 4] += (Uint)crypt[i + i0] << (24 - i0 * 8);
		}
	}
	for (int i = 0; i < 128; i += 4)
	{
		Uint tempRK = 0;
		for (int j = 0; j < 4; j++)
		{
			tempRK += (Uint)key[124 - i + j] << (24 - j * 8);
		}
		int n0 = (i / 4) % 4;
		int n1 = (n0 + 1) % 4;
		int n2 = (n0 + 2) % 4;
		int n3 = (n0 + 3) % 4;
		temp[n0] = temp[n0] ^ TMixChange2(temp[n1] ^ temp[n2] ^ temp[n3] ^ tempRK);
	}
	for (int i = 0; i < 4; i++)
	{
		for (int j = 0; j < 4; j++)
		{
			crypt[i * 4 + j] = (byte)(temp[3 - i] >> (24 - j * 8) & 0xff);
		}
	}
}

DogData::Data DogCryption::camelia::camelia_extend_key(DogData::Data key, Ullong mode)
{
	return DogData::Data();
}
