#include "symmetric_encryption.h"

dog_cryption::CryptionException::CryptionException(const char* msg, const char* file, const char* function, uint64_t line)
{
	this->msg = std::format("{}:{}\n at {}({}:{})", typeid(*this).name(), msg, function, file, line);
}
const char* dog_cryption::CryptionException::what() const throw()
{
	return this->msg.c_str();
}

dog_cryption::CryptionConfig::CryptionConfig(
	const std::string& cryption_algorithm, const uint64_t block_size, const uint64_t key_size, 
	bool using_padding, const std::string& padding_function, 
	const std::string& mult_function, bool using_iv, bool with_iv, 
	std::vector<std::pair<std::string, std::any>> extra_config)
{
	this->cryption_algorithm_ = cryption_algorithm;
	this->block_size_ = block_size;
	this->key_size_ = key_size;
	this->using_padding_ = using_padding;
	this->padding_function_ = padding_function;
	this->mult_function_ = mult_function;
	this->using_iv_ = using_iv;
	this->with_iv_ = with_iv;
	for (auto& [key, value] : extra_config)
	{
		if (value.type() == typeid(const char*))
		{
			this->extra_config_[key] = std::string(std::any_cast<const char*>(value));
		}
		else if (value.type() == typeid(std::string) ||
			value.type() == typeid(uint8_t) ||
			value.type() == typeid(uint16_t) ||
			value.type() == typeid(uint32_t) ||
			value.type() == typeid(uint64_t) ||
			value.type() == typeid(int8_t) ||
			value.type() == typeid(int16_t) ||
			value.type() == typeid(int32_t) ||
			value.type() == typeid(int64_t))
		{
			this->extra_config_[key] = value;
		}
	}
}

dog_cryption::CryptionConfig::CryptionConfig(
	const std::string& cryption_algorithm, const uint64_t block_size, const uint64_t key_size, 
	bool using_padding, const std::string& padding_function, 
	const std::string& mult_function, bool using_iv, bool with_iv, 
	std::unordered_map<std::string, std::any> extra_config)
{
	this->cryption_algorithm_ = cryption_algorithm;
	this->block_size_ = block_size;
	this->key_size_ = key_size;
	this->using_padding_ = using_padding;
	this->padding_function_ = padding_function;
	this->mult_function_ = mult_function;
	this->using_iv_ = using_iv;
	this->with_iv_ = with_iv;
	this->extra_config_ = extra_config;
}
dog_data::Data dog_cryption::CryptionConfig::to_data() const
{
	dog_data::Data res;
	
	auto string_append = [&res](const std::string& value) -> void
		{
			uint8_t type_size = dog_cryption::utils::get_type_size<std::string>(value);
			res.push_back(type_size);
			for (auto& c : value)
			{
				res.push_back(c);
			}
		};
	auto uint_append = [&res](const uint64_t& value, bool allow_zero) -> void
		{
			if (!allow_zero && value == 0)
			{
				throw dog_cryption::CryptionException("uint64_t value is zero", __FILE__, __FUNCTION__, __LINE__);
			}
			uint8_t type_size = dog_cryption::utils::get_type_size<uint64_t>(value);
			res.push_back(type_size);
			for (uint8_t i = (type_size & 0x0f); i > 0 ; i--)
			{
				res.push_back(dog_number::integer::pick_byte(value, i));
			}
		};
	auto int_append = [&res](const int64_t& value, bool allow_zero) -> void
		{
			if (!allow_zero && value == 0)
			{
				throw dog_cryption::CryptionException("int64_t value is zero", __FILE__, __FUNCTION__, __LINE__);	
			}
			uint8_t type_size = dog_cryption::utils::get_type_size<int64_t>(value);
			res.push_back(type_size);
			uint64_t value_abs = value < 0 ? -value : value;
			for (uint8_t i = (type_size & 0x0f); i > 0; i--)
			{
				res.push_back(dog_number::integer::pick_byte(value_abs, i));
			}
		};
	auto float_append = [&res](const float& value, bool allow_zero) -> void
		{
			if (!allow_zero && value == 0)
			{
				throw dog_cryption::CryptionException("float value is zero", __FILE__, __FUNCTION__, __LINE__);
			}
			uint8_t type_size = dog_cryption::utils::get_type_size<float>(value);
			res.push_back(type_size);
			float value_float = value;
			uint32_t value_int = *reinterpret_cast<uint32_t*>(&value_float);
			for (uint8_t i = 4; i > 0; i--)
			{
				res.push_back(value_int << (i * 8) >> 24);
			}
		};
	auto double_append = [&res](const double& value, bool allow_zero) -> void
		{
			if (!allow_zero && value == 0)
			{
				throw dog_cryption::CryptionException("double value is zero", __FILE__, __FUNCTION__, __LINE__);
			}
			uint8_t type_size = dog_cryption::utils::get_type_size<double>(value);
			res.push_back(type_size);
			double value_double = value;
			uint64_t value_int = *reinterpret_cast<uint64_t*>(&value_double);
			for (uint8_t i = 8; i > 0; i--)
			{
				res.push_back(value_int << (i * 8) >> 56);
			}
		};
	auto bool_append = [&res](const bool& value) -> void
		{
			uint8_t type_size = dog_cryption::utils::get_type_size<bool>(value);
			res.push_back(type_size);
		};

	string_append(this->cryption_algorithm_);
	uint_append(this->block_size_, false);
	uint_append(this->key_size_, false);
	
	{
		using namespace dog_cryption::mode;
		if (this->mult_function_ == ECB::name)          { res.push_back(ECB::CODE); }
		else if (this->mult_function_ == CBC::name)     { res.push_back(CBC::CODE); }
		else if (this->mult_function_ == OFB::name)     { res.push_back(OFB::CODE); }
		else if (this->mult_function_ == CTR::name)     { res.push_back(CTR::CODE); }
		else if (this->mult_function_ == CFBB::name) { res.push_back(CFBB::CODE); }
		else if (this->mult_function_ == CFBb::name)  { res.push_back(CFBb::CODE); }
	}
	bool_append(this->using_iv_);
	bool_append(this->with_iv_);
	bool_append(this->using_padding_);
	if (this->using_padding_)
	{
		using namespace dog_cryption::padding;
		if (this->padding_function_ == PKCS7)          { res.push_back(PKCS7_CODE); }
		else if (this->padding_function_ == ZERO)      { res.push_back(ZERO_CODE); }
		else if (this->padding_function_ == ANSIX923)  { res.push_back(ANSIX923_CODE); }
		else if (this->padding_function_ == ISO10126)  { res.push_back(ISO10126_CODE); }
		else if (this->padding_function_ == ISO7816_4) { res.push_back(ISO7816_4_CODE); }
	}
	for (auto& [key, value] : this->extra_config_)
	{
		if (value.type() == typeid(std::string))
		{
			string_append(key);
			string_append(std::any_cast<std::string>(value));
		}
		else if (value.type() == typeid(bool))
		{
			string_append(key);
			bool_append(std::any_cast<bool>(value));
		}
		else if (value.type() == typeid(uint8_t) || value.type() == typeid(uint16_t) || value.type() == typeid(uint32_t) || value.type() == typeid(uint64_t))
		{
			string_append(key);
			uint64_t value_num = std::any_cast<uint64_t>(value);
			uint_append(value_num, true);
		}
		else if (value.type() == typeid(int8_t) || value.type() == typeid(int16_t) || value.type() == typeid(int32_t) || value.type() == typeid(int64_t))
		{
			string_append(key);
			int64_t value_num = std::any_cast<int64_t>(value);
			int_append(value_num, true);
		}
		else if (value.type() == typeid(float))
		{
			string_append(key);
			float value_num = std::any_cast<float>(value);
			float_append(value_num, true);
		}
		else if (value.type() == typeid(double))
		{
			string_append(key);
			double value_num = std::any_cast<double>(value);
			double_append(value_num, true);
		}
	}
	res.push_back(0b00110000);
	return res;
}
std::string dog_cryption::CryptionConfig::to_string() const
{
	//{cryption_algorithm}_{block_size}_{key_size}_{mult_function}_{using_iv}_{with_iv}_{using_padding}_{padding_function}_{"key":value}
	std::string base_str = std::format("{}_{}_{}_{}_{}_{}_{}_{}",
		cryption_algorithm_, block_size_, key_size_,
		mult_function_, (using_iv_ ? "UsingIV" : "NotUsingIV"), (with_iv_ ? "WithIV" : "NotWithIv"),
		(using_padding_ ? "UsingPadding" : "NotUsingPadding"), padding_function_);
	if (!this->extra_config_.empty())
	{
		std::string extra_str = "{";
		for (auto& [key, value] : this->extra_config_)
		{
			if (value.type() == typeid(std::string))
			{
				std::string value_str = std::any_cast<std::string>(value);
				std::string single = std::vformat("\"{}\":\"{}\"", std::make_format_args(key, value_str));
				extra_str = extra_str + single + ",";
			}
			else if (value.type() == typeid(uint8_t))
			{
				uint64_t value_num = std::any_cast<uint8_t>(value);
				std::string single = std::vformat("\"{}\":{}", std::make_format_args(key, value_num));
				extra_str = extra_str + single + ",";
			}
			else if (value.type() == typeid(uint16_t))
			{
				uint64_t value_num = std::any_cast<uint16_t>(value);
				std::string single = std::vformat("\"{}\":{}", std::make_format_args(key, value_num));
				extra_str = extra_str + single + ",";
			}
			else if (value.type() == typeid(uint32_t))
			{
				uint64_t value_num = std::any_cast<uint32_t>(value);
				std::string single = std::vformat("\"{}\":{}", std::make_format_args(key, value_num));
				extra_str = extra_str + single + ",";
			}
			else if (value.type() == typeid(uint64_t))
			{
				uint64_t value_num = std::any_cast<uint64_t>(value);
				std::string single = std::vformat("\"{}\":{}", std::make_format_args(key, value_num));
				extra_str = extra_str + single + ",";
			}
			else if (value.type() == typeid(int8_t))
			{
				uint64_t value_num = std::any_cast<int8_t>(value);
				std::string single = std::vformat("\"{}\":{}", std::make_format_args(key, value_num));
				extra_str = extra_str + single + ",";
			}
			else if (value.type() == typeid(int16_t))
			{
				uint64_t value_num = std::any_cast<int16_t>(value);
				std::string single = std::vformat("\"{}\":{}", std::make_format_args(key, value_num));
				extra_str = extra_str + single + ",";
			}
			else if (value.type() == typeid(int32_t))
			{
				uint64_t value_num = std::any_cast<int32_t>(value);
				std::string single = std::vformat("\"{}\":{}", std::make_format_args(key, value_num));
				extra_str = extra_str + single + ",";
			}
			else if (value.type() == typeid(int64_t))
			{
				uint64_t value_num = std::any_cast<int64_t>(value);
				std::string single = std::vformat("\"{}\":{}", std::make_format_args(key, value_num));
				extra_str = extra_str + single + ",";
			}
			
		}
		return base_str + extra_str.substr(0, extra_str.size() - 1) + "}";
	}
	else
	{
		return base_str;
	}
}
dog_cryption::CryptionConfig dog_cryption::CryptionConfig::get_cryption_config(std::istream& config_stream, bool return_start)
{
	dog_cryption::CryptionConfig config;

	auto read_string = [&config_stream](std::bitset<8> type_size)->std::pair<bool, std::string>
		{
			std::string read_str = "";
			if (type_size[7] != 1 || type_size[6] != 1)
			{
				//throw CryptionException("invalid config format, must start with 0b 11xx xxxx to stand string", __FILE__, __FUNCTION__, __LINE__);
				return std::make_pair(false, read_str);
			}
			type_size[7] = 0; type_size[6] = 0;
			for (uint64_t i = 0; i < type_size.to_ulong(); i++)
			{
				read_str += config_stream.get();
			}
			return std::make_pair(true, read_str);
		};
	auto read_unsigned_integer = [&config_stream](std::bitset<8> type_size)->std::pair<bool, uint64_t>
		{
			uint64_t read_num = 0;
			if (type_size[7] != 0 || type_size[6] != 1 || type_size[5] != 0)
			{
				return std::make_pair(false, 0);
			}
			type_size[7] = 0; type_size[6] = 0; type_size[5] = 0; type_size[4] = 0;
			for (uint64_t i = 0; i < type_size.to_ulong(); i++)
			{
				read_num |= (config_stream.get()) << ((i - 1) * 8);
			}
			return std::make_pair(true, read_num);
		};
	auto read_signed_integer = [&config_stream](std::bitset<8> type_size)->std::pair<bool, int64_t>
		{
			int64_t read_num = 0;
			if (type_size[7] != 0 || type_size[6] != 1 || type_size[5] != 1)
			{
				return std::make_pair(false, 0);
			}
			for (uint64_t i = 0; i < (type_size & std::bitset<8>(0x0F)).to_ulong(); i++)
			{
				read_num |= (config_stream.get()) << ((i - 1) * 8);
			}
			if (type_size[4] == 1)
			{
				read_num *= -1;
			}
			return std::make_pair(true, read_num);
		};
	auto read_float = [&config_stream](std::bitset<8> type_size)->std::pair<bool, float>
		{
			float read_num = 0;
			if (type_size[7] != 1 || type_size[6] != 0)
			{
				return std::make_pair(false, 0);
			}
			type_size[7] = 0; type_size[6] = 0; type_size[5] = 0; type_size[4] = 0;
			if (type_size.to_ullong() != 4)
			{
				return std::make_pair(false, 0);
			}
			uint32_t read_uint = 0;
			read_uint |= (config_stream.get()) << 24;
			read_uint |= (config_stream.get()) << 16;
			read_uint |= (config_stream.get()) << 8;
			read_uint |= (config_stream.get());
			read_num = *reinterpret_cast<float*>(&read_uint);
			return std::make_pair(true, read_num);
		};
	auto read_double = [&config_stream](std::bitset<8> type_size)->std::pair<bool, double>
		{
			float read_num = 0;
			if (type_size[7] != 1 || type_size[6] != 0)
			{
				return std::make_pair(false, 0);
			}
			type_size[7] = 0; type_size[6] = 0; type_size[5] = 0; type_size[4] = 0;
			if (type_size.to_ullong() != 8)
			{
				return std::make_pair(false, 0);
			}
			uint64_t read_uint = 0;
			read_uint |= (config_stream.get()) << 56;
			read_uint |= (config_stream.get()) << 48;
			read_uint |= (config_stream.get()) << 40;
			read_uint |= (config_stream.get()) << 32;
			read_uint |= (config_stream.get()) << 24;
			read_uint |= (config_stream.get()) << 16;
			read_uint |= (config_stream.get()) << 8;
			read_uint |= (config_stream.get());
			read_num = *reinterpret_cast<double*>(&read_uint);
			return std::make_pair(true, read_num);
		};
	auto read_bool = [&config_stream](std::bitset<8> type_size)->std::pair<bool, bool>
		{
			bool read_bool = false;
			if (type_size[7] != 0 || type_size[6] != 0)
			{
				return std::make_pair(false, false);
			}
			type_size[7] = 0; type_size[6] = 0; type_size[5] = 0; type_size[4] = 0;
			return std::make_pair(true, type_size.to_ullong() == 0);
		};

	//算法名
	auto res0 = read_string(std::bitset<8>(config_stream.get()));
	if (!res0.first)
	{
		throw CryptionException("invalid config format, must start with 0b 11xx xxxx to stand string", __FILE__, __FUNCTION__, __LINE__);
	}
	config.cryption_algorithm_ = res0.second;
	//分块大小
	auto res1 = read_unsigned_integer(std::bitset<8>(config_stream.get()));
	if (!res1.first)
	{
		throw CryptionException("invalid config format, must start with 0b 10xx xxxx to stand unsigned integer", __FILE__, __FUNCTION__,__LINE__);
	}
	config.block_size_ = res1.second;
	//密钥大小
	auto res2 = read_unsigned_integer(std::bitset<8>(config_stream.get()));
	if (!res2.first)
	{
		throw CryptionException("invalid config format, must start with 0b 10xx xxxx to stand unsigned integer", __FILE__, __FUNCTION__, __LINE__);
	}
	config.key_size_ = res2.second;
	//分组加密模式
	switch (config_stream.get())
	{
	case dog_cryption::mode::ECB::CODE:
	{
		config.mult_function_ = dog_cryption::mode::ECB::name;
		break;
	}
	case dog_cryption::mode::CBC::CODE:
	{
		config.mult_function_ = dog_cryption::mode::CBC::name;
		break;
	}
	case dog_cryption::mode::OFB::CODE:
	{
		config.mult_function_ = dog_cryption::mode::OFB::name;
		break;
	}
	case dog_cryption::mode::CTR::CODE:
	{
		config.mult_function_ = dog_cryption::mode::CTR::name;
		break;
	}
	case dog_cryption::mode::CFBB::CODE:
	{
		config.mult_function_ = dog_cryption::mode::CFBB::name;
		break;
	}
	case dog_cryption::mode::CFBb::CODE:
	{
		config.mult_function_ = dog_cryption::mode::CFBb::name;
		break;
	}
	default:
	{
		throw CryptionException("invalid config format, wrong mode code.", __FILE__, __FUNCTION__, __LINE__);
	}
	}
	//使用iv
	auto res3 = read_bool(std::bitset<8>(config_stream.get()));
	if (!res3.first)
	{
		throw CryptionException("invalid config format, must start with 0b 00xx xxxx to stand bool", __FILE__, __FUNCTION__, __LINE__);
	}
	config.using_iv_ = res3.second;
	//携带iv
	auto res4 = read_bool(std::bitset<8>(config_stream.get()));
	if (!res4.first)
	{
		throw CryptionException("invalid config format, must start with 0b 00xx xxxx to stand bool", __FILE__, __FUNCTION__, __LINE__);
	}
	config.with_iv_ = res4.second;
	//使用填充
	auto res5 = read_bool(std::bitset<8>(config_stream.get()));
	if (!res5.first)
	{
		throw CryptionException("invalid config format, must start with 0b 00xx xxxx to stand bool", __FILE__, __FUNCTION__, __LINE__);
	}
	config.using_padding_ = res5.second;
	//填充方式
	if (config.using_padding_)
	{
		switch (config_stream.get())
		{
		case dog_cryption::padding::NONE_CODE:
		{
			config.padding_function_ = dog_cryption::padding::NONE;
			break;
		}
		case dog_cryption::padding::PKCS7_CODE:
		{
			config.padding_function_ = dog_cryption::padding::PKCS7;
			break;
		}
		case dog_cryption::padding::ZERO_CODE:
		{
			config.padding_function_ = dog_cryption::padding::ZERO;
			break;
		}
		case dog_cryption::padding::ANSIX923_CODE:
		{
			config.padding_function_ = dog_cryption::padding::ANSIX923;
			break;
		}
		case dog_cryption::padding::ISO10126_CODE:
		{
			config.padding_function_ = dog_cryption::padding::ISO10126;
			break;
		}
		default:
		{
			throw CryptionException("invalid config format, must start with 0b 10xx xxxx to stand unsigned integer", __FILE__, __FUNCTION__, __LINE__);
		}
		}
	}
	uint8_t type_size = config_stream.get();
	while (type_size != 0b00110000)
	{
		auto key_res = read_string(std::bitset<8>(type_size));
		if (!key_res.first)
		{
			throw CryptionException("invalid config format", __FILE__, __FUNCTION__, __LINE__);
		}
		std::string key = key_res.second;
		std::bitset<8> type_size = config_stream.get();
		switch ((type_size[7] << 1) | type_size[6])
		{
		case 0b00:
		{
			auto res = read_bool(std::bitset<8>(type_size));
			std::any value = res.second;
			config.extra_config_.insert(std::make_pair(key, value));
		}
		case 0b01:
		{
			if (type_size[5] == 0)
			{
				auto res = read_unsigned_integer(std::bitset<8>(type_size));
				std::any value = res.second;
				config.extra_config_.insert(std::make_pair(key, value));
			}
			else
			{
				auto res = read_signed_integer(std::bitset<8>(type_size));
				std::any value = res.second;
				config.extra_config_.insert(std::make_pair(key, value));
			}
		}
		case 0b10:
		{
			type_size[7] = 0; type_size[6] = 0; type_size[5] = 0; type_size[4] = 0;
			if (type_size.to_ullong() == 4)
			{
				type_size[7] = 1; type_size[6] = 0;
				auto res = read_float(std::bitset<8>(type_size));
				std::any value = res.second;
				config.extra_config_.insert(std::make_pair(key, value));
			}
			else if (type_size.to_ullong() == 8)
			{
				type_size[7] = 1; type_size[6] = 0;
				auto res = read_double(std::bitset<8>(type_size));
				std::any value = res.second;
				config.extra_config_.insert(std::make_pair(key, value));
			}
		}
		case 0b11:
		{
			auto res = read_string(std::bitset<8>(type_size));
			std::any value = res.second;
			config.extra_config_.insert(std::make_pair(key, value));
		}
		default:
		{
			throw CryptionException("invalid config format", __FILE__, __FUNCTION__, __LINE__);
		}
		}

	}
	if (return_start)
	{
		config_stream.seekg(0);
	}
	return config;
}
dog_cryption::CryptionConfig dog_cryption::CryptionConfig::get_cryption_config(const dog_data::Data& config_data)
{
	dog_cryption::CryptionConfig config;

	uint64_t pos = 0;

	auto get = [&config_data,&pos]() ->uint8_t
		{
			uint8_t res = config_data[pos];
			pos++;
			return res;
		};

	auto read_string = [&get](std::bitset<8> type_size)->std::pair<bool, std::string>
		{
			std::string read_str = "";
			if (type_size[7] != 1 || type_size[6] != 1)
			{
				//throw CryptionException("invalid config format, must start with 0b 11xx xxxx to stand string", __FILE__, __FUNCTION__, __LINE__);
				return std::make_pair(false, read_str);
			}
			type_size[7] = 0; type_size[6] = 0;
			for (uint64_t i = 0; i < type_size.to_ulong(); i++)
			{
				read_str += get();
			}
			return std::make_pair(true, read_str);
		};
	auto read_unsigned_integer = [&get](std::bitset<8> type_size)->std::pair<bool, uint64_t>
		{
			uint64_t read_num = 0;
			if (type_size[7] != 0 || type_size[6] != 1 || type_size[5] != 0)
			{
				return std::make_pair(false, 0);
			}
			type_size[7] = 0; type_size[6] = 0; type_size[5] = 0; type_size[4] = 0;
			for (uint64_t i = 0; i < type_size.to_ulong(); i++)
			{
				read_num |= (get()) << ((i - 1) * 8);
			}
			return std::make_pair(true, read_num);
		};
	auto read_signed_integer = [&get](std::bitset<8> type_size)->std::pair<bool, int64_t>
		{
			int64_t read_num = 0;
			if (type_size[7] != 0 || type_size[6] != 1 || type_size[5] != 1)
			{
				return std::make_pair(false, 0);
			}
			for (uint64_t i = 0; i < (type_size & std::bitset<8>(0x0F)).to_ulong(); i++)
			{
				read_num |= (get()) << ((i - 1) * 8);
			}
			if (type_size[4] == 1)
			{
				read_num *= -1;
			}
			return std::make_pair(true, read_num);
		};
	auto read_float = [&get](std::bitset<8> type_size)->std::pair<bool, float>
		{
			float read_num = 0;
			if (type_size[7] != 1 || type_size[6] != 0)
			{
				return std::make_pair(false, 0);
			}
			type_size[7] = 0; type_size[6] = 0; type_size[5] = 0; type_size[4] = 0;
			if (type_size.to_ullong() != 4)
			{
				return std::make_pair(false, 0);
			}
			uint32_t read_uint = 0;
			read_uint |= (get()) << 24;
			read_uint |= (get()) << 16;
			read_uint |= (get()) << 8;
			read_uint |= (get());
			read_num = *reinterpret_cast<float*>(&read_uint);
			return std::make_pair(true, read_num);
		};
	auto read_double = [&get](std::bitset<8> type_size)->std::pair<bool, double>
		{
			float read_num = 0;
			if (type_size[7] != 1 || type_size[6] != 0)
			{
				return std::make_pair(false, 0);
			}
			type_size[7] = 0; type_size[6] = 0; type_size[5] = 0; type_size[4] = 0;
			if (type_size.to_ullong() != 8)
			{
				return std::make_pair(false, 0);
			}
			uint64_t read_uint = 0;
			read_uint |= (get()) << 56;
			read_uint |= (get()) << 48;
			read_uint |= (get()) << 40;
			read_uint |= (get()) << 32;
			read_uint |= (get()) << 24;
			read_uint |= (get()) << 16;
			read_uint |= (get()) << 8;
			read_uint |= (get());
			read_num = *reinterpret_cast<double*>(&read_uint);
			return std::make_pair(true, read_num);
		};
	auto read_bool = [&get](std::bitset<8> type_size)->std::pair<bool, bool>
		{
			bool read_bool = false;
			if (type_size[7] != 0 || type_size[6] != 0)
			{
				return std::make_pair(false, false);
			}
			type_size[7] = 0; type_size[6] = 0; type_size[5] = 0; type_size[4] = 0;
			return std::make_pair(true, type_size.to_ullong() == 0);
		};

	//算法名
	auto res0 = read_string(std::bitset<8>(get()));
	if (!res0.first)
	{
		throw CryptionException("invalid config format, must start with 0b 11xx xxxx to stand string", __FILE__, __FUNCTION__, __LINE__);
	}
	config.cryption_algorithm_ = res0.second;
	//分块大小
	auto res1 = read_unsigned_integer(std::bitset<8>(get()));
	if (!res1.first)
	{
		throw CryptionException("invalid config format, must start with 0b 10xx xxxx to stand unsigned integer", __FILE__, __FUNCTION__, __LINE__);
	}
	config.block_size_ = res1.second;
	//密钥大小
	auto res2 = read_unsigned_integer(std::bitset<8>(get()));
	if (!res2.first)
	{
		throw CryptionException("invalid config format, must start with 0b 10xx xxxx to stand unsigned integer", __FILE__, __FUNCTION__, __LINE__);
	}
	config.key_size_ = res2.second;
	//分组加密模式
	switch (get())
	{
	case dog_cryption::mode::ECB::CODE:
	{
		config.mult_function_ = dog_cryption::mode::ECB::name;
		break;
	}
	case dog_cryption::mode::CBC::CODE:
	{
		config.mult_function_ = dog_cryption::mode::CBC::name;
		break;
	}
	case dog_cryption::mode::OFB::CODE:
	{
		config.mult_function_ = dog_cryption::mode::OFB::name;
		break;
	}
	case dog_cryption::mode::CTR::CODE:
	{
		config.mult_function_ = dog_cryption::mode::CTR::name;
		break;
	}
	case dog_cryption::mode::CFBB::CODE:
	{
		config.mult_function_ = dog_cryption::mode::CFBB::name;
		break;
	}
	case dog_cryption::mode::CFBb::CODE:
	{
		config.mult_function_ = dog_cryption::mode::CFBb::name;
		break;
	}
	default:
	{
		throw CryptionException("invalid config format, wrong mode code.", __FILE__, __FUNCTION__, __LINE__);
	}
	}
	//使用iv
	auto res3 = read_bool(std::bitset<8>(get()));
	if (!res3.first)
	{
		throw CryptionException("invalid config format, must start with 0b 00xx xxxx to stand bool", __FILE__, __FUNCTION__, __LINE__);
	}
	config.using_iv_ = res3.second;
	//携带iv
	auto res4 = read_bool(std::bitset<8>(get()));
	if (!res4.first)
	{
		throw CryptionException("invalid config format, must start with 0b 00xx xxxx to stand bool", __FILE__, __FUNCTION__, __LINE__);
	}
	config.with_iv_ = res4.second;
	//使用填充
	auto res5 = read_bool(std::bitset<8>(get()));
	if (!res5.first)
	{
		throw CryptionException("invalid config format, must start with 0b 00xx xxxx to stand bool", __FILE__, __FUNCTION__, __LINE__);
	}
	config.using_padding_ = res5.second;
	//填充方式
	if (config.using_padding_)
	{
		switch (get())
		{
		case dog_cryption::padding::NONE_CODE:
		{
			config.padding_function_ = dog_cryption::padding::NONE;
			break;
		}
		case dog_cryption::padding::PKCS7_CODE:
		{
			config.padding_function_ = dog_cryption::padding::PKCS7;
			break;
		}
		case dog_cryption::padding::ZERO_CODE:
		{
			config.padding_function_ = dog_cryption::padding::ZERO;
			break;
		}
		case dog_cryption::padding::ANSIX923_CODE:
		{
			config.padding_function_ = dog_cryption::padding::ANSIX923;
			break;
		}
		case dog_cryption::padding::ISO10126_CODE:
		{
			config.padding_function_ = dog_cryption::padding::ISO10126;
			break;
		}
		default:
		{
			throw CryptionException("invalid config format, must start with 0b 10xx xxxx to stand unsigned integer", __FILE__, __FUNCTION__, __LINE__);
		}
		}
	}
	uint8_t type_size = get();
	while (type_size != 0b00110000)
	{
		auto key_res = read_string(std::bitset<8>(type_size));
		if (!key_res.first)
		{
			throw CryptionException("invalid config format", __FILE__, __FUNCTION__, __LINE__);
		}
		std::string key = key_res.second;
		std::bitset<8> type_size = get();
		switch ((type_size[7] << 1) | type_size[6])
		{
		case 0b00:
		{
			auto res = read_bool(std::bitset<8>(type_size));
			std::any value = res.second;
			config.extra_config_.insert(std::make_pair(key, value));
		}
		case 0b01:
		{
			if (type_size[5] == 0)
			{
				auto res = read_unsigned_integer(std::bitset<8>(type_size));
				std::any value = res.second;
				config.extra_config_.insert(std::make_pair(key, value));
			}
			else
			{
				auto res = read_signed_integer(std::bitset<8>(type_size));
				std::any value = res.second;
				config.extra_config_.insert(std::make_pair(key, value));
			}
		}
		case 0b10:
		{
			type_size[7] = 0; type_size[6] = 0; type_size[5] = 0; type_size[4] = 0;
			if (type_size.to_ullong() == 4)
			{
				type_size[7] = 1; type_size[6] = 0;
				auto res = read_float(std::bitset<8>(type_size));
				std::any value = res.second;
				config.extra_config_.insert(std::make_pair(key, value));
			}
			else if (type_size.to_ullong() == 8)
			{
				type_size[7] = 1; type_size[6] = 0;
				auto res = read_double(std::bitset<8>(type_size));
				std::any value = res.second;
				config.extra_config_.insert(std::make_pair(key, value));
			}
		}
		case 0b11:
		{
			auto res = read_string(std::bitset<8>(type_size));
			std::any value = res.second;
			config.extra_config_.insert(std::make_pair(key, value));
		}
		default:
		{
			throw CryptionException("invalid config format", __FILE__, __FUNCTION__, __LINE__);
		}
		}

	}
	return config;
}
bool dog_cryption::Cryptor::is_config_available(const CryptionConfig& config)
{
	std::string name = config.cryption_algorithm_;
	if (name == dog_cryption::AES::name)
	{
		using namespace dog_cryption::AES;
		if (!dog_cryption::utils::is_in_region(KEY_REGION, config.key_size_))
		{
			throw CryptionException(std::format("invalid key size for {},{} only support number in {}", name, name, KEY_REGION).c_str(), __FILE__, __FUNCTION__, __LINE__);
		}
		if (!dog_cryption::utils::is_in_region(BLOCK_REGION, config.block_size_))
		{
			throw CryptionException(std::format("invalid block size for {},{} only support number in {}", name, name, BLOCK_REGION).c_str(), __FILE__, __FUNCTION__, __LINE__);
		}
	}
	else if (name == dog_cryption::SM4::name)
	{
		using namespace dog_cryption::SM4;
		if (!dog_cryption::utils::is_in_region(KEY_REGION, config.key_size_))
		{
			throw CryptionException(std::format("invalid key size for {},{} only support number in {}", name, name, KEY_REGION).c_str(), __FILE__, __FUNCTION__, __LINE__);
		}
		if (!dog_cryption::utils::is_in_region(BLOCK_REGION, config.block_size_))
		{
			throw CryptionException(std::format("invalid block size for {},{} only support number in {}", name, name, BLOCK_REGION).c_str(), __FILE__, __FUNCTION__, __LINE__);
		}
	}
	else if (name == dog_cryption::camellia::name)
	{
		using namespace dog_cryption::camellia;
		if (!dog_cryption::utils::is_in_region(KEY_REGION, config.key_size_))
		{
			throw CryptionException(std::format("invalid key size for {},{} only support number in {}", name, name, KEY_REGION).c_str(), __FILE__, __FUNCTION__, __LINE__);
		}
		if (!dog_cryption::utils::is_in_region(BLOCK_REGION, config.block_size_))
		{
			throw CryptionException(std::format("invalid block size for {},{} only support number in {}", name, name, BLOCK_REGION).c_str(), __FILE__, __FUNCTION__, __LINE__);
		}
		/*
		if (config.extra_config_.find("table") == config.extra_config_.end())
		{
			throw CryptionException(std::format("invalid config for {},{} need table", name, name).c_str(), __FILE__, __FUNCTION__, __LINE__);
		}
		std::any table = config.extra_config_.at("table");
		const std::type_info& type = typeid(table);
		if (type != typeid(uint8_t) && type != typeid(int8_t) &&
			type != typeid(uint16_t) && type != typeid(int16_t) &&
			type != typeid(uint32_t) && type != typeid(int32_t) &&
			type != typeid(uint64_t) && type != typeid(int64_t))
		{
			throw CryptionException(std::format("invalid config for {},{} table need integer", name, name).c_str(), __FILE__, __FUNCTION__, __LINE__);
		}
		*/
	}
	else
	{
		throw CryptionException("invalid cryption algorithm", __FILE__, __FUNCTION__, __LINE__);
	}

	{
		using namespace dog_cryption::padding;
		std::string padding_name = config.padding_function_;
		if (padding_name != PKCS7 && 
			padding_name != ZERO &&
			padding_name != ANSIX923 &&
			padding_name != ISO10126 &&
			padding_name != ISO7816_4 &&
			padding_name != NONE)
		{
			throw CryptionException("invalid padding function", __FILE__, __FUNCTION__, __LINE__);
		}
	}
	
	{
		using namespace dog_cryption::mode;
		std::string mult_mode = config.mult_function_;
		/*
		   vx:不强制 v:强制
				 iv|填充|
			ECB |vx|v |
			CBC |v |v |
			OFB |v |vx|
			CTR |v |vx|
			CFB |v |vx|
		*/
		if (mult_mode == ECB::name)
		{
			if (!config.using_padding_)
			{
				throw CryptionException("ECB mode must use padding", __FILE__, __FUNCTION__, __LINE__);
			}
		}
		else if (mult_mode == CBC::name)
		{
			if (!config.using_iv_)
			{
				throw CryptionException("CBC mode must use iv", __FILE__, __FUNCTION__, __LINE__);
			}
			if (!config.using_padding_)
			{
				throw CryptionException("CBC mode must use padding", __FILE__, __FUNCTION__, __LINE__);
			}
		}
		else if (mult_mode == CFBb::name || mult_mode == CFBB::name || mult_mode == OFB::name || mult_mode == CTR::name)
		{
			if (!config.using_iv_)
			{
				throw CryptionException("CFB mode must use iv", __FILE__, __FUNCTION__, __LINE__);
			}
		}
		else
		{
			throw CryptionException("invalid encryption mode", __FILE__, __FUNCTION__, __LINE__);
		}
	}
}

//cryptor
dog_cryption::Cryptor::Cryptor(
	const std::string& cryption_algorithm, const uint64_t block_size, const uint64_t key_size,
	bool using_padding, const std::string& padding_function,
	const std::string& mult_function, bool using_iv, bool with_iv,
	std::vector<std::pair<std::string, std::any>> extra_config)
{
	std::string name = cryption_algorithm;
	if (name == dog_cryption::AES::name)
	{
		using namespace dog_cryption::AES;
		if (!dog_cryption::utils::is_in_region(KEY_REGION, key_size))
		{
			throw CryptionException(std::format("invalid key size for {},{} only support number in {}", name, name, KEY_REGION).c_str(), __FILE__, __FUNCTION__, __LINE__);
		}
		if (!dog_cryption::utils::is_in_region(BLOCK_REGION, block_size))
		{
			throw CryptionException(std::format("invalid block size for {},{} only support number in {}", name, name, BLOCK_REGION).c_str(), __FILE__, __FUNCTION__, __LINE__);
		}

		this->extend_key_ = extend_key;

		this->block_encryption_ = encoding;
		this->block_decryption_ = decoding;

		this->block_decryption_self_ = encoding_self;
		this->block_encryption_self_ = decoding_self;
	}
	else if (name == dog_cryption::SM4::name)
	{
		using namespace dog_cryption::SM4;
		if (!dog_cryption::utils::is_in_region(KEY_REGION, key_size))
		{
			throw CryptionException(std::format("invalid key size for {},{} only support number in {}", name, name, KEY_REGION).c_str(), __FILE__, __FUNCTION__, __LINE__);
		}
		if (!dog_cryption::utils::is_in_region(BLOCK_REGION, block_size))
		{
			throw CryptionException(std::format("invalid block size for {},{} only support number in {}", name, name, BLOCK_REGION).c_str(), __FILE__, __FUNCTION__, __LINE__);
		}

		this->extend_key_ = extend_key;

		this->block_encryption_ = encoding;
		this->block_decryption_ = decoding;

		this->block_decryption_self_ = encoding_self;
		this->block_encryption_self_ = decoding_self;
	}
	/*
	else if (name == dog_cryption::camelia::name)
	{
		using namespace dog_cryption::camelia;
		this->extend_key_ = extend_key;

		this->block_encryption_ = encoding;
		this->block_decryption_ = decoding;

		this->block_decryption_self_ = encoding_self;
		this->block_encryption_self_ = decoding_self;
		
	}
	*/
	else
	{
		throw CryptionException("invalid cryption algorithm", __FILE__, __FUNCTION__, __LINE__);
	}

	{
		using namespace dog_cryption::padding;
		std::string padding_name = padding_function;
		if (padding_name == PKCS7)
		{
			this->padding_ = PKCS7_padding;
			this->unpadding_ = PKCS7_unpadding;
		}
		else if (padding_name == ZERO)
		{
			this->padding_ = ZERO_padding;
			this->unpadding_ = ZERO_unpadding;
		}
		else if (padding_name == ANSIX923)
		{
			this->padding_ = ANSIX923_padding;
			this->unpadding_ = ANSIX923_unpadding;
		}
		else if (padding_name == ISO10126)
		{
			this->padding_ = ISO10126_padding;
			this->unpadding_ = ISO10126_unpadding;
		}
		else if (padding_name == ISO7816_4)
		{
			this->padding_ = ISO7816_4_padding;
			this->unpadding_ = ISO7816_4_unpadding;
		}
		else if (padding_name == NONE)
		{
			this->padding_ = NONE_padding;
			this->unpadding_ = NONE_unpadding;
		}
		else
		{
			throw CryptionException("invalid padding function", __FILE__, __FUNCTION__, __LINE__);
		}
	}

	{
		using namespace dog_cryption::mode;
		std::string mult_mode = mult_function;
		/*
		   vx:不强制 v:强制
				 iv|填充|
			ECB |vx|v |
			CBC |v |v |
			OFB |v |vx|
			CTR |v |vx|
			CFB |v |vx|
		*/
		if (mult_mode == ECB::name)
		{
			this->config_.using_iv_ = using_iv;
			this->config_.using_padding_ = true;

			this->mult_encrypt_ = ECB::encrypt;
			this->mult_decrypt_ = ECB::decrypt;

			this->stream_encrypt_ = ECB::encrypt_stream;
			this->stream_decrypt_ = ECB::decrypt_stream;

			this->stream_encryptp_ = ECB::encrypt_streamp;
			this->stream_decryptp_ = ECB::decrypt_streamp;

		}
		else if (mult_mode == CBC::name)
		{
			this->config_.using_iv_ = true;
			this->config_.using_padding_ = true;

			this->mult_encrypt_ = CBC::encrypt;
			this->mult_decrypt_ = CBC::decrypt;

			this->stream_encrypt_ = CBC::encrypt_stream;
			this->stream_decrypt_ = CBC::decrypt_stream;

			this->stream_encryptp_ = CBC::encrypt_streamp;
			this->stream_decryptp_ = CBC::decrypt_streamp;

		}
		else if (mult_mode == CFBb::name)
		{
			this->config_.using_iv_ = true;
			this->config_.using_padding_ = using_padding;

			std::vector<std::pair<std::string, std::any>>::iterator shift_it =
				std::find_if(extra_config.begin(), extra_config.end(),
					[](std::pair<std::string, std::any> it) -> bool
					{
						return it.first == "shift";
					});

			if (shift_it == extra_config.end())
			{
				throw CryptionException("invalid config for CFBbit, need shift", __FILE__, __FUNCTION__, __LINE__);
			}

			std::any shift = shift_it->second;
			if (!utils::is_integer(shift))
			{
				throw CryptionException("invalid config for CFBbit, shift need integer", __FILE__, __FUNCTION__, __LINE__);
			}
			uint64_t shift_num = utils::get_integer(shift);
			if (shift_num > block_size / 8)
			{
				throw CryptionException("invalid config for CFBbit, shift need less than block size", __FILE__, __FUNCTION__, __LINE__);
			}
			this->config_.extra_config_.insert(std::make_pair("shift", shift_num));

			if (shift_num == 1)
			{
				this->mult_encrypt_ = CFBb::encrypt_CFB1;
				this->mult_decrypt_ = CFBb::decrypt_CFB1;

				this->stream_encrypt_ = CFBb::encrypt_stream;
				this->stream_decrypt_ = CFBb::decrypt_stream;

				this->stream_encryptp_ = CFBb::encrypt_streamp;
				this->stream_decryptp_ = CFBb::decrypt_streamp;
			}
			else
			{
				/*
				this->mult_encrypt_ = CFBb::encrypt;
				this->mult_decrypt_ = CFBb::decrypt;

				this->stream_encrypt_ = CFBb::encrypt_stream;
				this->stream_decrypt_ = CFBb::decrypt_stream;

				this->stream_encryptp_ = CFBb::encrypt_streamp;
				this->stream_decryptp_ = CFBb::decrypt_streamp;
				*/
			}
		}
		else if (mult_mode == CFBB::name)
		{
			this->config_.using_iv_ = true;
			this->config_.using_padding_ = using_padding;

			std::vector<std::pair<std::string, std::any>>::iterator shift_it =
				std::find_if(extra_config.begin(), extra_config.end(),
					[](std::pair<std::string, std::any> it) -> bool 
					{
						return it.first == "shift";
					});

			if (shift_it == extra_config.end())
			{
				throw CryptionException("invalid config for CFBbit, need shift", __FILE__, __FUNCTION__, __LINE__);
			}

			std::any shift = shift_it->second;
			if (!utils::is_integer(shift))
			{
				throw CryptionException("invalid config for CFBbit, shift need integer", __FILE__, __FUNCTION__, __LINE__);
			}
			uint64_t shift_num = utils::get_integer(shift);
			if (shift_num > block_size)
			{
				throw CryptionException("invalid config for CFBbit, shift need less than block size", __FILE__, __FUNCTION__, __LINE__);
			}
			this->config_.extra_config_.insert(std::make_pair("shift", shift_num));

			if (shift_num == 1)
			{
				this->mult_encrypt_ = CFBB::encrypt_CFB8;
				this->mult_decrypt_ = CFBB::decrypt_CFB8;

				this->stream_encrypt_ = CFBB::encrypt_CFB8_stream;
				this->stream_decrypt_ = CFBB::decrypt_CFB8_stream;

				this->stream_encryptp_ = CFBB::encrypt_CFB8_streamp;
				this->stream_decryptp_ = CFBB::decrypt_CFB8_streamp;
			}
			else if (shift_num == 16)
			{
				this->mult_encrypt_ = CFBB::encrypt_CFB128;
				this->mult_decrypt_ = CFBB::decrypt_CFB128;

				this->stream_encrypt_ = CFBB::encrypt_CFB128_stream;
				this->stream_decrypt_ = CFBB::decrypt_CFB128_stream;

				this->stream_encryptp_ = CFBB::encrypt_CFB128_streamp;
				this->stream_decryptp_ = CFBB::decrypt_CFB128_streamp;
			}
			else
			{
				/*
				this->mult_encrypt_ = CFBB::encrypt;
				this->mult_decrypt_ = CFBB::decrypt;

				this->stream_encrypt_ = CFBB::encrypt_stream;
				this->stream_decrypt_ = CFBB::decrypt_stream;

				this->stream_encryptp_ = CFBB::encrypt_streamp;
				this->stream_decryptp_ = CFBB::decrypt_streamp;
				*/
			}


		}
		else if (mult_mode == OFB::name)
		{
			this->config_.using_iv_ = true;
			this->config_.using_padding_ = using_padding;

			this->mult_encrypt_ = OFB::encrypt;
			this->mult_decrypt_ = OFB::decrypt;

			this->stream_encrypt_ = OFB::encrypt_stream;
			this->stream_decrypt_ = OFB::decrypt_stream;

			this->stream_encryptp_ = OFB::encrypt_streamp;
			this->stream_decryptp_ = OFB::decrypt_streamp;
		}
		else if (mult_mode == CTR::name)
		{
			this->config_.using_iv_ = true;
			this->config_.using_padding_ = using_padding;

			this->mult_encrypt_ = CTR::encrypt;
			this->mult_decrypt_ = CTR::decrypt;

			this->stream_encrypt_ = CTR::encrypt_stream;
			this->stream_decrypt_ = CTR::decrypt_stream;

			this->stream_encryptp_ = CTR::encrypt_streamp;
			this->stream_decryptp_ = CTR::decrypt_streamp;
		}
		else
		{
			throw CryptionException("invalid encryption mode", __FILE__, __FUNCTION__, __LINE__);
		}
	}
}
dog_cryption::Cryptor::Cryptor(
	const std::string& cryption_algorithm, const uint64_t block_size, const uint64_t key_size,
	bool using_padding, const std::string& padding_function,
	const std::string& mult_function, bool using_iv, bool with_iv,
	std::unordered_map<std::string, std::any> extra_config)

{
	std::string name = cryption_algorithm;
	if (name == dog_cryption::AES::name)
	{
		using namespace dog_cryption::AES;
		if (!dog_cryption::utils::is_in_region(KEY_REGION, key_size))
		{
			throw CryptionException(std::format("invalid key size for {},{} only support number in {}", name, name, KEY_REGION).c_str(), __FILE__, __FUNCTION__, __LINE__);
		}
		if (!dog_cryption::utils::is_in_region(BLOCK_REGION, block_size))
		{
			throw CryptionException(std::format("invalid block size for {},{} only support number in {}", name, name, BLOCK_REGION).c_str(), __FILE__, __FUNCTION__, __LINE__);
		}

		this->extend_key_ = extend_key;

		this->block_encryption_ = encoding;
		this->block_decryption_ = decoding;

		this->block_decryption_self_ = encoding_self;
		this->block_encryption_self_ = decoding_self;
	}
	else if (name == dog_cryption::SM4::name)
	{
		using namespace dog_cryption::SM4;
		if (!dog_cryption::utils::is_in_region(KEY_REGION, key_size))
		{
			throw CryptionException(std::format("invalid key size for {},{} only support number in {}", name, name, KEY_REGION).c_str(), __FILE__, __FUNCTION__, __LINE__);
		}
		if (!dog_cryption::utils::is_in_region(BLOCK_REGION, block_size))
		{
			throw CryptionException(std::format("invalid block size for {},{} only support number in {}", name, name, BLOCK_REGION).c_str(), __FILE__, __FUNCTION__, __LINE__);
		}

		this->extend_key_ = extend_key;

		this->block_encryption_ = encoding;
		this->block_decryption_ = decoding;

		this->block_decryption_self_ = encoding_self;
		this->block_encryption_self_ = decoding_self;
	}
	/*
	else if (name == dog_cryption::camelia::name)
	{
		using namespace dog_cryption::camelia;
		this->extend_key_ = extend_key;

		this->block_encryption_ = encoding;
		this->block_decryption_ = decoding;

		this->block_decryption_self_ = encoding_self;
		this->block_encryption_self_ = decoding_self;
		
	}
	*/
	else
	{
		throw CryptionException("invalid cryption algorithm", __FILE__, __FUNCTION__, __LINE__);
	}

	{
		using namespace dog_cryption::padding;
		std::string padding_name = padding_function;
		if (padding_name == PKCS7)
		{
			this->padding_ = PKCS7_padding;
			this->unpadding_ = PKCS7_unpadding;
		}
		else if (padding_name == ZERO)
		{
			this->padding_ = ZERO_padding;
			this->unpadding_ = ZERO_unpadding;
		}
		else if (padding_name == ANSIX923)
		{
			this->padding_ = ANSIX923_padding;
			this->unpadding_ = ANSIX923_unpadding;
		}
		else if (padding_name == ISO10126)
		{
			this->padding_ = ISO10126_padding;
			this->unpadding_ = ISO10126_unpadding;
		}
		else if (padding_name == ISO7816_4)
		{
			this->padding_ = ISO7816_4_padding;
			this->unpadding_ = ISO7816_4_unpadding;
		}
		else if (padding_name == NONE)
		{
			this->padding_ = NONE_padding;
			this->unpadding_ = NONE_unpadding;
		}
		else
		{
			throw CryptionException("invalid padding function", __FILE__, __FUNCTION__, __LINE__);
		}
	}

	{
		using namespace dog_cryption::mode;
		std::string mult_mode = mult_function;
		/*
		   vx:不强制 v:强制
				 iv|填充|
			ECB |vx|v |
			CBC |v |v |
			OFB |v |vx|
			CTR |v |vx|
			CFB |v |vx|
		*/
		if (mult_mode == ECB::name)
		{
			this->config_.using_iv_ = using_iv;
			this->config_.using_padding_ = true;

			this->mult_encrypt_ = ECB::encrypt;
			this->mult_decrypt_ = ECB::decrypt;

			this->stream_encrypt_ = ECB::encrypt_stream;
			this->stream_decrypt_ = ECB::decrypt_stream;

			this->stream_encryptp_ = ECB::encrypt_streamp;
			this->stream_decryptp_ = ECB::decrypt_streamp;

		}
		else if (mult_mode == CBC::name)
		{
			this->config_.using_iv_ = true;
			this->config_.using_padding_ = true;

			this->mult_encrypt_ = CBC::encrypt;
			this->mult_decrypt_ = CBC::decrypt;

			this->stream_encrypt_ = CBC::encrypt_stream;
			this->stream_decrypt_ = CBC::decrypt_stream;

			this->stream_encryptp_ = CBC::encrypt_streamp;
			this->stream_decryptp_ = CBC::decrypt_streamp;

		}
		else if (mult_mode == CFBb::name)
		{
			this->config_.using_iv_ = true;
			this->config_.using_padding_ = using_padding;

			auto shift_it = extra_config.find("shift");

			if (shift_it == extra_config.end())
			{
				throw CryptionException("invalid config for CFBbit, need shift", __FILE__, __FUNCTION__, __LINE__);
			}

			std::any shift = shift_it->second;
			if (!utils::is_integer(shift))
			{
				throw CryptionException("invalid config for CFBbit, shift need integer", __FILE__, __FUNCTION__, __LINE__);
			}
			uint64_t shift_num = utils::get_integer(shift);
			if (shift_num > block_size / 8)
			{
				throw CryptionException("invalid config for CFBbit, shift need less than block size", __FILE__, __FUNCTION__, __LINE__);
			}
			this->config_.extra_config_.insert(std::make_pair("shift", shift_num));

			if (shift_num == 1)
			{
				this->mult_encrypt_ = CFBb::encrypt_CFB1;
				this->mult_decrypt_ = CFBb::decrypt_CFB1;

				this->stream_encrypt_ = CFBb::encrypt_stream;
				this->stream_decrypt_ = CFBb::decrypt_stream;

				this->stream_encryptp_ = CFBb::encrypt_streamp;
				this->stream_decryptp_ = CFBb::decrypt_streamp;
			}
			else
			{
				/*
				this->mult_encrypt_ = CFBb::encrypt;
				this->mult_decrypt_ = CFBb::decrypt;

				this->stream_encrypt_ = CFBb::encrypt_stream;
				this->stream_decrypt_ = CFBb::decrypt_stream;

				this->stream_encryptp_ = CFBb::encrypt_streamp;
				this->stream_decryptp_ = CFBb::decrypt_streamp;
				*/
			}
		}
		else if (mult_mode == CFBB::name)
		{
			this->config_.using_iv_ = true;
			this->config_.using_padding_ = using_padding;

			auto shift_it = extra_config.find("shift");

			if (shift_it == extra_config.end())
			{
				throw CryptionException("invalid config for CFBbit, need shift", __FILE__, __FUNCTION__, __LINE__);
			}

			std::any shift = shift_it->second;
			if (!utils::is_integer(shift))
			{
				throw CryptionException("invalid config for CFBbit, shift need integer", __FILE__, __FUNCTION__, __LINE__);
			}
			uint64_t shift_num = utils::get_integer(shift);
			if (shift_num > block_size)
			{
				throw CryptionException("invalid config for CFBbit, shift need less than block size", __FILE__, __FUNCTION__, __LINE__);
			}
			this->config_.extra_config_.insert(std::make_pair("shift", shift_num));

			if (shift_num == 1)
			{
				this->mult_encrypt_ = CFBB::encrypt_CFB8;
				this->mult_decrypt_ = CFBB::decrypt_CFB8;

				this->stream_encrypt_ = CFBB::encrypt_CFB8_stream;
				this->stream_decrypt_ = CFBB::decrypt_CFB8_stream;

				this->stream_encryptp_ = CFBB::encrypt_CFB8_streamp;
				this->stream_decryptp_ = CFBB::decrypt_CFB8_streamp;
			}
			else if (shift_num == 16)
			{
				this->mult_encrypt_ = CFBB::encrypt_CFB128;
				this->mult_decrypt_ = CFBB::decrypt_CFB128;

				this->stream_encrypt_ = CFBB::encrypt_CFB128_stream;
				this->stream_decrypt_ = CFBB::decrypt_CFB128_stream;

				this->stream_encryptp_ = CFBB::encrypt_CFB128_streamp;
				this->stream_decryptp_ = CFBB::decrypt_CFB128_streamp;
			}
			else
			{
				/*
				this->mult_encrypt_ = CFBB::encrypt;
				this->mult_decrypt_ = CFBB::decrypt;

				this->stream_encrypt_ = CFBB::encrypt_stream;
				this->stream_decrypt_ = CFBB::decrypt_stream;

				this->stream_encryptp_ = CFBB::encrypt_streamp;
				this->stream_decryptp_ = CFBB::decrypt_streamp;
				*/
			}


		}
		else if (mult_mode == OFB::name)
		{
			this->config_.using_iv_ = true;
			this->config_.using_padding_ = using_padding;

			this->mult_encrypt_ = OFB::encrypt;
			this->mult_decrypt_ = OFB::decrypt;

			this->stream_encrypt_ = OFB::encrypt_stream;
			this->stream_decrypt_ = OFB::decrypt_stream;

			this->stream_encryptp_ = OFB::encrypt_streamp;
			this->stream_decryptp_ = OFB::decrypt_streamp;
		}
		else if (mult_mode == CTR::name)
		{
			this->config_.using_iv_ = true;
			this->config_.using_padding_ = using_padding;

			this->mult_encrypt_ = CTR::encrypt;
			this->mult_decrypt_ = CTR::decrypt;

			this->stream_encrypt_ = CTR::encrypt_stream;
			this->stream_decrypt_ = CTR::decrypt_stream;

			this->stream_encryptp_ = CTR::encrypt_streamp;
			this->stream_decryptp_ = CTR::decrypt_streamp;
		}
		else
		{
			throw CryptionException("invalid encryption mode", __FILE__, __FUNCTION__, __LINE__);
		}
	}
}
void dog_cryption::Cryptor::set_key(dog_data::Data key)
{
	this->original_key_ = key;
	this->key_ = this->extend_key_(key, this->config_.key_size_);
	this->is_setting_key_ = true;
}
void dog_cryption::Cryptor::swap(Cryptor& other)
{
	std::swap(this->is_valid_,            other.is_valid_);
	std::swap(this->config_,              other.config_);
	std::swap(this->key_,                 other.key_);
	std::swap(this->original_key_,        other.original_key_);
	std::swap(this->padding_,             other.padding_);
	std::swap(this->unpadding_,           other.unpadding_);
	std::swap(this->block_encryption_,    other.block_encryption_);
	std::swap(this->block_decryption_,    other.block_decryption_);
	std::swap(this->mult_encrypt_,        other.mult_encrypt_);
	std::swap(this->mult_decrypt_,        other.mult_decrypt_);
	std::swap(this->stream_encrypt_,      other.stream_encrypt_);
	std::swap(this->stream_decrypt_,      other.stream_decrypt_);
}
void dog_cryption::Cryptor::swap_config(Cryptor& other)
{
	std::swap(this->is_valid_, other.is_valid_);
	std::swap(this->config_, other.config_);
	std::swap(this->padding_, other.padding_);
	std::swap(this->unpadding_, other.unpadding_);
	std::swap(this->block_encryption_, other.block_encryption_);
	std::swap(this->block_decryption_, other.block_decryption_);
	std::swap(this->mult_encrypt_, other.mult_encrypt_);
	std::swap(this->mult_decrypt_, other.mult_decrypt_);
	std::swap(this->stream_encrypt_, other.stream_encrypt_);
	std::swap(this->stream_decrypt_, other.stream_decrypt_);
}
uint64_t dog_cryption::Cryptor::get_block_size() const
{
	return this->config_.block_size_;
}
uint64_t dog_cryption::Cryptor::get_key_size() const
{
	return this->config_.key_size_;
}
bool dog_cryption::Cryptor::get_using_iv() const
{
	return this->config_.using_iv_;
}
bool dog_cryption::Cryptor::get_using_padding() const
{
	return this->config_.using_padding_;
}
dog_data::Data dog_cryption::Cryptor::get_original_key() const
{
	return this->original_key_;
}
dog_data::Data dog_cryption::Cryptor::get_available_key() const
{
	return this->key_;
}
std::function<void(dog_data::Data&, uint8_t)> dog_cryption::Cryptor::get_padding() const
{
	return this->padding_;
}
std::function<void(dog_data::Data&, uint8_t)> dog_cryption::Cryptor::get_unpadding() const
{
	return this->unpadding_;
}
std::function<void(dog_data::Data&, uint8_t, const dog_data::Data&, uint8_t)> dog_cryption::Cryptor::get_block_encryption() const
{
	return this->block_encryption_;
}
std::function<void(dog_data::Data&, uint8_t, const dog_data::Data&, uint8_t)> dog_cryption::Cryptor::get_block_decryption() const
{
	return this->block_decryption_;
}
dog_cryption::CryptionConfig dog_cryption::Cryptor::get_config()
{
	return this->config_;
}
uint64_t dog_cryption::Cryptor::get_reback_size() const
{
	return std::any_cast<uint64_t>(this->config_.extra_config_.at("shift"));
}
bool dog_cryption::Cryptor::is_available() const
{
	if (!this->is_valid_)
	{
		throw CryptionException("Cryptor config is invalid", __FILE__, __FUNCTION__, __LINE__);
	}
	if (!this->is_setting_key_)
	{
		throw CryptionException("encrypt key is not set or key is invalid", __FILE__, __FUNCTION__, __LINE__);
	}
	return true;
}
std::pair<dog_data::Data, dog_data::Data> dog_cryption::Cryptor::encrypt(dog_data::Data iv, dog_data::Data plain)
{
	this->is_available();
	if (this->config_.using_iv_)
	{
		dog_data::Data crypt = this->mult_encrypt_(plain, iv, *this);
		if (this->config_.with_iv_)
		{
			return std::make_pair("", iv + crypt);
		}
	}
	else
	{
		return std::make_pair("", this->mult_encrypt_(plain, iv, *this));
	}
}
std::pair<dog_data::Data, dog_data::Data> dog_cryption::Cryptor::encrypt(dog_data::Data plain)
{
	this->is_available();
	if (this->config_.using_iv_)
	{
		dog_data::Data iv = dog_cryption::utils::randiv(this->get_block_size());
		dog_data::Data res = this->mult_encrypt_(plain, iv, *this);
		if (this->config_.with_iv_)
		{
			return std::make_pair(iv, iv + res);
		}
		else
		{
			return std::make_pair(iv, res);
		}
	}
	else
	{
		return std::make_pair("", this->mult_encrypt_(plain, "", *this));
	}
}
dog_data::Data dog_cryption::Cryptor::decrypt(std::pair<dog_data::Data, dog_data::Data> iv_crypt)
{
	this->is_available();
	if (this->config_.using_iv_)
	{
		if (this->config_.with_iv_)
		{
			if (iv_crypt.second.size() < this->get_block_size())
			{
				throw CryptionException(std::format("IV size is not enough,need {} now {}", this->get_block_size(), iv_crypt.second.size()).c_str(), __FILE__, __FUNCTION__, __LINE__);
			}
			return this->mult_decrypt_(
				iv_crypt.second.sub_by_len(0,this->get_block_size()),
				iv_crypt.second.sub_by_len(this->get_block_size(), iv_crypt.second.size() - this->get_block_size()),
				*this
			);
		}
		else
		{
			if (iv_crypt.first.size() < this->get_block_size())
			{
				throw CryptionException(std::format("IV size is not enough,need {} now {}", this->get_block_size(), iv_crypt.first.size()).c_str(), __FILE__, __FUNCTION__, __LINE__);
			}
			return this->mult_decrypt_(iv_crypt.first, iv_crypt.second, *this);
		}
	}
	else
	{
        return this->mult_decrypt_("", iv_crypt.second, *this);
	}
}
dog_data::Data dog_cryption::Cryptor::decrypt(dog_data::Data iv, dog_data::Data crypt)
{
	this->is_available();
	if (this->config_.using_iv_)
	{
		if (this->config_.with_iv_)
		{
			if (crypt.size() < this->get_block_size())
			{
				throw CryptionException(std::format("IV size is not enough,need {} now {}", this->get_block_size(), crypt.size()).c_str(), __FILE__, __FUNCTION__, __LINE__);
			}
			return this->mult_decrypt_(
				crypt.sub_by_len(0, this->get_block_size()),
				crypt.sub_by_len(this->get_block_size(), crypt.size() - this->get_block_size()),
				*this
			);
		}
		else
		{
			if (iv.size() < this->get_block_size())
			{
				throw CryptionException(std::format("IV size is not enough,need {} now {}", this->get_block_size(), iv.size()).c_str(), __FILE__, __FUNCTION__, __LINE__);
			}
			return this->mult_decrypt_(iv, crypt, *this);
		}
	}
	else
	{
		return this->mult_decrypt_("", crypt, *this);
	}
}
dog_data::Data dog_cryption::Cryptor::decrypt(dog_data::Data crypt)
{
	this->is_available();
	if (this->config_.using_iv_)
	{
		if (!this->config_.with_iv_)
		{
			throw CryptionException("IV is not given when using_iv is true", __FILE__, __FUNCTION__, __LINE__);
		}
		if (crypt.size() < this->get_block_size())
		{
			throw CryptionException(std::format("IV size is not enough,need {} now {}", this->get_block_size(), crypt.size()).c_str(), __FILE__, __FUNCTION__, __LINE__);
		}
		return this->mult_decrypt_(
			crypt.sub_by_len(0, this->get_block_size()),
			crypt.sub_by_len(this->get_block_size(), crypt.size() - this->get_block_size()),
			*this
		);
	}
	else
	{
		return this->mult_decrypt_("", crypt, *this);
	}
}

void dog_cryption::Cryptor::encrypt(std::istream& plain, std::ostream& crypt, dog_data::Data iv, bool with_config)
{
	this->is_available();
	if (with_config)
	{
		dog_data::Data config_data = this->get_config().to_data();
		crypt.write((char*)config_data.data(), config_data.size());
	}
	if (this->config_.using_iv_)
	{
		if (iv.size() < this->config_.block_size_)
		{
			throw CryptionException(std::format("IV size is not enough,need {} now {}", this->config_.block_size_, iv.size()).c_str(), __FILE__, __FUNCTION__, __LINE__);
		}
		if (this->config_.with_iv_)
		{
			crypt.write((char*)iv.data(), iv.size());
			this->stream_encrypt_(plain, iv, crypt, *this);
		}
		else
		{
			this->stream_encrypt_(plain, iv, crypt, *this);
		}
	}
	else
	{
		this->stream_encrypt_(plain, "", crypt, *this);
	}
}
void dog_cryption::Cryptor::encrypt(std::istream& plain, std::ostream& crypt, dog_data::Data iv)
{
	this->is_available();
	if (this->config_.using_iv_)
	{
		if (iv.size() < this->config_.block_size_)
		{
			throw CryptionException(std::format("IV size is not enough,need {} now {}", this->config_.block_size_, iv.size()).c_str(), __FILE__, __FUNCTION__, __LINE__);
		}
		if (this->config_.with_iv_)
		{
			crypt.write((char*)iv.data(), iv.size());
			this->stream_encrypt_(plain, iv, crypt, *this);
		}
		else
		{
			this->stream_encrypt_(plain, iv, crypt, *this);
		}
	}
	else
	{
		this->stream_encrypt_(plain, "", crypt, *this);
	}
}

dog_data::Data dog_cryption::Cryptor::encrypt(std::istream& plain, std::ostream& crypt, bool with_config)
{
	this->is_available();
	if (with_config)
	{
		dog_data::Data config_data = this->get_config().to_data();
		crypt.write((char*)config_data.data(), config_data.size());
	}
	if (this->config_.using_iv_)
	{
		dog_data::Data iv = dog_cryption::utils::randiv(this->config_.block_size_);
		if (this->config_.with_iv_)
		{
			crypt.write((char*)iv.data(), iv.size());
			this->stream_encrypt_(plain, iv, crypt, *this);
		}
		else
		{
			this->stream_encrypt_(plain, iv, crypt, *this);
		}
		return iv;
	}
	else
	{
		this->stream_encrypt_(plain, "", crypt, *this);
		return "";
	}
}
dog_data::Data dog_cryption::Cryptor::encryptp(std::istream& plain, std::ostream& crypt, bool with_config, std::atomic<double>* progress)
{
	this->is_available();
	if (with_config)
	{
		dog_data::Data config_data = this->get_config().to_data();
		crypt.write((char*)config_data.data(), config_data.size());
	}
	if (this->config_.using_iv_)
	{
		dog_data::Data iv = dog_cryption::utils::randiv(this->config_.block_size_);
		if (this->config_.with_iv_)
		{
			crypt.write((char*)iv.data(), iv.size());
			this->stream_encryptp_(plain, iv, crypt, *this, progress);
		}
		else
		{
			this->stream_encryptp_(plain, iv, crypt, *this, progress);
		}
		return iv;
	}
	else
	{
		this->stream_encryptp_(plain, "", crypt, *this, progress);
		return "";
	}
}

dog_data::Data dog_cryption::Cryptor::encrypt(std::istream& plain, std::ostream& crypt)
{
	this->is_available();
	if (this->config_.using_iv_)
	{
		dog_data::Data iv = dog_cryption::utils::randiv(this->config_.block_size_);
		if (this->config_.with_iv_)
		{
			crypt.write((char*)iv.data(), iv.size());
			this->stream_encrypt_(plain, iv, crypt, *this);
		}
		else
		{
			this->stream_encrypt_(plain, iv, crypt, *this);
		}
		return iv;
	}
	else
	{
		this->stream_encrypt_(plain, "", crypt, *this);
		return "";
	}
}
dog_data::Data dog_cryption::Cryptor::encryptp(std::istream& plain, std::ostream& crypt, std::atomic<double>* progress)
{
	this->is_available();
	if (this->config_.using_iv_)
	{
		dog_data::Data iv = dog_cryption::utils::randiv(this->config_.block_size_);
		if (this->config_.with_iv_)
		{
			crypt.write((char*)iv.data(), iv.size());
			this->stream_encryptp_(plain, iv, crypt, *this, progress);
		}
		else
		{
			this->stream_encryptp_(plain, iv, crypt, *this, progress);
		}
		return iv;
	}
	else
	{
		this->stream_encryptp_(plain, "", crypt, *this, progress);
		return "";
	}
}

void dog_cryption::Cryptor::decrypt(std::istream& crypt, std::ostream& plain, bool with_config)
{
	std::unique_ptr<dog_cryption::CryptionConfig> config;
	std::unique_ptr<dog_cryption::CryptionConfig> ori_config;
	if (with_config)
	{
		ori_config = std::make_unique<dog_cryption::CryptionConfig>(this->get_config());
		config = std::make_unique<dog_cryption::CryptionConfig>(dog_cryption::CryptionConfig::get_cryption_config(crypt));
		dog_cryption::Cryptor temp_cryptor(*config);
		this->swap_config(temp_cryptor);
	}
	this->is_available();

	if (this->config_.using_iv_)
	{
		if (this->config_.with_iv_)
		{
			dog_data::Data iv(this->config_.block_size_);
			crypt.read((char*)iv.data(), iv.size());
			this->stream_decrypt_(crypt, iv, plain, *this);
		}
		else
		{
			throw CryptionException("IV is not available", __FILE__, __FUNCTION__, __LINE__);
		}
	}
	else
	{
		this->stream_decrypt_(crypt, "", plain, *this);
	}

	if (with_config)
	{
		dog_cryption::Cryptor temp_cryptor(*ori_config);
		this->swap_config(temp_cryptor);
	}
}
void dog_cryption::Cryptor::decryptp(std::istream& crypt, std::ostream& plain, bool with_config, std::atomic<double>* progress)
{
	std::unique_ptr<dog_cryption::CryptionConfig> config;
	std::unique_ptr<dog_cryption::CryptionConfig> ori_config;
	if (with_config)
	{
		ori_config = std::make_unique<dog_cryption::CryptionConfig>(this->get_config());
		config = std::make_unique<dog_cryption::CryptionConfig>(dog_cryption::CryptionConfig::get_cryption_config(crypt));
		dog_cryption::Cryptor temp_cryptor(*config);
		this->swap_config(temp_cryptor);
	}
	this->is_available();

	if (this->config_.using_iv_)
	{
		if (this->config_.with_iv_)
		{
			dog_data::Data iv(this->config_.block_size_);
			crypt.read((char*)iv.data(), iv.size());
			this->stream_decryptp_(crypt, iv, plain, *this, progress);
		}
		else
		{
			throw CryptionException("IV is not available", __FILE__, __FUNCTION__, __LINE__);
		}
	}
	else
	{
		this->stream_decryptp_(crypt, "", plain, *this, progress);
	}

	if (with_config)
	{
		dog_cryption::Cryptor temp_cryptor(*ori_config);
		this->swap_config(temp_cryptor);
	}
}

void dog_cryption::Cryptor::decrypt(std::istream& crypt, std::ostream& plain)
{
	this->is_available();
	if (this->config_.using_iv_)
	{
		if (this->config_.with_iv_)
		{
			dog_data::Data iv(this->config_.block_size_);
			crypt.read((char*)iv.data(), iv.size());
			this->stream_decrypt_(crypt, iv, plain, *this);
		}
		else
		{
			throw CryptionException("IV is not available", __FILE__, __FUNCTION__, __LINE__);
		}
	}
	else
	{
		this->stream_decrypt_(crypt, "", plain, *this);
	}
}
void dog_cryption::Cryptor::decryptp(std::istream& crypt, std::ostream& plain, std::atomic<double>* progress)
{
	this->is_available();
	if (this->config_.using_iv_)
	{
		if (this->config_.with_iv_)
		{
			dog_data::Data iv(this->config_.block_size_);
			crypt.read((char*)iv.data(), iv.size());
			this->stream_decryptp_(crypt, iv, plain, *this, progress);
		}
		else
		{
			throw CryptionException("IV is not available", __FILE__, __FUNCTION__, __LINE__);
		}
	}
	else
	{
		this->stream_decryptp_(crypt, "", plain, *this, progress);
	}
}

//padding&unpadding
void dog_cryption::padding::NONE_padding(dog_data::Data& data, uint8_t block_size)
{
}
void dog_cryption::padding::NONE_unpadding(dog_data::Data& data, uint8_t block_size)
{
}

void dog_cryption::padding::PKCS7_padding(dog_data::Data& data, uint8_t block_size)
{
	if (data.size() > block_size)
	{
		throw CryptionException("Data size is bigger than block size", __FILE__, __FUNCTION__, __LINE__);
	}
	uint8_t end = block_size - data.size();
	for (uint8_t i = 0; i < end; i++)
	{
		data.push_back(end);
	}
}
void dog_cryption::padding::PKCS7_unpadding(dog_data::Data& data, uint8_t block_size)
{
	uint8_t value = *data.rbegin();
	if ((uint32_t)value <= block_size)
	{
		for (uint32_t i = 0; i < value; i++)
		{
			data.pop_back();
		}
	}
}

void dog_cryption::padding::ZERO_padding(dog_data::Data& data, uint8_t block_size)
{
	if (data.size() > block_size)
	{
		throw CryptionException("Data size is bigger than block size", __FILE__, __FUNCTION__, __LINE__);
	}
	uint64_t up_size = block_size - data.size();
	for (uint64_t i = 0; i < up_size; i++)
	{
        data.push_back(0x00);
	}
}
void dog_cryption::padding::ZERO_unpadding(dog_data::Data& data, uint8_t block_size)
{
	while (*data.rbegin() == 0x00)
	{
		data.pop_back();
		if (data.size() == 0) { return; }
	}
}

void dog_cryption::padding::ANSIX923_padding(dog_data::Data& data, uint8_t block_size)
{
	uint8_t end = block_size - data.size();
	for (uint8_t i = 0; i < end - 1; i++)
	{
		data.push_back(0x00);
	}
	data.push_back(end);
}
void dog_cryption::padding::ANSIX923_unpadding(dog_data::Data& data, uint8_t block_size)
{
	uint8_t value = *data.rbegin();
	if ((uint32_t)value <= block_size)
	{
		for (uint32_t i = 0; i < value; i++)
		{
			data.pop_back();
		}
	}
}

void dog_cryption::padding::ISO7816_4_padding(dog_data::Data& data, uint8_t block_size)
{
	if (data.size() > block_size)
	{
		throw CryptionException("Data size is bigger than block size", __FILE__, __FUNCTION__, __LINE__);
	}
	uint8_t end = block_size - data.size();
	data.push_back(0x80);
	for (uint8_t i = 0; i < end - 1; i++)
	{
		data.push_back(0x00);
	}
}
void dog_cryption::padding::ISO7816_4_unpadding(dog_data::Data& data, uint8_t block_size)
{
	while (*data.rbegin() == 0x00)
	{
		data.pop_back();
	}
	data.pop_back();
}

void dog_cryption::padding::ISO10126_padding(dog_data::Data& data, uint8_t block_size)
{
	uint8_t end = block_size - data.size();
	for (uint8_t i = 0; i < end - 1; i++)
	{
        data.push_back(dog_cryption::utils::rand_byte());
	}
    data.push_back(end);
}
void dog_cryption::padding::ISO10126_unpadding(dog_data::Data& data, uint8_t block_size)
{
	uint8_t value = *data.rbegin();
	if ((uint32_t)value <= block_size)
	{
		for (uint32_t i = 0; i < value; i++)
		{
			data.pop_back();
		}
	}
}

//utils
uint8_t dog_cryption::utils::rand_byte()
{
	std::random_device rd;
	return (uint8_t)rd() % 128;
}
bool dog_cryption::utils::is_in_region(std::string region_str, uint64_t num)
{
	/*
	* (a,b):c -> a+c  ,a+2c ,       ...  ,b-2c ,b-1c 
	* [a,b]:c -> a    ,a+c  ,a+2c , ...  ,b-2c ,b-1c ,b
	* (a,b]:c -> a+c  ,a+2c ,       ...  ,b-1c ,b
	* [a,b):c -> a    ,a+c  ,a+2c , ...  ,b-2c ,b-1c
	* $表示最大64位无符号整数
	* 
	* 表示从第一个正整数开始按第三个正整数为间隔,直到第二个正整数结束.[表达闭区间,(表示开区间
	* ^[\[\(][1-9][0-9]*,([1-9][0-9]*|\$)[\)\]]:[1-9][0-9]*$
	*/
	std::regex reg("^[\[\(][1-9][0-9]*,[1-9][0-9]*[\)\]]:[0-9]+$");
	if (!std::regex_match(region_str, reg))
	{
		throw CryptionException("Invalid block size array string.wrong in style", __FILE__, __FUNCTION__, __LINE__);
	}
	int64_t middle = region_str.find_first_of(",");
	int64_t behind = region_str.find_first_of("]") == std::basic_string<char>::npos ? region_str.find_first_of(")") : region_str.find_first_of("]");
	uint64_t start = std::stoull(region_str.substr(1, middle - 1));
	uint64_t end = region_str[middle + 1] == '$' ? UINT64_MAX : std::stoull(region_str.substr(middle + 1, behind - middle - 1));
	uint64_t step = std::stoull(region_str.substr(behind + 1, region_str.size() - behind - 1));
	if (start > end)
	{
		throw CryptionException("Invalid block size array string.start is bigger than end", __FILE__, __FUNCTION__, __LINE__);
	}
	if (region_str[0] == '(' && step == 0)
	{
		throw CryptionException("Invalid block size array string.step must not be 0 when start is not in region", __FILE__, __FUNCTION__, __LINE__);
	}
	if (region_str[0] == '[')
	{
		if (num == start) { return true; }
	}
	if (region_str[behind] == ']')
	{
		if (num == end) { return true; }
	}
	
	if (num < start || num > end)
	{
		return false;
	}
	if ((num - start) % step != 0)
	{
		return false;
	}
	else
	{
		return true;
	}
}

bool dog_cryption::utils::is_integer(std::any a)
{
	const std::type_info& type = a.type();
	return type == typeid(uint8_t) || type == typeid(int8_t) ||
		type == typeid(uint16_t) || type == typeid(int16_t) ||
		type == typeid(uint32_t) || type == typeid(int32_t) ||
		type == typeid(uint64_t) || type == typeid(int64_t);
}
uint64_t dog_cryption::utils::get_integer(std::any a)
{
	const std::type_info& type = a.type();
	if (type == typeid(uint8_t))
	{
		return (uint64_t)std::any_cast<uint8_t>(a);
	}
	else if (type == typeid(int8_t))
	{
		return (uint64_t)std::any_cast<int8_t>(a);
	}
	else if (type == typeid(uint16_t))
	{
		return (uint64_t)std::any_cast<uint16_t>(a);
	}
	else if (type == typeid(int16_t))
	{
		return (uint64_t)std::any_cast<int16_t>(a);
	}
	else if (type == typeid(uint32_t))
	{
		return (uint64_t)std::any_cast<uint32_t>(a);
	}
	else if (type == typeid(int32_t))
	{
		return (uint64_t)std::any_cast<int32_t>(a);
	}
	else if (type == typeid(uint64_t))
	{
		return (uint64_t)std::any_cast<uint64_t>(a);
	}
	else if (type == typeid(int64_t))
	{
		return (uint64_t)std::any_cast<int64_t>(a);
	}
	else
	{
		throw CryptionException("Invalid type", __FILE__, __FUNCTION__, __LINE__);
	}
}
dog_data::Data dog_cryption::utils::squareXOR(dog_data::Data& a, dog_data::Data& b, uint64_t size)
{
	dog_data::Data res;
	res.reserve(size);
	uint64_t n = a.size() < b.size() ? a.size() : b.size();
	for (uint64_t i = 0; i < (n > size ? size : n); i++)
	{
		res.push_back(a.at(i) ^ b.at(i));
	}
	return res;
}
void dog_cryption::utils::squareXOR_self(dog_data::Data& a, dog_data::Data& b, uint64_t size)
{
	uint64_t n = a.size() < b.size() ? a.size() : b.size();
	for (uint64_t i = 0; i < (n > size ? size : n); i++)
	{
		a[i] ^= b[i];
	}
}
dog_data::Data dog_cryption::utils::randiv(uint8_t block_size)
{
	dog_data::Data iv(block_size);
	for (int i = 0; i < block_size; i++)
	{
		iv[i] = dog_cryption::utils::rand_byte();
	}
	return iv;
}

double dog_cryption::mode::update_progress(double progress, double progress_step, double progress_max)
{
	return progress + progress_step*1.0 / progress_max;
}

//multi_mode
dog_data::Data dog_cryption::mode::ECB::encrypt(dog_data::Data plain, dog_data::Data iv, dog_cryption::Cryptor & cryptor)
{
	dog_data::Data res; uint8_t block_size = cryptor.get_block_size();
	res.reserve(((plain.size() / block_size) + 1) * block_size);
	dog_data::Data tempBlock;
	for (uint64_t i0 = 0; i0 <= plain.size(); i0 += block_size)
	{
		tempBlock = plain.sub_by_pos(i0, i0 + block_size);
		if (tempBlock.size() < block_size) { cryptor.get_padding()(tempBlock, block_size); }
		cryptor.get_block_encryption()(tempBlock, block_size, cryptor.get_available_key(), cryptor.get_key_size());
		res += tempBlock;
		tempBlock.clear_leave_pos();
	}
	return res;
}
dog_data::Data dog_cryption::mode::ECB::decrypt(dog_data::Data crypt, dog_data::Data iv, dog_cryption::Cryptor& cryptor)
{
	uint8_t block_size = cryptor.get_block_size();
	dog_data::Data res; res.reserve(crypt.size());
	dog_data::Data tempBlock(block_size);
	for (uint64_t i0 = 0; i0 < crypt.size(); i0 += block_size)
	{
		tempBlock = crypt.sub_by_pos(i0, i0 + block_size);
		cryptor.get_block_decryption()(tempBlock, block_size, cryptor.get_available_key(), cryptor.get_key_size());
		res += tempBlock;
	}
	cryptor.get_unpadding()(res, block_size);
	return res;
}
void dog_cryption::mode::ECB::encrypt_stream(std::istream& plain, dog_data::Data iv, std::ostream& crypt, dog_cryption::Cryptor& cryptor)
{
	uint8_t block_size = cryptor.get_block_size();
	plain.seekg(0, std::ios::end);
	uint64_t file_size = plain.tellg();
	plain.seekg(0, std::ios::beg);
	
	dog_data::Data tempBlock(block_size);
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
		for (uint64_t i = 0; i < block_size - plain.gcount(); ++i) { tempBlock.pop_back(); }
		cryptor.get_padding()(tempBlock, block_size);
		
	}
	cryptor.get_block_encryption()(tempBlock, block_size, cryptor.get_available_key(), cryptor.get_key_size());
	crypt.write((char*)tempBlock.data(), block_size);
	crypt.flush();
	//printf("100%%\r");
}
void dog_cryption::mode::ECB::decrypt_stream(std::istream& crypt, dog_data::Data iv, std::ostream& plain, dog_cryption::Cryptor& cryptor)
{
	uint8_t block_size = cryptor.get_block_size();
	uint64_t now_pos = crypt.tellg();
	crypt.seekg(0, std::ios::end);
	uint64_t file_size = crypt.tellg();
	crypt.seekg(now_pos);

	dog_data::Data tempBlock(block_size);
	
	for (uint64_t i = 0; i < (file_size - now_pos - 1) / block_size; ++i)
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
void dog_cryption::mode::ECB::encrypt_streamp(std::istream& plain, dog_data::Data iv, std::ostream& crypt, dog_cryption::Cryptor& cryptor, std::atomic<double>* progress)
{
	uint8_t block_size = cryptor.get_block_size();
	plain.seekg(0, std::ios::end);
	uint64_t file_size = plain.tellg();
	plain.seekg(0, std::ios::beg);

	dog_data::Data tempBlock(block_size);
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
		for (uint64_t i = 0; i < block_size - plain.gcount(); ++i) { tempBlock.pop_back(); }
		cryptor.get_padding()(tempBlock, block_size);

	}
	cryptor.get_block_encryption()(tempBlock, block_size, cryptor.get_available_key(), cryptor.get_key_size());
	if (progress->load() < 0.0) { return; }
	progress->store(update_progress(progress->load(), block_size, file_size));
	crypt.write((char*)tempBlock.data(), block_size);
	crypt.flush();
	progress->store(1.0);
}
void dog_cryption::mode::ECB::decrypt_streamp(std::istream& crypt, dog_data::Data iv, std::ostream& plain, dog_cryption::Cryptor& cryptor, std::atomic<double>* progress)
{
	uint8_t block_size = cryptor.get_block_size();
	uint64_t now_pos = crypt.tellg();
	crypt.seekg(0, std::ios::end);
	uint64_t file_size = crypt.tellg();
	crypt.seekg(now_pos);

	dog_data::Data tempBlock(block_size);

	for (uint64_t i = 0; i < (file_size - now_pos - 1) / block_size; ++i)
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

dog_data::Data dog_cryption::mode::CBC::encrypt(dog_data::Data plain, dog_data::Data iv, dog_cryption::Cryptor& cryptor)
{
	uint8_t block_size = cryptor.get_block_size();
	dog_data::Data res; res.reserve(((plain.size() / block_size) + 1) * block_size);
	dog_data::Data tempBlock; tempBlock.reserve(block_size);
	dog_data::Data tempKey = iv;
	for (uint64_t i0 = 0; i0 <= plain.size(); i0 += block_size)
	{
		tempBlock = plain.sub_by_pos(i0, i0 + block_size);
		if (tempBlock.size() < block_size) { cryptor.get_padding()(tempBlock, block_size); }
		dog_cryption::utils::squareXOR_self(tempBlock, tempKey, block_size);
		cryptor.get_block_encryption()(tempBlock, block_size, cryptor.get_available_key(), cryptor.get_key_size());
		res += tempBlock;
		tempKey = tempBlock;
	}
	return res;
}
dog_data::Data dog_cryption::mode::CBC::decrypt(dog_data::Data crypt, dog_data::Data iv, dog_cryption::Cryptor& cryptor)
{
	uint8_t block_size = cryptor.get_block_size();
	dog_data::Data res; res.reserve(((crypt.size() / block_size) + 1) * block_size);
	dog_data::Data tempBlock(block_size);
	dog_data::Data tempKey = iv;
	for (uint64_t i0 = 0; i0 < crypt.size(); i0 += block_size)
	{
		tempBlock = crypt.sub_by_pos(i0, i0 + block_size);
		cryptor.get_block_decryption()(tempBlock, block_size, cryptor.get_available_key(), cryptor.get_key_size());
        dog_cryption::utils::squareXOR_self(tempBlock, tempKey, block_size);
		res += tempBlock;
		tempKey = crypt.sub_by_pos(i0, i0 + block_size);
	}
	cryptor.get_unpadding()(res, block_size);
	return res;
}
void dog_cryption::mode::CBC::encrypt_stream(std::istream& plain, dog_data::Data iv, std::ostream& crypt, dog_cryption::Cryptor& cryptor)
{
	uint8_t block_size = cryptor.get_block_size();
	plain.seekg(0, std::ios::end);
	uint64_t file_size = plain.tellg();
	plain.seekg(0, std::ios::beg);

	dog_data::Data tempBlock(block_size);
	dog_data::Data tempKey = iv;
	while (plain.tellg() <= file_size - block_size)
	{
		plain.read((char*)tempBlock.data(), block_size);
		dog_cryption::utils::squareXOR_self(tempBlock, tempKey, block_size);
		cryptor.get_block_encryption()(tempBlock, block_size, cryptor.get_available_key(), cryptor.get_key_size());
		crypt.write((char*)tempBlock.data(), block_size);
		tempKey = tempBlock;
	}
	plain.read((char*)tempBlock.data(), block_size);
	if (plain.gcount() < block_size)
	{
		for (uint64_t i = 0; i < block_size - plain.gcount(); ++i) { tempBlock.pop_back(); }
		cryptor.get_padding()(tempBlock, block_size);
	}
	dog_cryption::utils::squareXOR_self(tempBlock, tempKey, block_size);
	cryptor.get_block_encryption()(tempBlock, block_size, cryptor.get_available_key(), cryptor.get_key_size());
	crypt.write((char*)tempBlock.data(), block_size);
	crypt.flush();
}
void dog_cryption::mode::CBC::decrypt_stream(std::istream& crypt, dog_data::Data iv, std::ostream& plain, dog_cryption::Cryptor& cryptor)
{
	uint8_t block_size = cryptor.get_block_size();
	uint64_t now_pos = crypt.tellg();
	crypt.seekg(0, std::ios::end);
	uint64_t file_size = crypt.tellg();
	crypt.seekg(now_pos);

	dog_data::Data tempBlock(block_size);
	dog_data::Data tempKey = iv;
	for (uint64_t i = 0; i < (file_size - now_pos - 1) / block_size; ++i)
	{
		crypt.read((char*)tempBlock.data(), block_size);
		cryptor.get_block_decryption()(tempBlock, block_size, cryptor.get_available_key(), cryptor.get_key_size());
		dog_cryption::utils::squareXOR_self(tempBlock, tempKey, block_size);
		plain.write((char*)tempBlock.data(), block_size);
		for (uint64_t i = 0; i < block_size; ++i) { crypt.unget(); }
		crypt.read((char*)tempKey.data(), block_size);
	}
	crypt.read((char*)tempBlock.data(), block_size);
	cryptor.get_block_decryption()(tempBlock, block_size, cryptor.get_available_key(), cryptor.get_key_size());
	dog_cryption::utils::squareXOR_self(tempBlock, tempKey, block_size);
	cryptor.get_unpadding()(tempBlock, block_size);
	plain.write((char*)tempBlock.data(), tempBlock.size());
	plain.flush();
}
void dog_cryption::mode::CBC::encrypt_streamp(std::istream& plain, dog_data::Data iv, std::ostream& crypt, dog_cryption::Cryptor& cryptor, std::atomic<double>* progress)
{
	uint8_t block_size = cryptor.get_block_size();
	plain.seekg(0, std::ios::end);
	uint64_t file_size = plain.tellg();
	plain.seekg(0, std::ios::beg);

	dog_data::Data tempBlock(block_size);
	dog_data::Data tempKey = iv;
	while (plain.tellg() <= file_size - block_size)
	{
		plain.read((char*)tempBlock.data(), block_size);
		dog_cryption::utils::squareXOR_self(tempBlock, tempKey, block_size);
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
		for (uint64_t i = 0; i < block_size - plain.gcount(); ++i) { tempBlock.pop_back(); }
		cryptor.get_padding()(tempBlock, block_size);
	}
	dog_cryption::utils::squareXOR_self(tempBlock, tempKey, block_size);
	cryptor.get_block_encryption()(tempBlock, block_size, cryptor.get_available_key(), cryptor.get_key_size());
	crypt.write((char*)tempBlock.data(), block_size);
	if(progress->load()<0){return;}progress->store(update_progress(progress->load(), block_size, file_size));
	crypt.flush();
	progress->store(1.0);
}
void dog_cryption::mode::CBC::decrypt_streamp(std::istream& crypt, dog_data::Data iv, std::ostream& plain, dog_cryption::Cryptor& cryptor, std::atomic<double>* progress)
{
	uint8_t block_size = cryptor.get_block_size();
	uint64_t now_pos = crypt.tellg();
	crypt.seekg(0, std::ios::end);
	uint64_t file_size = crypt.tellg();
	crypt.seekg(now_pos);

	dog_data::Data tempBlock(block_size);
	dog_data::Data tempKey = iv;
	for (uint64_t i = 0; i < (file_size - now_pos - 1) / block_size; ++i)
	{
		crypt.read((char*)tempBlock.data(), block_size);
		cryptor.get_block_decryption()(tempBlock, block_size, cryptor.get_available_key(), cryptor.get_key_size());
		dog_cryption::utils::squareXOR_self(tempBlock, tempKey, block_size);
		plain.write((char*)tempBlock.data(), block_size);
		for (uint64_t i = 0; i < block_size; ++i) { crypt.unget(); }
		crypt.read((char*)tempKey.data(), block_size);
		if(progress->load()<0){return;}progress->store(update_progress(progress->load(), block_size, file_size));
	}
	crypt.read((char*)tempBlock.data(), block_size);
	cryptor.get_block_decryption()(tempBlock, block_size, cryptor.get_available_key(), cryptor.get_key_size());
	dog_cryption::utils::squareXOR_self(tempBlock, tempKey, block_size);
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

dog_data::Data dog_cryption::mode::OFB::encrypt(dog_data::Data plain, dog_data::Data iv, dog_cryption::Cryptor& cryptor)
{
	uint8_t block_size = cryptor.get_block_size();
	dog_data::Data res; res.reserve(((plain.size() / block_size) + 1) * block_size);
	dog_data::Data tempBlock0 = iv;
	dog_data::Data tempBlock1;
	for (uint64_t i0 = 0; i0 <= plain.size(); i0 += block_size)
	{
		cryptor.get_block_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
		tempBlock1 = plain.sub_by_pos(i0, i0 + block_size);
		if (tempBlock1.size() <= block_size && cryptor.get_using_padding()) { cryptor.get_padding()(tempBlock1, block_size); }
		res = res + dog_cryption::utils::squareXOR(tempBlock1, tempBlock0, tempBlock1.size());
	}
	return res;
}
dog_data::Data dog_cryption::mode::OFB::decrypt(dog_data::Data crypt, dog_data::Data iv, dog_cryption::Cryptor& cryptor)
{
	uint8_t block_size = cryptor.get_block_size();
	dog_data::Data res; res.reserve(crypt.size());
	dog_data::Data tempBlock0 = iv;
	dog_data::Data tempBlock1; tempBlock1.reserve(block_size);
	for (uint64_t i0 = 0; i0 < crypt.size(); i0 += block_size)
	{
		cryptor.get_block_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
		tempBlock1 = crypt.sub_by_len(i0, block_size);
		res = res + dog_cryption::utils::squareXOR(tempBlock1, tempBlock0, tempBlock1.size());
		tempBlock1.clear_leave_pos();
	}
	if (cryptor.get_using_padding())
	{
		cryptor.get_unpadding()(res, block_size);
	}
	return res;
}
void dog_cryption::mode::OFB::encrypt_stream(std::istream& plain, dog_data::Data iv, std::ostream& crypt, dog_cryption::Cryptor& cryptor)
{
	uint8_t block_size = cryptor.get_block_size();
	plain.seekg(0, std::ios::end);
	uint64_t file_size = plain.tellg();
	plain.seekg(0, std::ios::beg);
	dog_data::Data tempBlock0 = iv;
	dog_data::Data tempBlock1(block_size);
	while (plain.tellg() <= file_size - block_size)
	{
		cryptor.get_block_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
        plain.read((char*)tempBlock1.data(), block_size);
		crypt.write((char*)dog_cryption::utils::squareXOR(tempBlock0, tempBlock1, block_size).data(), block_size);
	}
	cryptor.get_block_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
	plain.read((char*)tempBlock1.data(), block_size);
	for (uint64_t i = 0; i < block_size - plain.gcount(); ++i) { tempBlock1.pop_back(); }
	if (cryptor.get_using_padding() && plain.gcount() < block_size)
	{
		cryptor.get_padding()(tempBlock1, block_size);
	}
	crypt.write((char*)dog_cryption::utils::squareXOR(tempBlock1, tempBlock0, tempBlock1.size()).data(), tempBlock1.size());
	crypt.flush();
}
void dog_cryption::mode::OFB::decrypt_stream(std::istream& crypt, dog_data::Data iv, std::ostream& plain, dog_cryption::Cryptor& cryptor)
{
	uint8_t block_size = cryptor.get_block_size();
	uint64_t now_pos = crypt.tellg();
	crypt.seekg(0, std::ios::end);
	uint64_t file_size = crypt.tellg();
	crypt.seekg(now_pos);

	dog_data::Data tempBlock0 = iv;
	dog_data::Data tempBlock1(block_size);
	for (uint64_t i = 0; i < (file_size - now_pos - 1) / block_size; ++i)
	{
		cryptor.get_block_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
		crypt.read((char*)tempBlock1.data(), block_size);
		plain.write((char*)dog_cryption::utils::squareXOR(tempBlock0, tempBlock1, block_size).data(), block_size);
	}
	cryptor.get_block_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
	crypt.read((char*)tempBlock1.data(), block_size);
	uint64_t s = crypt.gcount();
	for (uint64_t i = 0; i < block_size - crypt.gcount(); ++i) { tempBlock1.pop_back(); }
	dog_cryption::utils::squareXOR_self(tempBlock1, tempBlock0, tempBlock1.size());
	if (cryptor.get_using_padding())
	{
		cryptor.get_unpadding()(tempBlock1, block_size);
	}
	plain.write((char*)tempBlock1.data(), tempBlock1.size());
	plain.flush();
}
void dog_cryption::mode::OFB::encrypt_streamp(std::istream& plain, dog_data::Data iv, std::ostream& crypt, dog_cryption::Cryptor& cryptor, std::atomic<double>* progress)
{
	uint8_t block_size = cryptor.get_block_size();
	plain.seekg(0, std::ios::end);
	uint64_t file_size = plain.tellg();
	plain.seekg(0, std::ios::beg);
	dog_data::Data tempBlock0 = iv;
	dog_data::Data tempBlock1(block_size);
	while (plain.tellg() <= file_size - block_size)
	{
		cryptor.get_block_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
		plain.read((char*)tempBlock1.data(), block_size);
		crypt.write((char*)dog_cryption::utils::squareXOR(tempBlock0, tempBlock1, block_size).data(), block_size);
		if (progress->load() < 0.0)
		{
			return;
		}
		progress->store(update_progress(progress->load(), block_size, file_size));
	}
	cryptor.get_block_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
	plain.read((char*)tempBlock1.data(), block_size);
	for (uint64_t i = 0; i < block_size - plain.gcount(); ++i) { tempBlock1.pop_back(); }
	if (cryptor.get_using_padding() && plain.gcount() < block_size)
	{
		cryptor.get_padding()(tempBlock1, block_size);
	}
	crypt.write((char*)dog_cryption::utils::squareXOR(tempBlock1, tempBlock0, tempBlock1.size()).data(), tempBlock1.size());
	if(progress->load()<0){return;}progress->store(update_progress(progress->load(), block_size, file_size));
	crypt.flush();
	progress->store(1.0);
}
void dog_cryption::mode::OFB::decrypt_streamp(std::istream& crypt, dog_data::Data iv, std::ostream& plain, dog_cryption::Cryptor& cryptor, std::atomic<double>* progress)
{
	uint8_t block_size = cryptor.get_block_size();
	uint64_t now_pos = crypt.tellg();
	crypt.seekg(0, std::ios::end);
	uint64_t file_size = crypt.tellg();
	crypt.seekg(now_pos);

	dog_data::Data tempBlock0 = iv;
	dog_data::Data tempBlock1(block_size);
	for (uint64_t i = 0; i < (file_size - now_pos - 1) / block_size; ++i)
	{
		cryptor.get_block_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
		crypt.read((char*)tempBlock1.data(), block_size);
		plain.write((char*)dog_cryption::utils::squareXOR(tempBlock0, tempBlock1, block_size).data(), block_size);
		if (progress->load() < 0.0)
		{
			return;
		}
		progress->store(update_progress(progress->load(), block_size, file_size));
	}
	cryptor.get_block_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
	crypt.read((char*)tempBlock1.data(), block_size);
	uint64_t s = crypt.gcount();
	for (uint64_t i = 0; i < block_size - crypt.gcount(); ++i) { tempBlock1.pop_back(); }
	dog_cryption::utils::squareXOR_self(tempBlock1, tempBlock0, tempBlock1.size());
	if (cryptor.get_using_padding())
	{
		cryptor.get_unpadding()(tempBlock1, block_size);
	}
	plain.write((char*)tempBlock1.data(), tempBlock1.size());
	if(progress->load()<0){return;}progress->store(update_progress(progress->load(), block_size, file_size));
	plain.flush();
	progress->store(1.0);
}

dog_data::Data dog_cryption::mode::CTR::encrypt(dog_data::Data plain, dog_data::Data iv, dog_cryption::Cryptor& cryptor)
{
	uint8_t block_size = cryptor.get_block_size();
	dog_data::Data res; res.reserve(((plain.size() / block_size) + 1) * block_size);
	dog_data::Data tempBlock0 = iv;
	uint64_t endNum = 0;
	for (uint64_t i0 = 0; i0 < 8; i0++)
	{
		endNum += (uint64_t)tempBlock0[i0 + 8] << (8 * (7 - i0));
	}
	dog_data::Data tempBlock1;
	dog_data::Data tempBlock2;
	for (uint64_t i0 = 0; i0 <= plain.size(); i0 += block_size)
	{
		tempBlock2 = tempBlock0;
		cryptor.get_block_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
		tempBlock1 = plain.sub_by_len(i0, block_size);
		if (tempBlock1.size() < block_size && cryptor.get_using_padding()) { cryptor.get_padding()(tempBlock1, block_size); }
		res = res + dog_cryption::utils::squareXOR(tempBlock1, tempBlock0, tempBlock1.size());
		tempBlock1.clear_leave_pos();
		endNum++;
		for (int i1 = 0; i1 < 8; i1++)
		{
			tempBlock2[i1 + 8] = (uint8_t)(endNum >> (8 * (7 - i1)));
		}
		tempBlock0 = tempBlock2;
	}
	return res;
}
dog_data::Data dog_cryption::mode::CTR::decrypt(dog_data::Data crypt, dog_data::Data iv, dog_cryption::Cryptor& cryptor)
{
	uint8_t block_size = cryptor.get_block_size();
	dog_data::Data res; res.reserve(((crypt.size() / block_size) + 1) * block_size);
	dog_data::Data tempBlock0 = iv;
	uint64_t endNum = 0;
	for (uint64_t i0 = 0; i0 < 8; i0++)
	{
		endNum += (uint64_t)tempBlock0[i0 + 8] << (8 * (7 - i0));
	}
	dog_data::Data tempBlock1;
	dog_data::Data tempBlock2;
	for (uint64_t i0 = 0; i0 < crypt.size(); i0 += block_size)
	{
		tempBlock2 = tempBlock0;
		cryptor.get_block_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
		tempBlock1 = crypt.sub_by_pos(i0, i0 + block_size);
		res = res + dog_cryption::utils::squareXOR(tempBlock1, tempBlock0, tempBlock1.size());
		endNum++;
		for (int i1 = 0; i1 < 8; i1++)
		{
			tempBlock2[i1 + 8] = (uint8_t)(endNum >> (8 * (7 - i1)));
		}
		tempBlock0 = tempBlock2;
	}
	if (cryptor.get_using_padding()) { cryptor.get_unpadding()(res, block_size); }
	return res;
}
void dog_cryption::mode::CTR::encrypt_stream(std::istream& plain, dog_data::Data iv, std::ostream& crypt, dog_cryption::Cryptor& cryptor)
{
	uint8_t block_size = cryptor.get_block_size();
	plain.seekg(0, std::ios::end);
	uint64_t file_size = plain.tellg();
	plain.seekg(0, std::ios::beg);

	dog_data::Data tempBlock0 = iv;
	uint64_t endNum = 0;
	for (uint64_t i0 = 0; i0 < 8; i0++)
	{
		endNum += (uint64_t)tempBlock0[i0 + 8] << (8 * (7 - i0));
	}
	dog_data::Data tempBlock1(block_size);
	dog_data::Data tempBlock2(block_size);
	while (plain.tellg() <= file_size - block_size)
	{
		tempBlock2 = tempBlock0;
		cryptor.get_block_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
		plain.read((char*)tempBlock1.data(), block_size);
		crypt.write((char*)dog_cryption::utils::squareXOR(tempBlock0, tempBlock1, block_size).data(), block_size);
		endNum++;
		for (int i1 = 0; i1 < 8; i1++)
		{
			tempBlock2[i1 + 8] = (uint8_t)(endNum >> (8 * (7 - i1)));
		}
		tempBlock0 = tempBlock2;
	}
	tempBlock2 = tempBlock0;
	cryptor.get_block_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
	plain.read((char*)tempBlock1.data(), block_size);
	for (uint64_t i = 0; i < block_size - plain.gcount(); ++i) { tempBlock1.pop_back(); }
	if (cryptor.get_using_padding() && plain.gcount() < block_size)
	{
		cryptor.get_padding()(tempBlock1, block_size);
	}
	crypt.write((char*)dog_cryption::utils::squareXOR(tempBlock1, tempBlock0, tempBlock1.size()).data(), tempBlock1.size());
	crypt.flush();
}
void dog_cryption::mode::CTR::decrypt_stream(std::istream& crypt, dog_data::Data iv, std::ostream& plain, dog_cryption::Cryptor& cryptor)
{
	uint8_t block_size = cryptor.get_block_size();
	uint64_t now_pos = crypt.tellg();
	crypt.seekg(0, std::ios::end);
	uint64_t file_size = crypt.tellg();
	crypt.seekg(now_pos);

	dog_data::Data tempBlock0 = iv;
	uint64_t endNum = 0;
	for (uint64_t i0 = 0; i0 < 8; i0++)
	{
		endNum += (uint64_t)tempBlock0[i0 + 8] << (8 * (7 - i0));
	}
	dog_data::Data tempBlock1(block_size);
	dog_data::Data tempBlock2(block_size);
	for (uint64_t i = 0; i < (file_size - now_pos - 1) / block_size; ++i)
	{
		tempBlock2 = tempBlock0;
		cryptor.get_block_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
		crypt.read((char*)tempBlock1.data(), block_size);
		plain.write((char*)dog_cryption::utils::squareXOR(tempBlock1, tempBlock0, block_size).data(), block_size);
		endNum++;
		for (int i1 = 0; i1 < 8; i1++)
		{
			tempBlock2[i1 + 8] = (uint8_t)(endNum >> (8 * (7 - i1)));
		}
		tempBlock0 = tempBlock2;
	}
	tempBlock2 = tempBlock0;
	cryptor.get_block_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
	crypt.read((char*)tempBlock1.data(), block_size);
	for (uint64_t i = 0; i < block_size - crypt.gcount(); ++i) { tempBlock1.pop_back(); }
	dog_cryption::utils::squareXOR_self(tempBlock1, tempBlock0, tempBlock1.size());
	if (cryptor.get_using_padding())
	{
		cryptor.get_unpadding()(tempBlock1, block_size);
	}
	plain.write((char*)tempBlock1.data(), tempBlock1.size());
	plain.flush();
}
void dog_cryption::mode::CTR::encrypt_streamp(std::istream& plain, dog_data::Data iv, std::ostream& crypt, dog_cryption::Cryptor& cryptor, std::atomic<double>* progress)
{
	uint8_t block_size = cryptor.get_block_size();
	plain.seekg(0, std::ios::end);
	uint64_t file_size = plain.tellg();
	plain.seekg(0, std::ios::beg);

	dog_data::Data tempBlock0 = iv;
	uint64_t endNum = 0;
	for (uint64_t i0 = 0; i0 < 8; i0++)
	{
		endNum += (uint64_t)tempBlock0[i0 + 8] << (8 * (7 - i0));
	}
	dog_data::Data tempBlock1(block_size);
	dog_data::Data tempBlock2(block_size);
	while (plain.tellg() <= file_size - block_size)
	{
		tempBlock2 = tempBlock0;
		cryptor.get_block_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
		plain.read((char*)tempBlock1.data(), block_size);
		crypt.write((char*)dog_cryption::utils::squareXOR(tempBlock0, tempBlock1, block_size).data(), block_size);
		if (progress->load() < 0.0)
		{
			return;
		}
		progress->store(update_progress(progress->load(), block_size, file_size));
		endNum++;
		for (int i1 = 0; i1 < 8; i1++)
		{
			tempBlock2[i1 + 8] = (uint8_t)(endNum >> (8 * (7 - i1)));
		}
		tempBlock0 = tempBlock2;
	}
	tempBlock2 = tempBlock0;
	cryptor.get_block_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
	plain.read((char*)tempBlock1.data(), block_size);
	for (uint64_t i = 0; i < block_size - plain.gcount(); ++i) { tempBlock1.pop_back(); }
	if (cryptor.get_using_padding() && plain.gcount() < block_size)
	{
		cryptor.get_padding()(tempBlock1, block_size);
	}
	crypt.write((char*)dog_cryption::utils::squareXOR(tempBlock1, tempBlock0, tempBlock1.size()).data(), tempBlock1.size());
	if(progress->load()<0){return;}progress->store(update_progress(progress->load(), block_size, file_size));
	crypt.flush();
	progress->store(1.0);
}
void dog_cryption::mode::CTR::decrypt_streamp(std::istream& crypt, dog_data::Data iv, std::ostream& plain, dog_cryption::Cryptor& cryptor, std::atomic<double>* progress)
{
	uint8_t block_size = cryptor.get_block_size();
	uint64_t now_pos = crypt.tellg();
	crypt.seekg(0, std::ios::end);
	uint64_t file_size = crypt.tellg();
	crypt.seekg(now_pos);

	dog_data::Data tempBlock0 = iv;
	uint64_t endNum = 0;
	for (uint64_t i0 = 0; i0 < 8; i0++)
	{
		endNum += (uint64_t)tempBlock0[i0 + 8] << (8 * (7 - i0));
	}
	dog_data::Data tempBlock1(block_size);
	dog_data::Data tempBlock2(block_size);
	for (uint64_t i = 0; i < (file_size - now_pos - 1) / block_size; ++i)
	{
		tempBlock2 = tempBlock0;
		cryptor.get_block_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
		crypt.read((char*)tempBlock1.data(), block_size);
		plain.write((char*)dog_cryption::utils::squareXOR(tempBlock1, tempBlock0, block_size).data(), block_size);
		if (progress->load() < 0.0)
		{
			return;
		}
		progress->store(update_progress(progress->load(), block_size, file_size));
		endNum++;
		for (int i1 = 0; i1 < 8; i1++)
		{
			tempBlock2[i1 + 8] = (uint8_t)(endNum >> (8 * (7 - i1)));
		}
		tempBlock0 = tempBlock2;
	}
	tempBlock2 = tempBlock0;
	cryptor.get_block_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
	crypt.read((char*)tempBlock1.data(), block_size);
	for (uint64_t i = 0; i < block_size - crypt.gcount(); ++i) { tempBlock1.pop_back(); }
	dog_cryption::utils::squareXOR_self(tempBlock1, tempBlock0, tempBlock1.size());
	if (cryptor.get_using_padding())
	{
		cryptor.get_unpadding()(tempBlock1, block_size);
	}
	plain.write((char*)tempBlock1.data(), tempBlock1.size());
	if(progress->load()<0){return;}progress->store(update_progress(progress->load(), block_size, file_size));
	plain.flush();
	progress->store(1.0);
}

dog_data::Data dog_cryption::mode::CFBB::encrypt(dog_data::Data plain, dog_data::Data iv, dog_cryption::Cryptor& cryptor)
{
	uint8_t block_size = cryptor.get_block_size();
	//反馈字节数
	uint8_t nbyte = cryptor.get_reback_size();

	dog_data::Data res; res.reserve(((plain.size() / nbyte) + 1) * nbyte);
	dog_data::Data tempBlock0 = iv;
	dog_data::Data tempBlock1(nbyte);
	dog_data::Data tempBlock2(nbyte);
	uint64_t i = 0;
	for (i = 0; i <= plain.size() - nbyte; i += nbyte);
	{
		cryptor.get_block_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
		tempBlock1 = plain.sub_by_len(i, nbyte);
		tempBlock2 = tempBlock0.sub_by_len(0, nbyte);
		dog_cryption::utils::squareXOR_self(tempBlock1, tempBlock2, tempBlock1.size());
        res += tempBlock1;
		tempBlock0 = tempBlock0.sub_by_len(nbyte, block_size - nbyte) + tempBlock1;
	}
	cryptor.get_block_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
	tempBlock1 = plain.sub_by_len(i, nbyte);
	if (cryptor.get_using_padding()) { cryptor.get_padding()(tempBlock1, nbyte); }
	tempBlock2 = tempBlock0.sub_by_len(0, nbyte);
	dog_cryption::utils::squareXOR_self(tempBlock1, tempBlock2, tempBlock1.size());
	res += tempBlock1;
	return res;
}
dog_data::Data dog_cryption::mode::CFBB::decrypt(dog_data::Data crypt, dog_data::Data iv, dog_cryption::Cryptor& cryptor)
{
	uint8_t block_size = cryptor.get_block_size();
	uint8_t nbyte = cryptor.get_reback_size();

	dog_data::Data res; res.reserve(((crypt.size() / nbyte) + 1) * nbyte);
	dog_data::Data tempBlock0 = iv;
	dog_data::Data tempBlock1(nbyte);
	dog_data::Data tempBlock2(nbyte);
	uint64_t i = 0;
	for (i = 0; i < crypt.size() - nbyte; i += nbyte);
	{
		cryptor.get_block_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
		tempBlock1 = crypt.sub_by_len(i, nbyte);
		tempBlock2 = tempBlock0.sub_by_len(0, nbyte);
		dog_cryption::utils::squareXOR_self(tempBlock1, tempBlock2, tempBlock1.size());
		res += tempBlock1;
		tempBlock0 = tempBlock0.sub_by_len(nbyte, block_size - nbyte) + tempBlock1;
	}
	cryptor.get_block_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
	tempBlock1 = crypt.sub_by_len(i, nbyte);
	if (cryptor.get_using_padding() && tempBlock1.size() == nbyte) { cryptor.get_unpadding()(tempBlock1, nbyte); }
    tempBlock2 = tempBlock0.sub_by_len(0, nbyte);
	dog_cryption::utils::squareXOR_self(tempBlock1, tempBlock2, tempBlock1.size());
	res += tempBlock1;
	return res;
}
void dog_cryption::mode::CFBB::encrypt_stream(std::istream& plain, dog_data::Data iv, std::ostream& crypt, dog_cryption::Cryptor& cryptor)
{
	uint8_t block_size = cryptor.get_block_size();
	plain.seekg(0, std::ios::end);
	uint64_t file_size = plain.tellg();
	plain.seekg(0, std::ios::beg);
	//反馈字节数
	uint8_t nbyte = cryptor.get_reback_size();

	dog_data::Data tempBlock0 = iv;
	dog_data::Data tempBlock1(nbyte);
	dog_data::Data tempBlock2(nbyte);
	while (plain.tellg() <= file_size - nbyte)
	{
		cryptor.get_block_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
		plain.read((char*)tempBlock1.data(), nbyte);
		tempBlock2 = tempBlock0.sub_by_len(0, nbyte);
		dog_cryption::utils::squareXOR_self(tempBlock1, tempBlock2, nbyte);
		crypt.write((char*)tempBlock1.data(), nbyte);
		tempBlock0 = tempBlock0.sub_by_len(nbyte, block_size - nbyte) + tempBlock1;
	}
	cryptor.get_block_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
	plain.read((char*)tempBlock1.data(), nbyte);
	tempBlock2 = tempBlock0.sub_by_len(0, nbyte);
	for (int i = 0; i < nbyte - plain.gcount(); ++i) { tempBlock1.pop_back(); }
	if (cryptor.get_using_padding() && plain.gcount() < nbyte) { cryptor.get_padding()(tempBlock1, nbyte); }
	dog_cryption::utils::squareXOR_self(tempBlock1, tempBlock2, tempBlock1.size());
	crypt.write((char*)tempBlock1.data(), nbyte);
	crypt.flush();
}
void dog_cryption::mode::CFBB::decrypt_stream(std::istream& crypt, dog_data::Data iv, std::ostream& plain, dog_cryption::Cryptor& cryptor)
{
	uint8_t block_size = cryptor.get_block_size();
	uint64_t now_pos = crypt.tellg();
	crypt.seekg(0, std::ios::end);
	uint64_t file_size = crypt.tellg();
	crypt.seekg(now_pos);
	
	//反馈字节数
	uint8_t nbyte = cryptor.get_reback_size();

	dog_data::Data tempBlock0 = iv;
	dog_data::Data tempBlock1(nbyte);
	dog_data::Data tempBlock2(nbyte);
	while (crypt.tellg() < file_size - nbyte)
	{
		cryptor.get_block_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
		crypt.read((char*)tempBlock1.data(), nbyte);
		tempBlock2 = tempBlock0.sub_by_len(0, nbyte);
		dog_cryption::utils::squareXOR_self(tempBlock1, tempBlock2, nbyte);
		plain.write((char*)tempBlock1.data(), nbyte);
		tempBlock0 = tempBlock0.sub_by_len(nbyte, block_size - nbyte) + tempBlock1;
	}
	cryptor.get_block_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
	crypt.read((char*)tempBlock1.data(), nbyte);
	tempBlock2 = tempBlock0.sub_by_len(0, nbyte);
	dog_cryption::utils::squareXOR_self(tempBlock1, tempBlock2, tempBlock1.size());
	if (cryptor.get_using_padding()) { cryptor.get_unpadding()(tempBlock1, nbyte); }
	plain.write((char*)tempBlock1.data(), nbyte);
	plain.flush();
}
void dog_cryption::mode::CFBB::encrypt_streamp(std::istream& plain, dog_data::Data iv, std::ostream& crypt, dog_cryption::Cryptor& cryptor, std::atomic<double>* progress)
{
	uint8_t block_size = cryptor.get_block_size();
	plain.seekg(0, std::ios::end);
	uint64_t file_size = plain.tellg();
	plain.seekg(0, std::ios::beg);
	//反馈字节数
	uint8_t nbyte = cryptor.get_reback_size();

	dog_data::Data tempBlock0 = iv;
	dog_data::Data tempBlock1(nbyte);
	dog_data::Data tempBlock2(nbyte);
	while (plain.tellg() <= file_size - nbyte)
	{
		cryptor.get_block_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
		plain.read((char*)tempBlock1.data(), nbyte);
		tempBlock2 = tempBlock0.sub_by_len(0, nbyte);
		dog_cryption::utils::squareXOR_self(tempBlock1, tempBlock2, nbyte);
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
	dog_cryption::utils::squareXOR_self(tempBlock1, tempBlock2, tempBlock1.size());
	crypt.write((char*)tempBlock1.data(), nbyte);
	if(progress->load()<0){return;}progress->store(update_progress(progress->load(), nbyte, file_size));
	crypt.flush();
	progress->store(1.0);
}
void dog_cryption::mode::CFBB::decrypt_streamp(std::istream& crypt, dog_data::Data iv, std::ostream& plain, dog_cryption::Cryptor& cryptor, std::atomic<double>* progress)
{
	uint8_t block_size = cryptor.get_block_size();
	uint64_t now_pos = crypt.tellg();
	crypt.seekg(0, std::ios::end);
	uint64_t file_size = crypt.tellg();
	crypt.seekg(now_pos);

	//反馈字节数
	uint8_t nbyte = cryptor.get_reback_size();

	dog_data::Data tempBlock0 = iv;
	dog_data::Data tempBlock1(nbyte);
	dog_data::Data tempBlock2(nbyte);
	while (crypt.tellg() < file_size - nbyte)
	{
		cryptor.get_block_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
		crypt.read((char*)tempBlock1.data(), nbyte);
		tempBlock2 = tempBlock0.sub_by_len(0, nbyte);
		dog_cryption::utils::squareXOR_self(tempBlock1, tempBlock2, nbyte);
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
	dog_cryption::utils::squareXOR_self(tempBlock1, tempBlock2, tempBlock1.size());
	if (cryptor.get_using_padding()) { cryptor.get_unpadding()(tempBlock1, nbyte); }
	plain.write((char*)tempBlock1.data(), nbyte);
	if(progress->load()<0){return;}progress->store(update_progress(progress->load(), nbyte, file_size));
	plain.flush();
	progress->store(1.0);
}

dog_data::Data dog_cryption::mode::CFBB::encrypt_CFB8(dog_data::Data plain, dog_data::Data iv, dog_cryption::Cryptor& cryptor)
{
	uint8_t block_size = cryptor.get_block_size();
	dog_data::Data res; res.reserve(((plain.size() / block_size) + 1) * block_size);
	dog_data::Data tempBlock0 = iv;
	dog_data::Data tempBlock1; tempBlock1.reserve(block_size);
	for (uint64_t i0 = 0; i0 < plain.size(); i0++)
	{
		tempBlock1 = tempBlock0;
		cryptor.get_block_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
		uint8_t b = plain[i0] ^ tempBlock0[0];
		res.push_back(b);
		tempBlock1.push_back(b);
	}
	return res;
}
dog_data::Data dog_cryption::mode::CFBB::decrypt_CFB8(dog_data::Data crypt, dog_data::Data iv, dog_cryption::Cryptor& cryptor)
{
	uint8_t block_size = cryptor.get_block_size();
	dog_data::Data res; res.reserve(((crypt.size() / block_size) + 1) * block_size);
	dog_data::Data tempBlock0 = iv;
	dog_data::Data tempBlock1; tempBlock1.reserve(block_size);
	for (uint64_t i0 = 0; i0 < crypt.size(); i0++)
	{
		tempBlock1 = tempBlock0;
		cryptor.get_block_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
		uint8_t b = crypt[i0] ^ tempBlock0[0];
		res.push_back(b);
		tempBlock0.push_back(crypt[i0]);
	}
	return res;
}
void dog_cryption::mode::CFBB::encrypt_CFB8_stream(std::istream& plain, dog_data::Data iv, std::ostream& crypt, dog_cryption::Cryptor& cryptor)
{
	uint8_t block_size = cryptor.get_block_size();
	plain.seekg(0, std::ios::end);
	uint64_t file_size = plain.tellg();
	plain.seekg(0, std::ios::beg);

	dog_data::Data tempBlock0 = iv;
	dog_data::Data tempBlock1(block_size);
	dog_data::Data middleResult;middleResult.reserve(block_size);
	while (plain.tellg() < file_size)
	{
		tempBlock1 = tempBlock0;
		cryptor.get_block_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
		uint8_t b = plain.get() ^ tempBlock0[0];
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
void dog_cryption::mode::CFBB::decrypt_CFB8_stream(std::istream& crypt, dog_data::Data iv, std::ostream& plain, dog_cryption::Cryptor& cryptor)
{
	uint8_t block_size = cryptor.get_block_size();
	uint64_t now_pos = crypt.tellg();
	crypt.seekg(0, std::ios::end);
	uint64_t file_size = crypt.tellg();
	crypt.seekg(now_pos);

	dog_data::Data tempBlock0 = iv;
	dog_data::Data tempBlock1; tempBlock1.reserve(block_size);
	dog_data::Data middleResult; middleResult.reserve(block_size);
	while (crypt.tellg() < file_size)
	{
		tempBlock1 = tempBlock0;
		cryptor.get_block_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
		uint8_t b = crypt.peek() ^ tempBlock0[0];
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
void dog_cryption::mode::CFBB::encrypt_CFB8_streamp(std::istream& plain, dog_data::Data iv, std::ostream& crypt, dog_cryption::Cryptor& cryptor, std::atomic<double>* progress)
{
	uint8_t block_size = cryptor.get_block_size();
	plain.seekg(0, std::ios::end);
	uint64_t file_size = plain.tellg();
	plain.seekg(0, std::ios::beg);

	dog_data::Data tempBlock0 = iv;
	dog_data::Data tempBlock1(block_size);
	dog_data::Data middleResult; middleResult.reserve(block_size);
	while (plain.tellg() < file_size)
	{
		tempBlock1 = tempBlock0;
		cryptor.get_block_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
		uint8_t b = plain.get() ^ tempBlock0[0];
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
void dog_cryption::mode::CFBB::decrypt_CFB8_streamp(std::istream& crypt, dog_data::Data iv, std::ostream& plain, dog_cryption::Cryptor& cryptor, std::atomic<double>* progress)
{
	uint8_t block_size = cryptor.get_block_size();
	uint64_t now_pos = crypt.tellg();
	crypt.seekg(0, std::ios::end);
	uint64_t file_size = crypt.tellg();
	crypt.seekg(now_pos);

	dog_data::Data tempBlock0 = iv;
	dog_data::Data tempBlock1; tempBlock1.reserve(block_size);
	dog_data::Data middleResult; middleResult.reserve(block_size);
	while (crypt.tellg() < file_size)
	{
		tempBlock1 = tempBlock0;
		cryptor.get_block_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
		uint8_t b = crypt.peek() ^ tempBlock0[0];
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

dog_data::Data dog_cryption::mode::CFBb::encrypt(dog_data::Data plain, dog_data::Data iv, dog_cryption::Cryptor& cryptor)
{
	throw CryptionException("not using", __FILE__, __FUNCTION__, __LINE__);
	return dog_data::Data();
}
dog_data::Data dog_cryption::mode::CFBb::decrypt(dog_data::Data crypt, dog_data::Data iv, dog_cryption::Cryptor& cryptor)
{
	throw CryptionException("not using", __FILE__, __FUNCTION__, __LINE__);
	return dog_data::Data();
}
void dog_cryption::mode::CFBb::encrypt_stream(std::istream& plain, dog_data::Data iv, std::ostream& crypt, dog_cryption::Cryptor& cryptor)
{
	throw CryptionException("not using", __FILE__, __FUNCTION__, __LINE__);
}
void dog_cryption::mode::CFBb::decrypt_stream(std::istream& crypt, dog_data::Data iv, std::ostream& plain, dog_cryption::Cryptor& cryptor)
{
	throw CryptionException("not using", __FILE__, __FUNCTION__, __LINE__);
}
void dog_cryption::mode::CFBb::encrypt_streamp(std::istream& plain, dog_data::Data iv, std::ostream& crypt, dog_cryption::Cryptor& cryptor, std::atomic<double>* progress)
{
	throw CryptionException("not using", __FILE__, __FUNCTION__, __LINE__);
}
void dog_cryption::mode::CFBb::decrypt_streamp(std::istream& crypt, dog_data::Data iv, std::ostream& plain, dog_cryption::Cryptor& cryptor, std::atomic<double>* progress)
{
	throw CryptionException("not using", __FILE__, __FUNCTION__, __LINE__);
}

dog_data::Data dog_cryption::mode::CFBb::encrypt_CFB1(dog_data::Data plain, dog_data::Data iv, dog_cryption::Cryptor& cryptor)
{
	uint8_t block_size = cryptor.get_block_size();
	dog_data::Data res; res.reserve(((plain.size() / block_size) + 1) * block_size);
	dog_data::Data tempBlock0 = iv;
	dog_data::Data tempBlock1; tempBlock1.reserve(block_size);
	for (uint64_t i0 = 0; i0 < plain.size(); i0++)
	{
		uint8_t B = 0x00;
		for (int j = 0; j < 8; j++)
		{
			tempBlock1 = tempBlock0;
			cryptor.get_block_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
			uint8_t b = (plain[i0] >> (7 - j) & 0x01) ^ (tempBlock0[0] >> (7 - j) & 0x01);
			B += b << (7 - j);
			uint8_t c = b, d = 0x00;
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
dog_data::Data dog_cryption::mode::CFBb::decrypt_CFB1(dog_data::Data crypt, dog_data::Data iv, dog_cryption::Cryptor& cryptor)
{
	uint8_t block_size = cryptor.get_block_size();
	dog_data::Data res; res.reserve(((crypt.size() / block_size) + 1) * block_size);
	dog_data::Data tempBlock0 = iv;
	dog_data::Data tempBlock1; tempBlock1.reserve(block_size);
	for (uint64_t i0 = 0; i0 < crypt.size(); i0++)
	{
		uint8_t B = 0x00;
		for (int j = 0; j < 8; j++)
		{
			tempBlock1 = tempBlock0;
			cryptor.get_block_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
			uint8_t b = (crypt[i0] >> (7 - j) & 0x01) ^ (tempBlock0[0] >> (7 - j) & 0x01);
			B += b << (7 - j);
			uint8_t c = crypt[i0] >> (7 - j) & 0x01, d = 0x00;
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
void dog_cryption::mode::CFBb::encrypt_CFB1_stream(std::istream& plain, dog_data::Data iv, std::ostream& crypt, dog_cryption::Cryptor& cryptor)
{
	uint8_t block_size = cryptor.get_block_size();
	plain.seekg(0, std::ios::end);
	uint64_t file_size = plain.tellg();
	plain.seekg(0, std::ios::beg);

	dog_data::Data tempBlock0 = iv;
	dog_data::Data tempBlock1(block_size);
	while (plain.tellg() < file_size) 
	{
		//uint64_t s = plain.tellg();
		//printf("%llu\r", s);
		uint8_t B = 0x00;
		for (int j = 0; j < 8; j++)
		{
			tempBlock1 = tempBlock0;
			cryptor.get_block_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
			uint8_t b = (plain.peek() >> (7 - j) & 0x01) ^ (tempBlock0[0] >> (7 - j) & 0x01);
			B += b << (7 - j);
			uint8_t c = b, d = 0x00;
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
void dog_cryption::mode::CFBb::decrypt_CFB1_stream(std::istream& crypt, dog_data::Data iv, std::ostream& plain, dog_cryption::Cryptor& cryptor)
{
	uint8_t block_size = cryptor.get_block_size();
	uint64_t now_pos = crypt.tellg();
	crypt.seekg(0, std::ios::end);
	uint64_t file_size = crypt.tellg();
	crypt.seekg(now_pos);

	dog_data::Data tempBlock0 = iv;
	dog_data::Data tempBlock1; tempBlock1.reserve(block_size);
	while (crypt.tellg() < file_size)
	{
		//uint64_t s = crypt.tellg();
		//printf("%llu\r", s);

		uint8_t B = 0x00;
		for (int j = 0; j < 8; j++)
		{
			tempBlock1 = tempBlock0;
			cryptor.get_block_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
			uint8_t b = (crypt.peek() >> (7 - j) & 0x01) ^ (tempBlock0[0] >> (7 - j) & 0x01);
			B += b << (7 - j);
			uint8_t c = crypt.peek() >> (7 - j) & 0x01, d = 0x00;
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
void dog_cryption::mode::CFBb::encrypt_CFB1_streamp(std::istream& plain, dog_data::Data iv, std::ostream& crypt, dog_cryption::Cryptor& cryptor, std::atomic<double>* progress)
{
	uint8_t block_size = cryptor.get_block_size();
	plain.seekg(0, std::ios::end);
	uint64_t file_size = plain.tellg();
	plain.seekg(0, std::ios::beg);

	dog_data::Data tempBlock0 = iv;
	dog_data::Data tempBlock1(block_size);
	while (plain.tellg() < file_size)
	{
		//uint64_t s = plain.tellg();
		//printf("%llu\r", s);
		uint8_t B = 0x00;
		for (int j = 0; j < 8; j++)
		{
			tempBlock1 = tempBlock0;
			cryptor.get_block_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
			uint8_t b = (plain.peek() >> (7 - j) & 0x01) ^ (tempBlock0[0] >> (7 - j) & 0x01);
			B += b << (7 - j);
			uint8_t c = b, d = 0x00;
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
void dog_cryption::mode::CFBb::decrypt_CFB1_streamp(std::istream& crypt, dog_data::Data iv, std::ostream& plain, dog_cryption::Cryptor& cryptor, std::atomic<double>* progress)
{
	uint8_t block_size = cryptor.get_block_size();
	uint64_t now_pos = crypt.tellg();
	crypt.seekg(0, std::ios::end);
	uint64_t file_size = crypt.tellg();
	crypt.seekg(now_pos);

	dog_data::Data tempBlock0 = iv;
	dog_data::Data tempBlock1; tempBlock1.reserve(block_size);
	while (crypt.tellg() < file_size)
	{
		//uint64_t s = crypt.tellg();
		//printf("%llu\r", s);

		uint8_t B = 0x00;
		for (int j = 0; j < 8; j++)
		{
			tempBlock1 = tempBlock0;
			cryptor.get_block_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
			uint8_t b = (crypt.peek() >> (7 - j) & 0x01) ^ (tempBlock0[0] >> (7 - j) & 0x01);
			B += b << (7 - j);
			uint8_t c = crypt.peek() >> (7 - j) & 0x01, d = 0x00;
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

dog_data::Data dog_cryption::mode::CFBB::encrypt_CFB128(dog_data::Data plain, dog_data::Data iv, dog_cryption::Cryptor& cryptor)
{
	uint8_t block_size = cryptor.get_block_size();
	dog_data::Data res; res.reserve(((plain.size() / block_size) + 1) * block_size);
	dog_data::Data tempBlock0 = iv;
	dog_data::Data tempBlock1(block_size);
	uint64_t i0 = 0;
	for (i0 = 0; i0 <= plain.size() - 16 && plain.size() >= 16; i0 += 16)
	{
		cryptor.get_block_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
		tempBlock1 = plain.sub_by_len(i0, block_size);
		dog_cryption::utils::squareXOR_self(tempBlock1, tempBlock0, 16);
		res = res + tempBlock1;
		tempBlock0 = tempBlock1;
	}
	cryptor.get_block_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
	tempBlock1 = plain.sub_by_len(i0, block_size);
	if (tempBlock1.size() < 16 && cryptor.get_using_padding()) { cryptor.get_padding()(tempBlock1, 16); }
	dog_cryption::utils::squareXOR_self(tempBlock1, tempBlock0, tempBlock1.size());
	res += tempBlock1;
	return res;
}
dog_data::Data dog_cryption::mode::CFBB::decrypt_CFB128(dog_data::Data crypt, dog_data::Data iv, dog_cryption::Cryptor& cryptor)
{
	uint8_t block_size = cryptor.get_block_size();
	dog_data::Data res; res.reserve(((crypt.size() / block_size) + 1) * block_size);
	dog_data::Data tempBlock0 = iv;
	dog_data::Data tempBlock1(block_size);
	uint64_t i0 = 0;
	for (i0 = 0; i0 < crypt.size() - 16 && crypt.size() > 16; i0 += 16)
	{
		cryptor.get_block_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
		tempBlock1 = crypt.sub_by_pos(i0, i0 + 16);
		res = res + dog_cryption::utils::squareXOR(tempBlock0, tempBlock1, block_size);
		tempBlock0 = tempBlock1;
	}
	cryptor.get_block_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
	tempBlock1 = crypt.sub_by_pos(i0, i0 + 16);
	dog_cryption::utils::squareXOR_self(tempBlock1, tempBlock0, tempBlock0.size());
	if (cryptor.get_using_padding())
	{
		cryptor.get_unpadding()(tempBlock1, 16);
	}
	res += tempBlock1;
	return res;
}
void dog_cryption::mode::CFBB::encrypt_CFB128_stream(std::istream& plain, dog_data::Data iv, std::ostream& crypt, dog_cryption::Cryptor& cryptor)
{
	uint8_t block_size = cryptor.get_block_size();
	plain.seekg(0, std::ios::end);
	uint64_t file_size = plain.tellg();
	plain.seekg(0, std::ios::beg);

	dog_data::Data tempBlock0 = iv;
	dog_data::Data tempBlock1(block_size);
	while (plain.tellg() <= file_size - block_size)
	{
		cryptor.get_block_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
		plain.read((char*)tempBlock1.data(), 16);
		dog_cryption::utils::squareXOR_self(tempBlock0, tempBlock1, block_size);
		crypt.write((char*)tempBlock0.data(), 16);
	}
	cryptor.get_block_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
	plain.read((char*)tempBlock1.data(), 16);
	for (int i = 0; i < 16 - plain.gcount(); i++) { tempBlock1.pop_back(); }
	if (cryptor.get_using_padding() && plain.gcount() < 16) { cryptor.get_padding()(tempBlock1, 16); }
	dog_cryption::utils::squareXOR_self(tempBlock1, tempBlock0, tempBlock1.size());
	crypt.write((char*)tempBlock1.data(), tempBlock1.size());
	crypt.flush();
}
void dog_cryption::mode::CFBB::decrypt_CFB128_stream(std::istream& crypt, dog_data::Data iv, std::ostream& plain, dog_cryption::Cryptor& cryptor)
{
	uint8_t block_size = cryptor.get_block_size();
	uint64_t now_pos = crypt.tellg();
	crypt.seekg(0, std::ios::end);
	uint64_t file_size = crypt.tellg();
	crypt.seekg(now_pos);

	dog_data::Data tempBlock0 = iv;
	dog_data::Data tempBlock1(block_size);
	for (uint64_t i = 0; i < (file_size - now_pos - 1) / block_size; ++i)
	{
		cryptor.get_block_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
		crypt.read((char*)tempBlock1.data(), block_size);
		plain.write((char*)dog_cryption::utils::squareXOR(tempBlock0, tempBlock1, block_size).data(), block_size);
		tempBlock0 = tempBlock1;
	}
	cryptor.get_block_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
	crypt.read((char*)tempBlock1.data(), block_size);
	for (int i = 0; i < 16 - crypt.gcount(); i++) { tempBlock1.pop_back(); }
	dog_cryption::utils::squareXOR_self(tempBlock1, tempBlock0, block_size);
	cryptor.get_unpadding()(tempBlock1, block_size);
	plain.write((char*)tempBlock1.data(), tempBlock1.size());
	plain.flush();
}
void dog_cryption::mode::CFBB::encrypt_CFB128_streamp(std::istream& plain, dog_data::Data iv, std::ostream& crypt, dog_cryption::Cryptor& cryptor, std::atomic<double>* progress)
{
	uint8_t block_size = cryptor.get_block_size();
	plain.seekg(0, std::ios::end);
	uint64_t file_size = plain.tellg();
	plain.seekg(0, std::ios::beg);

	dog_data::Data tempBlock0 = iv;
	dog_data::Data tempBlock1(block_size);
	while (plain.tellg() <= file_size - block_size)
	{
		cryptor.get_block_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
		plain.read((char*)tempBlock1.data(), 16);
		dog_cryption::utils::squareXOR_self(tempBlock0, tempBlock1, block_size);
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
	dog_cryption::utils::squareXOR_self(tempBlock1, tempBlock0, tempBlock1.size());
	crypt.write((char*)tempBlock1.data(), tempBlock1.size());
	if (progress->load() < 0) { return; }progress->store(update_progress(progress->load(), 16, file_size));
	crypt.flush();
	progress->store(1.0);

}
void dog_cryption::mode::CFBB::decrypt_CFB128_streamp(std::istream& crypt, dog_data::Data iv, std::ostream& plain, dog_cryption::Cryptor& cryptor, std::atomic<double>* progress)
{
	uint8_t block_size = cryptor.get_block_size();
	uint64_t now_pos = crypt.tellg();
	crypt.seekg(0, std::ios::end);
	uint64_t file_size = crypt.tellg();
	crypt.seekg(now_pos);

	dog_data::Data tempBlock0 = iv;
	dog_data::Data tempBlock1(block_size);
	for (uint64_t i = 0; i < (file_size - now_pos - 1) / block_size; ++i)
	{
		cryptor.get_block_encryption()(tempBlock0, block_size, cryptor.get_available_key(), cryptor.get_key_size());
		crypt.read((char*)tempBlock1.data(), block_size);
		plain.write((char*)dog_cryption::utils::squareXOR(tempBlock0, tempBlock1, block_size).data(), block_size);
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
	dog_cryption::utils::squareXOR_self(tempBlock1, tempBlock0, block_size);
	cryptor.get_unpadding()(tempBlock1, block_size);
	plain.write((char*)tempBlock1.data(), tempBlock1.size());
	if (progress->load() < 0) { return; }progress->store(update_progress(progress->load(), 16, file_size));
	plain.flush();
	progress->store(1.0);
}

//AES
dog_data::Data dog_cryption::AES::extendKey128(dog_data::Data& key)
{
	dog_data::Data res;
	res.reserve(176);
	
	if (key.size() < 16)
	{
		throw CryptionException(std::format("Error:Invalid Key Size {}  < 16\n错误:密钥长度过短 {} < 16", key.size(), key.size()).c_str(),
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
			uint8_t temp1[4] = { res.at(i - 4), res.at(i - 3), res.at(i - 2), res.at(i - 1) };
			//列位移
			uint8_t typeB = temp1[0];
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
			uint8_t temp2[4] = { res.at(i - 16), res.at(i - 15), res.at(i - 14), res.at(i - 13) };
			for (int i = 0; i < 4; i++)
			{
				res.push_back(temp1[i] ^ temp2[i]);
			}
		}
		else
		{
			//取当前列-1
			uint8_t temp1[4] = { res.at(i - 4), res.at(i - 3), res.at(i - 2), res.at(i - 1) };
			//取当前列-4并异或
			uint8_t temp2[4] = { res.at(i - 16), res.at(i - 15), res.at(i - 14), res.at(i - 13) };
			for (int i = 0; i < 4; i++)
			{
				res.push_back(temp1[i] ^ temp2[i]);
			}
		}
	}
	return res;
}
dog_data::Data dog_cryption::AES::extendKey192(dog_data::Data& key)
{
	dog_data::Data res;
	res.reserve(208);
	if (key.size() < 24)
	{
		throw CryptionException(std::format("Error:Invalid Key Size {}  < 24\n错误:密钥长度过短 {} < 24", key.size(), key.size()).c_str(),
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
			uint8_t temp1[4] = { res.at(i - 4), res.at(i - 3), res.at(i - 2), res.at(i - 1) };
			//列位移
			uint8_t typeB = temp1[0];
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
			uint8_t temp2[4] = { res.at(i - 24), res.at(i - 23), res.at(i - 22), res.at(i - 21) };
			for (int i = 0; i < 4; i++)
			{
				res.push_back(temp1[i] ^ temp2[i]);
			}
		}
		else
		{
			//取当前列-1
			uint8_t temp1[4] = { res.at(i - 4), res.at(i - 3), res.at(i - 2), res.at(i - 1) };
			//取当前列-6并异或
			uint8_t temp2[4] = { res.at(i - 24), res.at(i - 23), res.at(i - 22), res.at(i - 21) };
			for (int i = 0; i < 4; i++)
			{
				res.push_back(temp1[i] ^ temp2[i]);
			}
		}
	}
	return res;
}
dog_data::Data dog_cryption::AES::extendKey256(dog_data::Data& key)
{
	dog_data::Data res;
	res.reserve(240);
	if (key.size() < 32)
	{
		throw CryptionException(std::format("Error:Invalid Key Size {}  < 32\n错误:密钥长度过短 {} < 32", key.size(), key.size()).c_str(),
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
			uint8_t temp1[4] = { res.at(i - 4), res.at(i - 3), res.at(i - 2), res.at(i - 1) };
			//列位移
			uint8_t typeB = temp1[0];
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
			uint8_t temp2[4] = { res.at(i - 32), res.at(i - 31), res.at(i - 30), res.at(i - 29) };
			for (int i0 = 0; i0 < 4; i0++)
			{
				res.push_back(temp1[i0] ^ temp2[i0]);
			}
		}
		else if (i % 16 == 0)
		{
			//取当前列-1
			uint8_t temp1[4] = { res.at(i - 4), res.at(i - 3), res.at(i - 2), res.at(i - 1) };
			for (int i0 = 0; i0 < 4; i0++)
			{
				temp1[i0] = SBox[temp1[i0] >> 4][temp1[i0] & 0x0f];
			}
			//取当前列-8并异或
			uint8_t temp2[4] = { res.at(i - 32), res.at(i - 31), res.at(i - 30), res.at(i - 29) };
			for (int i0 = 0; i0 < 4; i0++)
			{
				res.push_back(temp1[i0] ^ temp2[i0]);
			}
		}
		else
		{
			//取当前列-1
			uint8_t temp1[4] = { res.at(i - 4), res.at(i - 3), res.at(i - 2), res.at(i - 1) };
			//取当前列-8并异或
			uint8_t temp2[4] = { res.at(i - 32), res.at(i - 31), res.at(i - 30), res.at(i - 29) };
			for (int i0 = 0; i0 < 4; i0++)
			{
				res.push_back(temp1[i0] ^ temp2[i0]);
			}
		}
	}
	return res;
}
dog_data::Data dog_cryption::AES::extend_key(dog_data::Data& key, uint64_t key_size)
{
	if (key_size == 16)
	{
		return extendKey128(key);
	}
	else if (key_size == 24)
	{
		return extendKey192(key);
	}
	else if (key_size == 32)
	{
		return extendKey256(key);
	}
	else
	{
		throw CryptionException("wrong key length", __FILE__, __FUNCTION__, __LINE__);
	}
}

uint8_t dog_cryption::AES::Xtime(uint8_t a, uint8_t b)
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
		throw CryptionException("wrong value of a", __FILE__, __FUNCTION__, __LINE__);
	}
}
dog_data::Data dog_cryption::AES::middle_encryption(dog_data::Data datablock, int flag, int mode)
{

	dog_data::Data res;
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
	uint8_t b1, b2;
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
				uint8_t tempB = 0;
				for (int i2 = 0; i2 < 4; i2++)
				{
					tempB ^= dog_cryption::AES::Xtime(MixTable[i1 + i2], datablock[i0 + i2]);
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
dog_data::Data dog_cryption::AES::middle_decryption(dog_data::Data datablock, int flag, int mode)
{
	dog_data::Data res;
	res.reserve(16);
	//列混合
	if (flag != 0)
	{
		for (int i0 = 0; i0 < 16; i0 += 4)
		{
			for (int i1 = 0; i1 < 16; i1 += 4)
			{
				uint8_t tempB = 0;
				for (int i2 = 0; i2 < 4; i2++)
				{
					tempB ^= dog_cryption::AES::Xtime(UMixTable[i1 + i2], datablock[i0 + i2]);
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
	uint8_t b1, b2;
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
dog_data::Data dog_cryption::AES::encoding(dog_data::Data& plain, uint8_t block_size, const dog_data::Data& key, uint8_t key_size)
{
	dog_data::Data temp_key = key.sub_by_pos(0, 16);
	dog_data::Data mid_block = dog_cryption::utils::squareXOR(plain, temp_key, 16);
	for (int i = 0; i < ((key_size / 4) + 6); i++)
	{
		mid_block = AES::middle_encryption(mid_block, i, key_size << 3);
		temp_key = key.sub_by_pos(16 * (i + 1), 16 * (i + 2));
		mid_block = dog_cryption::utils::squareXOR(mid_block, temp_key, 16);
	}
	return mid_block;
}
dog_data::Data dog_cryption::AES::decoding(dog_data::Data& crypt, uint8_t block_size, const dog_data::Data& key, uint8_t key_size)
{
	dog_data::Data tempKey = key.sub_by_pos((key_size * 4) + 96, (key_size * 4) + 112);
	dog_data::Data mid_block = dog_cryption::utils::squareXOR(crypt, tempKey, 16);
	for (int i = 0; i < ((key_size / 4) + 6); i++)
	{
		mid_block = middle_decryption(mid_block, i, key_size << 3);
		tempKey = key.sub_by_pos(16 * ((key_size / 4) + 5 - i), 16 * ((key_size / 4) + 6 - i));//取当前轮密钥
		mid_block = dog_cryption::utils::squareXOR(mid_block, tempKey, 16);//轮密钥加
	}
	return mid_block;
}
void dog_cryption::AES::encoding_self(dog_data::Data& plain, uint8_t block_size, const dog_data::Data& key, uint8_t key_size)
{
	dog_data::Data tempKey = key.sub_by_pos(0, 16);
	plain = dog_cryption::utils::squareXOR(plain, tempKey, 16);
	for (int i = 0; i < ((key_size / 4) + 6); i++)
	{
		plain = AES::middle_encryption(plain, i, key_size << 3);
		tempKey = key.sub_by_pos(16 * (i + 1), 16 * (i + 2));
		plain = dog_cryption::utils::squareXOR(plain, tempKey, 16);
	}
}
void dog_cryption::AES::decoding_self(dog_data::Data& crypt, uint8_t block_size, const dog_data::Data& key, uint8_t key_size)
{
	dog_data::Data tempKey = key.sub_by_pos((key_size * 4) + 96, (key_size * 4) + 112);
	crypt = dog_cryption::utils::squareXOR(crypt, tempKey, 16);
	for (int i = 0; i < ((key_size / 4) + 6); i++)
	{
		crypt = middle_decryption(crypt, i, key_size << 3);
		tempKey = key.sub_by_pos(16 * ((key_size / 4) + 5 - i), 16 * ((key_size / 4) + 6 - i));//取当前轮密钥
		crypt = dog_cryption::utils::squareXOR(crypt, tempKey, 16);//轮密钥加
	}
}

//SM4
uint32_t dog_cryption::SM4::TMixChange1(uint32_t n)
{
	uint32_t res = 0;
	for (int i = 0; i < 4; i++)
	{
		uint8_t bs = (n >> (24 - i * 8)) & 0xff;
		bs = SBox[bs >> 4][(bs & 0x0f)];
		res += (uint32_t)bs << (24 - i * 8);
	}
	return res ^ dog_number::integer::CLMB(res, 13) ^ dog_number::integer::CLMB(res, 23);
}
uint32_t dog_cryption::SM4::TMixChange2(uint32_t n)
{
	uint32_t res = 0;
	for (int i0 = 0; i0 < 4; ++i0)
	{
		uint8_t bs = (n >> (24 - i0 * 8)) & 0xff;
		bs = SBox[bs >> 4][(bs & 0x0f)];
		res += (uint32_t)bs << (24 - i0 * 8);
	}
	uint32_t e = res ^ dog_number::integer::CLMB(res, 2) ^ dog_number::integer::CLMB(res, 10) ^ dog_number::integer::CLMB(res, 18) ^ dog_number::integer::CLMB(res, 24);
	return e;
}
dog_data::Data dog_cryption::SM4::extend_key(dog_data::Data key, uint64_t key_size)
{
	dog_data::Data res; res.reserve(128);
	uint32_t K[36];
	for (uint64_t i = 0; i < 16; i += 4)
	{
		K[i / 4] = (uint32_t)key[i] << 24 | (uint32_t)key[i + 1] << 16 | (uint32_t)key[i + 2] << 8 | (uint32_t)key[i + 3];
		K[i / 4] ^= FK[i / 4];
	}
	for (uint64_t i = 4; i < 36; i++)
	{
		K[i] = K[i - 4] ^ TMixChange1(K[i - 3] ^ K[i - 2] ^ K[i - 1] ^ CK[i - 4]);
		for (int i0 = 0; i0 < 4; i0++)
		{
			res.push_back((uint8_t)(K[i] >> (24 - i0 * 8) & 0xff));
		}
	}
	return res;
}
dog_data::Data dog_cryption::SM4::encoding(dog_data::Data& plain, uint8_t block_size, const dog_data::Data& key, uint8_t key_size)
{
	uint32_t temp[4] = { 0,0,0,0 };
	for (int i = 0; i < 16; i += 4)
	{
		for (int i0 = 0; i0 < 4; i0++)
		{
			temp[i / 4] += (uint32_t)plain[i + i0] << (24 - i0 * 8);
		}
	}
	for (int i = 0; i < 128; i += 4)
	{
		uint32_t tempRK = 0;
		//printf("%d\n", i);
		for (int j = 0; j < 4; j++)
		{
			tempRK += (uint32_t)key[i + j] << (24 - j * 8);
		}
		int n0 = (i / 4) % 4;// 2025/03/07-23:40 int n0 = (i / 4) % 4改成int n0=(i>>2)&0xff 出现i从108跃至-439497484 原因不明
		int n1 = (n0 + 1) % 4;
		int n2 = (n0 + 2) % 4;
		int n3 = (n0 + 3) % 4;
		temp[n0] = temp[n0] ^ TMixChange2(temp[n1] ^ temp[n2] ^ temp[n3] ^ tempRK);// 2025/03/07-23:40 发生上句修改后 此句执行后 出现i从108跃至-439497484 原因不明
	}
	dog_data::Data res; res.reserve(16);
	for (int i = 0; i < 4; i++)
	{
		for (int j = 0; j < 4; j++)
		{
			res.push_back((uint8_t)(temp[3 - i] >> (24 - j * 8) & 0xff));
		}
	}
	return res;
}
dog_data::Data dog_cryption::SM4::decoding(dog_data::Data& crypt, uint8_t block_size, const dog_data::Data& key, uint8_t key_size)
{
	uint32_t temp[4] = { 0,0,0,0 };
	for (int i = 0; i < 16; i += 4)
	{
		for (int i0 = 0; i0 < 4; i0++)
		{
			temp[i / 4] += (uint32_t)crypt[i + i0] << (24 - i0 * 8);
		}
	}
	for (int i = 0; i < 128; i += 4)
	{
		uint32_t tempRK = 0;
		for (int j = 0; j < 4; j++)
		{
			tempRK += (uint32_t)key[124 - i + j] << (24 - j * 8);
		}
		int n0 = (i / 4) % 4;
		int n1 = (n0 + 1) % 4;
		int n2 = (n0 + 2) % 4;
		int n3 = (n0 + 3) % 4;
		temp[n0] = temp[n0] ^ TMixChange2(temp[n1] ^ temp[n2] ^ temp[n3] ^ tempRK);
	}
	dog_data::Data res; res.reserve(16);
	for (int i = 0; i < 4; i++)
	{
		for (int j = 0; j < 4; j++)
		{
			res.push_back((uint8_t)(temp[3 - i] >> (24 - j * 8) & 0xff));
		}
	}
	return res;
}
void dog_cryption::SM4::encoding_self(dog_data::Data& plain, uint8_t block_size, const dog_data::Data& key, uint8_t key_size)
{
	uint32_t temp[4] = { 0,0,0,0 };
	for (int i = 0; i < 16; i += 4)
	{
		for (int i0 = 0; i0 < 4; i0++)
		{
			temp[i / 4] += (uint32_t)plain[i + i0] << (24 - i0 * 8);
		}
	}
	for (int i = 0; i < 128; i += 4)
	{
		uint32_t tempRK = 0;
		//printf("%d\n", i);
		for (int j = 0; j < 4; j++)
		{
			tempRK += (uint32_t)key[i + j] << (24 - j * 8);
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
			plain[i * 4 + j] = (uint8_t)(temp[3 - i] >> (24 - j * 8) & 0xff);
		}
	}
}
void dog_cryption::SM4::decoding_self(dog_data::Data& crypt, uint8_t block_size, const dog_data::Data& key, uint8_t key_size)
{
	uint32_t temp[4] = { 0,0,0,0 };
	for (int i = 0; i < 16; i += 4)
	{
		for (int i0 = 0; i0 < 4; i0++)
		{
			temp[i / 4] += (uint32_t)crypt[i + i0] << (24 - i0 * 8);
		}
	}
	for (int i = 0; i < 128; i += 4)
	{
		uint32_t tempRK = 0;
		for (int j = 0; j < 4; j++)
		{
			tempRK += (uint32_t)key[124 - i + j] << (24 - j * 8);
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
			crypt[i * 4 + j] = (uint8_t)(temp[3 - i] >> (24 - j * 8) & 0xff);
		}
	}
}


//camellia
std::pair<uint64_t, uint64_t> dog_cryption::camellia::CLMB(uint64_t l, uint64_t r, uint64_t i)
{
	i %= 128;
	if (i == 0)
	{
		return std::make_pair(l, r);
	}
	else if (i == 64)
	{
		return std::make_pair(r, l);
	}
	else if (i < 64)
	{
		uint64_t l_ = (l << i) | (r >> (64 - i));
		uint64_t r_ = (r << i) | (l >> (64 - i));
		return std::make_pair(l_, r_);
	}
	else
	{
		return CLMB(r, l, i - 64);
	}
}
uint8_t dog_cryption::camellia::s1(uint8_t n)
{
	return Sbox[n];
}
uint8_t dog_cryption::camellia::s2(uint8_t n)
{
	return ((Sbox[n] << 1) + (Sbox[n] >> 7));
}
uint8_t dog_cryption::camellia::s3(uint8_t n)
{
	return ((Sbox[n] << 7) + (Sbox[n] >> 1));
}
uint8_t dog_cryption::camellia::s4(uint8_t n)
{
	return Sbox[(uint8_t)(((n) << 1) + ((n) >> 7))];
}
uint64_t dog_cryption::camellia::s(uint64_t n)
{
	typedef uint8_t byte;
	byte a1 = (n >> 56) & 0xff;
	byte a2 = (n >> 48) & 0xff;
	byte a3 = (n >> 40) & 0xff;
	byte a4 = (n >> 32) & 0xff;
	byte a5 = (n >> 24) & 0xff;
	byte a6 = (n >> 16) & 0xff;
	byte a7 = (n >> 8) & 0xff;
	byte a8 = n & 0xff;

	byte l1 = s1(a1);
	byte l2 = s2(a2);
	byte l3 = s3(a3);
	byte l4 = s4(a4);
	byte l5 = s2(a5);
	byte l6 = s3(a6);
	byte l7 = s4(a7);
	byte l8 = s1(a8);

	return ((uint64_t)l1 << 56) | ((uint64_t)l2 << 48) | ((uint64_t)l3 << 40) | ((uint64_t)l4 << 32) | ((uint64_t)l5 << 24) | ((uint64_t)l6 << 16) | ((uint64_t)l7 << 8) | ((uint64_t)l8);
}
uint64_t dog_cryption::camellia::p(uint64_t n)
{
	typedef uint8_t byte;

	byte z1 = (n >> 56) & 0xff;
	byte z2 = (n >> 48) & 0xff;
	byte z3 = (n >> 40) & 0xff;
	byte z4 = (n >> 32) & 0xff;
	byte z5 = (n >> 24) & 0xff;
	byte z6 = (n >> 16) & 0xff;
	byte z7 = (n >> 8) & 0xff;
	byte z8 = n & 0xff;

	byte z_1 = z1 ^ z3 ^ z4 ^ z6 ^ z7 ^ z8;
	byte z_2 = z1 ^ z2 ^ z4 ^ z5 ^ z7 ^ z8;
	byte z_3 = z1 ^ z2 ^ z3 ^ z5 ^ z6 ^ z8;
	byte z_4 = z2 ^ z3 ^ z4 ^ z5 ^ z6 ^ z7;
	byte z_5 = z1 ^ z2 ^ z6 ^ z7 ^ z8;
	byte z_6 = z2 ^ z3 ^ z5 ^ z7 ^ z8;
	byte z_7 = z3 ^ z4 ^ z5 ^ z6 ^ z8;
	byte z_8 = z1 ^ z4 ^ z5 ^ z6 ^ z7;

	return (
		(uint64_t)z_1 << 56) | 
		((uint64_t)z_2 << 48) | 
		((uint64_t)z_3 << 40) | 
		((uint64_t)z_4 << 32) | 
		((uint64_t)z_5 << 24) | 
		((uint64_t)z_6 << 16) | 
		((uint64_t)z_7 << 8) | 
		((uint64_t)z_8);
}
uint64_t dog_cryption::camellia::FL(uint64_t x, uint64_t kl)
{
	uint32_t xl = (x >> 32) & 0xffffffff;
	uint32_t xr = x & 0xffffffff;
	uint32_t kll = (kl >> 32) & 0xffffffff;
	uint32_t klr = kl & 0xffffffff;
	uint32_t yr = (dog_number::integer::CLMB(xl & kll, 1)) ^ xr;
	uint32_t yl = (yr | klr) ^ xl;
	//2025.5.22 原语句(uint64_t)yr << 32 | (uint64_t)yl;
	//把yr(y_right放左边),yl(y_left放右边)
	return (uint64_t)yl << 32 | (uint64_t)yr;
}
uint64_t dog_cryption::camellia::FL_inv(uint64_t y, uint64_t kl)
{
	uint32_t yl = (y >> 32) & 0xffffffff;
	uint32_t yr = y & 0xffffffff;
	uint32_t kll = (kl >> 32) & 0xffffffff;
	uint32_t klr = kl & 0xffffffff;
	uint32_t xl = (yr | klr) ^ yl;
	uint32_t xr = (dog_number::integer::CLMB(xl & kll, 1)) ^ yr;
	//2025.5.22 (uint64_t)xr << 32 | (uint64_t)xl
	//把xr(x_right放左边),xl(x_left放右边)
	return (uint64_t)xl << 32 | (uint64_t)xr;
}
uint64_t dog_cryption::camellia::F(uint64_t x, uint64_t k)
{
	return p(s(x ^ k));
}
dog_data::Data dog_cryption::camellia::extend_key(dog_data::Data key, uint64_t key_size)
{
	dog_data::Data res;
	if (key.size() < 16)
	{
		throw CryptionException(std::format("key is to short need {} now {}", 16, key.size()).c_str(), __FILE__, __FUNCTION__, __LINE__);
	}
	uint64_t kll = 0, klr = 0, krl = 0, krr = 0;
	for (uint64_t i = 0; i < 8; i++)
	{
		kll |= ((uint64_t)key[i]) << (56 - i * 8);
		klr |= ((uint64_t)key[i + 8]) << (56 - i * 8);
	}
	uint64_t kal = kll, kar = klr;
	if (key_size == 24)
	{
		if (key.size() < 24)
		{
			throw CryptionException(std::format("key is to short need 24 now {}", key.size()).c_str(), __FILE__, __FUNCTION__, __LINE__);
		}
		for (uint64_t i = 0; i < 8; i++)
		{
			krl |= (uint64_t)(key[i + 16]) << (56 - i * 8);
			krr |=  ((0xFFUi64) << (56 - i * 8)) & (uint64_t)(~key[i + 16]) << (56 - i * 8);
		}
	}
	else if (key_size == 32)
	{
		if (key.size() < 32)
		{
			throw CryptionException(std::format("key is to short need 32 now {}", key.size()).c_str(), __FILE__, __FUNCTION__, __LINE__);
		}
		for (uint64_t i = 0; i < 8; i++)
		{
			krl |= ((uint64_t)key[i + 16]) << (56 - i * 8);
			krr |= ((uint64_t)key[i + 24]) << (56 - i * 8);
		}
	}
	else if(key_size != 16)
	{
		throw CryptionException("key size is not 16, 24 or 32", __FILE__, __FUNCTION__, __LINE__);
	}
	auto add_uint64 = [&res](uint64_t n) -> void
		{
			for (uint64_t i = 0; i < 8; i++)
			{
				res.push_back((n >> (56 - i * 8)) & 0xff);
			}
		};

	kal ^= krl; kar ^= krr;
	kar ^= F(sigma[0], kal);
	std::swap(kal, kar);
	kar ^= F(sigma[1], kal);
	std::swap(kal, kar);

	kal ^= kll; kar ^= klr;
	kar ^= F(sigma[2], kal);
	std::swap(kal, kar);
	kar ^= F(sigma[3], kal);
	std::swap(kal, kar);

	uint64_t shift[8] = { 0,15,30,45,60,77,94,111 };
	if (key_size == 16)
	{
		res.reserve(208);
		for (uint64_t i = 0; i < 8; i++)
		{
			auto kl_ = dog_cryption::camellia::CLMB(kll, klr, shift[i]);
			auto ka_ = dog_cryption::camellia::CLMB(kal, kar, shift[i]);
			switch (shift[i])
			{
			case 0:
			{
				add_uint64(kl_.first);//kw1
				add_uint64(kl_.second);//kw2
				add_uint64(ka_.first);//k1
				add_uint64(ka_.second);//k2
				break;
			}
			case 15:
			{
				add_uint64(kl_.first);//k3
				add_uint64(kl_.second);//k4
				add_uint64(ka_.first);//k5
				add_uint64(ka_.second);//k6
				break;
			}
			case 30:
			{
				add_uint64(ka_.first);//kl1
				add_uint64(ka_.second);//kl2
				break;
			}
			case 45:
			{
				add_uint64(kl_.first);//k7
				add_uint64(kl_.second);//k8
				add_uint64(ka_.first);//k9
				break;
			}
			case 60:
			{
				add_uint64(kl_.second);//k10
				add_uint64(ka_.first);//k11
				add_uint64(ka_.second);//k12
				break;
			}
			case 77:
			{
				add_uint64(kl_.first);//kl3
				add_uint64(kl_.second);//kl4
				break;
			}
			case 94:
			{
				add_uint64(kl_.first);//k13
				add_uint64(kl_.second);//k14
				add_uint64(ka_.first);//k15
				add_uint64(ka_.second);//k16
				break;
			}
			case 111:
			{
				add_uint64(kl_.first);//k17
				add_uint64(kl_.second);//k18
				add_uint64(ka_.first);//kw3
				add_uint64(ka_.second);//kw4
				break;
			}
			}
		}
		return res;
	}
	else if (key_size != 16)
	{
		
		uint64_t kbl = kal, kbr = kar;
		kbl ^= krl; kbr ^= krr;
		kbr ^= F(sigma[4], kbl);
		std::swap(kbl, kbr);
		kbr ^= F(sigma[5], kbl);
		std::swap(kbl, kbr);
		for (uint64_t i = 0; i < 8; i++)
		{
			auto kl_ = dog_cryption::camellia::CLMB(kll, klr, shift[i]);
			auto kr_ = dog_cryption::camellia::CLMB(krl, krr, shift[i]);
			auto ka_ = dog_cryption::camellia::CLMB(kal, kar, shift[i]);
			auto kb_ = dog_cryption::camellia::CLMB(kbl, kbr, shift[i]);
			switch (shift[i])
			{
			case 0:
			{
				add_uint64(kl_.first);//kw1
				add_uint64(kl_.second);//kw2
				add_uint64(kb_.first);//k1
				add_uint64(kb_.second);//k2
				break;
			}
			case 15:
			{
				add_uint64(kr_.first);//k3
                add_uint64(kr_.second);//k4
				add_uint64(ka_.first);//k5
				add_uint64(ka_.second);//k6
				break;
			}
			case 30:
			{
				add_uint64(kr_.first);//kl1
				add_uint64(kr_.second);//kl2
				add_uint64(kb_.first);//k7
				add_uint64(kb_.second);//k8
				break;
			}
			case 45:
			{
				add_uint64(kl_.first);//k9
				add_uint64(kl_.second);//k10
				add_uint64(ka_.first);//k11
				add_uint64(ka_.second);//k12

				break;
			}
			case 60:
			{
				add_uint64(kl_.first);//kl3
				add_uint64(kl_.second);//kl4
				add_uint64(kr_.first);//k13
				add_uint64(kr_.second);//k14
				add_uint64(kb_.first);//k15
				add_uint64(kb_.second);//k16
				break;
			}
			case 77:
			{
				add_uint64(kl_.first);//k17
				add_uint64(kl_.second);//k18
				add_uint64(ka_.first);//kl5
				add_uint64(ka_.second);//kl6
				break;
			}
			case 94:
			{
				add_uint64(kr_.first);//k19
				add_uint64(kr_.second);//k20
				add_uint64(ka_.first);//k21
				add_uint64(ka_.second);//k22
				break;
			}
			case 111:
			{
				add_uint64(kl_.first);//k23
                add_uint64(kl_.second);//k24
				add_uint64(kb_.first);//kw3
				add_uint64(kb_.second);//kw4
				break;
			}
			}
		}
		return res;
	}

	
}
dog_data::Data dog_cryption::camellia::encoding(dog_data::Data& plain, uint8_t block_size, const dog_data::Data& key, uint8_t key_size)
{
	auto take_uint64 = [](const dog_data::Data& data, uint64_t pos) -> uint64_t
		{
			uint64_t res = 0;
			for (uint64_t i = 0; i < 8; i++)
			{
				res |= (uint64_t)(data[pos + i]) << (56 - 8 * i);
			}
			return res;
		};
	uint64_t pl = take_uint64(plain, 0), pr = take_uint64(plain, 8);
	uint64_t pos = 16;
	auto round = [&take_uint64, &key, &pos, &pl, &pr]()->void
		{
			for (uint64_t i = 0; i < 6; i++)
			{
				uint64_t kn = take_uint64(key, pos);
				pos += 8;
				pr ^= F(kn, pl);
				std::swap(pl, pr);
			}
		};
	//std::println("{:0>16x} {:0>16x}", pl, pr);

	uint64_t kw1 = take_uint64(key, 0), kw2 = take_uint64(key, 8);
	pl ^= kw1, pr ^= kw2;
	//16-2 24/32-3
	for (uint64_t j = 0; j < 2; j++)
	{
		round();
		uint64_t kl_1 = take_uint64(key, pos), kl_2 = take_uint64(key, pos + 8);
		pos += 16;
		pl = FL(pl, kl_1); pr = FL_inv(pr, kl_2);
	}
	if(key_size != 16)
	{
		round();
		uint64_t kl_1 = take_uint64(key, pos), kl_2 = take_uint64(key, pos + 8);
		pos += 16;
		pl = FL(pl, kl_1); pr = FL_inv(pr, kl_2);
	}
	round();
	std::swap(pl, pr);
	uint64_t kw3 = take_uint64(key, pos), kw4 = take_uint64(key, pos + 8);
	pl ^= kw3, pr ^= kw4;
	//std::println("{:0>16x} {:0>16x}", pl, pr);
	dog_data::Data crypt(16);
	for (uint64_t i = 0; i < 8; i++)
	{
		crypt[i] = pl >> (56 - 8 * i) & 0xff;
		crypt[i + 8] = pr >> (56 - 8 * i) & 0xff;
	}
	return crypt;

}
dog_data::Data dog_cryption::camellia::decoding(dog_data::Data& crypt, uint8_t block_size, const dog_data::Data& key, uint8_t key_size)
{
	auto take_uint64 = [](const dog_data::Data& data, uint64_t pos) -> uint64_t
		{
			uint64_t res = 0;
			for (uint64_t i = 0; i < 8; i++)
			{
				res |= (uint64_t)(data[pos + i]) << (56 - 8 * i);
			}
			return res;
		};
	uint64_t cr = take_uint64(crypt, 0), cl = take_uint64(crypt, 8);
	uint64_t pos = key_size == 16 ? 200 : 264;
	uint64_t kw4 = take_uint64(key, pos), kw3 = take_uint64(key, pos - 8);
	pos -= 16;
	cl ^= kw4, cr ^= kw3;
	auto round = [&take_uint64, &key, &pos, &cl, &cr]()->void
		{
			for (uint64_t i = 0; i < 6; i++)
			{
				uint64_t kn = take_uint64(key, pos);
				pos -= 8;
				cl ^= F(kn, cr);
				std::swap(cl, cr);
			}
		};
	for (int j = 0; j < 2; j++)
	{
		round();
		uint64_t kl_1 = take_uint64(key, pos), kl_2 = take_uint64(key, pos - 8);
		pos -= 16;
		cr = FL(cr, kl_1); cl = FL_inv(cl, kl_2);
	}
	if (key_size != 16)
	{
		round();
		uint64_t kl_1 = take_uint64(key, pos), kl_2 = take_uint64(key, pos - 8);
		pos -= 16;
		cr = FL(cr, kl_1); cl = FL_inv(cl, kl_2);
	}
	round();
	std::swap(cl, cr);
	uint64_t kw1 = take_uint64(key, 0), kw2 = take_uint64(key, 8);
	cr ^= kw1, cl ^= kw2;
	//std::println("{:0>16x} {:0>16x}", cr, cl);
	dog_data::Data plain(16);
	for (uint64_t i = 0; i < 8; i++)
	{
		plain[i] = cr >> (56 - 8 * i) & 0xff;
		plain[i + 8] = cl >> (56 - 8 * i) & 0xff;
	}
	return plain;
}
void dog_cryption::camellia::encoding_self(dog_data::Data& plain, uint8_t block_size, const dog_data::Data& key, uint8_t key_size)
{
	auto take_uint64 = [](const dog_data::Data& data, uint64_t pos) -> uint64_t
		{
			uint64_t res = 0;
			for (uint64_t i = 0; i < 8; i++)
			{
				res |= (uint64_t)(data[pos + i]) << (56 - 8 * i);
			}
			return res;
		};
	uint64_t pl = take_uint64(plain, 0), pr = take_uint64(plain, 8);
	uint64_t pos = 16;
	auto round = [&take_uint64, &key, &pos, &pl, &pr]()->void
		{
			for (uint64_t i = 0; i < 6; i++)
			{
				uint64_t kn = take_uint64(key, pos);
				pos += 8;
				pr ^= F(kn, pl);
				std::swap(pl, pr);
			}
		};
	//std::println("{:0>16x} {:0>16x}", pl, pr);

	uint64_t kw1 = take_uint64(key, 0), kw2 = take_uint64(key, 8);
	pl ^= kw1, pr ^= kw2;
	//16-2 24/32-3
	for (uint64_t j = 0; j < 2; j++)
	{
		round();
		uint64_t kl_1 = take_uint64(key, pos), kl_2 = take_uint64(key, pos + 8);
		pos += 16;
		pl = FL(pl, kl_1); pr = FL_inv(pr, kl_2);
	}
	if (key_size != 16)
	{
		round();
		uint64_t kl_1 = take_uint64(key, pos), kl_2 = take_uint64(key, pos + 8);
		pos += 16;
		pl = FL(pl, kl_1); pr = FL_inv(pr, kl_2);
	}
	round();
	std::swap(pl, pr);
	uint64_t kw3 = take_uint64(key, pos), kw4 = take_uint64(key, pos + 8);
	pl ^= kw3, pr ^= kw4;
	//std::println("{:0>16x} {:0>16x}", pl, pr);
	for (uint64_t i = 0; i < 8; i++)
	{
		plain[i] = pl >> (56 - 8 * i) & 0xff;
		plain[i + 8] = pr >> (56 - 8 * i) & 0xff;
	}
}
void dog_cryption::camellia::decoding_self(dog_data::Data& crypt, uint8_t block_size, const dog_data::Data& key, uint8_t key_size)
{
	auto take_uint64 = [](const dog_data::Data& data, uint64_t pos) -> uint64_t
		{
			uint64_t res = 0;
			for (uint64_t i = 0; i < 8; i++)
			{
				res |= (uint64_t)(data[pos + i]) << (56 - 8 * i);
			}
			return res;
		};
	uint64_t cr = take_uint64(crypt, 0), cl = take_uint64(crypt, 8);
	uint64_t pos = key_size == 16 ? 200 : 264;
	uint64_t kw4 = take_uint64(key, pos), kw3 = take_uint64(key, pos - 8);
	pos -= 16;
	cl ^= kw4, cr ^= kw3;
	auto round = [&take_uint64, &key, &pos, &cl, &cr]()->void
		{
			for (uint64_t i = 0; i < 6; i++)
			{
				uint64_t kn = take_uint64(key, pos);
				pos -= 8;
				cl ^= F(kn, cr);
				std::swap(cl, cr);
			}
		};
	for (int j = 0; j < 2; j++)
	{
		round();
		uint64_t kl_1 = take_uint64(key, pos), kl_2 = take_uint64(key, pos - 8);
		pos -= 16;
		cr = FL(cr, kl_1); cl = FL_inv(cl, kl_2);
	}
	if (key_size != 16)
	{
		round();
		uint64_t kl_1 = take_uint64(key, pos), kl_2 = take_uint64(key, pos - 8);
		pos -= 16;
		cr = FL(cr, kl_1); cl = FL_inv(cl, kl_2);
	}
	round();
	std::swap(cl, cr);
	uint64_t kw1 = take_uint64(key, 0), kw2 = take_uint64(key, 8);
	cr ^= kw1, cl ^= kw2;
	//std::println("{:0>16x} {:0>16x}", cr, cl);
	for (uint64_t i = 0; i < 8; i++)
	{
		crypt[i] = cr >> (56 - 8 * i) & 0xff;
		crypt[i + 8] = cl >> (56 - 8 * i) & 0xff;
	}
}
