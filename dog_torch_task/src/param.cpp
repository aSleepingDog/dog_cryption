#include "../include/task/param.h"

dog_param::IOConfig::IOConfig(std::unordered_map<std::string, std::any> params, bool is_input)
{
#define DOG_WRONG_TYPE_EXCEPTION(key,right,wrong) DOG_EXCEPTION(std::format("{}类型错误 需要{} 当前{}",key,right.name(),wrong.name()))
#define IOConfig_CHECK_TYPE_AND_FILL(key,type_name) if(params.find(key) == params.end()) \
{\
throw DOG_EXCEPTION(std::format("IOConfig缺少参数{}",key));\
}\
if(params[key].type() != typeid(type_name)) \
{\
throw DOG_WRONG_TYPE_EXCEPTION(key, params[key].type(), typeid(type_name));\
}\
this->params_[key] = params[key];

	this->is_input_ = is_input;
	std::string ori_str = "";
	IOConfig_CHECK_TYPE_AND_FILL("is_file", bool);
	if (std::any_cast<bool>(this->params_["is_file"]) || is_input)
	{
		IOConfig_CHECK_TYPE_AND_FILL("ori_str", std::string);
        ori_str = std::any_cast<std::string>(this->params_["ori_str"]);
		if (std::any_cast<bool>(this->params_["is_file"])) { return; }
	}
	if (params.find("type") == params.end())
	{
		throw DOG_EXCEPTION("IOConfig缺少参数type type必须是utf8/base64[][][]/hex Hex");
	}
	if (params["type"].type() != typeid(uint64_t))
	{
		throw DOG_EXCEPTION(std::format("{}类型错误 需要{} 当前{}", "type", params["type"].type().name(), typeid(uint64_t).name()));
	}
	this->params_["type"] = params["type"];

	if (std::any_cast<uint64_t>(this->params_["type"]) > 2)
	{
		throw DOG_EXCEPTION(std::format("type必须是utf8/base64[][][]/hex Hex 当前{}",std::any_cast<uint64_t>(this->params_["type"])));
	}
	else if (std::any_cast<uint64_t>(this->params_["type"]) == 2)
	{
		IOConfig_CHECK_TYPE_AND_FILL("is_upper", bool);
		if (is_input)
		{
			for (uint64_t i = 0; i < ori_str.size(); ++i)
			{
				char c = ori_str[i];
				if ((c < '0' || c > '9') && (c < 'A' || c>'F') && (c < 'a' || c>'f'))
				{
					throw DOG_EXCEPTION(std::format("Hex16进制字符串中只能包含0123456789ABCDEFabcdef 错误出现在{}",
						ori_str.substr(i < 2 ? 0 : i - 2, 5)
					));
				}
			}
		}
	}
	else if (std::any_cast<uint64_t>(this->params_["type"]) == 1)
	{
		IOConfig_CHECK_TYPE_AND_FILL("replace0", char);
		IOConfig_CHECK_TYPE_AND_FILL("replace1", char);
		IOConfig_CHECK_TYPE_AND_FILL("replace2", char);
		char replace0 = std::any_cast<char>(this->params_["replace0"]);
		char replace1 = std::any_cast<char>(this->params_["replace1"]);
		char replace2 = std::any_cast<char>(this->params_["replace2"]);
		char allow_list[34] = " !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";
		bool is_replace0_in = false;
		bool is_replace1_in = false;
		bool is_replace2_in = false;
		for (uint64_t i = 0; i < 33; ++i)
		{
			if (allow_list[i] == replace0)
			{
				is_replace0_in = true;
			}
			if (allow_list[i] == replace1)
			{
				is_replace1_in = true;
			}
			if (allow_list[i] == replace2)
			{
				is_replace2_in = true;
			}
		}
		if (!is_replace0_in)
		{
			std::string msg = "base64的替换字符必须是 !\"#$%&'()*+,-./:;<=>?@[\\]^_`|}{~ 中的一个 当前";
			msg + replace0;
			throw DOG_EXCEPTION(msg);
		}
		if (!is_replace1_in)
		{
			std::string msg = "base64的替换字符必须是 !\"#$%&'()*+,-./:;<=>?@[\\]^_`|}{~ 中的一个 当前";
			msg + replace1;
			throw DOG_EXCEPTION(msg);
		}
		if (!is_replace2_in)
		{
			std::string msg = "base64的替换字符必须是 !\"#$%&'()*+,-./:;<=>?@[\\]^_`|}{~ 中的一个 当前";
			msg + replace2;
			throw DOG_EXCEPTION(msg);
		}
		if (replace0 == replace1 || replace0 == replace2 || replace1 == replace2)
		{
			throw DOG_EXCEPTION("base64的替换字符两两不能相同");
		}
		if (is_input)
		{
			for (uint64_t i = 0; i < ori_str.size(); ++i)
			{
				if ((ori_str[i] < '0' || ori_str[i] > '9') &&
					(ori_str[i] < 'A' || ori_str[i] > 'Z') &&
					(ori_str[i] < 'a' || ori_str[i] > 'z') &&
					(ori_str[i] != replace0) && (ori_str[i] != replace1) && (ori_str[i] != replace2)
					)
				{
					throw DOG_EXCEPTION(std::format("base64{}{}{}进制字符串中只能包含0123456789ABCDEFabcdef 错误出现在{}",
						replace0, replace1, replace2, ori_str.substr(i - 2, 5)
					));
				}
			}
		}
	}
#undef IOConfig_CHECK_TYPE_AND_FILL
#undef DOG_WRONG_TYPE_EXCEPTION
}
dog_param::IOConfig::IOConfig(dog_torch::serialize::json::Object json, bool is_input)
{
	auto check = [&json,this](std::string key, dog_torch::serialize::json::Type type)->void
		{
			if (json.find(key) == json.end())
			{
                throw DOG_EXCEPTION(std::format("IOConfig缺少{}字段", key));
			}
			if (json[key].get_type() != type)
			{
				std::string right = dog_torch::serialize::json::to_string(type);
				std::string wrong = dog_torch::serialize::json::to_string(json[key].get_type());
                throw DOG_EXCEPTION(std::format("{}类型错误 需要{} 当前{}", key, right, wrong));
			}
			switch (type)
			{
				case dog_torch::serialize::json::Type::null:
				{
					this->params_[key] = nullptr;
					break;
				}
				case dog_torch::serialize::json::Type::boolean:
				{
					this->params_[key] = json[key].to_bool();
					break;
				}
				case dog_torch::serialize::json::Type::number:
				{
					double n = json[key].to_number();
					if (n - (uint64_t)n == 0)
					{
						this->params_[key] = (uint64_t)n;
					}
					else
					{
						this->params_[key] = n;
					}
					break;
				}
				case dog_torch::serialize::json::Type::string:
				{
					this->params_[key] = json[key].to_string();
					break;
				}
				case dog_torch::serialize::json::Type::array:
				{
					this->params_[key] = json[key].to_array();
					break;
				}
				case dog_torch::serialize::json::Type::object:
				{
					this->params_[key] = json[key].to_object();
					break;
				}
			};
		};
	this->is_input_ = is_input;
	check("is_file", dog_torch::serialize::json::Type::boolean);
	std::string ori_str = "";
	if (std::any_cast<bool>(this->params_["is_file"]) || is_input)
	{
		check("ori_str", dog_torch::serialize::json::Type::string);
		ori_str = std::any_cast<std::string>(this->params_["ori_str"]);
		if (std::any_cast<bool>(this->params_["is_file"])) { return; }
	}
	//check("type", dog_torch::serialize::json::Type::number);
	if (json.find("type") == json.end())
	{
		throw DOG_EXCEPTION("IOConfig缺少参数type type必须是utf8/base64[][][]/hex Hex");
	}
	if (json["type"].get_type() != dog_torch::serialize::json::Type::number)
	{
		std::string right = dog_torch::serialize::json::to_string(dog_torch::serialize::json::Type::number);
		std::string wrong = dog_torch::serialize::json::to_string(json["type"].get_type());
		throw DOG_EXCEPTION(std::format("type类型错误 需要{} 当前{}", right, wrong));
	}
	double n = json["type"].to_number();
	if (n - (uint64_t)n == 0)
	{
		this->params_["type"] = (uint64_t)n;
	}
	else
	{
		this->params_["type"] = n;
	}
	if (std::any_cast<uint64_t>(this->params_["type"]) > 2)
	{
		throw DOG_EXCEPTION(std::format("type必须是utf8/base64[][][]/hex Hex 当前{}", std::any_cast<uint64_t>(this->params_["type"])));
	}
	else if (std::any_cast<uint64_t>(this->params_["type"]) == 2)
	{
		check("is_upper", dog_torch::serialize::json::Type::boolean);
		if (is_input)
		{
			for (uint64_t i = 0; i < ori_str.size(); ++i)
			{
				char c = ori_str[i];
				if ((c < '0' || c > '9') && (c < 'A' || c>'F') && (c < 'a' || c>'f'))
				{
					throw DOG_EXCEPTION(std::format("Hex16进制字符串中只能包含0123456789ABCDEFabcdef 错误出现在{}",
						ori_str.substr(i - 2, 5)
					));
				}
			}
		}
	}
	else if (std::any_cast<uint64_t>(this->params_["type"]) == 1)
	{
		check("replace0", dog_torch::serialize::json::Type::string);
		this->params_["replace0"] = std::any_cast<std::string>(this->params_["replace0"])[0];
		check("replace1", dog_torch::serialize::json::Type::string);
		this->params_["replace1"] = std::any_cast<std::string>(this->params_["replace1"])[0];
		check("replace2", dog_torch::serialize::json::Type::string);
		this->params_["replace2"] = std::any_cast<std::string>(this->params_["replace2"])[0];
		char replace0 = std::any_cast<char>(this->params_["replace0"]);
		char replace1 = std::any_cast<char>(this->params_["replace1"]);
		char replace2 = std::any_cast<char>(this->params_["replace2"]);
		char allow_list[34] = " !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";
		bool is_replace0_in = false;
		bool is_replace1_in = false;
		bool is_replace2_in = false;
		for (uint64_t i = 0; i < 33; ++i)
		{
			if (allow_list[i] == replace0)
			{
				is_replace0_in = true;
			}
			if (allow_list[i] == replace1)
			{
				is_replace1_in = true;
			}
			if (allow_list[i] == replace2)
			{
				is_replace2_in = true;
			}
		}
		if (!is_replace0_in)
		{
			std::string msg = "base64的替换字符必须是 !\"#$%&'()*+,-./:;<=>?@[\\]^_`|}{~ 中的一个 当前";
			msg + replace0;
			throw DOG_EXCEPTION(msg);
		}
		if (!is_replace1_in)
		{
			std::string msg = "base64的替换字符必须是 !\"#$%&'()*+,-./:;<=>?@[\\]^_`|}{~ 中的一个 当前";
			msg + replace1;
			throw DOG_EXCEPTION(msg);
		}
		if (!is_replace2_in)
		{
			std::string msg = "base64的替换字符必须是 !\"#$%&'()*+,-./:;<=>?@[\\]^_`|}{~ 中的一个 当前";
			msg + replace2;
			throw DOG_EXCEPTION(msg);
		}
		if (replace0 == replace1 || replace0 == replace2 || replace1 == replace2)
		{
			throw DOG_EXCEPTION("base64的替换字符两两不能相同");
		}
		if (is_input)
		{
			for (uint64_t i = 0; i < ori_str.size(); ++i)
			{
				if ((ori_str[i] < '0' || ori_str[i] > '9') &&
					(ori_str[i] < 'A' || ori_str[i] > 'Z') &&
					(ori_str[i] < 'a' || ori_str[i] > 'z') &&
					(ori_str[i] != replace0) && (ori_str[i] != replace1) && (ori_str[i] != replace2)
					)
				{
					throw DOG_EXCEPTION(std::format("base64{}{}{}进制字符串中只能包含0123456789ABCDEFabcdef 错误出现在{}",
						replace0, replace1, replace2, ori_str.substr(i - 2, 5)
					));
				}
			}
		}
	}
}
bool dog_param::IOConfig::is_file()
{
	if (this->params_.find("is_file") == this->params_.end())
	{
		return false;
	}
	return std::any_cast<bool>(this->params_["is_file"]);
}
bool dog_param::IOConfig::is_data()
{
	if (this->params_.find("is_file") == this->params_.end())
	{
		return true;
	}
	return !std::any_cast<bool>(this->params_["is_file"]);
}
uint64_t dog_param::IOConfig::get_data_type()
{
	if (std::any_cast<bool>(this->params_["is_file"]))
	{
		throw DOG_EXCEPTION("该IOConfig是文件类型，没有data_type");
	}
	return std::any_cast<uint64_t>(this->params_["type"]);
}
std::string dog_param::IOConfig::get_IO_string()
{
	if (std::any_cast<bool>(this->params_["is_file"]))
	{
		return std::string("文件");
	}
	switch (std::any_cast<uint64_t>(this->params_["type"]))
	{
	case 0: { return std::string("UTF-8"); }
	case 1: 
	{
		return std::format("Base64{}{}{}", get_replace0(), get_replace1(), get_replace2());
	}
	case 2: 
	{
		if (get_is_upper())
		{
			return std::string("Hex16大写");
		}
		else
		{
			return std::string("Hex16小写");
		}
	}
	}
}
char dog_param::IOConfig::get_replace0()
{
	if (is_file())
	{
		throw DOG_EXCEPTION("该IOConfig是文件类型，没有replace0");
	}
	if (get_data_type() != 1)
	{
		throw DOG_EXCEPTION("该IOConfig不是base64类型，没有replace0");
	}
	return std::any_cast<char>(this->params_["replace0"]);
}
char dog_param::IOConfig::get_replace1()
{
	if (is_file())
	{
		throw DOG_EXCEPTION("该IOConfig是文件类型，没有replace1");
	}
	if (get_data_type() != 1)
	{
		throw DOG_EXCEPTION("该IOConfig不是base64类型，没有replace1");
	}
	return std::any_cast<char>(this->params_["replace1"]);
}
char dog_param::IOConfig::get_replace2()
{
	if (is_file())
	{
		throw DOG_EXCEPTION("该IOConfig是文件类型，没有replace2");
	}
	if (get_data_type() != 1)
	{
		throw DOG_EXCEPTION("该IOConfig不是base64类型，没有replace2");
	}
	return std::any_cast<char>(this->params_["replace2"]);
}
bool dog_param::IOConfig::get_is_upper()
{
	if (is_file())
	{
		throw DOG_EXCEPTION("该IOConfig是文件类型，没有is_upper");
	}
	if (get_data_type() != 2)
	{
		throw DOG_EXCEPTION("该IOConfig不是hex类型，没有is_upper");
	}
	return std::any_cast<bool>(this->params_["is_upper"]);
}
dog_torch::serialize::Data dog_param::IOConfig::get_data()
{
	if (is_file())
	{
		throw DOG_EXCEPTION("该IOConfig是文件类型，没有data");
	}
	return dog_torch::serialize::Data
	(
		std::any_cast<std::string>(this->params_["ori_str"]),
        std::any_cast<uint64_t>(this->params_["type"])
	);
}
std::string dog_param::IOConfig::get_file_path()
{
	if (is_data())
	{
		throw DOG_EXCEPTION("该IOConfig是数据类型，没有file_path");
	}
	return std::any_cast<std::string>(this->params_["ori_str"]);
}
std::string dog_param::IOConfig::fmt_data(dog_torch::serialize::Data data)
{
	if (this->is_file())
	{
		throw DOG_EXCEPTION("该IOConfig是文件类型，无法格式化data");
	}
	switch (this->get_data_type())
	{
	case 0:
	{
		return data.to_utf8_string();
	}
	case 1:
	{
		return data.to_base64_string(this->get_replace0(), this->get_replace1(), this->get_replace2());
	}
	case 2:
	{
		return data.to_hex_string(this->get_is_upper());
	}
	}
}
std::string dog_param::IOConfig::get_ori_str()
{
	if (!this->is_input_)
	{
		throw DOG_EXCEPTION("该IOConfig是输出类型，没有ori_str");
	}
	return std::any_cast<std::string>(this->params_["ori_str"]);
}