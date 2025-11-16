#pragma once

#include <unordered_map>

#include "oatpp/core/macro/codegen.hpp"
#include "oatpp/core/Types.hpp"
#include "oatpp/core/utils/ConversionUtils.hpp"
#include "task/param.h"

#include OATPP_CODEGEN_BEGIN(DTO)

class IOParam : public oatpp::DTO
{
private:
	DTO_INIT(IOParam, DTO);

	DTO_FIELD_INFO(ori_str)
	{
		info->description = "原始字符串";
		info->required = true;
	}
	DTO_FIELD(oatpp::String, ori_str) = "Hello Cryptography";

	DTO_FIELD_INFO(is_file)
	{
		info->description = "是否是文件";
		info->required = true;
	}
	DTO_FIELD(oatpp::Boolean, is_file) = false;

	DTO_FIELD_INFO(type)
	{
		info->description = "字符串类型 0-UTF8 1-Base64 2-Hex";
	}
	DTO_FIELD(oatpp::UInt64, type) = (v_int64)(0);
	
	DTO_FIELD_INFO(replace0)
	{
		info->description = "Base64中+替换字符 Base64模式下必传";
	}
	DTO_FIELD(oatpp::String, replace0) = "+";

	DTO_FIELD_INFO(replace1)
	{
		info->description = "Base64中/替换字符 Base64模式下必传";
	}
	DTO_FIELD(oatpp::String, replace1) = "/";

	DTO_FIELD_INFO(replace2)
	{
		info->description = "Base64中=替换字符 Base64模式下必传";
	}
	DTO_FIELD(oatpp::String, replace2) = "=";

	DTO_FIELD_INFO(is_upper)
	{
		info->description = "输出Hex中 字母是否大写";
	}
	DTO_FIELD(oatpp::Boolean, is_upper) = true;

public:
	dog_param::IOConfig to_IOConfig(bool is_input);
};


#include OATPP_CODEGEN_END(DTO)