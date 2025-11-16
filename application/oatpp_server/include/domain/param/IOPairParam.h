#pragma once

#include <unordered_map>

#include "oatpp/core/macro/codegen.hpp"
#include "oatpp/core/Types.hpp"
#include "oatpp/core/utils/ConversionUtils.hpp"
#include "task/param.h"

#include "IOParam.h"

#include OATPP_CODEGEN_BEGIN(DTO)

class IOPairParam : public oatpp::DTO
{
private:
	DTO_INIT(IOPairParam, DTO);

	DTO_FIELD_INFO(input)
	{
		info->description = "输入参数组";
		info->required = true;
	}
	DTO_FIELD(oatpp::Object<IOParam>, input);

	DTO_FIELD_INFO(output)
	{
		info->description = "输出参数组";
		info->required = true;
	}
	DTO_FIELD(oatpp::Object<IOParam>, output);

public:
	IOParam get_input();
    IOParam get_output();
};


#include OATPP_CODEGEN_END(DTO)