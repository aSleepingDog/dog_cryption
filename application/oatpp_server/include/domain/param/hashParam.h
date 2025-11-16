#pragma once
#include "oatpp/core/macro/codegen.hpp"
#include "oatpp/core/Types.hpp"
#include "oatpp/core/utils/ConversionUtils.hpp"

#include OATPP_CODEGEN_BEGIN(DTO)


class HashParam : public oatpp::DTO
{
	DTO_INIT(HashParam, DTO);

	DTO_FIELD_INFO(type)
	{
		info->description = "散列函数类型";
		info->required = true;
	}
	DTO_FIELD(oatpp::String, type) = "SHA2";

	DTO_FIELD_INFO(effective)
	{
		info->description = "散列函数规格";
		info->required = true;
	}
	DTO_FIELD(oatpp::UInt64, effective) = (v_int64)(256);

};

#include OATPP_CODEGEN_END(DTO)