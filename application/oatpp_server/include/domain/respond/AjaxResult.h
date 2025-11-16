#pragma once

#include "oatpp/core/macro/codegen.hpp"
#include "oatpp/core/Types.hpp"

#include OATPP_CODEGEN_BEGIN(DTO)

//使用oatpp::之外的其他DTO类需要用oatpp::Object<>来包裹
template <typename T>
class AjaxResult : public oatpp::DTO 
{
	DTO_INIT(AjaxResult, DTO);

	DTO_FIELD_INFO(code)
	{
		info->required = true;
		info->description = "状态码";
	}
	DTO_FIELD(Int64, code) = 200;
	
	DTO_FIELD_INFO(msg)
	{
		info->required = true;
		info->description = "处理消息";
	}
	DTO_FIELD(String, msg);
	
	DTO_FIELD_INFO(time)
	{
		info->required = true;
		info->description = "处理时间 单位:毫秒 ms";
	}
	DTO_FIELD(Float64, time);

	DTO_FIELD_INFO(data)
	{
		info->required = true;
		info->description = "返回数据 视具体业务而定";
	}
	DTO_FIELD(T, data);
};

#include OATPP_CODEGEN_END(DTO)
