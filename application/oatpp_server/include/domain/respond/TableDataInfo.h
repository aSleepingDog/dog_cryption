#pragma once

#include "oatpp/core/macro/codegen.hpp"
#include "oatpp/core/Types.hpp"

#include OATPP_CODEGEN_BEGIN(DTO)

template<typename T>
class TableDataInfo : public oatpp::DTO {
  
  DTO_INIT(TableDataInfo, DTO)
  
  DTO_FIELD(Int64, code);
  DTO_FIELD(String, msg);
  DTO_FIELD(Int64, count);
  DTO_FIELD(oatpp::Vector<T>, data);
  
};

#include OATPP_CODEGEN_END(DTO)