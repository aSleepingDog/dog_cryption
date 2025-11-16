#include "oatpp/web/server/api/ApiController.hpp"
#include "oatpp/parser/json/mapping/ObjectMapper.hpp"
#include "oatpp/core/macro/codegen.hpp"

#include "domain/param/IOPairParam.h"
#include "service/ExchangeService.h"
#include "task/task.h";

#include "domain/respond/AjaxResult.h"

#include OATPP_CODEGEN_BEGIN(ApiController)

#define TO_STR(str) #str
#define ROOT_URL(url) TO_STR(data##url)
class ExchangeController : public oatpp::web::server::api::ApiController
{
private:
	ExchangeService* m_exchangeService;
public:
	ExchangeController(OATPP_COMPONENT(std::shared_ptr<ObjectMapper>, objectMapper)) : oatpp::web::server::api::ApiController(objectMapper) {};
	static std::shared_ptr<ExchangeController> createShared(
		OATPP_COMPONENT(std::shared_ptr<ObjectMapper>, objectMapper)
	) {
		return std::make_shared<ExchangeController>(objectMapper);
	}

	ENDPOINT_INFO(exchange)
	{
		info->summary = "基本数据转换";
		info->description = "将输入的编码字符串转换为指定编码的字符串";
		info->path = ROOT_URL(/exchange);
		info->method = "POST";
		
		info->addConsumes<oatpp::Object<IOPairParam>>(("application/json"));

		info->addResponse<oatpp::Object<AjaxResult<oatpp::String>>>(Status::CODE_200, ("application/json"));
	}
	ENDPOINT("POST", ROOT_URL(/exchange), exchange, BODY_DTO(oatpp::Object<IOPairParam>,iO_pair_param));

	ENDPOINT_INFO(size)
	{
		info->summary = "数据长度计算";
		info->description = "计算输入的编码字符串的长度";
		info->path = ROOT_URL(/size);
		info->method = "POST";

		info->addConsumes<oatpp::Object<IOParam>>(("application/json"));

		info->addResponse<oatpp::Object<AjaxResult<oatpp::UInt64>>>(Status::CODE_200, ("application/json"));
	}
	ENDPOINT("POST", ROOT_URL(/size), size, BODY_DTO(oatpp::Object<IOParam>, io_param));
};
#undef ROOT_URL(url)
#undef TO_STR(str)

#include OATPP_CODEGEN_END(ApiController)