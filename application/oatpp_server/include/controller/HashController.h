#include "oatpp/web/server/api/ApiController.hpp"
#include "oatpp/parser/json/mapping/ObjectMapper.hpp"
#include "oatpp/core/macro/codegen.hpp"

#include "domain/param/HashParam.h"
#include "service/HashService.h"
#include "task/task.h"

#include "base/UniqueObject.h"
#include "task/task.h"

#include "domain/respond/AjaxResult.h"

#include OATPP_CODEGEN_BEGIN(ApiController)

#define TO_STR(str) #str
#define ROOT_URL(url) TO_STR(hash##url)
class HashController : public oatpp::web::server::api::ApiController
{
private:
	HashService* m_hashService;
public:
	HashController(OATPP_COMPONENT(std::shared_ptr<ObjectMapper>, objectMapper)) : oatpp::web::server::api::ApiController(objectMapper) {};
	static std::shared_ptr<HashController> createShared(
		OATPP_COMPONENT(std::shared_ptr<ObjectMapper>, objectMapper)
	) {
		return std::make_shared<HashController>(objectMapper);
	};

	ENDPOINT_INFO(test)
	{
		info->summary = "散列函数性能测试";
		info->description = "测试散列函数的性能";
		info->path = ROOT_URL(/test);
		info->method = "POST";

		info->addConsumes<oatpp::Object<HashParam>>(("application/json"));

		info->addResponse<oatpp::Object<AjaxResult<oatpp::Float64>>>(Status::CODE_200, ("application/json"));
	}
	ENDPOINT("POST", ROOT_URL(/test), test, BODY_DTO(oatpp::Object<HashParam>, hash_param));

};
#undef ROOT_URL(url)
#undef TO_STR(str)

#include OATPP_CODEGEN_END(ApiController)