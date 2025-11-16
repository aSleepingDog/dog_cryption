#include "controller/HashController.h"

std::shared_ptr<oatpp::web::protocol::http::outgoing::Response> HashController::test(const oatpp::Object<HashParam>& hash_param)
{
	try
	{
		auto spend = m_hashService->test(hash_param);
		auto res = AjaxResult<oatpp::Float64>::createShared();
		res->code = 200;
		res->data = spend;
		res->msg = "success";
		res->time = spend;
		//std::cout << (uint64_t)(&UniqueTaskPool::get(8)) << std::endl;
		return createDtoResponse(Status::CODE_200, res);
	}
	catch(std::exception& e)
	{
		auto res = AjaxResult<oatpp::Float64>::createShared();
		res->code = 500;
		res->msg = e.what();
		return createDtoResponse(Status::CODE_500, res);
	}
}