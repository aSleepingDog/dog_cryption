#include "../include/controller/ExchangeController.h"

std::shared_ptr<oatpp::web::protocol::http::outgoing::Response> ExchangeController::exchange(const oatpp::Object<IOPairParam>& iO_pair_param)
{
	try
	{
		dog_work::Timer timer;
		timer.start();
		oatpp::String res = this->m_exchangeService->exchange(iO_pair_param);
		timer.end();
		auto result = AjaxResult<oatpp::String>::createShared();
		result->code = 200;
		result->data = res;
		result->time = timer.get_time();
		result->msg = "success";
		return createDtoResponse(Status::CODE_200, result);
	}
	catch (dog_torch::utils::Exception& e)
	{
		auto result = AjaxResult<oatpp::String>::createShared();
		result->code = 500;
		result->msg = e.what();
		return createDtoResponse(Status::CODE_500, result);
	}
}

std::shared_ptr<oatpp::web::protocol::http::outgoing::Response> ExchangeController::size(const oatpp::Object<IOParam>& io_param)
{
	try
	{
		dog_work::Timer timer;
		timer.start();
		oatpp::UInt64 res = this->m_exchangeService->size(io_param);
		timer.end();
		auto result = AjaxResult<oatpp::UInt64>::createShared();
		result->code = 200;
		result->data = res;
		result->time = timer.get_time();
		result->msg = "success";
		return createDtoResponse(Status::CODE_200, result);
	}
	catch (dog_torch::utils::Exception& e)
	{
		auto result = AjaxResult<oatpp::String>::createShared();
		result->code = 500;
		result->msg = e.what();
		return createDtoResponse(Status::CODE_500, result);
	}
}
