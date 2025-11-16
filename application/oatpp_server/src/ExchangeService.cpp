#include "../include/service/ExchangeService.h"

oatpp::String ExchangeService::exchange(const oatpp::Object<IOPairParam>& io_pair_param)
{
	dog_param::IOConfig input = io_pair_param->get_input().to_IOConfig(true);
	dog_param::IOConfig output = io_pair_param->get_output().to_IOConfig(false);
	std::string input_str = output.fmt_data(input.get_data());
	return input_str;
}

oatpp::UInt64 ExchangeService::size(const oatpp::Object<IOParam>& io_param)
{
	return io_param->to_IOConfig(true).get_data().size();
}
