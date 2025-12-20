#include "domain/respond/AjaxResult.h"
/*
template<typename T>
void AjaxResult<T>::add_msg(const std::string language, const std::string msg)
{
	std::vector<oatpp::Object<Message>>& inmsg = *(this->msg.get());
	std::vector<oatpp::Object<Message>>::iterator value = std::find_if(inmsg.begin(), inmsg.end(),
		[language](const oatpp::Object<Message>& item) -> bool
		{
			return item->language == language;
		}
	);
	if (value != inmsg.end())
	{
		value->get()->content = msg;
	}
	else
	{
		oatpp::Object<Message> newMsg = Message::createShared();
		newMsg->language = language;
		newMsg->content = msg;
		this->msg->emplace_back(newMsg);
	}
}

template<typename T>
oatpp::data::mapping::type::DTOWrapper<AjaxResult<T>> AjaxResult<T>::success(const T& data, const double& spend, const std::vector<std::pair<std::string, std::string>> msgs)
{
	auto result = AjaxResult<T>::createShared();
	result->code = 200;
	result->data = data;
	result->time = spend;
	for (auto& msg : msgs)
	{
		result->add_msg(msg.first, msg.second);
	}
	return result;
}

template<typename T>
oatpp::data::mapping::type::DTOWrapper<AjaxResult<T>> AjaxResult<T>::success(const T& data, const std::vector<std::pair<std::string, std::string>> msgs)
{
	return AjaxResult<T>::success(data, -1, msgs);
}

template<typename T>
oatpp::data::mapping::type::DTOWrapper<AjaxResult<T>> AjaxResult<T>::success(const T& data, const double& spend)
{
	return AjaxResult<T>::success(data, spend, { {"en","success"},{"zh","操作成功"} });
}

template<typename T>
oatpp::data::mapping::type::DTOWrapper<AjaxResult<T>> AjaxResult<T>::success(const T& data)
{
	return AjaxResult<T>::success(data, -1, { {"en","success"},{"zh","操作成功"} });
}

template<typename T>
oatpp::data::mapping::type::DTOWrapper<AjaxResult<oatpp::String>> AjaxResult<T>::failure(const std::string& error, const double& spend, const std::vector<std::pair<std::string, std::string>> msgs)
{
	auto result = AjaxResult<oatpp::String>::createShared();
	result->code = 200;
	result->data = error;
	result->time = spend;
	for (auto& msg : msgs)
	{
		result->add_msg(msg.first, msg.second);
	}
	return result;
}

template<typename T>
oatpp::data::mapping::type::DTOWrapper<AjaxResult<oatpp::String>> AjaxResult<T>::failure(const std::string& error, const double& spend)
{
	return AjaxResult<oatpp::String>::success(error, -1, { {"en","error"},{"zh","发生错误"} });
}

template<typename T>
oatpp::data::mapping::type::DTOWrapper<AjaxResult<oatpp::String>> AjaxResult<T>::failure(const std::string& error)
{
	return AjaxResult<oatpp::String>::success(error, -1, { {"en","error"},{"zh","发生错误"} });
}
*/