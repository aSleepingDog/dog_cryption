#include "domain/respond/TableDataInfo.h"
/*
template<typename T>
inline void TableDataInfo<T>::add_msg(const std::string language, const std::string msg)
{
	oatpp::Object<Message> msg_ = Message::createShared();
	msg_->language = language;
	msg_->content = msg;
	if (this->msg == nullptr)
	{
		this->msg = oatpp::Vector<oatpp::Object<Message>>::createShared();
	}
	this->msg->push_back(msg_);
}

template<typename T>
TableDataInfo<T>::Wrapper TableDataInfo<T>::success(const oatpp::Vector<T>& data)
{
	auto res = TableDataInfo<T>::createShared();
	res->code = 200;
	res->add_msg("en", "success");
	res->add_msg("zh", "获取成功");
	res->data = data;
	res->count = data->size();
	return res;
}

template<typename T>
TableDataInfo<T>::Wrapper TableDataInfo<T>::success(const std::vector<T>& data)
{
	auto res = TableDataInfo<T>::createShared();
	res->code = 200;
	res->add_msg("en", "success");
	res->add_msg("zh", "获取成功");
	res->data = data;
	res->count = data.size();
	return res;
}
*/