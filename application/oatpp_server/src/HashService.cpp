#include "service/HashService.h"

oatpp::Float64 HashService::test(const oatpp::Object<HashParam>& hash_param)
{
	dog_torch::crypto::hash::HashCrypher hash(hash_param->type, hash_param->effective / 8);
	dog_torch::serialize::Data data = "";
	dog_work::Timer t;
	t.start();
	hash.get_data_hash(data);
	t.end();
	return t.get_time();
}
