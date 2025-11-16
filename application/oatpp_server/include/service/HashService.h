#include "oatpp/web/protocol/http/Http.hpp"
#include "oatpp/core/macro/component.hpp"

#include "domain/param/IOPairParam.h"
#include "domain/param/IOParam.h"
#include "domain/param/HashParam.h"
#include "domain/respond/AjaxResult.h"

#include "dog_torch.h"
#include "task/task.h"

class HashService
{
private:
	typedef oatpp::web::protocol::http::Status Status;
public:
	oatpp::Float64 test(const oatpp::Object<HashParam>& hash_param);
};
