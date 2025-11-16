#include "oatpp/web/protocol/http/Http.hpp"
#include "oatpp/core/macro/component.hpp"

#include "../domain/param/IOPairParam.h"
#include "../domain/param/IOParam.h"
#include "../domain/respond/AjaxResult.h"

class ExchangeService
{
private:
	typedef oatpp::web::protocol::http::Status Status;
public:
	oatpp::String exchange(const oatpp::Object<IOPairParam>& io_pair_param);

	oatpp::UInt64 size(const oatpp::Object<IOParam>& io_param);
};