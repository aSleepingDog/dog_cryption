#include "oatpp/web/server/interceptor/ResponseInterceptor.hpp"
#include "oatpp/web/server/HttpConnectionHandler.hpp"

class CORSResponseInterceptor : public oatpp::web::server::interceptor::ResponseInterceptor {
public:
  std::shared_ptr<OutgoingResponse> intercept(const std::shared_ptr<IncomingRequest>& request,
                                              const std::shared_ptr<OutgoingResponse>& response) override {
    // 设置允许的源，这里可以根据请求的 Origin 头动态设置或使用固定值
    response->putHeaderIfNotExists("Access-Control-Allow-Origin", "*"); // 生产环境建议指定具体域名而非通配符
    response->putHeaderIfNotExists("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
    response->putHeaderIfNotExists("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With");
    response->putHeaderIfNotExists("Access-Control-Max-Age", "86400"); // 预检请求缓存时间（秒）
    
    // 处理 OPTIONS 预检请求
    if (request->getStartingLine().method == "OPTIONS") {
        auto optionsResponse = OutgoingResponse::createShared(oatpp::web::protocol::http::Status::CODE_200, nullptr);
        optionsResponse->putHeader("Access-Control-Allow-Origin", "*");
        optionsResponse->putHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
        optionsResponse->putHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With");
        return optionsResponse;
    }
    
    return response;
  }
};