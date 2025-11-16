#include <iostream>

#include "oatpp/network/Server.hpp"
#include "oatpp-swagger/Controller.hpp"
#include "oatpp/web/server/HttpRequestHandler.hpp"
#include "oatpp/web/server/HttpConnectionHandler.hpp"
#include "oatpp/network/tcp/server/ConnectionProvider.hpp"

#include "controller/ExchangeController.h"
#include "controller/HashController.h"
#include "base/AppComponent.h"
#include "base/CORSResponseInterceptor.h"

#include "dog_torch.h"

#include <string>

void run(uint16_t port, const std::string& swagger_path)
{
    AppComponent components(swagger_path);
 
    auto router = oatpp::web::server::HttpRouter::createShared();
    auto connectionHandler = oatpp::web::server::HttpConnectionHandler::createShared(router);

    connectionHandler->addResponseInterceptor(std::make_shared<CORSResponseInterceptor>());

    oatpp::web::server::api::Endpoints docEndpoints;
    docEndpoints.append(router->addController(ExchangeController::createShared())->getEndpoints());
    docEndpoints.append(router->addController(HashController::createShared())->getEndpoints());
    router->addController(oatpp::swagger::Controller::createShared(docEndpoints));

    auto connectionProvider = oatpp::network::tcp::server::ConnectionProvider::createShared({ "localhost", (v_uint16)port, oatpp::network::Address::IP_4 });
    oatpp::network::Server server(connectionProvider, connectionHandler);

    OATPP_LOGI("dog_cryption oatpp Server", "Server running on port %s", connectionProvider->getProperty("port").getData());
    OATPP_LOGI("dog_cryption oatpp Server", "服务器运行在端口 %s", connectionProvider->getProperty("port").getData());

    server.run();
}

int main(int argc, const char** argv)
{
    dog_torch::serialize::jsonx::Object config;
    std::string jsont_str = R"({
        "port":uint64,
        "swagger":{
            "switch":boolean,
            "path":string,
             "url":string,
         },
        "log":{
            "switch":boolean,
            "path":string
        }
    })";
    dog_torch::serialize::jsont::Object jsont(jsont_str);
    if (argc > 1)
    {
        std::vector<std::string> args;
        for (int i = 1; i < argc; i++)
        {
            args.emplace_back(argv[i]);
        }
        std::filesystem::path config_path = args[0];
        if (!std::filesystem::exists(config_path))
        {
            OATPP_LOGE("dog_cryption oatpp Server", "config path not exists");
            OATPP_LOGE("dog_cryption oatpp Server", "配置文件路径不存在");
            return 1;
        }
        std::ifstream ifs(config_path);
        std::string config_str((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
        std::cout << config_str << std::endl;
        config = dog_torch::serialize::jsonx::Object(config_str);
        if (!jsont.match(config))
        {
            OATPP_LOGE("dog_cryption oatpp Server", "config not match");
            OATPP_LOGE("dog_cryption oatpp Server", "配置文件不匹配");
            return 1;
        }
    }
    else
    {
        dog_torch::serialize::jsonx::Value port = dog_torch::serialize::jsonx::Value((uint64_t)8000);
        config["port"] = port;
        std::unordered_map<std::string, dog_torch::serialize::jsonx::Value> swagger;
        swagger["switch"] = dog_torch::serialize::jsonx::Value(true);
        swagger["path"] = dog_torch::serialize::jsonx::Value("./page/res");
        swagger["url"] = dog_torch::serialize::jsonx::Value("/api-docs");
        config["swagger"] = dog_torch::serialize::jsonx::Value(swagger);
        std::unordered_map<std::string, dog_torch::serialize::jsonx::Value> log;
        log["switch"] = dog_torch::serialize::jsonx::Value(true);
        log["path"] = dog_torch::serialize::jsonx::Value("./log");
        config["log"] = dog_torch::serialize::jsonx::Value(log);
    }


    oatpp::base::Environment::init();
    try
    {
        run(8000,"./page/res");
    }
    catch (std::exception& e)
    {
        OATPP_LOGE("MyApp", "Error: %s", e.what());
    }
    
    // 销毁 oatpp 环境
    oatpp::base::Environment::destroy();

    return 0;
}