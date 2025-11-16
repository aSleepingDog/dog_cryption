
#ifndef SwaggerComponent_hpp
#define SwaggerComponent_hpp

#include "oatpp-swagger/Model.hpp"
#include "oatpp-swagger/Resources.hpp"
#include "oatpp/core/macro/component.hpp"


/**
 *  Swagger ui is served at
 *  http://host:port/swagger/ui
 */
class SwaggerComponent {
public:
    std::string swagger_path;

    SwaggerComponent(const std::string& swagger_path) : swagger_path(swagger_path) {}
  
  /**
   *  General API docs info
   */
  OATPP_CREATE_COMPONENT(std::shared_ptr<oatpp::swagger::DocumentInfo>, swaggerDocumentInfo)([] {
    
    oatpp::swagger::DocumentInfo::Builder builder;
    
    builder
    .setTitle("dog_cryption oatpp Server")
    .setDescription("simple cryptography API project with swagger docs")
    .setVersion("1.0")
    
    .addServer("http://localhost:8000", "server on localhost");
    
    return builder.build();
    
  }());
  
  
  /**
   *  Swagger-Ui Resources (<oatpp-examples>/lib/oatpp-swagger/res)
   */
   // Make sure to specify correct full path to oatpp-swagger/res folder !!!
  OATPP_CREATE_COMPONENT(std::shared_ptr<oatpp::swagger::Resources>, swaggerResources)
      (
          [this]
          {
              try
              {
                  return oatpp::swagger::Resources::loadResources(this->swagger_path);
              }
              catch (std::exception& e)
              {
                  OATPP_LOGE("dog_cryption oatpp Server", "uneffective swagger path %s", this->swagger_path);
                  OATPP_LOGE("dog_cryption oatpp Server", "无效的swagger路径 %s", this->swagger_path);
                  throw e;
              }
              
          }()
      );
  
};

#endif /* SwaggerComponent_hpp */
