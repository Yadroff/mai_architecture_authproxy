#pragma once

#include <string>
#include <userver/clients/http/client.hpp>
#include <userver/components/component_context.hpp>
#include <userver/server/handlers/http_handler_base.hpp>

namespace authproxy::handlers::proxy_handler {

class View final : public userver::server::handlers::HttpHandlerBase {
public:
  static constexpr std::string_view kName = "proxy-handler";

  ProxyHandler(const userver::components::ComponentConfig& config,
               const userver::components::ComponentContext& context);

  std::string HandleRequestThrow(
      const userver::server::http::HttpRequest& request,
      userver::request::RequestContext& context) const override;
  
  static yaml_config::Schema GetStaticConfigSchema();
private:
  static constexpr std::string_view kServiceName = "authproxy";
  userver::clients::http::Client& http_client_;
  std::string target_url_;
  std::string service_name_;
};

}  // authproxy::handlers::proxy_handler