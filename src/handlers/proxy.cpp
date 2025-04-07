#include "proxy.hpp"

namespace authproxy::handlers::proxy_handler {

View::ProxyHandler(
    const userver::components::ComponentConfig& config,
    const userver::components::ComponentContext& context)
    : HttpHandlerBase(config, context),
      http_client_(context.FindComponent<userver::components::HttpClient>().GetHttpClient()),
      target_url_(config["proxy_settings"]["target_url"].As<std::string>()),
      service_prefix_(config["proxy_settings"]["service_prefix"].As<std::string>()) 
{}

std::string View::HandleRequestThrow(
    const userver::server::http::HttpRequest& request,
    userver::request::RequestContext& context) const {
  const std::string_view original_path = request.GetRequestPath();

  // Проверка префикса сервиса
  if (!original_path.starts_with(kServiceName)) {
    throw userver::server::handlers::ClientError(
        userver::server::handlers::ExternalBody{
            std::format("Request path must start with {}", kServiceName)});
  }

  // Формирование нового пути
  std::string new_path = original_path.substr(kServiceName.length());
  if (new_path.empty()) new_path = "/";

  // Проксирование запроса
  auto proxy_request = http_client_.CreateRequest()
                           ->method(request.GetMethod())
                           ->url(target_url_ + new_path);

  // Копирование заголовков
  for (const auto& [name, value] : request.GetHeaders()) {
    if (name != "Host") {
      proxy_request->headers().emplace(name, value);
    }
  }

  // Добавление служебных заголовков
  if (!request.HasHeader("X-Forwarded-For") && request.GetPeerAddress()) {
    proxy_request->headers().emplace("X-Forwarded-For",
                                     request.GetPeerAddress()->address);
  }

  // Выполнение запроса
  auto response = proxy_request->body(request.RequestBody())->perform();
  response->raise_for_status();

  return response->body();
}

yaml_config::Schema ProxyHandler::GetStaticConfigSchema() {
  return yaml_config::Schema(R"(
type: object
description: Proxy handler with JWT auth
additionalProperties: false
properties:
    target_url:
        type: string
        description: target URL to proxy requests to
    service_name:
        type: string
        description: service name prefix for URLs
        defaultDescription: "/my-proxy"
    secret:
        type: string
        description: secret key for JWT verification
)");
}

}  // namespace authproxy::handlers::proxy_handler