#pragma once

#include <userver/components/component_config.hpp>
#include <userver/components/component_context.hpp>
#include <userver/components/loggable_component_base.hpp>
#include <userver/server/handlers/auth/auth_checker_base.hpp>
#include <userver/yaml_config/schema.hpp>


namespace authproxy::auth::jwt {

using namespace userver;

class JwtChecker final : public server::handlers::auth::AuthCheckerBase {
 public:
  using AuthCheckResult = server::handlers::auth::AuthCheckResult;

  JwtChecker(const std::string& secret);

  AuthCheckResult CheckAuth(
      const server::http::HttpRequest& request,
      server::request::RequestContext& context) const override;
  bool SupportsUserAuth() const noexcept override { return true; }

 private:
  std::string secret_;
};

using JwtCheckerPtr = std::shared_ptr<JwtChecker>;

class JwtAuthComponent final : public components::LoggableComponentBase {
 public:
  static constexpr auto kName = "jwt-auth-checker";

  JwtAuthComponent(const components::ComponentConfig& config,
                   const components::ComponentContext& context);

  JwtCheckerPtr Get() const;

  static yaml_config::Schema GetStaticConfigSchema();

 private:
  JwtCheckerPtr authorizer_;
};

}  // namespace authproxy::auth::jwt