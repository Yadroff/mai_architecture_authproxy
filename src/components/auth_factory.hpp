#pragma once

#include <userver/server/handlers/auth/auth_checker_factory.hpp>

#include <components/jwt_checker.hpp>

namespace authproxy::auth::jwt {

class JwtAuthCheckerFactory final
    : public server::handlers::auth::AuthCheckerFactoryBase {
 public:
  static constexpr const char* kAuthType = "jwt-auth";

  JwtAuthCheckerFactory() = default;

  server::handlers::auth::AuthCheckerBasePtr operator()(
      const components::ComponentContext&,
      const server::handlers::auth::HandlerAuthConfig&,
      const server::handlers::auth::AuthCheckerSettings&) const override;

 private:
  authproxy::auth::jwt::JwtCheckerPtr jwt_checker_ptr_;
};

}  // namespace authproxy::auth::jwt