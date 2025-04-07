#include "auth_factory.hpp"

namespace authproxy::auth::jwt {

server::handlers::auth::AuthCheckerBasePtr JwtAuthCheckerFactory::operator()(
    const components::ComponentContext& context,
    const server::handlers::auth::HandlerAuthConfig&,
    const server::handlers::auth::AuthCheckerSettings&) const {
  return std::shared_ptr<authproxy::auth::jwt::JwtChecker>(
      context.FindComponent<authproxy::auth::jwt::JwtAuthComponent>().Get());
}
}  // namespace authproxy::auth::jwt