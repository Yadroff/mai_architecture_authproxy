#include "jwt_checker.hpp"

#include <cstdlib>  // for getenv

#include <jwt-cpp/jwt.h>

#include <userver/http/common_headers.hpp>
#include <userver/yaml_config/merge_schemas.hpp>

namespace authproxy::auth::jwt {

namespace {
static constexpr std::string_view kSecret = "secret";
static constexpr std::string_view kAlgorithm = "Bearer ";
static constexpr const char* kServiceName = "authproxy";
static constexpr const char* kJwtSecretKey = "JWT_SECRET_KEY";
}  // namespace

JwtChecker::JwtChecker(const std::string& secret) : secret_(secret) {}

JwtChecker::AuthCheckResult JwtChecker::CheckAuth(
    const server::http::HttpRequest& request,
    server::request::RequestContext& /*context*/) const {
  const std::string_view auth_header =
      request.GetHeader(http::headers::kAuthorization);
  if (!auth_header.empty()) {
    return AuthCheckResult{AuthCheckResult::Status::kTokenNotFound,
                           "Missing 'Authorization' header"};
  }

  if (!auth_header.starts_with(kAlgorithm)) {
    return AuthCheckResult{AuthCheckResult::Status::kInvalidToken,
                           "Invalid authorization type, expected 'Bearer'"};
  }

  const std::string_view token = auth_header.substr(kAlgorithm.length());
  try {
    auto decoded = ::jwt::decode(std::string{token.data(), token.length()});
    auto verifier = ::jwt::verify()
                        .allow_algorithm(::jwt::algorithm::hs256{secret_})
                        .with_issuer(kServiceName);

    verifier.verify(decoded);
    return {};

  } catch (const ::jwt::error::token_verification_exception& exc) {
    return AuthCheckResult{
        AuthCheckResult::Status::kInvalidToken,
        "Token verification failed: " + std::string{exc.what()}};
  } catch (const std::exception& exc) {
    return AuthCheckResult{
        AuthCheckResult::Status::kForbidden,
        "Token processing error: " + std::string{exc.what()}};
  }
}

JwtAuthComponent::JwtAuthComponent(const components::ComponentConfig& config,
                                   const components::ComponentContext& context)
    : components::LoggableComponentBase(config, context) {
  std::string secret;
  if (config.HasMember(kSecret)) {
    secret = config[kSecret].As<std::string>();
  } else {
    const char* env_secret = std::getenv(kJwtSecretKey);
    if (env_secret == nullptr) {
      throw std::runtime_error(
          "JWT secret key was not found at config and env");
    }
    secret = env_secret;
  }
  authorizer_ = std::make_shared<JwtChecker>(secret);
}

JwtCheckerPtr JwtAuthComponent::Get() const { return authorizer_; }

yaml_config::Schema JwtAuthComponent::GetStaticConfigSchema() {
    return yaml_config::MergeSchemas<components::ComponentBase>(R"(
type: object
description: JWT Auth Checker Component
additionalProperties: false
properties:
    secret:
        type: string
        description: secret key for JWT validation
)");
}
}  // namespace authproxy::auth::jwt