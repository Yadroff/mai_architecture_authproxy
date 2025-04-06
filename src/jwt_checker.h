#include <userver/server/handlers/auth/auth_checker_base.hpp>


namespace authproxy::jwt {

class JwtChecker final: public server::handlers::auth::AuthCheckerBase {
public:
    using AuthCheckResult = server::handlers::auth::AuthCheckResult;

    JwtChecker(const components::ComponentContext& context, const components::ComponentConfig& config);

    AuthCheckResult CheckAuth(const server::http::HttpRequest& request, server::request::RequestContext& context) const override;
private:
    std::string secret_;
};

}