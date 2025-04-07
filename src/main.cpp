#include <userver/clients/dns/component.hpp>
#include <userver/clients/http/component.hpp>
#include <userver/components/minimal_server_component_list.hpp>
#include <userver/server/handlers/ping.hpp>
#include <userver/server/handlers/tests_control.hpp>
#include <userver/testsuite/testsuite_support.hpp>
#include <userver/utils/daemon_run.hpp>

#include "components/auth_factory.hpp"
#include "handlers/hello.hpp"

int main(int argc, char* argv[]) {
  userver::server::handlers::auth::RegisterAuthCheckerFactory(
      authproxy::auth::jwt::JwtAuthCheckerFactory::kAuthType,
      std::make_unique<authproxy::auth::jwt::JwtAuthCheckerFactory>());

  auto component_list = userver::components::MinimalServerComponentList()
                            .Append<userver::server::handlers::Ping>()
                            .Append<userver::components::TestsuiteSupport>()
                            .Append<userver::components::HttpClient>()
                            .Append<userver::clients::dns::Component>()
                            .Append<userver::server::handlers::TestsControl>()
                            .Append<authproxy::auth::jwt::JwtAuthComponent>();

  service_template::AppendHello(component_list);

  return userver::utils::DaemonMain(argc, argv, component_list);
}
