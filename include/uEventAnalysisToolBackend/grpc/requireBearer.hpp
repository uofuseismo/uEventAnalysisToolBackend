#ifndef UEVENT_ANALYSIS_TOOL_BACKEND_GRPC_REQUIRE_BEARER_HPP
#define UEVENT_ANALYSIS_TOOL_BACKEND_GRPC_REQUIRE_BEARER_HPP
#include <expected>
#include <grpcpp/server_context.h>
#include <grpcpp/support/status.h>
 
namespace UEventAnalysisToolBackend::Auth
{
 class AdministratorTokenVerifier;
 class Claims;
 class UserTokenVerifier;
}

namespace UEventAnalysisToolBackend::GRPC
{

[[nodiscard]] std::expected<Auth::Claims, grpc::Status>
    requireBearer(const grpc::CallbackServerContext &context,
                  const UEventAnalysisToolBackend::Auth::UserTokenVerifier &verifier);

[[nodiscard]] std::expected<Auth::Claims, grpc::Status>
    requireBearer(const grpc::CallbackServerContext &context,
                  const UEventAnalysisToolBackend::Auth::AdministratorTokenVerifier &verifier);


}
#endif
