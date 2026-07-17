#ifndef UEVENT_ANALYSIS_TOOL_BACKEND_SERVICES_LOGIN_REACTOR_HPP
#define UEVENT_ANALYSIS_TOOL_BACKEND_SERVICES_LOGIN_REACTOR_HPP
#include <spdlog/logger.h>
#include <grpcpp/server_context.h>
#include <grpcpp/support/server_callback.h>
#include <memory>

namespace UEventAnalysisToolAPI::V1::Login
{
 class BasicRequest;
 class BasicResponse;
}

namespace UEventAnalysisToolBackend::Auth
{
 class AuthNZ;
}

namespace UEventAnalysisToolBackend::Services
{

/// @brief Implements the login services for the gRPC server.
class BasicLoginReactor final : public grpc::ServerUnaryReactor
{
public:
    /// @brief Handles a basic login request.  This is where users get their
    ///        JWT and start their processing journey.
    /// @param[out] response   The response message.
    /// @param[in] context     The server context with client details.
    /// @param[in] request     The user request.
    /// @param[in] authnzer    The application authenticator/authorizer.
    /// @param[in] logger      The application logger.
    BasicLoginReactor(UEventAnalysisToolAPI::V1::Login::BasicResponse *response,
                      grpc::CallbackServerContext *context,
                      const UEventAnalysisToolAPI::V1::Login::BasicRequest &request,
                      const UEventAnalysisToolBackend::Auth::AuthNZ &authNZ,
                      std::shared_ptr<spdlog::logger> logger);
    virtual ~BasicLoginReactor();
private:
    void OnDone() override;
    void OnCancel() override;
    class Impl; 
    std::unique_ptr<Impl> pImpl{nullptr};
};
}
#endif
