#ifndef UEVENT_ANALYSIS_TOOL_BACKEND_SERVICES_LOGIN_HPP
#define UEVENT_ANALYSIS_TOOL_BACKEND_SERVICES_LOGIN_HPP
#include <spdlog/logger.h>
#include <grpcpp/server_context.h>
#include <grpcpp/support/server_callback.h>
#include <memory>
#include <uEventAnalysisToolAPI/v1/login/service.grpc.pb.h>

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

/// @class Login login.hpp
/// @brief Implements the login services for the gRPC server.
/// @copyright Ben Baker (University of Utah) distributed under
///            the MIT NO AI license.
class LoginService final : public UEventAnalysisToolAPI::V1::Login::LoginService::CallbackService
{
public:
    /// @brief Constructor
    /// @param[in] authNZ   The authenticator/authorizer.
    /// @param[in] logger   The application logger.
    LoginService(std::shared_ptr<UEventAnalysisToolBackend::Auth::AuthNZ> authNZ,
                 std::shared_ptr<spdlog::logger> logger);

    grpc::ServerUnaryReactor
        *BasicLogin(
            grpc::CallbackServerContext *context,
            const UEventAnalysisToolAPI::V1::Login::BasicRequest *request,
            UEventAnalysisToolAPI::V1::Login::BasicResponse *response) override;

    virtual ~LoginService();
private:
    class LoginServiceImpl;
    std::unique_ptr<LoginServiceImpl> pImpl;
};

}
#endif
