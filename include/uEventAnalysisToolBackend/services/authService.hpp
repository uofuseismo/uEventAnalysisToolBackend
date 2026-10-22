#ifndef UEVENT_ANALYSIS_TOOL_BACKEND_SERVICES_AUTH_SERVICE_HPP
#define UEVENT_ANALYSIS_TOOL_BACKEND_SERVICES_AUTH_SERVICE_HPP
#include <spdlog/logger.h>
#include <grpcpp/server_context.h>
#include <grpcpp/support/server_callback.h>
#include <memory>
#include <uEventAnalysisToolAPI/auth/v1/service.grpc.pb.h>

namespace UEventAnalysisToolAPI::Auth::V1
{
 class LoginWithPasswordRequest;
 class LoginWithPasswordResponse;
}

namespace UEventAnalysisToolBackend::Auth
{
 class AuthNZ;
}

namespace UEventAnalysisToolBackend::Services
{

/// @class AuthService authService.hpp
/// @brief Implements the user login service and account credentials management
///        for the gRPC server.
/// @copyright Ben Baker (University of Utah) distributed under
///            the MIT NO AI license.
class AuthService final : 
    public UEventAnalysisToolAPI::Auth::V1::AuthService::CallbackService
{
public:
    /// @brief Constructor
    /// @param[in] authNZ   The authenticator/authorizer.
    /// @param[in] logger   The application logger.
    AuthService(std::shared_ptr<UEventAnalysisToolBackend::Auth::AuthNZ> authNZ,
                std::shared_ptr<spdlog::logger> logger);

    grpc::ServerUnaryReactor
        *LoginWithPassword(
            grpc::CallbackServerContext *context,
            const UEventAnalysisToolAPI::Auth::V1::LoginWithPasswordRequest *request,
            UEventAnalysisToolAPI::Auth::V1::LoginWithPasswordResponse *response) override;

    virtual ~AuthService();

    AuthService() = delete;
    AuthService(const AuthService &) = delete;
    AuthService(AuthService &&) noexcept = delete;
    AuthService& operator=(const AuthService &) = delete;
    AuthService& operator=(AuthService &&) noexcept = delete;
private:
    class AuthServiceImpl;
    std::unique_ptr<AuthServiceImpl> pImpl;
};

}
#endif
