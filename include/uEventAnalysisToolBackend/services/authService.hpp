#ifndef UEVENT_ANALYSIS_TOOL_BACKEND_SERVICES_AUTH_SERVICE_HPP
#define UEVENT_ANALYSIS_TOOL_BACKEND_SERVICES_AUTH_SERVICE_HPP
#include <spdlog/logger.h>
#include <grpcpp/server_context.h>
#include <grpcpp/support/server_callback.h>
#include <memory>
#include <uEventAnalysisToolAPI/auth/v1/service.grpc.pb.h>

namespace UEventAnalysisToolAPI::Auth::V1
{
 class AddKeyRequest;
 class AddKeyResponse;
 class ChangePasswordRequest;
 class ChangePasswordResponse;
 class ListKeysRequest;
 class ListKeysResponse;
 class LoginWithPasswordRequest;
 class LoginWithPasswordResponse;
 class GetPasswordRequirementsRequest;
 class PasswordRequirements;
 class RevokeKeyRequest;
 class RevokeKeyResponse;
}

namespace UEventAnalysisToolBackend::Auth
{
 class UserLoginAuthority;
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
    /// @param[in] logger   The application logger.
    AuthService(std::shared_ptr<UEventAnalysisToolBackend::Auth::UserLoginAuthority> loginAuthority,
                std::shared_ptr<spdlog::logger> logger);

    grpc::ServerUnaryReactor
        *LoginWithKey(
            grpc::CallbackServerContext *context,
            const UEventAnalysisToolAPI::Auth::V1::LoginWithKeyRequest *request,
            UEventAnalysisToolAPI::Auth::V1::LoginWithKeyResponse *response) override;

    grpc::ServerUnaryReactor
        *LoginWithPassword(
            grpc::CallbackServerContext *context,
            const UEventAnalysisToolAPI::Auth::V1::LoginWithPasswordRequest *request,
            UEventAnalysisToolAPI::Auth::V1::LoginWithPasswordResponse *response) override;

    grpc::ServerUnaryReactor
        *ChangePassword(
            grpc::CallbackServerContext *context,
            const UEventAnalysisToolAPI::Auth::V1::ChangePasswordRequest *request,
            UEventAnalysisToolAPI::Auth::V1::ChangePasswordResponse *response) override;

    grpc::ServerUnaryReactor
        *GetPasswordRequirements(
            grpc::CallbackServerContext *context,
            const UEventAnalysisToolAPI::Auth::V1::GetPasswordRequirementsRequest *request,
            UEventAnalysisToolAPI::Auth::V1::PasswordRequirements *response) override;

/*
    grpc::ServerUnaryReactor
        *AddKey(
            grpc::CallbackServerContext *context,
            const UEventAnalysisToolAPI::Auth::V1::AddKeyRequest *request,
            UEventAnalysisToolAPI::Auth::V1::AddKeyResponse *response) override;

    grpc::ServerUnaryReactor
        *RevokeKey(
            grpc::CallbackServerContext *context,
            const UEventAnalysisToolAPI::Auth::V1::RevokeKeyRequest *request,
            UEventAnalysisToolAPI::Auth::V1::RevokeKeyResponse *response) override;

    grpc::ServerUnaryReactor
        *ListKeys(
            grpc::CallbackServerContext *context,
            const UEventAnalysisToolAPI::Auth::V1::ListKeysRequest *request,
            UEventAnalysisToolAPI::Auth::V1::ListKeysResponse *response) override;
*/


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
