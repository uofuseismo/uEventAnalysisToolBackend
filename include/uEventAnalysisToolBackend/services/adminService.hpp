#ifndef UEVENT_ANALYSIS_TOOL_BACKEND_SERVICES_ADMIN_SERVICE_HPP
#define UEVENT_ANALYSIS_TOOL_BACKEND_SERVICES_ADMIN_SERVICE_HPP
#include <spdlog/logger.h>
#include <grpcpp/server_context.h>
#include <grpcpp/support/server_callback.h>
#include <memory>
#include <uEventAnalysisToolAPI/admin/v1/service.grpc.pb.h>

namespace UEventAnalysisToolAPI::Admin::V1
{
 class LoginWithPasswordRequest;
 class LoginWithPasswordResponse;
}

namespace UEventAnalysisToolBackend::Auth
{
 class AdministratorLoginAuthority;
 class AdministratorTokenVerifier;
}

namespace UEventAnalysisToolBackend::Services
{

/// @class AdminService adminService.hpp
/// @brief Implements the system administrator routes.
/// @copyright Ben Baker (University of Utah) distributed under
///            the MIT NO AI license.
class AdminService final : 
    public UEventAnalysisToolAPI::Admin::V1::AdminService::CallbackService
{
public:
    /// @brief Constructor
    /// @param[in] tokenVerifier  Verifies admin tokens.
    /// @param[in] logger         The application logger.
    AdminService(
        std::shared_ptr<UEventAnalysisToolBackend::Auth::AdministratorLoginAuthority> loginAuthority,
        std::shared_ptr<UEventAnalysisToolBackend::Auth::AdministratorTokenVerifier> tokenVerifier,
        std::shared_ptr<spdlog::logger> logger);

    grpc::ServerUnaryReactor
        *LoginWithPassword(
            grpc::CallbackServerContext *context,
            const UEventAnalysisToolAPI::Admin::V1::LoginWithPasswordRequest *request,
            UEventAnalysisToolAPI::Admin::V1::LoginWithPasswordResponse *response) override;

    virtual ~AdminService();

    AdminService() = delete;
    AdminService(const AdminService &) = delete;
    AdminService(AdminService &&) noexcept = delete;
    AdminService& operator=(const AdminService &) = delete;
    AdminService& operator=(AdminService &&) noexcept = delete;
private:
    class AdminServiceImpl;
    std::unique_ptr<AdminServiceImpl> pImpl;
};

}
#endif
