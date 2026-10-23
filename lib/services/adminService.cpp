#include <chrono>
#include <memory>
#include <optional>
#include <stdexcept>
#include <utility>
#include <spdlog/spdlog.h>
#include <spdlog/logger.h>
//NOLINTNEXTLINE(misc-include-cleaner)
#include <spdlog/sinks/stdout_color_sinks.h>
#include <grpcpp/server_context.h>
#include <grpcpp/support/server_callback.h>
#include <grpcpp/support/status.h>
#include "uEventAnalysisToolBackend/services/adminService.hpp"
#include "uEventAnalysisToolBackend/auth/authNZ.hpp"
#include "uEventAnalysisToolBackend/auth/database.hpp"
#include "uEventAnalysisToolBackend/grpc/parseAuthorizationHeader.hpp"
#include "uEventAnalysisToolBackend/grpc/toRequestIdentifier.hpp"
//#include "uEventAnalysisToolBackend/grpc/validateClientAccessToken.hpp"
#include <uEventAnalysisToolAPI/admin/v1/service.grpc.pb.h>
#include <uEventAnalysisToolAPI/admin/v1/login_with_password_request.pb.h>
#include <uEventAnalysisToolAPI/admin/v1/login_with_password_response.pb.h>

using namespace UEventAnalysisToolBackend::Services;

namespace UAuth = UEventAnalysisToolBackend::Auth;

class AdminService::AdminServiceImpl
{
public:
    AdminServiceImpl
    (
        std::shared_ptr<UAuth::AuthNZ> authNZ,
        std::shared_ptr<spdlog::logger> logger
    ) :
        mAuthNZ(std::move(authNZ)),
        mLogger(std::move(logger))
    {
        if (mAuthNZ == nullptr)
        {
            throw std::invalid_argument("AuthNZ is null");
        }
        if (mLogger == nullptr)
        {
            // NOLINTBEGIN(misc-include-cleaner)
            constexpr const char *loggerName{"AdminServiceConsole"};
            mLogger = spdlog::get(loggerName);
            if (mLogger == nullptr)
            {
                mLogger = spdlog::stdout_color_mt(loggerName);
            }
            // NOLINTEND(misc-include-cleaner)
        }
    }
//private:
    std::shared_ptr<UAuth::AuthNZ> mAuthNZ{nullptr};
    std::shared_ptr<spdlog::logger> mLogger{nullptr};
};

/// Constructor
AdminService::AdminService
(
    std::shared_ptr<UEventAnalysisToolBackend::Auth::AuthNZ> authNZ,
    std::shared_ptr<spdlog::logger> logger
) :
    pImpl(std::make_unique<AdminServiceImpl>
          (std::move(authNZ), std::move(logger)))
{
}

grpc::ServerUnaryReactor
*AdminService::LoginWithPassword(
     grpc::CallbackServerContext *context,
     const UEventAnalysisToolAPI::Admin::V1::LoginWithPasswordRequest *request,
     UEventAnalysisToolAPI::Admin::V1::LoginWithPasswordResponse *response) override
{

}

/// Destructor
AdminService::~AdminService() = default;

