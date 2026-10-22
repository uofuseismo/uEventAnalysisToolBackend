#include <memory>
#include <stdexcept>
#include <utility>
#include <spdlog/logger.h>
#include "uEventAnalysisToolBackend/services/authService.hpp"
#include "uEventAnalysisToolBackend/auth/authNZ.hpp"
#include "uEventAnalysisToolBackend/auth/database.hpp"
#include <uEventAnalysisToolAPI/auth/v1/login_with_password_request.pb.h>
#include <uEventAnalysisToolAPI/auth/v1/login_with_password_response.pb.h>

using namespace UEventAnalysisToolBackend::Services;

namespace UAuth = UEventAnalysisToolBackend::Auth;

class AuthService::AuthServiceImpl
{
public:
    AuthServiceImpl(
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
    }
//private:
    std::shared_ptr<UAuth::AuthNZ> mAuthNZ{nullptr};
    std::shared_ptr<spdlog::logger> mLogger{nullptr};

};

/// Constructor
AuthService::AuthService
    (
        std::shared_ptr<UAuth::AuthNZ> authNZ,
        std::shared_ptr<spdlog::logger> logger
    ) :
    pImpl(std::make_unique<AuthServiceImpl>
          (std::move(authNZ), std::move(logger))),
    UEventAnalysisToolAPI::Auth::V1::AuthService::CallbackService {}
{
} 

grpc::ServerUnaryReactor
*AuthService::LoginWithPassword(
    grpc::CallbackServerContext *context,
    const UEventAnalysisToolAPI::Auth::V1::LoginWithPasswordRequest *request,
    UEventAnalysisToolAPI::Auth::V1::LoginWithPasswordResponse *response)
{

}

/// Destructor
AuthService::~AuthService() = default;
