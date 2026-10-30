#include <chrono>
#include <exception>
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
#include "uEventAnalysisToolBackend/auth/administratorLoginAuthority.hpp"
#include "uEventAnalysisToolBackend/auth/administratorTokenVerifier.hpp"
#include "uEventAnalysisToolBackend/auth/authenticator.hpp"
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
        std::shared_ptr<UAuth::AdministratorLoginAuthority> loginAuthority,
        std::shared_ptr<UAuth::AdministratorTokenVerifier> tokenVerifier,
        std::shared_ptr<spdlog::logger> logger
    ) :
        mLoginAuthority(std::move(loginAuthority)),
        mTokenVerifier(std::move(tokenVerifier)),
        mLogger(std::move(logger))
    {
        if (mLoginAuthority == nullptr)
        {
            throw std::invalid_argument("Login authority is null");
        }
        if (!mLoginAuthority->isInitialized())
        {
            throw std::invalid_argument("Login authority not initialized");
        }
        if (mTokenVerifier == nullptr)
        {
            throw std::invalid_argument("Token verifier is null");
        }
        if (!mTokenVerifier->isInitialized())
        {
            throw std::invalid_argument("Token verifier not initialized");
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
    std::shared_ptr<UAuth::AdministratorLoginAuthority>
        mLoginAuthority{nullptr};
    std::shared_ptr<UAuth::AdministratorTokenVerifier> mTokenVerifier{nullptr};
    std::shared_ptr<spdlog::logger> mLogger{nullptr};
};

/// Constructor
AdminService::AdminService
(
    std::shared_ptr<UAuth::AdministratorLoginAuthority> loginAuthority,
    std::shared_ptr<UAuth::AdministratorTokenVerifier> tokenVerifier,
    std::shared_ptr<spdlog::logger> logger
) :
    pImpl(std::make_unique<AdminServiceImpl>
          (std::move(loginAuthority),
           std::move(tokenVerifier),
           std::move(logger)))
{
}

grpc::ServerUnaryReactor
*AdminService::LoginWithPassword(
    grpc::CallbackServerContext *context,
    const UEventAnalysisToolAPI::Admin::V1::LoginWithPasswordRequest *request,
    UEventAnalysisToolAPI::Admin::V1::LoginWithPasswordResponse *response)
{
    namespace UAdminV1 = UEventAnalysisToolAPI::Admin::V1;
    class Reactor : public grpc::ServerUnaryReactor
    {
    public:
        Reactor(UAdminV1::LoginWithPasswordResponse *response,
                grpc::CallbackServerContext *context,
                const UAdminV1::LoginWithPasswordRequest &request,
                UAuth::AdministratorLoginAuthority &loginAuthority,
                std::shared_ptr<spdlog::logger> logger) :
            mLogger(std::move(logger))
        {
            auto requestIdentifier = GRPC::toRequestIdentifier(*context);
            // Extract the username and password from Basic
            auto basicField = context->client_metadata().find("authorization");
            if (basicField == context->client_metadata().end())
            {
                SPDLOG_LOGGER_WARN(mLogger,
                    "{} did not provide basic authorization - rejected",
                     requestIdentifier);
                //metrics.incrementUnauthenticatedCounter(mRouteName);
                Finish({grpc::StatusCode::UNAUTHENTICATED,
                        "No authorization header field specified"});
                return;
            }
            auto userNameAndPassword
                = GRPC::authorizationHeaderToUserNameAndPassword(
                     basicField->second);
            if (!userNameAndPassword.has_value())
            {
                SPDLOG_LOGGER_WARN(mLogger,
                     "{} provided malformed credentials - rejected",
                     requestIdentifier);
                Finish(userNameAndPassword.error());
                return;
            }
            // Check the user
            try
            {
                auto result
                    = loginAuthority.loginWithPassword(*userNameAndPassword);
                if (result)
                {
                    SPDLOG_LOGGER_INFO(mLogger,
                                       "Processed {}; {} logged in as admin",
                                       requestIdentifier,
                                       userNameAndPassword->first); 
                    response->set_json_web_token(*result);
                }
                else
                {
                    if (result.error() ==
                        UAuth::IAuthenticator::Result::InvalidCredentials) 
                    {
                        //metrics.incrementUnauthenticatedCounter(mRouteName);
                        SPDLOG_LOGGER_WARN(mLogger,
                                 "Rejected {}; {} provided invalid credentials",
                                 requestIdentifier,
                                 userNameAndPassword->first);
                        Finish({grpc::StatusCode::UNAUTHENTICATED,
                                "Invalid credentials"});
                        return;
                    }
                    //metrics.incrementServerErrorCounter(mRouteName);
                    SPDLOG_LOGGER_ERROR(mLogger,
                                        "Failed processing {}",
                                        requestIdentifier);
                    Finish({grpc::StatusCode::INTERNAL,
                            "Server error - contact maintainer"});
                    return;
                }
            }
            catch (const std::exception &e)
            {
                //metrics.incrementServerErrorCounter(mRouteName);
                SPDLOG_LOGGER_ERROR(mLogger,
                     "Failed to process login request for {} because {}",
                     requestIdentifier, e.what());
                Finish({grpc::StatusCode::INTERNAL,
                        "Server error - contact maintainer"});
                return;
            }
           
            mSuccess = true;
            Finish(grpc::Status::OK);
            SPDLOG_LOGGER_DEBUG(
                mLogger,
                "{} successfully logged in with password",
                requestIdentifier);
        }

    private:
        void OnDone() override
        {
            if (mLogger)
            {
                SPDLOG_LOGGER_DEBUG(mLogger,
                                    "{} RPC completed", mRouteName);
            }
            //auto &metrics = Metrics::Singleton::getInstance();
            if (mSuccess)
            {
                //metrics.incrementSuccessCounter(mRouteName);
                const auto endTime = std::chrono::steady_clock::now();
                auto elapsedTime
                    = std::chrono::duration<double>
                      (mRPCStartTime - endTime);
                //metrics.recordRouteDuration(elapsedTime, mRouteName);
            }
            delete this;
        }

        void OnCancel() override
        {
            if (mLogger)
            {
                SPDLOG_LOGGER_DEBUG(mLogger,
                                    "{} RPC canceled", mRouteName);
            }
        }
//private:
        std::shared_ptr<spdlog::logger> mLogger{nullptr};
        const std::chrono::time_point<std::chrono::steady_clock> mRPCStartTime
        {
            std::chrono::steady_clock::now()
        };
        const std::string mRouteName{"LoginWithPassword"};
        bool mSuccess{false};
    };
    return new Reactor(response,
                       context,
                       *request,
                       *pImpl->mLoginAuthority,
                       pImpl->mLogger);
}

/// Destructor
AdminService::~AdminService() = default;

