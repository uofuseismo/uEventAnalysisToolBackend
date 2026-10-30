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
#include "uEventAnalysisToolBackend/services/authService.hpp"
#include "uEventAnalysisToolBackend/auth/userLoginAuthority.hpp"
#include "uEventAnalysisToolBackend/auth/userTokenVerifier.hpp"
#include "uEventAnalysisToolBackend/grpc/parseAuthorizationHeader.hpp"
#include "uEventAnalysisToolBackend/grpc/requireBearer.hpp"
#include "uEventAnalysisToolBackend/grpc/toRequestIdentifier.hpp"
//#include "uEventAnalysisToolBackend/grpc/validateClientAccessToken.hpp"
#include <uEventAnalysisToolAPI/auth/v1/service.grpc.pb.h>
#include <uEventAnalysisToolAPI/auth/v1/login_with_password_request.pb.h>
#include <uEventAnalysisToolAPI/auth/v1/login_with_password_response.pb.h>

using namespace UEventAnalysisToolBackend::Services;

namespace UAuth = UEventAnalysisToolBackend::Auth;

class AuthService::AuthServiceImpl
{
public:
    AuthServiceImpl
    (
        std::shared_ptr<UAuth::UserLoginAuthority> loginAuthority,
        std::shared_ptr<UAuth::UserTokenVerifier> tokenVerifier,
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
            throw std::invalid_argument("User token verifier is null");
        }
        if (!mTokenVerifier->isInitialized())
        {
            throw std::invalid_argument("User token verifier not initialized");
        }
        if (mLogger == nullptr)
        {
            // NOLINTBEGIN(misc-include-cleaner)
            constexpr const char *loggerName{"AuthServiceConsole"};
            mLogger = spdlog::get(loggerName);
            if (mLogger == nullptr)
            {
                mLogger = spdlog::stdout_color_mt(loggerName);
            }
            // NOLINTEND(misc-include-cleaner)
        }
    }
//private:
    std::shared_ptr<UAuth::UserLoginAuthority> mLoginAuthority{nullptr};
    std::shared_ptr<UAuth::UserTokenVerifier> mTokenVerifier{nullptr};
    std::shared_ptr<spdlog::logger> mLogger{nullptr};
};

/// Constructor
AuthService::AuthService
    (
        std::shared_ptr<UAuth::UserLoginAuthority> loginAuthority,
        std::shared_ptr<UAuth::UserTokenVerifier> tokenVerifier,
        std::shared_ptr<spdlog::logger> logger
    ) :
    pImpl(std::make_unique<AuthServiceImpl>
          (std::move(loginAuthority),
           std::move(tokenVerifier),
           std::move(logger)))//,
    //UEventAnalysisToolAPI::Auth::V1::AuthService::CallbackService {}
{
} 

///---------------------------Login With Password----------------------------///
grpc::ServerUnaryReactor
*AuthService::LoginWithPassword(
    grpc::CallbackServerContext *context,
    const UEventAnalysisToolAPI::Auth::V1::LoginWithPasswordRequest *request,
    UEventAnalysisToolAPI::Auth::V1::LoginWithPasswordResponse *response)
{
    namespace UAuthV1 = UEventAnalysisToolAPI::Auth::V1;
    class Reactor : public grpc::ServerUnaryReactor
    {
    public:
        Reactor(UAuthV1::LoginWithPasswordResponse *response,
                grpc::CallbackServerContext *context,
                const UAuthV1::LoginWithPasswordRequest &request,
                std::shared_ptr<UAuth::UserLoginAuthority> &loginAuthority,
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
                      (endTime - mRPCStartTime);
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
                       pImpl->mLoginAuthority,
                       pImpl->mLogger);

}

///------------------------------Change Password-----------------------------///
grpc::ServerUnaryReactor
*AuthService::ChangePassword(
    grpc::CallbackServerContext *context,
    const UEventAnalysisToolAPI::Auth::V1::ChangePasswordRequest *request,
    UEventAnalysisToolAPI::Auth::V1::ChangePasswordResponse *response)
{
    namespace UAuthV1 = UEventAnalysisToolAPI::Auth::V1;
    class Reactor : public grpc::ServerUnaryReactor
    {   
    public:
        Reactor(UAuthV1::ChangePasswordResponse *response,
                grpc::CallbackServerContext *context,
                const UAuthV1::ChangePasswordRequest &request,
                //std::shared_ptr<UAuth::UserLoginAuthority> &loginAuthority,
                const UAuth::UserTokenVerifier &tokenVerifier,
                std::shared_ptr<spdlog::logger> logger) :
            mLogger(std::move(logger))
        {
            auto requestIdentifier = GRPC::toRequestIdentifier(*context);
            auto bearerResult = GRPC::requireBearer(*context, tokenVerifier);
            if (!bearerResult.has_value())
            {
                //metrics.incrementUnauthenticatedCounter(mRouteName);
                SPDLOG_LOGGER_WARN(mLogger,
                    "{} did not provide bearer authorization - rejected",
                     requestIdentifier);
                Finish(bearerResult.error());
                return;
            }

            mSuccess = true;
            Finish(grpc::Status::OK);
            SPDLOG_LOGGER_DEBUG(
                mLogger,
                "{} successfully changed password",
                requestIdentifier);
        };

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
                      (endTime - mRPCStartTime);
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
        const std::string mRouteName{"ChangePassword"}; 
        bool mSuccess{false};
    };
    return new Reactor(response,
                       context,
                       *request,
                       *pImpl->mTokenVerifier,
                       pImpl->mLogger);
    
}   


/// Destructor
AuthService::~AuthService() = default;
