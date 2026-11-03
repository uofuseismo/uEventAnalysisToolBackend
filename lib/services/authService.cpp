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
#include "uEventAnalysisToolBackend/auth/authenticator.hpp"
#include "uEventAnalysisToolBackend/auth/userLoginAuthority.hpp"
#include "uEventAnalysisToolBackend/auth/password/passwordPolicy.hpp"
#include "uEventAnalysisToolBackend/grpc/parseAuthorizationHeader.hpp"
#include "uEventAnalysisToolBackend/grpc/requireBearer.hpp"
#include "uEventAnalysisToolBackend/grpc/toRequestIdentifier.hpp"
#include <uEventAnalysisToolAPI/auth/v1/service.grpc.pb.h>
#include <uEventAnalysisToolAPI/auth/v1/change_password_request.pb.h>
#include <uEventAnalysisToolAPI/auth/v1/change_password_response.pb.h>
#include <uEventAnalysisToolAPI/auth/v1/login_with_password_request.pb.h>
#include <uEventAnalysisToolAPI/auth/v1/login_with_password_response.pb.h>
#include <uEventAnalysisToolAPI/auth/v1/get_password_requirements_request.pb.h>
#include <uEventAnalysisToolAPI/auth/v1/password_requirements.pb.h>


using namespace UEventAnalysisToolBackend::Services;

namespace UAuth = UEventAnalysisToolBackend::Auth;

class AuthService::AuthServiceImpl
{
public:
    AuthServiceImpl
    (
        std::shared_ptr<UAuth::UserLoginAuthority> loginAuthority,
        std::shared_ptr<spdlog::logger> logger
    ) :
        mLoginAuthority(std::move(loginAuthority)),
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
    std::shared_ptr<spdlog::logger> mLogger{nullptr};
};

/// Constructor
AuthService::AuthService
    (
        std::shared_ptr<UAuth::UserLoginAuthority> loginAuthority,
        std::shared_ptr<spdlog::logger> logger
    ) :
    pImpl(std::make_unique<AuthServiceImpl>
          (std::move(loginAuthority),
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
                //metrics.incrementUnauthenticatedCounter(mRouteName);
                Finish(userNameAndPassword.error());
                return;
            }
            auto loginResult
                = loginAuthority->loginWithPassword(*userNameAndPassword);
            if (loginResult.has_value())
            {
                SPDLOG_LOGGER_INFO(mLogger, 
                    "Processed {}; {} logged in",
                    requestIdentifier,
                    userNameAndPassword->first); 
                response->set_json_web_token(*loginResult);
            }
            else
            {
                if (loginResult.error() ==
                    Auth::IAuthenticator::Result::InvalidCredentials)
                {
                    SPDLOG_LOGGER_WARN(mLogger,
                        "Rejected {}; {} provided invalid credentials",
                        requestIdentifier,
                        userNameAndPassword->first);
                    //metrics.incrementUnauthenticatedCounter(mRouteName);
                    Finish({grpc::StatusCode::UNAUTHENTICATED,
                           "Invalid credentials"});
                    return;
                }
                if (loginResult.error() ==
                    Auth::IAuthenticator::Result::PasswordChangeRequired)
                {
                    SPDLOG_LOGGER_WARN(mLogger,
                        "Rejected {}; {} must change password",
                        requestIdentifier,
                        userNameAndPassword->first);
                    //metrics.incrementClientErrorCounter(mRouteName);
                    // System is not in correct state - do not retry this route
                    // until first changing password thereby correcting state
                    Finish({grpc::StatusCode::FAILED_PRECONDITION,
                           "Password must be changed prior to logging in"});
                    return;
                }
                else if (loginResult.error() ==
                         Auth::IAuthenticator::Result::ServerError)
                {
                    SPDLOG_LOGGER_ERROR(mLogger,
                        "Failed to process {}; could not auth {}",
                        requestIdentifier,
                        userNameAndPassword->first);
                }
                //metrics.incrementServerErrorCounter(mRouteName);
                Finish({grpc::StatusCode::INTERNAL,
                        "Server error during login - contact maintainer"});
                return;
            }
 
            mSuccess = true;
            SPDLOG_LOGGER_DEBUG(
                mLogger,
                "{} successfully logged in with password",
                requestIdentifier);
            Finish(grpc::Status::OK);
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
                UAuth::UserLoginAuthority &loginAuthority,
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
                //metrics.incrementUnauthenticatedCounter(mRouteName);
                Finish(userNameAndPassword.error());
                return;
            }

            const auto &user = userNameAndPassword->first;
            if (user.empty())
            {
                Finish({grpc::StatusCode::UNAUTHENTICATED,
                        "User not set"});
                return;
            }
            const auto &oldPassword = userNameAndPassword->second;
            if (!request.has_new_password())
            {
                Finish({grpc::StatusCode::INVALID_ARGUMENT,
                        "New password not set"});
                //metrics.incrementClientErrorCounter(mRouteName);
                return;
            }
            const std::pair<std::string, std::string> currentCredentials
            {
                user,
                oldPassword
            };
            const auto &newPassword{request.new_password()};
            auto changeResult
                = loginAuthority.changePassword(currentCredentials,
                                                newPassword); 
            if (!changeResult.has_value())
            {
                if (changeResult.error() == 
                    UAuth::UserLoginAuthority::ChangePasswordError::
                    Unauthenticated)
                {
                    Finish({grpc::StatusCode::UNAUTHENTICATED,
                            "Current password likely wrong"});
                }
                else if (changeResult.error() ==  
                          UAuth::UserLoginAuthority::ChangePasswordError::
                          PasswordTooShort)
                {
                    Finish({grpc::StatusCode::INVALID_ARGUMENT,
                            "New password too short"});
                }
                else if (changeResult.error() ==
                          UAuth::UserLoginAuthority::ChangePasswordError::
                          PasswordTooLong)
                {   
                    Finish({grpc::StatusCode::INVALID_ARGUMENT,
                            "New password too long"});
                }
                else if (changeResult.error() ==
                          UAuth::UserLoginAuthority::ChangePasswordError::
                          PasswordNeedsNumber)
                {   
                    Finish({grpc::StatusCode::INVALID_ARGUMENT,
                            "New password requires a number"});
                }
                else if (changeResult.error() ==
                          UAuth::UserLoginAuthority::ChangePasswordError::
                          PasswordNeedsSpecialCharacter)
                {   
                    Finish({grpc::StatusCode::INVALID_ARGUMENT,
                            "New password requires a special character"});
                }
                else if (changeResult.error() ==
                          UAuth::UserLoginAuthority::ChangePasswordError::
                          PasswordsMatch)
                {   
                    Finish({grpc::StatusCode::INVALID_ARGUMENT,
                            "New and old password match"});
                }
                else
                {
                    Finish({grpc::StatusCode::INTERNAL,
                            "Could not change password - contact maintainer"});
                }
                return;
            }

            mSuccess = true;
            SPDLOG_LOGGER_DEBUG(
                mLogger,
                "{} successfully changed password",
                requestIdentifier);
            Finish(grpc::Status::OK);
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
                       *pImpl->mLoginAuthority,
                       pImpl->mLogger);
    
}   

///-------------------------Password Requirements----------------------------///
grpc::ServerUnaryReactor
*AuthService::GetPasswordRequirements(
    grpc::CallbackServerContext *context,
    const UEventAnalysisToolAPI::Auth::V1::GetPasswordRequirementsRequest *request,
    UEventAnalysisToolAPI::Auth::V1::PasswordRequirements *response)
{
    namespace UAuthV1 = UEventAnalysisToolAPI::Auth::V1;
    class Reactor : public grpc::ServerUnaryReactor
    {   
    public:
        Reactor(UAuthV1::PasswordRequirements *response,
                grpc::CallbackServerContext *context,
                const UAuthV1::GetPasswordRequirementsRequest &request,
                UAuth::Password::PasswordPolicy &policy,
                std::shared_ptr<spdlog::logger> logger) :
            mLogger(std::move(logger))
        {
            *response = policy.toMessage<UAuthV1::PasswordRequirements> ();

            mSuccess = true;
            SPDLOG_LOGGER_DEBUG(
                mLogger,
                "Successfully retrieved password requirement for request {}",
                GRPC::toRequestIdentifier(*context));
            Finish(grpc::Status::OK);
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
        const std::string mRouteName{"GetPasswordRequirements"};
        bool mSuccess{false};
    };
    auto policy = pImpl->mLoginAuthority->getPasswordPolicy();
    return new Reactor(response,
                       context,
                       *request,
                       policy,
                       pImpl->mLogger);

}

/// Destructor
AuthService::~AuthService() = default;
