#include <chrono>
#include <exception>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>
#include <spdlog/spdlog.h>
#include <spdlog/logger.h>
//NOLINTNEXTLINE(misc-include-cleaner)
#include <spdlog/sinks/stdout_color_sinks.h>
#include <grpcpp/server_context.h>
#include <grpcpp/support/server_callback.h>
#include <grpcpp/support/status.h>
#include <jwt-cpp/jwt.h>
#include <jwt-cpp/traits/boost-json/traits.h>
#include "uEventAnalysisToolBackend/services/authService.hpp"
#include "uEventAnalysisToolBackend/auth/authenticator.hpp"
#include "uEventAnalysisToolBackend/auth/userList.hpp"
#include "uEventAnalysisToolBackend/auth/userLoginAuthority.hpp"
#include "uEventAnalysisToolBackend/auth/userTokenVerifier.hpp"
#include "uEventAnalysisToolBackend/auth/password/passwordPolicy.hpp"
#include "uEventAnalysisToolBackend/grpc/clientVersion.hpp"
#include "uEventAnalysisToolBackend/grpc/parseAuthorizationHeader.hpp"
#include "uEventAnalysisToolBackend/grpc/requireBearer.hpp"
#include "uEventAnalysisToolBackend/grpc/toRequestIdentifier.hpp"
#include "uEventAnalysisToolBackend/grpc/unaryReactor.hpp"
#include <uEventAnalysisToolAPI/auth/v1/service.grpc.pb.h>
#include <uEventAnalysisToolAPI/auth/v1/add_key_request.pb.h>
#include <uEventAnalysisToolAPI/auth/v1/add_key_response.pb.h>
#include <uEventAnalysisToolAPI/auth/v1/change_password_request.pb.h>
#include <uEventAnalysisToolAPI/auth/v1/change_password_response.pb.h>
#include <uEventAnalysisToolAPI/auth/v1/list_keys_request.pb.h>
#include <uEventAnalysisToolAPI/auth/v1/list_keys_response.pb.h>
#include <uEventAnalysisToolAPI/auth/v1/login_with_key_request.pb.h>
#include <uEventAnalysisToolAPI/auth/v1/login_with_key_response.pb.h>
#include <uEventAnalysisToolAPI/auth/v1/login_with_password_request.pb.h>
#include <uEventAnalysisToolAPI/auth/v1/login_with_password_response.pb.h>
#include <uEventAnalysisToolAPI/auth/v1/get_password_requirements_request.pb.h>
#include <uEventAnalysisToolAPI/auth/v1/password_requirements.pb.h>
#include <uEventAnalysisToolAPI/auth/v1/revoke_key_request.pb.h>
#include <uEventAnalysisToolAPI/auth/v1/revoke_key_response.pb.h>
#include <uEventAnalysisToolAPI/auth/v1/signature_algorithm.pb.h>

using namespace UEventAnalysisToolBackend::Services;

namespace UAuth = UEventAnalysisToolBackend::Auth;

namespace
{
grpc::Status enumToStatus(const UAuth::UserLoginAuthority::KeyError code,
                          const std::string &keyName)
{
    if (code ==
        UAuth::UserLoginAuthority::KeyError::Unauthenticated)
    {
        return {grpc::StatusCode::UNAUTHENTICATED,
                "Invalid credentials"};
    }
    else if (code ==
             UAuth::UserLoginAuthority::KeyError::PasswordChangeRequired)
    {
        return {grpc::StatusCode::FAILED_PRECONDITION,
                "Password change required before adding a key"};
    }
    else if (code ==
             UAuth::UserLoginAuthority::KeyError::InvalidName)
    {
        return {grpc::StatusCode::INVALID_ARGUMENT,
                "Invalid key name - use 1 to 64 of a-z, 0-9, '.', '_', '@', '-'"};
    }
    else if (code ==
             UAuth::UserLoginAuthority::KeyError::InvalidKey)
    {
        return {grpc::StatusCode::INVALID_ARGUMENT,
                "Invalid public key or proof of possession"};
    }
    else if (code ==
             UAuth::UserLoginAuthority::KeyError::InvalidExpiration)
    {
        return {grpc::StatusCode::INVALID_ARGUMENT,
                "Invalid expiration - must be positive and within the maximum key lifetime"};
    }
    else if (code ==
             UAuth::UserLoginAuthority::KeyError::NameInUse)
    {
        return {grpc::StatusCode::ALREADY_EXISTS,
                "Key " + keyName + " already exists"};
    }
    else if (code ==
             UAuth::UserLoginAuthority::KeyError::KeyInUse)
    {
        return {grpc::StatusCode::ALREADY_EXISTS,
                "Public key is already registered"};
    }
    else if (code ==
             UAuth::UserLoginAuthority::KeyError::NoKeyFound)
    {
        return {grpc::StatusCode::NOT_FOUND,
                "No active key named " + keyName};
    }
    else if (code ==
             UAuth::UserLoginAuthority::KeyError::TooManyKeys)
    {
        return {grpc::StatusCode::RESOURCE_EXHAUSTED,
                "Active key limit reached - revoke a key first"};
    }
    else if (code ==
             UAuth::UserLoginAuthority::KeyError::ServerError)
    {
        return {grpc::StatusCode::INTERNAL,
                "Server error - contact maintainer"};
    }
    return {grpc::StatusCode::INTERNAL,
            "Unhandled status code - server error - contact maintainer"};
}
}

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
            throw std::invalid_argument("Token verifier is null");
        }
        if (!mTokenVerifier->isInitialized())
        {
            throw std::invalid_argument("Token verifier not initialized");
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
    std::optional<GRPC::ClientVersion> mMinimumClientVersion{std::nullopt};
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
                const std::optional<GRPC::ClientVersion> &minimumClientVersion,
                std::shared_ptr<spdlog::logger> logger) :
            mLogger(std::move(logger))
        {
            auto requestIdentifier = GRPC::toRequestIdentifier(*context);
            // Check min version?
            if (minimumClientVersion != std::nullopt)
            {
                auto header 
                    = context->client_metadata().find("x-client-version");
                if (header == context->client_metadata().end())
                {
                    context->AddTrailingMetadata(
                        "x-minimum-client-version",
                        minimumClientVersion->toString());
                    Finish({grpc::StatusCode::INVALID_ARGUMENT,
                            "x-client-version not set in header"});
                    return;
                }
                const auto clientVersion
                    = GRPC::ClientVersion::parse(
                          std::string_view {header->second.data(),
                                            header->second.size()});
                if (!clientVersion)
                {
                    Finish({grpc::StatusCode::INVALID_ARGUMENT,
                            "x-client-version must be MAJOR.MINOR.PATCH"});
                    return;
                }
                if (clientVersion < *minimumClientVersion)
                {
                    Finish({grpc::StatusCode::FAILED_PRECONDITION,
                           "x-client-version must be at least "
                          + minimumClientVersion->toString()});
                    return;
                }
            }

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
                else
                {
                    SPDLOG_LOGGER_ERROR(mLogger,
                        "Failed to process {}; {} not logged in; unhandled error code",
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
                "{}: {} successfully logged in with password",
                requestIdentifier, userNameAndPassword->first);
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
                       pImpl->mMinimumClientVersion,
                       pImpl->mLogger);

}

///---------------------------Login With Key-------------------------------///
grpc::ServerUnaryReactor
*AuthService::LoginWithKey(
    grpc::CallbackServerContext *context,
    const UEventAnalysisToolAPI::Auth::V1::LoginWithKeyRequest *request,
    UEventAnalysisToolAPI::Auth::V1::LoginWithKeyResponse *response)
{
    namespace UAuthV1 = UEventAnalysisToolAPI::Auth::V1;
    class Reactor : public grpc::ServerUnaryReactor
    {   
    public:
        Reactor(UAuthV1::LoginWithKeyResponse *response,
                grpc::CallbackServerContext *context,
                const UAuthV1::LoginWithKeyRequest &request,
                std::shared_ptr<UAuth::UserLoginAuthority> &loginAuthority,
                std::shared_ptr<spdlog::logger> logger) :
            mLogger(std::move(logger))
        {
            auto requestIdentifier = GRPC::toRequestIdentifier(*context);
            if (!request.has_public_key())
            {
                //metrics.incrementUnauthenticated(mRouteName);
                Finish({grpc::StatusCode::UNAUTHENTICATED,
                        "Public key not provided"});
                return;
            }
            if (request.public_key().empty())
            {
                //metrics.incrementUnauthenticated(mRouteName);
                Finish({grpc::StatusCode::UNAUTHENTICATED,
                        "Public key is empty"});
                return;
            }
            if (!request.has_assertion())
            {
                //metrics.incrementUnauthenticated(mRouteName);
                Finish({grpc::StatusCode::UNAUTHENTICATED,
                        "Assertion not provided"});
                return;
            }
            if (request.assertion().empty())
            {
                //metrics.incrementUnauthenticated(mRouteName);
                Finish({grpc::StatusCode::UNAUTHENTICATED,
                        "Assertion is empty"});
                return;
            }
 
            const std::vector<unsigned char>
                publicKey{request.public_key().data(),
                          request.public_key().data()
                        + request.public_key().size()};
            auto loginResult
                = loginAuthority->loginWithKey(publicKey,
                                               request.assertion());
            if (loginResult.has_value())
            {
                // Try to lift the user name from the token
                std::string user;
                try
                {
                    const auto decoded
                        = jwt::decode<jwt::traits::boost_json> (*loginResult);
                    if (decoded.has_subject()){user = decoded.get_subject();} 
                }
                catch (const std::exception &e)
                {
                    SPDLOG_LOGGER_WARN(mLogger,
                        "{}: could not decode minted token because {}",
                        requestIdentifier, e.what());
                }

                if (!user.empty())
                {
                    SPDLOG_LOGGER_INFO(mLogger,
                        "{}: {} logged in",
                        requestIdentifier, user);
                }
                else
                {
                    SPDLOG_LOGGER_INFO(mLogger,
                        "{}: logged in user but could not determine name",
                        requestIdentifier);
                }
                response->set_json_web_token(*loginResult);
            }
            else
            {
                if (loginResult.error() ==
                    Auth::IAuthenticator::Result::InvalidCredentials)
                {
                    SPDLOG_LOGGER_WARN(mLogger,
                        "{} rejected; invalid key credentials",
                        requestIdentifier);
                    //metrics.incrementUnauthenticatedCounter(mRouteName);
                    Finish({grpc::StatusCode::UNAUTHENTICATED,
                           "Invalid credentials"});
                    return;
                }
                else if (loginResult.error() ==
                         Auth::IAuthenticator::Result::ServerError)
                {
                    SPDLOG_LOGGER_ERROR(mLogger,
                        "Failed to process {}; could not auth user with key",
                        requestIdentifier);
                }
                else
                {
                    SPDLOG_LOGGER_ERROR(mLogger,
                        "Failed to process {}; unhandled error code",
                        requestIdentifier);
                }
                //metrics.incrementServerErrorCounter(mRouteName);
                Finish({grpc::StatusCode::INTERNAL,
                        "Server error during login - contact maintainer"});
                return;
            }
            mSuccess = true;
            SPDLOG_LOGGER_DEBUG(
                mLogger,
                "{}: successfully logged in with key",
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
        const std::string mRouteName{"LoginWithKey"};
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

///-----------------------------------Add Key--------------------------------///
grpc::ServerUnaryReactor
*AuthService::AddKey(
    grpc::CallbackServerContext *context,
    const UEventAnalysisToolAPI::Auth::V1::AddKeyRequest *request,
    UEventAnalysisToolAPI::Auth::V1::AddKeyResponse *response)
{
    namespace UAuthV1 = UEventAnalysisToolAPI::Auth::V1;
    class Reactor final : public GRPC::UnaryReactor
    {
    public:
        Reactor(UAuthV1::AddKeyResponse *, //response,
                grpc::CallbackServerContext *context,
                const UAuthV1::AddKeyRequest &request,
                UAuth::UserLoginAuthority &loginAuthority,
                std::shared_ptr<spdlog::logger> loggerPtr) :
            UnaryReactor(context, "Auth.V1.AddKey", std::move(loggerPtr))
        {
            run([&]() -> grpc::Status
            {
                // Extract the username and password from Basic
                auto basicField
                    = context->client_metadata().find("authorization");
                if (basicField == context->client_metadata().end())
                {
                    return {grpc::StatusCode::UNAUTHENTICATED,
                            "No authorization header field specified"};
                }
                auto userNameAndPassword
                    = GRPC::authorizationHeaderToUserNameAndPassword(
                         basicField->second);
                if (!userNameAndPassword.has_value())
                {
                    return userNameAndPassword.error();
                }
                if (!request.has_name())
                {
                     return {grpc::StatusCode::INVALID_ARGUMENT,
                             "Key name not set"};
                }
                if (!request.has_public_key())
                {
                     return {grpc::StatusCode::INVALID_ARGUMENT,
                             "Public key not set"};
                }
                if (!request.has_assertion())
                {
                     return {grpc::StatusCode::INVALID_ARGUMENT,
                             "Assertion not set"};
                }
                if (!request.has_algorithm())
                {
                    return {grpc::StatusCode::INVALID_ARGUMENT,
                            "Algorithm not set"};
                }
                if (request.algorithm()
                    != UAuthV1::SignatureAlgorithm::SIGNATURE_ALGORITHM_ED25519)
                {
                    return {grpc::StatusCode::INVALID_ARGUMENT,
                            "Unsupported signature algorithm - only ed25519"};
                }
                std::optional<std::chrono::seconds> expiresAfter{std::nullopt};
                if (request.has_expires_after())
                {
                    // N.B. this drops fractional part
                    expiresAfter
                        = std::chrono::seconds {request.expires_after().seconds()};
                }
                const std::vector<unsigned char>
                    publicKey{request.public_key().data(),
                              request.public_key().data()
                            + request.public_key().size()};
                auto result
                    = loginAuthority.addKey(
                         *userNameAndPassword,
                         request.name(),
                         publicKey,
                         request.assertion(),
                         expiresAfter);
                if (!result.has_value())
                {
                    SPDLOG_LOGGER_WARN(&logger(),
                                       "{} - {} could not add key {}",
                                       requestIdentifier(),
                                       userNameAndPassword->first,
                                       request.name());
                    return ::enumToStatus(result.error(), request.name());
                }
                SPDLOG_LOGGER_INFO(&logger(),
                                   "{} - {} added key {}",
                                   requestIdentifier(),
                                   userNameAndPassword->first,
                                   request.name()); 
                return grpc::Status::OK;
            });
        }
    };
    return new Reactor(response,
                       context,
                       *request,
                       *pImpl->mLoginAuthority,
                       pImpl->mLogger);

}


///----------------------------------List Keys-------------------------------///
grpc::ServerUnaryReactor
*AuthService::ListKeys(
    grpc::CallbackServerContext *context,
    const UEventAnalysisToolAPI::Auth::V1::ListKeysRequest *request,
    UEventAnalysisToolAPI::Auth::V1::ListKeysResponse *response)
{
    namespace UAuthV1 = UEventAnalysisToolAPI::Auth::V1;
    class Reactor final : public GRPC::UnaryReactor
    {
    public:
        Reactor(UAuthV1::ListKeysResponse *response,
                grpc::CallbackServerContext *context,
                const UAuthV1::ListKeysRequest &request,
                UAuth::UserLoginAuthority &loginAuthority,
                const UAuth::UserTokenVerifier &verifier,
                std::shared_ptr<spdlog::logger> loggerPtr) :
            UnaryReactor(context,
                         "Auth.V1.ListKeys",
                         std::move(loggerPtr),
                         verifier)
        {   
            if (!isAuthenticated()){return;}
            run([&]() -> grpc::Status
            {
                const auto &user = getClaims()->getUser();
                auto result = loginAuthority.listKeys(user);
                if (!result.has_value())
                {
                    return ::enumToStatus(result.error(), "");
                }
                for (const auto &key : result->first)
                {
                    response->mutable_active_keys()->Add(
                        key.toMessage<UAuthV1::ListKeysResponse::ActiveKey>()
                    );
                }
                for (const auto &key : result->second)
                {
                    response->mutable_inactive_keys()->Add(
                       key.toMessage<UAuthV1::ListKeysResponse::InactiveKey> ()
                    );
                }
                SPDLOG_LOGGER_DEBUG(&logger(),
                                    "{} - listed keys for {}",
                                    requestIdentifier(),
                                    user);
                return grpc::Status::OK;
            });
        }
    };
    return new Reactor(response,
                       context,
                       *request,
                       *pImpl->mLoginAuthority,
                       *pImpl->mTokenVerifier,
                       pImpl->mLogger);
}

///----------------------------------Revoke Key------------------------------///
grpc::ServerUnaryReactor
*AuthService::RevokeKey(
    grpc::CallbackServerContext *context,
    const UEventAnalysisToolAPI::Auth::V1::RevokeKeyRequest *request,
    UEventAnalysisToolAPI::Auth::V1::RevokeKeyResponse *response)
{
    namespace UAuthV1 = UEventAnalysisToolAPI::Auth::V1;
    class Reactor final : public GRPC::UnaryReactor
    {   
    public:
        Reactor(UAuthV1::RevokeKeyResponse *response,
                grpc::CallbackServerContext *context,
                const UAuthV1::RevokeKeyRequest &request,
                UAuth::UserLoginAuthority &loginAuthority,
                const UAuth::UserTokenVerifier &verifier,
                std::shared_ptr<spdlog::logger> loggerPtr) :
            UnaryReactor(context,
                         "Auth.V1.RevokeKey",
                         std::move(loggerPtr),
                         verifier)
        {
            if (!isAuthenticated()){return;}
            run([&]() -> grpc::Status
            {
                const auto &user = getClaims()->getUser();
                if (!request.has_name())
                {
                    return {grpc::StatusCode::INVALID_ARGUMENT,
                            "Key name is required"};
                }
                auto result
                    = loginAuthority.revokeKey(user, request.name());
                if (!result.has_value())
                {
                    return ::enumToStatus(result.error(), request.name());
                }
                SPDLOG_LOGGER_INFO(&logger(),
                                   "{} - {} revoked key {}",
                                   requestIdentifier(),
                                   user,
                                   request.name());
                return grpc::Status::OK;
            });
        }
    };
    return new Reactor(response,
                       context,
                       *request,
                       *pImpl->mLoginAuthority,
                       *pImpl->mTokenVerifier,
                       pImpl->mLogger);
}


/// Destructor
AuthService::~AuthService() = default;
