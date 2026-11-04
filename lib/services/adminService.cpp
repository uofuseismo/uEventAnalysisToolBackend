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
#include "uEventAnalysisToolBackend/auth/userAdministration.hpp"
#include "uEventAnalysisToolBackend/auth/userTokenVerifier.hpp"
#include "uEventAnalysisToolBackend/auth/authenticator.hpp"
#include "uEventAnalysisToolBackend/grpc/requireBearer.hpp"
//#include "uEventAnalysisToolBackend/grpc/parseAuthorizationHeader.hpp"
#include "uEventAnalysisToolBackend/grpc/toRequestIdentifier.hpp"
#include "uEventAnalysisToolBackend/grpc/unaryReactor.hpp"
#include <uEventAnalysisToolAPI/admin/v1/service.grpc.pb.h>
#include <uEventAnalysisToolAPI/admin/v1/create_user_request.pb.h>
#include <uEventAnalysisToolAPI/admin/v1/create_user_response.pb.h>
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
        std::shared_ptr<UAuth::AdministratorTokenVerifier> adminTokenVerifier,
        std::shared_ptr<UAuth::UserTokenVerifier> userTokenVerifier,
        std::shared_ptr<spdlog::logger> logger
    ) :
        mLoginAuthority(std::move(loginAuthority)),
        mAdministratorTokenVerifier(std::move(adminTokenVerifier)),
        mUserTokenVerifier(std::move(userTokenVerifier)),
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
        if (mAdministratorTokenVerifier == nullptr)
        {
            throw std::invalid_argument("Admin token verifier is null");
        }
        if (!mAdministratorTokenVerifier->isInitialized())
        {
            throw std::invalid_argument("Admin token verifier not initialized");
        }
        if (mUserTokenVerifier == nullptr)
        {
            throw std::invalid_argument("User token verifier is null");
        }
        if (!mUserTokenVerifier->isInitialized())
        {
            throw std::invalid_argument("User token verifier not initialized");
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
    std::shared_ptr<UAuth::AdministratorTokenVerifier>
        mAdministratorTokenVerifier{nullptr};
    std::shared_ptr<UAuth::UserAdministration> 
        mUserAdministration{nullptr};
    std::shared_ptr<UAuth::UserTokenVerifier>
        mUserTokenVerifier{nullptr};
    std::shared_ptr<spdlog::logger> mLogger{nullptr};
};

/// Constructor
AdminService::AdminService
(
    std::shared_ptr<UAuth::AdministratorLoginAuthority> loginAuthority,
    std::shared_ptr<UAuth::AdministratorTokenVerifier> adminTokenVerifier,
    std::shared_ptr<UAuth::UserTokenVerifier> userTokenVerifier,
    std::shared_ptr<spdlog::logger> logger
) :
    pImpl(std::make_unique<AdminServiceImpl>
          (std::move(loginAuthority),
           std::move(adminTokenVerifier),
           std::move(userTokenVerifier),
           std::move(logger)))
{
}

///--------------------------------Admin Login-------------------------------///
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
                const UAuth::UserTokenVerifier &userTokenVerifier,
                std::shared_ptr<spdlog::logger> logger) :
            mLogger(std::move(logger))
        {
            auto requestIdentifier = GRPC::toRequestIdentifier(*context);
            auto bearerResult
                = GRPC::requireBearer(*context, userTokenVerifier);
            if (!bearerResult.has_value())
            {
                //metrics.incrementUnauthenticatedCounter(mRouteName);
                SPDLOG_LOGGER_WARN(mLogger,
                    "{} did not provide bearer authorization - rejected",
                     requestIdentifier);
                Finish(bearerResult.error());
                return;
            }

            auto user = bearerResult->getUser();
            std::string password{""};
            // Despite being awful stupid the password can be empty
            if (request.has_password()){password = request.password();}
            // Check the user
            try
            {
                auto result
                    = loginAuthority.loginWithPassword(
                        *bearerResult, password);
                if (result)
                {
                    SPDLOG_LOGGER_INFO(mLogger,
                                       "Processed {}; {} logged in as admin",
                                       requestIdentifier,
                                       user);
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
                                 user);
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
                     requestIdentifier,
                     e.what());
                Finish({grpc::StatusCode::INTERNAL,
                        "Server error - contact maintainer"});
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
                       *pImpl->mLoginAuthority,
                       *pImpl->mUserTokenVerifier,
                       pImpl->mLogger);
}

///------------------------------Create User---------------------------------///
grpc::ServerUnaryReactor
*AdminService::CreateUser(
    grpc::CallbackServerContext *context,
    const UEventAnalysisToolAPI::Admin::V1::CreateUserRequest *request,
    UEventAnalysisToolAPI::Admin::V1::CreateUserResponse *response)
{
    namespace UAdminV1 = UEventAnalysisToolAPI::Admin::V1;
    class Reactor final : public GRPC::UnaryReactor
    {
    public:
        Reactor(UAdminV1::CreateUserResponse *response,
                grpc::CallbackServerContext *context,
                const UAdminV1::CreateUserRequest &request,
                UAuth::UserAdministration &administration,
                const UAuth::AdministratorTokenVerifier &verifier,
                std::shared_ptr<spdlog::logger> loggerPtr) :
            UnaryReactor(context,
                         "Admin.V1.CreateUser",
                         std::move(loggerPtr),
                         verifier)
        {
            if (!isAuthenticated()){return;}
            run([&]() -> grpc::Status
            {
                const auto &actor = getClaims()->getUser();
                if (request.name().empty())
                {
                    return {grpc::StatusCode::INVALID_ARGUMENT,
                            "User name is required"};
                }
                auto result
                    = administration.createProvisionalUser(actor,
                                                           request.name());
                if (!result.has_value())
                {
/*
                    if (result.error() ==
                        UAuth::ReturnCode::AlreadyExists)
                    {
                        return {grpc::StatusCode::ALREADY_EXISTS,
                                "User " + request.name() + " already exists"};
                    }
                    else if (result.error() ==
                             UAuth::ReturnCode::NotAuthorized)
                    {
                        return {grpc::StatusCode::PERMISSION_DENIED,
                                "Not an administrator"};
                    }
                    else if (result.error() ==
                             UAuth::ReturnCode::InvalidArgument)
                    { 
                        return {grpc::StatusCode::INVALID_ARGUMENT,
                                "Invalid user name"};
                    }
                    else if (result.error() ==
                             UAuth::ReturnCode::ServerError)
                    {
                        return {grpc::StatusCode::INTERNAL,
                                "Server error - contact maintainer"};
                    }
*/
                    return {grpc::StatusCode::INTERNAL,
                            "Server error - contact maintainer"};
                }
                SPDLOG_LOGGER_INFO(&logger(),
                                   "{} created provisional user {}",
                                   actor, request.name());
//                response->set_user(request.name());
                response->set_temporary_password(
                    std::move(result->issuedPassword));
                return grpc::Status::OK;
            });
        };
    };
    return new Reactor(response,
                       context,
                       *request,
                       *pImpl->mUserAdministration,
                       *pImpl->mAdministratorTokenVerifier,
                       pImpl->mLogger);
}

/// Destructor
AdminService::~AdminService() = default;

