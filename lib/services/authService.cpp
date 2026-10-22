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
#include "uEventAnalysisToolBackend/auth/authNZ.hpp"
#include "uEventAnalysisToolBackend/auth/database.hpp"
#include "uEventAnalysisToolBackend/grpc/parseAuthorizationHeader.hpp"
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
    namespace UAuthV1 = UEventAnalysisToolAPI::Auth::V1;
    class Reactor : public grpc::ServerUnaryReactor
    {
    public:
        Reactor(UAuthV1::LoginWithPasswordResponse *response,
                grpc::CallbackServerContext *context,
                const UAuthV1::LoginWithPasswordRequest &request,
                std::shared_ptr<UAuth::AuthNZ> &authenticator,
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
                       pImpl->mAuthNZ,
                       pImpl->mLogger);

}

/// Destructor
AuthService::~AuthService() = default;
