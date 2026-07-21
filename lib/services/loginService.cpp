#include <chrono>
#include <exception>
#include <memory> 
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>
#include <boost/algorithm/string/split.hpp>
#include <boost/algorithm/string/classification.hpp>
#include <spdlog/spdlog.h>
#include <spdlog/logger.h>
#include <spdlog/sinks/stdout_color_sinks.h> //NOLINT
#include <grpcpp/server_context.h>
#include <grpcpp/support/server_callback.h>
#include <grpcpp/support/status.h>
#include <uEventAnalysisToolAPI/v1/login/basic_request.pb.h>
#include <uEventAnalysisToolAPI/v1/login/basic_response.pb.h>
#include "uEventAnalysisToolBackend/services/loginService.hpp"
#include "uEventAnalysisToolBackend/auth/grpc.hpp"

using namespace UEventAnalysisToolBackend::Services;

namespace
{

struct MajorMinorPatch
{
    explicit MajorMinorPatch(const std::string &version) :
        str(version)
    {
        std::vector<std::string> split;
        boost::algorithm::split(split, version, boost::is_any_of("."));
        if (split.size() != 3)
        {
            throw std::invalid_argument("Version string invalid");
        }
        major = std::stoi(split[0]);
        minor = std::stoi(split[1]);
        patch = std::stoi(split[2]);
    }
    /// Check if the candidate match
    /// @result True indicates the other version is at least as 'high'
    ///         as this version.
    [[nodiscard]] bool isAtLeast(const MajorMinorPatch &other) const noexcept
    {
         if (other.major < major){return false;}
         if (other.major > major){return true;}
         if (other.minor < minor){return false;}
         if (other.minor > minor){return true;}
         return other.patch >= patch;
    }
    std::string str;
    int major{0};
    int minor{0};
    int patch{0};
};

class BasicLoginReactor : public grpc::ServerUnaryReactor
{
public:
    BasicLoginReactor(
        UEventAnalysisToolAPI::V1::Login::BasicResponse *response,
        grpc::CallbackServerContext *context,
        const UEventAnalysisToolAPI::V1::Login::BasicRequest &request,
        const UEventAnalysisToolBackend::Auth::AuthNZ &authNZ,
        std::shared_ptr<spdlog::logger> logger
    ) :
        mLogger(std::move(logger)),
        mPeer(context->peer())
    {
        // Manage the version
        std::string messages;
        try
        {
            const ::MajorMinorPatch version{request.version()};
            if (!mMinimumRequiredVersion.isAtLeast(version))
            {
                SPDLOG_LOGGER_WARN(mLogger,
                   "Rejecting {} because frontend insufficient version",
                    mPeer);
                messages
                    = "You must upgrade your frontend version to at least v"
                    + mMinimumRequiredVersion.str
                    + ".  Check the git repo builds.";
                Finish({grpc::StatusCode::INVALID_ARGUMENT, messages});
                return;
            }
            if (!mRecommendedVersion.isAtLeast(version))
            {
                 messages = "It is recommended you upgrade to version v"
                          + mRecommendedVersion.str
                          + " of the frontend.  Check the git repo builds.";
            }
        }
        catch (const std::exception &e)
        {
            SPDLOG_LOGGER_WARN(mLogger,
               "{} offered invalid version string.  Parser failed with {}",
               mPeer, e.what());
            Finish({grpc::StatusCode::INVALID_ARGUMENT,
                   "Version string must of form XXX.YYY.ZZZ"});
            return;
        }

        // Now login 
        auto jwt
            = UEventAnalysisToolBackend::Auth::loginBasic(
                 authNZ, *context, mLogger.get());
        if (!jwt.has_value())
        {
            SPDLOG_LOGGER_DEBUG(mLogger,
                                "BasicLoginReactor failed for {}",
                                 mPeer);
            mSuccess = false;
            Finish(std::move(jwt.error()));
            return;
        }
        // Success - finish populating resonse
        if (request.has_identifier())
        {
            *response->mutable_identifier() = request.identifier();
        }
        *response->mutable_json_web_token() = std::move(*jwt);
        *response->mutable_details() = std::move(messages);
        mSuccess = true;
        SPDLOG_LOGGER_DEBUG(mLogger,
                            "BasicLoginSuccessful for {}",
                            mPeer);
        Finish(grpc::Status::OK);
    }
private:
    // Done
    void OnDone() override
    {
        SPDLOG_LOGGER_DEBUG(mLogger,
                            "BasicLogin RPC completed for {}",
                            mPeer);
        // Update metrics
        if (mSuccess)
        {
            auto endTime
                = std::chrono::duration_cast<std::chrono::nanoseconds>
                  ((std::chrono::high_resolution_clock::now()).time_since_epoch());
            auto elapsedTime
                = static_cast<double>
                  (endTime.count() - mRPCStartTime.count())*1.e-9;
        }
        delete this;
    }

    // Cancel
    void OnCancel() override
    {
        SPDLOG_LOGGER_DEBUG(mLogger,
                            "BasicLogin canceled by {}",
                            mPeer);
    }
//private:
    std::shared_ptr<spdlog::logger> mLogger{nullptr};
    // Frontend must be at this version
    ::MajorMinorPatch mMinimumRequiredVersion{"0.0.0"};
    // Prefer the frontend be at this version
    ::MajorMinorPatch mRecommendedVersion{"0.0.0"};
    std::string mPeer;
    std::chrono::nanoseconds mRPCStartTime
    {
        std::chrono::duration_cast<std::chrono::nanoseconds>
        ((std::chrono::high_resolution_clock::now()).time_since_epoch())
    };
    bool mSuccess{false};
};

}

///--------------------------------------------------------------------------///
///                               Actual Class                               ///
///--------------------------------------------------------------------------///

class LoginService::LoginServiceImpl
{
public:
    LoginServiceImpl(
        std::shared_ptr<UEventAnalysisToolBackend::Auth::AuthNZ> authNZ,
        std::shared_ptr<spdlog::logger> logger
    ) :
        mAuthNZ(std::move(authNZ)),
        mLogger(std::move(logger))
    {
        if (mAuthNZ == nullptr)
        {
            throw std::runtime_error("AuthNZ is null");
        }
        if (mLogger == nullptr)
        {
            // NOLINTBEGIN(misc-include-cleaner)
            constexpr const char *loggerName{"LoginServiceConsole"};
            mLogger = spdlog::get(loggerName);
            if (mLogger == nullptr)
            {   
                mLogger = spdlog::stdout_color_mt(loggerName);
            }
            // NOLINTEND(misc-include-cleaner)
        }
    }
//private:
    std::shared_ptr<UEventAnalysisToolBackend::Auth::AuthNZ> mAuthNZ;
    std::shared_ptr<spdlog::logger> mLogger;
};

/// Constructor
LoginService::LoginService(
        std::shared_ptr<UEventAnalysisToolBackend::Auth::AuthNZ> authNZ,
        std::shared_ptr<spdlog::logger> logger
    ) :
    pImpl(std::make_unique<LoginServiceImpl> (std::move(authNZ), 
                                              std::move(logger)))
{
}

/// Basic login RPC
grpc::ServerUnaryReactor *LoginService::BasicLogin(
    grpc::CallbackServerContext *context,
    const UEventAnalysisToolAPI::V1::Login::BasicRequest *request,
    UEventAnalysisToolAPI::V1::Login::BasicResponse *response)
{
    return new ::BasicLoginReactor(response,
                                   context,
                                   *request,
                                   *pImpl->mAuthNZ,
                                   pImpl->mLogger);
}

/// Destructor
LoginService::~LoginService() = default;
