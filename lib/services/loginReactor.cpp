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
#include <grpcpp/server_context.h>
#include <grpcpp/support/status.h>
#include <uEventAnalysisToolAPI/v1/login/basic_request.pb.h>
#include <uEventAnalysisToolAPI/v1/login/basic_response.pb.h>
#include "uEventAnalysisToolBackend/services/loginReactor.hpp"
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
         if (major < other.major){return false;}
         if (major > other.major){return true;}
         if (minor < other.minor){return false;}
         if (minor > other.minor){return true;}
         if (patch < other.patch){return false;}
         return true;
    }
    std::string str;
    int major{0};
    int minor{0};
    int patch{0};
};

}

class BasicLoginReactor::Impl
{
public:
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

BasicLoginReactor::BasicLoginReactor(
    UEventAnalysisToolAPI::V1::Login::BasicResponse *response,
    grpc::CallbackServerContext *context,
    const UEventAnalysisToolAPI::V1::Login::BasicRequest &request,
    const UEventAnalysisToolBackend::Auth::AuthNZ &authNZ,
    std::shared_ptr<spdlog::logger> logger
) :
    pImpl(std::make_unique<Impl> ())
{
    pImpl->mLogger = std::move(logger);
    pImpl->mPeer = context->peer();

    // Manage the version
    std::string messages;
    try
    {
        const ::MajorMinorPatch version{request.version()};
        if (!pImpl->mMinimumRequiredVersion.isAtLeast(version))
        {
            if (pImpl->mLogger)
            {
                SPDLOG_LOGGER_WARN(pImpl->mLogger,
                   "Rejecting {} because frontend insufficient version",
                   pImpl->mPeer); 
            }
            messages = "You must upgrade your frontend version to at least v"
                     + pImpl->mMinimumRequiredVersion.str 
                     + ".  Check the git repo builds.";
            Finish({grpc::StatusCode::INVALID_ARGUMENT, messages});
            return;
        }
        if (!pImpl->mRecommendedVersion.isAtLeast(version))
        {
             messages = "It is recommended you upgrade to version v"
                      + pImpl->mRecommendedVersion.str
                      + " of the frontend.  Check the git repo builds.";
        }
    }
    catch (const std::exception &e)
    {
        if (pImpl->mLogger)
        {
            SPDLOG_LOGGER_WARN(pImpl->mLogger,
               "{} offered invalid version string.  Parser failed with {}",
               pImpl->mPeer, e.what());
        }
        Finish({grpc::StatusCode::INVALID_ARGUMENT,
                "Version string must of form XXX.YYY.ZZZ"});
        return;  
    }


    // Now login 
    auto jwt
       = UEventAnalysisToolBackend::Auth::loginBasic(
             authNZ, *context, pImpl->mLogger.get());
    if (jwt.has_value())
    {
        // TODO lift the claims - i think i need a slightly better login
        //      function in authnz that returns the jwt AND permissions
        //      or i could just always return the jwt in the Claims
        //      though it's a little bit redundant for when i'm checking
        //      the user via the jwt (since i clearly already have the jwt)
        if (request.has_identifier())
        {
            *response->mutable_identifier() = request.identifier();
        }
        *response->mutable_json_web_token() = std::move(*jwt);
        *response->mutable_details() = std::move(messages);
        pImpl->mSuccess = true;
    }
    else
    {
        if (pImpl->mLogger)
        {
            SPDLOG_LOGGER_DEBUG(pImpl->mLogger,
                                "BasicLoginReactor failed for {}",
                                 pImpl->mPeer);
        }
        pImpl->mSuccess = false;
        Finish(std::move(jwt.error()));
        return;
    }
    pImpl->mSuccess = true;
    Finish(grpc::Status::OK);
    if (pImpl->mLogger)
    {
        SPDLOG_LOGGER_DEBUG(pImpl->mLogger,
                            "BasicLoginSuccessful for {}",
                            pImpl->mPeer);
    }

}

BasicLoginReactor::~BasicLoginReactor() = default;

void BasicLoginReactor::OnDone()
{
    if (pImpl->mLogger)
    {
        SPDLOG_LOGGER_DEBUG(pImpl->mLogger,
                            "BasicLogin RPC completed for {}",
                            pImpl->mPeer);
    }
    // Update metrics
    if (pImpl->mSuccess)
    {
        auto endTime
            = std::chrono::duration_cast<std::chrono::nanoseconds>
              ((std::chrono::high_resolution_clock::now()).time_since_epoch());
        auto elapsedTime
            = static_cast<double>
              (endTime.count() - pImpl->mRPCStartTime.count())*1.e-9;
    }

    delete this;
}

void BasicLoginReactor::OnCancel()
{
    if (pImpl->mLogger)
    {
        SPDLOG_LOGGER_DEBUG(pImpl->mLogger,
                            "BasicLogin canceled by {}",
                            pImpl->mPeer);
    }
}
