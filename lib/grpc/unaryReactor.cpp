#include <chrono>
#include <exception>
#include <functional>
#include <memory>
#include <string>
#include <optional>
#include <utility>
#include <spdlog/logger.h>
#include <spdlog/spdlog.h>
#include <grpcpp/server_context.h>
#include <grpcpp/support/server_callback.h>
#include <grpcpp/support/status.h>
#include "uEventAnalysisToolBackend/grpc/unaryReactor.hpp"
#include "uEventAnalysisToolBackend/auth/administratorTokenVerifier.hpp"
#include "uEventAnalysisToolBackend/auth/claims.hpp"
#include "uEventAnalysisToolBackend/auth/userTokenVerifier.hpp"
#include "uEventAnalysisToolBackend/grpc/requireBearer.hpp"
#include "uEventAnalysisToolBackend/grpc/toRequestIdentifier.hpp"

 
using namespace UEventAnalysisToolBackend::GRPC;
namespace UAuth = UEventAnalysisToolBackend::Auth;

UnaryReactor::UnaryReactor(grpc::CallbackServerContext *context,
                           const std::string &routeName,
                           std::shared_ptr<spdlog::logger> logger) :
    grpc::ServerUnaryReactor {},
    mContext(context),
    mRouteName(routeName),
    mLogger(std::move(logger))
{
    mRequestIdentifier = toRequestIdentifier(*mContext);
}

UnaryReactor::UnaryReactor(grpc::CallbackServerContext *context,
                           const std::string &routeName,
                           std::shared_ptr<spdlog::logger> logger,
                           const UAuth::UserTokenVerifier &verifier) :
    UnaryReactor{context, routeName, std::move(logger)}
{
    try
    {
        auto bearerResult = GRPC::requireBearer(*context, verifier);
        if (!bearerResult.has_value())
        {
            //metrics.incrementUnauthenticatedCounter(mRouteName);
            SPDLOG_LOGGER_WARN(mLogger,
                "{} did not provide user bearer authorization - rejected",
                mRequestIdentifier);
            finish(bearerResult.error());
            return;
        }
        mClaims = std::make_optional(std::move(*bearerResult));
    }
    catch (const std::exception &e)
    {
        SPDLOG_LOGGER_ERROR(mLogger,
                          "Bearer identification failed in {} for {} because {}",
                          mRouteName,
                          mRequestIdentifier,
                          e.what());
        finish({grpc::StatusCode::INTERNAL, "Authentication failure"});
    }
}

UnaryReactor::UnaryReactor(grpc::CallbackServerContext *context,
                           const std::string &routeName,
                           std::shared_ptr<spdlog::logger> logger,
                           const UAuth::AdministratorTokenVerifier &verifier) :
    UnaryReactor{context, routeName, std::move(logger)}
{
    try
    {
        auto bearerResult = GRPC::requireBearer(*context, verifier);
        if (!bearerResult.has_value())
        {   
            //metrics.incrementUnauthenticatedCounter(mRouteName);
            SPDLOG_LOGGER_WARN(mLogger,
            "{} did not provide administrator bearer authorization - rejected",
            mRequestIdentifier);
            finish(bearerResult.error());
            return;
        }   
        mClaims = std::make_optional(std::move(*bearerResult));
    }
    catch (const std::exception &e)
    {
        SPDLOG_LOGGER_ERROR(mLogger,
                          "Bearer identification failed in {} for {} because {}",
                          mRouteName,
                          mRequestIdentifier, 
                          e.what());
        finish({grpc::StatusCode::INTERNAL, "Authentication failure"});
    }
}

void UnaryReactor::run(const std::function<grpc::Status ()> &work)
{
    try
    {
        finish(work());
    }
    catch (const std::exception &e)
    {
        SPDLOG_LOGGER_ERROR(mLogger, "{} failed for {} because {}",
                            mRouteName, mRequestIdentifier, e.what());
        finish({grpc::StatusCode::INTERNAL, "Server error"});
    }
}

spdlog::logger &UnaryReactor::logger() const noexcept
{
    return *mLogger;
}

bool UnaryReactor::isAuthenticated() const noexcept
{
    return mClaims.has_value();
}

const std::optional<UAuth::Claims> &UnaryReactor::getClaims() const noexcept
{
    return mClaims;
}

void UnaryReactor::finish(const  grpc::Status &status)
{
    if (mFinished)
    {
        SPDLOG_LOGGER_DEBUG(mLogger,
                            "{} finished twice for {}; ignoring",
                            mRouteName,
                            mRequestIdentifier);
        return;
    }
    if (status.ok())
    {
        mSuccess = true;
        SPDLOG_LOGGER_INFO(mLogger,
                           "{} successfully completed for {}",
                           mRouteName,
                           mRequestIdentifier);
    }
    mFinished = true;
    Finish(status);
}


void UnaryReactor::OnDone()
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

void UnaryReactor::OnCancel()
{
    if (mLogger)
    {
        SPDLOG_LOGGER_DEBUG(mLogger,
                            "{} RPC canceled", mRouteName);
    }
}

