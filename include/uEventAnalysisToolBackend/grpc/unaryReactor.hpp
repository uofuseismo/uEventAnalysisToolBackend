#ifndef UEVENT_ANALYSIS_TOOL_BACKEND_GRPC_UNARY_REACTOR_HPP
#define UEVENT_ANALYSIS_TOOL_BACKEND_GRPC_UNARY_REACTOR_HPP
#include <chrono>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <spdlog/logger.h>
#include <grpcpp/server_context.h>
#include <grpcpp/support/server_callback.h>
#include <grpcpp/support/status.h>
#include <uEventAnalysisToolBackend/auth/claims.hpp>

namespace UEventAnalysisToolBackend::Auth
{
 class AdministratorTokenVerifier;
 class UserTokenVerifier;
}
namespace UEventAnalysisToolBackend::GRPC
{

/// @class UnaryReactor unaryReactor.hpp
/// @brief Defines the default behavior for a ServerUnaryReactor in this
///        library.  It logs, completion, cancellation, and checks
///        bearer tokens.
/// @note Derived reactors do their work in the constructor and
///       should be marked final.
/// @copyright Ben Baker (University of Utah) distriuted under the
///            MIT NO AI licnese.
class UnaryReactor : public grpc::ServerUnaryReactor
{
protected:
    UnaryReactor(grpc::CallbackServerContext *context,
                 const std::string &routeName,
                 std::shared_ptr<spdlog::logger> logger);

    UnaryReactor(grpc::CallbackServerContext *context,
                 const std::string &routeName,
                 std::shared_ptr<spdlog::logger> logger,
                 const Auth::AdministratorTokenVerifier &verifier);

    UnaryReactor(grpc::CallbackServerContext *context,
                 const std::string &routeName,
                 std::shared_ptr<spdlog::logger> logger,
                 const Auth::UserTokenVerifier &verifier);


    /// @brief Runs work and finishes with its status; an exception from work
    ///        is logged and becomes INTERNAL.
    void run(const std::function<grpc::Status ()> &work);

    /// Finishes the call; records success when the status is OK.
    void finish(const grpc::Status &status);

    /// @result True indicates the user was authenticated.
    [[nodiscard]] bool isAuthenticated() const noexcept;
    /// @result The Claims.
    [[nodiscard]] const std::optional<Auth::Claims> &getClaims() const noexcept;
    /// @result The request identifier.
    [[nodiscard]] const std::string &requestIdentifier() const noexcept;
    /// @result A handle to the logger.
    [[nodiscard]] spdlog::logger &logger() const noexcept;
private:
    /// @brief Logs "{route} completed and metrics.
    void OnDone() final;
    /// @brief Logs the cancel.
    void OnCancel() final;
    grpc::CallbackServerContext *mContext{nullptr};
    std::string mRouteName;
    std::shared_ptr<spdlog::logger> mLogger{nullptr};
    std::string mRequestIdentifier;
    std::optional<Auth::Claims> mClaims{std::nullopt};
    const std::chrono::time_point<std::chrono::steady_clock> mRPCStartTime
    {
        std::chrono::steady_clock::now()
    };    
    bool mSuccess{false};
    bool mFinished{false};
};

}
#endif
