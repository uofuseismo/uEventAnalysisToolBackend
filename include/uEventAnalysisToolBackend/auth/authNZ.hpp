#ifndef UEVENT_ANALYSIS_TOOL_BACKEND_AUTH_AUTHNZ_HPP
#define UEVENT_ANALYSIS_TOOL_BACKEND_AUTH_AUTHNZ_HPP
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <spdlog/logger.h>
#include <uEventAnalysisToolBackend/auth/authenticator.hpp>
#include <uEventAnalysisToolBackend/auth/jsonWebToken.hpp>

namespace UEventAnalysisToolBackend::Auth
{
 class Database;
}

namespace UEventAnalysisToolBackend::Auth
{
/// @class AuthNZ authNZ.hpp
/// @brief Authentication (who are you?) and authorization (what may you
///        do?) rolled into the one-stop utility the gRPC interceptor
///        consults.  Login performs basic authentication against the
///        database and mints a signed token carrying the user's
///        permissions; every subsequent request is authenticated and
///        authorized from the token alone - no database traffic.
/// @copyright Ben Baker (University of Utah) distributed under the
///            MIT NO AI license.
class AuthNZ
{
public:

    /// @brief Constructor.
    /// @param[in,out] databaseAuthenticator  Performs the basic (user and
    ///                                       password) authentication and
    ///                                       provides the permissions.
    /// @param[in,out] tokenAuthority  Mints and verifies the bearer tokens.
    /// @param[in] logger  The application's logger.
    /// @throws std::invalid_argument if either utility is null or the
    ///         token authority does not sign its tokens - clients could
    ///         forge permissions on an unsigned token.
    AuthNZ(std::unique_ptr<Database> &&databaseAuthenticator,
           std::unique_ptr<JSONWebToken> &&tokenAuthority,
           std::shared_ptr<spdlog::logger> logger);

    /// @brief Logs a user in with basic authentication.  On success the
    ///        user's permissions are read from the database and baked
    ///        into the returned signed token.
    /// @param[in] userNameAndPassword  The user name and password.
    /// @result The authentication result and, on Authenticated, the token.
    /// @throws std::invalid_argument if the user is empty.
    [[nodiscard]] std::pair<IAuthenticator::Result, std::string>
        login(const std::pair<std::string, std::string> &userNameAndPassword);

    /// @brief Authenticates a bearer token; this is the per-RPC check.
    /// @param[in] jwt  The token from the request's authorization metadata.
    /// @result The authentication result and, on Authenticated, who the
    ///         caller is and what they may do.
    /// @throws std::invalid_argument if the token is empty.
    [[nodiscard]] std::pair<IAuthenticator::Result, std::optional<JSONWebToken::Claims>>
        authenticate(const std::string &jwt) const;

    /// @result True if the identity may act at the required permission
    ///         level on the schema.  read_write satisfies read_only.
    [[nodiscard]] static bool isAuthorized(
        const JSONWebToken::Claims &identity,
        const std::string &schema,
        const std::string &permission) noexcept;

    /// @brief Destructor.
    ~AuthNZ();

    AuthNZ() = delete;
    AuthNZ(const AuthNZ &) = delete;
    AuthNZ(AuthNZ &&) noexcept = delete;
    AuthNZ& operator=(const AuthNZ &) = delete;
    AuthNZ& operator=(AuthNZ &&) noexcept = delete;
private:
    class AuthNZImpl;
    std::unique_ptr<AuthNZImpl> pImpl;
};
}
#endif