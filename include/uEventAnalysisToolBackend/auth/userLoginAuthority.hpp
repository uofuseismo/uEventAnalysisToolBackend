#ifndef UEVENT_ANALYSIS_TOOL_BACKEND_AUTH_USER_LOGIN_AUTHORITY_HPP
#define UEVENT_ANALYSIS_TOOL_BACKEND_AUTH_USER_LOGIN_AUTHORITY_HPP
#include <expected>
#include <memory>
#include <utility>
#include <spdlog/logger.h>
#include <uEventAnalysisToolBackend/auth/authenticator.hpp>
namespace UEventAnalysisToolBackend::Auth
{
 class Database;
 class LoginAuthorityOptions;
}
namespace UEventAnalysisToolBackend::Auth
{
/// @class UserLoginAuthority userLoginAuthority.hpp
/// @brief Converts credentials into tokens for user logins.
/// @copyright Ben Baker (University of Utah) distributed under the
///            MIT NO AI license.
class UserLoginAuthority
{
public:
    /// @brief Constructor.
    /// @param[in] userOptions  Defines the claims, TTL, and signature
    ///                         algorithm in user JWTs.
    /// @param[in] administratorOptions  Defines the claims, TTL, and signature
    ///                                  algorithm in administrator JWTs.
    /// @param[in] database  The auth.* database from which we will obtain
    ///                      users and their keys and permissions.
    /// @param[in] logger    The application logger.
    /// @throws std::invalid_argument if the database is null, the
    ///         algorithm is unsigned, or there is no private key.
    UserLoginAuthority(const LoginAuthorityOptions &options,
                       std::unique_ptr<Database> &&database,
                       std::shared_ptr<spdlog::logger> logger); 

    /// @brief Password login.
    /// @param[in] userNameAndPassword  The user name (first) and password
    ///                                 (second). 
    /// @result On success, this mints a new user token - i.e., this is
    ///         not an admin claim.  
    [[nodiscard]] std::expected<std::string, IAuthenticator::Result>
        loginWithPassword(const std::pair<std::string, std::string> &userNameAndPassword) const;
 
    /// @brief Key-based login.
    /// @param[in] userNameAndKey   The user name (first) and the
    ///                             user's public key (second).
    /// @result On success, this mints a new user token - i.e., this is
    ///         not an admin token and cannot be used in administartor
    ///         routes.
    [[nodiscard]] std::expected<std::string, IAuthenticator::Result>
        loginWithKey(const std::pair<std::string, std::string> &userNameAndKey) const; 

    /// @brief Checks a password without minting a token.  This is for
    ///        changing a password and changing a key which demand the
    ///        user provide their password.
    /// @result On success, the user name.
    [[nodiscard]] std::expected<std::string, IAuthenticator::Result>
        verifyPassword(const std::pair<std::string, std::string> &userNameAndPassword) const;

    /// @brief Destructor
    ~UserLoginAuthority();

    UserLoginAuthority() = delete;
    UserLoginAuthority(const UserLoginAuthority &) = delete;
    UserLoginAuthority(UserLoginAuthority &&) noexcept = delete;
    UserLoginAuthority& operator=(const UserLoginAuthority &) = delete;
    UserLoginAuthority& operator=(UserLoginAuthority &&) noexcept = delete;
private:
    class UserLoginAuthorityImpl;
    std::unique_ptr<UserLoginAuthorityImpl> pImpl;
};
}
#endif
