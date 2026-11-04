#ifndef UEVENT_ANALYSIS_TOOL_BACKEND_AUTH_USER_LOGIN_AUTHORITY_HPP
#define UEVENT_ANALYSIS_TOOL_BACKEND_AUTH_USER_LOGIN_AUTHORITY_HPP
#include <expected>
#include <memory>
#include <utility>
#include <spdlog/logger.h>
#include <uEventAnalysisToolBackend/auth/authenticator.hpp>
namespace UEventAnalysisToolBackend::Auth
{
 class UserLoginAuthorityOptions;
 namespace Password
 {
  class PasswordPolicy;
 }
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
    enum class ChangePasswordError
    {
        Unauthenticated,     /*!< Could not authenticate this user. */
        PasswordTooShort,    /*!< New password is too short. */
        PasswordNeedsNumber, /*!< The new password requires a number. */
        PasswordNeedsSpecialCharacter, /*!< The new password needs a new character. */
        PasswordTooLong, /*!< The new password is too long. */
        PasswordsMatch,  /*!< The new and old password match. */
        ServerError
    };
public:
    /// @brief Constructor.
    /// @param[in] options   The login authority options.
    /// @param[in] logger    The application logger.
    /// @throws std::invalid_argument if the database is null, the
    ///         algorithm is unsigned, or there is no private key.
    UserLoginAuthority(const UserLoginAuthorityOptions &options,
                       std::shared_ptr<spdlog::logger> logger); 

    /// @result True indicates that the authority is initialized.
    [[nodiscard]] bool isInitialized() const noexcept;

    /// @brief Password login.
    /// @param[in] userNameAndPassword  The user name (first) and password
    ///                                 (second). 
    /// @result On success, this mints a new user token - i.e., this is
    ///         not an admin claim.  
    [[nodiscard]] std::expected<std::string, IAuthenticator::Result>
        loginWithPassword(const std::pair<std::string, std::string> &userNameAndPassword) const;

    /// @brief Changes password.
    /// @param[in] userNameAndPassword  The user name (frist) and password
    ///                                 (second).
    /// @param[in] newPassword  The password.
    /// @result True indicates this was successful.
    [[nodiscard]] auto changePassword(const std::pair<std::string, std::string> &userNameAndPassword,
                                      const std::string &newPassword) -> std::expected<void, ChangePasswordError>;

    /// @brief Key-based login.
    /// @param[in] publicKey  The user's public key.
    /// @param[in] assertion  A JSON Web Signature signed by the client with
    ///                       the EdDSA algorithm.
    /// @result On success, this mints a new user token.
    [[nodiscard]] std::expected<std::string, IAuthenticator::Result>
        loginWithKey(const std::vector<unsigned char> &publicKey,
                     const std::string &assertion) const;

    /// @brief Checks a password without minting a token.  This is for
    ///        changing a password and changing a key which demand the
    ///        user provide their password.
    [[nodiscard]] auto verifyPassword(
         const std::pair<std::string, std::string> &userNameAndPassword) const
         -> std::expected<void, IAuthenticator::Result>;

    /// @result The password policy.
    /// @note This is a convenience function to benefit an RPC.
    /// @throws std::runtime_error if \c isInitialized() is false.
    [[nodiscard]] Password::PasswordPolicy getPasswordPolicy() const;


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
