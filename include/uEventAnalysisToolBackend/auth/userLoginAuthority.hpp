#ifndef UEVENT_ANALYSIS_TOOL_BACKEND_AUTH_USER_LOGIN_AUTHORITY_HPP
#define UEVENT_ANALYSIS_TOOL_BACKEND_AUTH_USER_LOGIN_AUTHORITY_HPP
#include <expected>
#include <memory>
#include <utility>
#include <vector>
#include <spdlog/logger.h>
#include <uEventAnalysisToolBackend/auth/authenticator.hpp>
namespace UEventAnalysisToolBackend::Auth
{
 class ActiveKey;
 class InactiveKey;
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

    enum class KeyError
    {
        Unauthenticated,        /*!< Bad user name or password (add only). */
        PasswordChangeRequired, /*!< User still holds an issued password. */
        InvalidName,            /*!< Key name is empty or malformed. */
        InvalidKey,             /*!< Not a 32-byte ed25519 key, or the proof
                                     of possession failed. */
        InvalidExpiration,      /*!< Expiration is in the past or too far out. */
        NameInUse,              /*!< The user already has a key by this name. */
        KeyInUse,               /*!< This public key is already registered. */
        NoKeyFound,             /*!< No active key by this name (revoke only). */
        TooManyKeys,            /*!< No key was added because the user has hit 
                                     their limit. */
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

    /// @brief Registers a key.  The password is demanded because a key
    ///        outlives a password.
    /// @param[in] userNameAndPassword  The user's current credentials.
    /// @param[in] keyName     The user's label - e.g., laptop.
    /// @param[in] publicKey   The raw 32-byte ed25519 public key.
    /// @param[in] assertion   A JWS signed by the new key's private half,
    ///                        proving the caller holds it.
    /// @param[in] expiresAfter  If set, the key stops working this long
    ///                          from now.
    [[nodiscard]] auto addKey(
        const std::pair<std::string, std::string> &userNameAndPassword,
        const std::string &keyName,
        const std::vector<unsigned char> &publicKey,
        const std::string &assertion,
        const std::optional<std::chrono::seconds> &expiresAfter)
        -> std::expected<void, KeyError>;

    /// @param[in] user  The user who is requesting their claims.  
    /// @result The keys (active and inactive) owned by this user.
    [[nodiscard]] auto listKeys(const std::string &user) const
        -> std::expected
           <
              std::pair
              <
                 std::vector<ActiveKey>,
                 std::vector<InactiveKey>
              >,
              KeyError
           >;

    /// @param[in] user     From a verified token's claims - never the request.
    /// @param[in] keyName  The key to revoke.
    [[nodiscard]] auto revokeKey(const std::string &user,
                                 const std::string &keyName)
        -> std::expected<void, KeyError>;

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
