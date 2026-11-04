#include <algorithm>
#include <cctype>
#include <chrono>
#include <exception>
#include <expected>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>
#include <spdlog/spdlog.h>
#include <spdlog/logger.h>
#include <spdlog/sinks/stdout_color_sinks.h> //NOLINT
#include <boost/json/object.hpp>
#include <sodium/crypto_sign.h>
#include <jwt-cpp/jwt.h>
#include <jwt-cpp/traits/boost-json/traits.h>
#include "uEventAnalysisToolBackend/auth/userLoginAuthority.hpp"
#include "uEventAnalysisToolBackend/auth/authenticator.hpp"
#include "uEventAnalysisToolBackend/auth/userLoginAuthorityOptions.hpp"
#include "uEventAnalysisToolBackend/auth/password/hasher.hpp"
#include "uEventAnalysisToolBackend/auth/password/hasherOptions.hpp"
#include "uEventAnalysisToolBackend/auth/password/passwordPolicy.hpp"
#include "databaseUtilities.hpp"

using namespace UEventAnalysisToolBackend::Auth;

class UserLoginAuthority::UserLoginAuthorityImpl :
    public Detail::DatabaseConnection::Database
{
public:
    UserLoginAuthorityImpl(
        const UserLoginAuthorityOptions &options,
        std::shared_ptr<spdlog::logger> logger) :
        Detail::DatabaseConnection::Database
        {
            "UserLoginAuthorityConsole",
            options.getDatabaseCredentials(),
            std::move(logger)
        },
        mOptions(options)
    {
        if (!mOptions.hasKeyPairAndAlgorithm())
        {
            throw std::invalid_argument("Key pair and algorithm not set");
        }
        if (!mOptions.hasIssuer())
        {
            throw std::invalid_argument("Issuer not set");
        }
        if (!mOptions.hasTimeToLive())
        {
            throw std::invalid_argument("Time-to-live not set");
        }
        mPasswordHasher
            = std::make_unique<Password::Hasher>
              (mOptions.getPasswordHasherOptions());
        // Connect since this will get hit fairly often
        try
        {
            connect();
            if (!isConnected())
            {
                throw std::runtime_error("Failed to connect to user database");
            }
            SPDLOG_LOGGER_INFO(mLogger, "Connected to user auth database");
        }
        catch (const std::exception &e) 
        {
            throw std::runtime_error(
                std::string {"Failed to connect to user database because "}
              + e.what());
        }
        mInitialized = true;
    }

    /// @brief Gets the user name from the database.  This enforces
    ///        consistency in casing.
    [[nodiscard]] std::optional<std::string>
        getUserName(const std::string &user)
    {
        constexpr std::string_view query{"SELECT auth.get_user_name($1)"};
        const pqxx::params parameters{user};
        return withTransaction<pqxx::read_transaction>(
            [&](pqxx::read_transaction &transaction)
             -> std::optional<std::string>
            {
                auto row = transaction.exec(query, parameters).one_row();
                if (row.at(0).is_null()){return std::nullopt;}
                return row[0].as<std::string> ();
            });
    }

    /// @brief Creates the token; permissions, when present, ride in the
    ///        signed payload.
    [[nodiscard]] std::string createToken(const std::string &user)
    {   
        auto isAdmin = isAdministrator(user);
        auto permissions = getPermissions(user);
        auto name = getUserName(user);
        if (name == std::nullopt)
        {
            throw std::runtime_error(user + " does not exist");
        }
        const std::chrono::seconds expiration{mOptions.getTimeToLive()};
        auto token = jwt::create<jwt::traits::boost_json> (); 
        token.set_subject(*name)
             .set_issuer(mOptions.getIssuer())
             .set_type("JWT")
             .set_issued_now()
             .set_expires_in(expiration);
        token.set_payload_claim("administrator", isAdmin); 
        token.set_payload_claim("scope", "user");
        if (!permissions.empty())
        {
            boost::json::object permissionsObject;
            for (const auto &[schema, permission] : permissions)
            {
                permissionsObject[schema] = permission;
            }
            const std::string permissionsClaim{"permissions"};
            token.set_payload_claim(
                permissionsClaim,
                jwt::basic_claim<jwt::traits::boost_json>
                    {boost::json::value {permissionsObject}});
        }
        if (mOptions.getAlgorithm() ==
            UserLoginAuthorityOptions::Algorithm::EdDSA25519)
        {
            const std::string publicKeyPassword{""};
            const std::string privateKeyPassword{""};
            auto [publicKey, privateKey] = mOptions.getKeyPair();
            return token.sign(jwt::algorithm::ed25519(
                                  publicKey,
                                  privateKey,
                                  publicKeyPassword,
                                  privateKeyPassword));
        }
        else
        {
            throw std::runtime_error("Only eddsa25519 implemented");
        }
    }

    /// @brief Gets the (schema, permission) pairs for the user.
    [[nodiscard]] std::vector<std::pair<std::string, std::string>>
        getPermissions(const std::string &user)
    {   
        if (user.empty()){throw std::invalid_argument("User is empty");}
        constexpr std::string_view query{
            "SELECT schema_name, permission_name FROM auth.list_user_schemas($1)"};
        const pqxx::params parameters{user};
        return withTransaction<pqxx::read_transaction>(
            [&](pqxx::read_transaction &transaction)
                -> std::vector<std::pair<std::string, std::string>>
            {
                std::vector<std::pair<std::string, std::string>> result;
                for (const auto &row : transaction.exec(query, parameters))
                {
                    result.emplace_back(row.at(0).as<std::string> (), 
                                        row.at(1).as<std::string> ());
                }
                return result;
            });
    }

    /// @brief Verify this user is an admin.
    [[nodiscard]] bool isAdministrator(const std::string &user)
    {   
        constexpr std::string_view query{"SELECT auth.user_is_admin($1)"};
        const pqxx::params parameters{user};
        return withTransaction<pqxx::read_transaction>(
            [&](pqxx::read_transaction &transaction) -> bool
            {   
                auto row = transaction.exec(query, parameters).one_row();
                const auto isAdmin = row.at(0).as<bool> (); 
                return isAdmin;
            }); 
    }

    /// @brief Updates the password. 
    /// @note If this the user's first login this will also clear
    ///       provisional_until and stamp activated.
    /// @result True indicates the user's password was updated.
    ///         False indicates either - the user doesn't exist or
    ///         user is provisional and the issued password has expired.
    [[nodiscard]] 
    bool changePassword(
        const std::pair<std::string, std::string> &userAndHashedPassword)
    {
        constexpr std::string_view query{"SELECT auth.update_user_password($1, $2)"};
        const pqxx::params parameters{userAndHashedPassword.first,
                                      userAndHashedPassword.second};
        return withTransaction<pqxx::work>(
            [&](pqxx::work &transaction) -> bool
            {
                const auto success
                   = transaction.exec(query, parameters).one_row()
                                                        .at(0).as<bool> ();
                transaction.commit();
                return success;
            });
    }

    /// @brief Record a successful login.
    [[nodiscard]] bool recordLogin(const std::string &user)
    {
        constexpr std::string_view query{"SELECT auth.record_login($1)"};
        const pqxx::params parameters{user};
        return withTransaction<pqxx::work>(
            [&](pqxx::work &transaction) -> bool
            {
                auto row = transaction.exec(query, parameters).one_row();
                const auto success = row.at(0).as<bool> ();
                // Without the commit the last_login update rolls back on
                // the transaction's destruction.
                transaction.commit();
                return success;
            });
    }

    /// @brief Records key use.
    [[nodiscard]] bool recordKeyUse(const std::string &key)
    {
        constexpr std::string_view query{"SELECT auth.record_key_use($1)"};
        const pqxx::params parameters{key};
        return withTransaction<pqxx::work>(
            [&](pqxx::work &transaction) -> bool
            {
                auto row = transaction.exec(query, parameters).one_row();
                const auto success = row.at(0).as<bool> ();
                // Without the commit the last_login update rolls back on
                // the transaction's destruction.
                transaction.commit();
                return success;
            });
    } 

    /// @brief Gets the hashed password from the database.
    /// @result The hashed password (or null if the user does not exist).
    [[nodiscard]] std::optional<std::string> 
        getHashedPasswordFromDatabase(const std::string &user)
    {
        if (user.empty())
        {
            throw std::runtime_error("User is empty");
        }
        constexpr std::string_view query{"SELECT auth.get_password_hash($1)"};
        const pqxx::params parameters{user};
        return withTransaction<pqxx::read_transaction>(
            [&](pqxx::read_transaction &transaction) -> std::optional<std::string>
            {
                auto row = transaction.exec(query, parameters).one_row();
                // Null indicates no user
                if (row.at(0).is_null()){return std::nullopt;}
                return row[0].as<std::string> ();
            });
    }

    /// @brief Indicates the user must (first) change their password.
    /// @result True means the user must first change their password before
    ///         logging in.
    [[nodiscard]] std::optional<bool> userMustChangePassword(const std::string &user)
    {
        if (user.empty())
        {
            throw std::runtime_error("User is empty");
        }
        constexpr std::string_view query{"SELECT auth.user_must_change_password($1)"};
        const pqxx::params parameters{user};
        return withTransaction<pqxx::read_transaction>(
            [&](pqxx::read_transaction &transaction) -> std::optional<bool>
            {
                auto row = transaction.exec(query, parameters).one_row();
                // Null indicates no user
                if (row.at(0).is_null()){return std::nullopt;}
                return row[0].as<bool> ();
            });
    }

    // @result The key owner (user) name if the key is active (i.e., exists and
    //         is not revoked or expired etc.) 
    [[nodiscard]] std::optional<std::string> getUserByKey(const std::string &key)
    {
        if (key.empty())
        {   
            throw std::runtime_error("Key is empty");
        }
        constexpr std::string_view query{"SELECT auth.get_user_by_key($1)"};
        const pqxx::params parameters{key};
        return withTransaction<pqxx::read_transaction>(
            [&](pqxx::read_transaction &transaction)->std::optional<std::string>
            {
                auto row = transaction.exec(query, parameters).one_row();
                // Null indicates no user
                if (row.at(0).is_null()){return std::nullopt;}
                return row[0].as<std::string> (); 
            });
    }

    // Check the user's password
    [[nodiscard]] IAuthenticator::Result authenticateByUserNameAndPassword(
        const std::pair<std::string, std::string> &userAndPassword)
    {   
        auto user = userAndPassword.first;
        auto password = userAndPassword.second;
        auto hashedPassword = getHashedPasswordFromDatabase(user);
        if (hashedPassword != std::nullopt)
        {
            if (Password::Hasher::verify(password, *hashedPassword))
            {
                auto mustChangePassword = userMustChangePassword(user);
                if (mustChangePassword.has_value() && *mustChangePassword)
                {
                    SPDLOG_LOGGER_WARN(mLogger,
                                       "Rejecting {} - password not yet changed",
                                       user);
                    return IAuthenticator::Result::PasswordChangeRequired;
                }
                // Rehash required?
                try
                {
                    if (mPasswordHasher->needsRehash(*hashedPassword))
                    {
                        SPDLOG_LOGGER_INFO(mLogger,
                                           "Rehashing password for {}", user);
                        auto newPassword = mPasswordHasher->hash(password);
                        if (!changePassword(std::pair{user, newPassword}))
                        {
                            // Should not happen but want this to be really
                            // annoying for me instead of locking them out for
                            // specifying the right credentials - hence no return
                            // servererrorr
                            SPDLOG_LOGGER_ERROR(mLogger,
                               "Failed to change password for {}; proceeding",
                               user);
                        }
                    }
                }
                catch (const std::exception &e)
                {
                    SPDLOG_LOGGER_ERROR(mLogger,
                    "Failed to rehash password for {} because {}; proceeding",
                    user, e.what());
                } 

                try
                {
                    if (!recordLogin(user))
                    {
                        SPDLOG_LOGGER_WARN(mLogger,
                                           "Failed to record login for {}",
                                           user); 
                    }
                }
                catch (const std::exception &e)
                {
                    SPDLOG_LOGGER_ERROR(mLogger,
                    "Failed to to record login for {} because {}; proceeding",
                    user, e.what());
                }
                return IAuthenticator::Result::Authenticated;
            }
            else
            {
                // Wrong password
                SPDLOG_LOGGER_WARN(mLogger,
                                   "{} provided incorrect password",
                                   user);
                return IAuthenticator::Result::InvalidCredentials; 
            }
        }
        else
        {
            SPDLOG_LOGGER_WARN(mLogger, "{} not in database", user);
            return IAuthenticator::Result::InvalidCredentials;
        }
        SPDLOG_LOGGER_ERROR(mLogger, "Unhandled login workflow");
        return IAuthenticator::Result::ServerError;
    }

//private:
    UserLoginAuthorityOptions mOptions;
    std::unique_ptr<Password::Hasher> mPasswordHasher{nullptr};
    bool mInitialized{false};
};

/// Constructor
UserLoginAuthority::UserLoginAuthority
(
    const UserLoginAuthorityOptions &options,
    std::shared_ptr<spdlog::logger> logger
) :
    pImpl(std::make_unique<UserLoginAuthorityImpl> (options,
                                                    std::move(logger)))
{
}
    
/// Initialized
bool UserLoginAuthority::isInitialized() const noexcept
{
    return pImpl->mInitialized;
}

/// Get the password policy
Password::PasswordPolicy UserLoginAuthority::getPasswordPolicy() const
{
    if (!isInitialized()) 
    {
        throw std::runtime_error("Class not initialized");
    }
    return pImpl->mOptions.getPasswordPolicy();
}

/// Login with password and get a token
std::expected<std::string, IAuthenticator::Result>
UserLoginAuthority::loginWithPassword(
    const std::pair<std::string, std::string> &userNameAndPassword) const
{
    if (!isInitialized())
    {   
        SPDLOG_LOGGER_ERROR(pImpl->mLogger,
                            "UserLoginAuthority not initialized");
        return std::unexpected(IAuthenticator::Result::ServerError);
    }   
    auto user = userNameAndPassword.first;
    std::ranges::transform(user, user.begin(),
                       [](const unsigned char c)
                       {
                           return static_cast<char> (std::tolower(c));
                       });
    if (user.empty())
    {
        SPDLOG_LOGGER_WARN(pImpl->mLogger,
                         "Rejecting user login attempt because user is empty");
        return std::unexpected(IAuthenticator::Result::InvalidCredentials);
    }
    // Check against database
    try 
    {   
        auto result
            = pImpl->authenticateByUserNameAndPassword(
                 std::pair{ user, userNameAndPassword.second} );
        if (result == IAuthenticator::Result::Authenticated)
        {
            // Create the JWT
            try
            {
                return pImpl->createToken(user); 
            }
            catch (const std::exception &e) 
            {
                SPDLOG_LOGGER_ERROR(pImpl->mLogger,
                                    "Failed to create token for {} because {}",
                                    user, e.what());
                return std::unexpected(IAuthenticator::Result::ServerError);
            }
        }
        return std::unexpected(result);
    }   
    catch (const std::exception &e) 
    {   
        SPDLOG_LOGGER_WARN(pImpl->mLogger,
                           "Database failure {} when authentcating {}",
                           e.what(), user);
        return std::unexpected(IAuthenticator::Result::ServerError);
    }   
}

/// Login with password and get a token
std::expected<std::string, IAuthenticator::Result>
UserLoginAuthority::loginWithKey(
    const std::pair<std::string, std::string> &keyAndSignature) const
{
    if (!isInitialized())
    {
        SPDLOG_LOGGER_ERROR(pImpl->mLogger,
                            "UserLoginAuthority not initialized");
        return std::unexpected(IAuthenticator::Result::ServerError);
    }
    if (keyAndSignature.first.empty())
    {
        SPDLOG_LOGGER_WARN(pImpl->mLogger,
                         "Rejecting user login attempt because key is empty");
        return std::unexpected(IAuthenticator::Result::InvalidCredentials);
    }
// TODO copy public key and check size
    std::string user;
    try
    {
        auto userResult = pImpl->getUserByKey(keyAndSignature.first);
        if (!userResult.has_value())
        {
            SPDLOG_LOGGER_WARN(pImpl->mLogger,
               "No corresponding key found for user login attempt");
            return std::unexpected(IAuthenticator::Result::InvalidCredentials);
        } 
        user = std::move(*userResult);
    }
    catch (const std::exception &e)
    {
        SPDLOG_LOGGER_WARN(pImpl->mLogger,
                           "Error getting user by key - {}", e.what());
        return std::unexpected(IAuthenticator::Result::ServerError);
    }
    unsigned char signature[crypto_sign_BYTES];
    unsigned char publicKey[crypto_sign_PUBLICKEYBYTES];
    std::vector<unsigned char> signedMessage;
    if (crypto_sign_verify_detached(signature,
                                    signedMessage.data(),
                                    signedMessage.size(),
                                    publicKey) != 0)
    {
        SPDLOG_LOGGER_WARN(pImpl->mLogger,
              "Rejecting user login attempt; invalid signature");
        return std::unexpected(IAuthenticator::Result::InvalidCredentials);
    }
    // Create the JWT
    std::string token;
    try          
    {
        token = pImpl->createToken(user);
    }
    catch (const std::exception &e) 
    { 
        SPDLOG_LOGGER_ERROR(pImpl->mLogger,
                            "Failed to create token for {} because {}",
                            user, e.what());
        return std::unexpected(IAuthenticator::Result::ServerError);
    }
    try
    {
        if (!pImpl->recordKeyUse(keyAndSignature.second))
        {
            SPDLOG_LOGGER_WARN(pImpl->mLogger,
                               "Failed to record key use for {}",
                               user);
        }
    }
    catch (const std::exception &e)
    {
        SPDLOG_LOGGER_WARN(pImpl->mLogger,
                           "Failed to record key use for {} because {}",
                           user, e.what());
    }
// TODO do i need to do this?
    try
    {
        if (!pImpl->recordLogin(user))
        {
            SPDLOG_LOGGER_WARN(pImpl->mLogger,
                               "Failed to record login for {}",
                               user);
        }
    }
    catch (const std::exception &e)
    {
        SPDLOG_LOGGER_WARN(pImpl->mLogger, "Error recording login because {}", e.what());
    }
    return token;
}

/// Change the user name and password
std::expected<void, UserLoginAuthority::ChangePasswordError>
UserLoginAuthority::changePassword(
    const std::pair<std::string, std::string> &userNameAndPassword,
    const std::string &newPassword)
{
    if (!isInitialized())
    {       
        SPDLOG_LOGGER_ERROR(pImpl->mLogger,
                            "UserLoginAuthority not initialized");
        return std::unexpected(
           UserLoginAuthority::ChangePasswordError::ServerError);
    }   
    // Validate the new password
    auto policy = pImpl->mOptions.getPasswordPolicy();
    auto validationResult
        = policy.validate(std::pair {newPassword, userNameAndPassword.second});
    if (validationResult ==
        Password::PasswordPolicy::ValidationResult::TooShort)
    {
        return std::unexpected(ChangePasswordError::PasswordTooShort);
    }
    else if (validationResult ==
             Password::PasswordPolicy::ValidationResult::TooLong)
    {
        return std::unexpected(ChangePasswordError::PasswordTooLong);
    }
    else if (validationResult ==
             Password::PasswordPolicy::ValidationResult::NoNumber)
    {
        return std::unexpected(ChangePasswordError::PasswordNeedsNumber);
    }
    else if (validationResult ==
             Password::PasswordPolicy::ValidationResult::NoSpecialCharacter)
    {
        return std::unexpected(
            ChangePasswordError::PasswordNeedsSpecialCharacter);
    }
    else if (validationResult ==
             Password::PasswordPolicy::ValidationResult::PasswordsMatch)
    {
        return std::unexpected(
            ChangePasswordError::PasswordsMatch);
    }

    // Check user's password (but not do a full login)
    auto verifyPasswordResult = verifyPassword(userNameAndPassword);
    if (verifyPasswordResult.has_value())
    {
        std::string hashedPassword;
        try
        {
            hashedPassword = pImpl->mPasswordHasher->hash(newPassword);
        }
        catch (const std::exception &e)
        {
            SPDLOG_LOGGER_ERROR(
                pImpl->mLogger,
                "Failed to hash password; skpping password update");
            return std::unexpected(ChangePasswordError::ServerError);
        }
        if (hashedPassword.empty())
        {
            SPDLOG_LOGGER_ERROR(pImpl->mLogger,
                                "Resulting hashed password is empty");
            return std::unexpected(ChangePasswordError::ServerError);
        }
        try
        {
            auto wasSuccess = pImpl->changePassword(
                  std::pair {userNameAndPassword.first, hashedPassword}); 
            if (!wasSuccess)
            {
                // Indicates provisional password expired between the
                // verify and update.
                SPDLOG_LOGGER_ERROR(pImpl->mLogger,
                                    "Failed to update password for {}",
                                    userNameAndPassword.first);
                return std::unexpected(ChangePasswordError::Unauthenticated);
            }
            else
            {
                SPDLOG_LOGGER_INFO(pImpl->mLogger,
                                   "{} updated password",
                                   userNameAndPassword.first);
            }
        }
        catch (const std::exception &e)
        {
            SPDLOG_LOGGER_ERROR(pImpl->mLogger,
                                "Failed to change password for {} because {}",
                                userNameAndPassword.first, e.what());
            return std::unexpected(ChangePasswordError::ServerError);
        }
    }
    else
    {
        if (verifyPasswordResult.error() ==
            IAuthenticator::Result::InvalidCredentials)
        {
            return std::unexpected(ChangePasswordError::Unauthenticated);
        }
        return std::unexpected(ChangePasswordError::ServerError);
    }
    return {};
}

/// Verify password
std::expected<void, IAuthenticator::Result>
UserLoginAuthority::verifyPassword(
    const std::pair<std::string, std::string> &userNameAndPassword) const
{
    if (!isInitialized())
    {       
        SPDLOG_LOGGER_ERROR(pImpl->mLogger,
                            "UserLoginAuthority not initialized");
        return std::unexpected(IAuthenticator::Result::ServerError);
    }   
    auto user = userNameAndPassword.first;
    if (user.empty())
    {
        SPDLOG_LOGGER_DEBUG(pImpl->mLogger, "Cannot verify an empty user name");
        return std::unexpected(IAuthenticator::Result::InvalidCredentials);
    }
    auto password = userNameAndPassword.second;
    try
    {
        auto hashedPassword = pImpl->getHashedPasswordFromDatabase(user);
        if (hashedPassword != std::nullopt)
        {
            if (Password::Hasher::verify(password, *hashedPassword))
            {
                return {};
            }
            SPDLOG_LOGGER_DEBUG(pImpl->mLogger, "{} passwords do not match",
                                user);
            return std::unexpected(IAuthenticator::Result::InvalidCredentials);
        }
        else
        {   
            SPDLOG_LOGGER_WARN(pImpl->mLogger, "{} not in database", user);
            return std::unexpected(IAuthenticator::Result::InvalidCredentials);
        }
    }
    catch (const std::exception &e)
    {
        SPDLOG_LOGGER_ERROR(pImpl->mLogger, "Hit exception {}", e.what());
        return std::unexpected(IAuthenticator::Result::ServerError);           
    }   
    SPDLOG_LOGGER_ERROR(pImpl->mLogger, "Unhandled verify password workflow");
    return std::unexpected(IAuthenticator::Result::ServerError);
}


/// Destructor
UserLoginAuthority::~UserLoginAuthority() = default;
