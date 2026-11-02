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

    /// @brief Creates the token; permissions, when present, ride in the
    ///        signed payload.
    [[nodiscard]] std::string createToken(const std::string &user)
    {   
        auto isAdmin = isAdministrator(user);
        auto permissions = getPermissions(user);
        const std::chrono::seconds expiration{mOptions.getTimeToLive()};
        auto token = jwt::create<jwt::traits::boost_json> (); 
        token.set_subject(user)
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

    // Check the users password
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
                if (!recordLogin(user))
                {
                    SPDLOG_LOGGER_WARN(mLogger,
                                       "Failed to record login for {}",
                                       user); 
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
    const auto &user = userNameAndPassword.first;
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
            = pImpl->authenticateByUserNameAndPassword(userNameAndPassword);
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

/// Change the user name and password
std::expected<void, UserLoginAuthority::ChangePasswordError>
UserLoginAuthority::changePassword(
    const std::pair<std::string, std::string> &userNameAndPassword,
    const std::string &newPassword)
{
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

    // Make the user login
    auto loginResult = loginWithPassword(userNameAndPassword);
    if (loginResult.has_value())
    {
        try
        {
            auto hashedPassword = pImpl->mPasswordHasher->hash(newPassword);
            if (hashedPassword.empty())
            {
                SPDLOG_LOGGER_ERROR(pImpl->mLogger,
                                    "Resulting hashed password is empty");
                return std::unexpected(ChangePasswordError::ServerError);
            }
            auto wasSuccess = pImpl->changePassword(
                  std::pair {userNameAndPassword.first, hashedPassword}); 
            if (!wasSuccess)
            {
                SPDLOG_LOGGER_ERROR(pImpl->mLogger,
                                    "Failed to update password for {}",
                                    userNameAndPassword.first);
                return std::unexpected(ChangePasswordError::ServerError);
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
        if (loginResult.error() == IAuthenticator::Result::InvalidCredentials)
        {
            return std::unexpected(ChangePasswordError::Unauthenticated);
        }
        return std::unexpected(ChangePasswordError::ServerError);
    }
    return {};
}


/// Destructor
UserLoginAuthority::~UserLoginAuthority() = default;
