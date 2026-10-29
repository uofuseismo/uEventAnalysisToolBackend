#include <chrono>
#include <exception>
#include <expected>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string_view>
#include <utility>
#include <spdlog/spdlog.h>
#include <spdlog/logger.h>
#include <spdlog/sinks/stdout_color_sinks.h> //NOLINT
#include <jwt-cpp/jwt.h>
#include <jwt-cpp/traits/boost-json/traits.h>
#include <pqxx/pqxx>
#include "uEventAnalysisToolBackend/auth/administratorLoginAuthority.hpp"
#include "uEventAnalysisToolBackend/auth/authenticator.hpp"
#include "uEventAnalysisToolBackend/auth/database.hpp"
// NOLINTNEXTLINE(misc-include-cleaner)
#include "uEventAnalysisToolBackend/auth/databaseOptions.hpp"
#include "uEventAnalysisToolBackend/auth/loginAuthorityOptions.hpp"
#include "uEventAnalysisToolBackend/auth/password/hasher.hpp"
// NOLINTNEXTLINE(misc-include-cleaner)
#include "uEventAnalysisToolBackend/auth/password/hasherOptions.hpp"
//#include "uEventAnalysisToolBackend/auth/password/passwordPolicy.hpp"
#include "databaseUtilities.hpp"

using namespace UEventAnalysisToolBackend::Auth;

class AdministratorLoginAuthority::AdministratorLoginAuthorityImpl : 
    public ::IDatabase
{
public:
    AdministratorLoginAuthorityImpl(
        const LoginAuthorityOptions &options,
        std::shared_ptr<spdlog::logger> logger) :
        ::IDatabase
        {
            "AdministratorLoginAdministratorConsole",
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
        mInitialized = true;
    }

    /// @brief Creates the token; permissions, when present, ride in the
    ///        signed payload.
    [[nodiscard]] std::string createToken(const std::string &user) const
    {
        const std::chrono::seconds expiration{mOptions.getTimeToLive()};
        auto token = jwt::create<jwt::traits::boost_json> ();
        token.set_subject(user)
             .set_issuer(mOptions.getIssuer())
             .set_type("JWT")
             .set_issued_now()
             .set_expires_in(expiration);
        token.set_payload_claim("scope", "administrator");
        if (mOptions.getAlgorithm() ==
            LoginAuthorityOptions::Algorithm::EdDSA25519)
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
        return withTransaction(
            [&](pqxx::work &transaction) -> std::optional<std::string>
            {
                auto row = transaction.exec(query, parameters).one_row();
                // Null indicates no user
                if (row.at(0).is_null()){return std::nullopt;}
                return row[0].as<std::string> (); 
            });
    }

    /// @brief Record a successful login.
    [[nodiscard]] bool recordLogin(const std::string &user)
    {
        constexpr std::string_view query{"SELECT auth.record_login($1)"};
        const pqxx::params parameters{user};
        return withTransaction(
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

    /// @brief Updates the user password.
    /// @result True on success; false if the user does not exist.
    [[nodiscard]] bool updatePassword(
        const std::pair<std::string, std::string> &userAndPassword)
    {
        const auto &user = userAndPassword.first;
        if (user.empty()){throw std::invalid_argument("User is empty");}
        const auto &password = userAndPassword.second;
        if (password.empty()){throw std::invalid_argument("Password is empty");}
        // Hash outside the transaction: it is slow and needn't be redone
        // on a retry.
        auto hashedPassword = mPasswordHasher->hash(password);
        constexpr std::string_view query{"SELECT auth.update_user_password($1, $2)"};
        const pqxx::params parameters{user, hashedPassword};
        return withTransaction(
            [&](pqxx::work &transaction) -> bool
            {
                auto row = transaction.exec(query, parameters).one_row();
                const auto success = row.at(0).as<bool> (); 
                transaction.commit();
                return success;
            }); 
    }   

    // Check the administrators password
    [[nodiscard]] IAuthenticator::Result authenticateByUserNameAndPassword(
        const std::pair<std::string, std::string> &userAndPassword)
    {
        auto user = userAndPassword.first;
        auto password = userAndPassword.second;
        auto hashedPassword = getHashedPasswordFromDatabase(user);
        if (hashedPassword != std::nullopt)
        {
            if (mPasswordHasher->verify(password, *hashedPassword))
            {
                // Okay, we're in update
                if (!recordLogin(user))
                {
                    SPDLOG_LOGGER_WARN(mLogger,
                                       "Failed to record login for {}",
                                       user); 
                }
                // In case I changed some parameters see if we need a rehash
                bool needsRehash{false};
                try
                {
                    needsRehash = mPasswordHasher->needsRehash(*hashedPassword);
                }
                catch (const std::exception &e)
                {
                    needsRehash = true;
                    SPDLOG_LOGGER_WARN(mLogger,
                                       "Will rehash password because {}",
                                       e.what());
                }
                if (needsRehash)
                {
                    // Stored hash uses old/different params. 
                    // We'll update that now.
                    SPDLOG_LOGGER_INFO(mLogger, "Reshashing password for {}",
                                       user);
                    try
                    {
                        if (!updatePassword(std::pair{user, password}))
                        {
                            SPDLOG_LOGGER_WARN(mLogger,
                                               "Password rehash did not update {}",
                                               user);
                        }
                    }
                    catch (const std::exception &e)
                    {
                        // It's actually okay - we'll just try again on next
                        // login.  But the user is good to go
                        SPDLOG_LOGGER_WARN(mLogger,
                                           "Password update failed because {}",
                                           std::string {e.what()});
                    }
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


    LoginAuthorityOptions mOptions;
    std::unique_ptr<Password::Hasher> mPasswordHasher{nullptr};
    bool mInitialized{false};
};

/// Constructor
AdministratorLoginAuthority::AdministratorLoginAuthority
(
    const LoginAuthorityOptions &options,
    std::shared_ptr<spdlog::logger> logger
) :
    pImpl(std::make_unique<AdministratorLoginAuthorityImpl> 
             (
                 options,
                 std::move(logger)
             )
         )
{
}

/// Initialized?
bool AdministratorLoginAuthority::isInitialized() const noexcept
{
    return pImpl->mInitialized;
}

/// Login with password and get a token
std::expected<std::string, IAuthenticator::Result>
AdministratorLoginAuthority::loginWithPassword(
    const std::pair<std::string, std::string> &userNameAndPassword) const
{
    if (!isInitialized())
    {
        SPDLOG_LOGGER_ERROR(pImpl->mLogger,
                            "AdministratorLoginAuthority not initialized");
        return std::unexpected(IAuthenticator::Result::ServerError);
    }
    const auto &user = userNameAndPassword.first;
    if (user.empty())
    {
        SPDLOG_LOGGER_WARN(pImpl->mLogger,
                         "Rejecting admin login attempt because user is empty");
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
        return  std::unexpected(IAuthenticator::Result::ServerError);
    } 
}

/// Destructor
AdministratorLoginAuthority::~AdministratorLoginAuthority() = default;
